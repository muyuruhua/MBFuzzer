#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# run_mosquitto_parallel_docker.sh
#
# Parallel MBFuzzer campaign orchestrator for mosquitto.
#
# Architecture:
#   ┌──────────────────────────────────────────────────────────────┐
#   │ HOST                                                         │
#   │  worker01 (fuzz.py)          worker02 (fuzz.py)              │
#   │   server_module :1884          server_module :1894           │
#   │   cache_broker  :1885          cache_broker  :1895           │
#   │        │                             │                       │
#   │  ──────┼─────────────────────────────┼───── mqtt_network ──  │
#   │        │                             │                       │
#   │  mosquitto-w01 (172.199.0.11)  mosquitto-w02 (172.199.0.12) │
#   │   bridge → host:1884            bridge → host:1894           │
#   │   gcov-instrumented              gcov-instrumented           │
#   └──────────────────────────────────────────────────────────────┘
#
# Each worker gets:
#   • A unique mosquitto container (gcov-instrumented) on mqtt_network
#   • A patched copy of the MBFuzzer source with unique IPs/ports
#   • An independent output directory
#   • gcov branch-coverage collection after fuzzing completes
#
# Usage:
#   ./run_mosquitto_parallel_docker.sh --runs 2 --parallelism 2 --timeout 30
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MBFUZZER_SRC="${SCRIPT_DIR}/mbfuzzer"
DOCKER_DIR="${SCRIPT_DIR}/Docker"

# ─── Defaults ─────────────────────────────────────────────────────────────
DEFAULT_GCOV_IMAGE="mbfuzzer-mosquitto-gcov:2.0.18"
DEFAULT_PLAIN_IMAGE="eclipse-mosquitto:2"

RUN_COUNT=2
RUN_PARALLELISM=2
RUN_TIMEOUT_MINUTES=30
IMAGE_NAME="${MOSQUITTO_IMAGE:-${DEFAULT_GCOV_IMAGE}}"
DOCKER_NETWORK="${MQTT_DOCKER_NETWORK:-mqtt_network}"
CONDA_PYTHON="${CONDA_PYTHON:-/home/ckt/miniconda3/bin/python}"

# Worker IP allocation: 172.199.0.<WORKER_IP_OFFSET + run_index>
WORKER_IP_OFFSET="${WORKER_IP_OFFSET:-10}"
# Port spacing between workers (server_module, cache_broker)
SERVER_PORT_BASE=1884
CACHE_PORT_BASE=1885
PORT_STEP=10

# Host IP reachable from containers (auto-detected if empty)
HOST_BRIDGE_IP="${HOST_BRIDGE_IP:-}"

# ─── Usage ────────────────────────────────────────────────────────────────
usage() {
  cat <<'EOF'
Usage: run_mosquitto_parallel_docker.sh [OPTIONS]

Options:
  --runs N            Number of independent fuzzing runs (default: 2)
  --parallelism N     Maximum concurrent workers (default: 2)
  --timeout MINUTES   Fuzzing duration per run in minutes (default: 30)
                      Bare number = minutes; suffixed with s/m/h also accepted.
  --image IMAGE       Docker image (default: mbfuzzer-mosquitto-gcov:2.0.18)
  --network NET       Docker network name (default: mqtt_network)
  --python PATH       Path to Python interpreter
  -h, --help          Show this help message

Environment variables:
  MOSQUITTO_IMAGE         Override default Docker image
  MQTT_DOCKER_NETWORK     Override Docker network name
  CONDA_PYTHON            Override Python interpreter path
  HOST_BRIDGE_IP          Override auto-detected host bridge IP
  WORKER_IP_OFFSET        Starting offset for worker container IPs (default: 10)

Example:
  ./run_mosquitto_parallel_docker.sh --runs 2 --parallelism 2 --timeout 30
  ./run_mosquitto_parallel_docker.sh --runs 10 --parallelism 4 --timeout 60

Each run launches an independent:
  1. mosquitto container (gcov-instrumented) on a unique Docker network IP
  2. MBFuzzer Python process (unique output dir, ports, bridge config)
After fuzzing, gcovr collects branch coverage from each container.
Results are aggregated into a summary CSV.
EOF
}

fatal() {
  echo "[parallel] FATAL: $*" >&2
  exit 1
}

info() {
  echo "[parallel] $*"
}

warn() {
  echo "[parallel] WARNING: $*" >&2
}

# ─── Argument Parsing ────────────────────────────────────────────────────
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs)       shift; RUN_COUNT="${1:?--runs requires a value}" ;;
    --runs=*)     RUN_COUNT="${1#*=}" ;;
    --parallelism)  shift; RUN_PARALLELISM="${1:?--parallelism requires a value}" ;;
    --parallelism=*) RUN_PARALLELISM="${1#*=}" ;;
    --timeout)    shift; RUN_TIMEOUT_MINUTES="${1:?--timeout requires a value}" ;;
    --timeout=*)  RUN_TIMEOUT_MINUTES="${1#*=}" ;;
    --image)      shift; IMAGE_NAME="${1:?--image requires a value}" ;;
    --image=*)    IMAGE_NAME="${1#*=}" ;;
    --network)    shift; DOCKER_NETWORK="${1:?--network requires a value}" ;;
    --network=*)  DOCKER_NETWORK="${1#*=}" ;;
    --python)     shift; CONDA_PYTHON="${1:?--python requires a value}" ;;
    --python=*)   CONDA_PYTHON="${1#*=}" ;;
    -h|--help)    usage; exit 0 ;;
    *)            fatal "Unknown option: $1  (use --help for usage)" ;;
  esac
  shift
done

# ─── Normalize Timeout ───────────────────────────────────────────────────
# Accept bare integer (minutes), or suffixed: 30s, 30m, 2h
parse_timeout_to_seconds() {
  local raw="$1"
  if [[ "${raw}" =~ ^([0-9]+)s$ ]]; then
    echo "${BASH_REMATCH[1]}"
  elif [[ "${raw}" =~ ^([0-9]+)m$ ]]; then
    echo $(( BASH_REMATCH[1] * 60 ))
  elif [[ "${raw}" =~ ^([0-9]+)h$ ]]; then
    echo $(( BASH_REMATCH[1] * 3600 ))
  elif [[ "${raw}" =~ ^[0-9]+$ ]]; then
    # Bare number → minutes (consistent with live555 script)
    echo $(( raw * 60 ))
  else
    fatal "Invalid timeout value: ${raw}"
  fi
}

TIMEOUT_SECONDS="$(parse_timeout_to_seconds "${RUN_TIMEOUT_MINUTES}")"

# ─── Validation ──────────────────────────────────────────────────────────
[[ "${RUN_COUNT}" =~ ^[0-9]+$ ]] && (( RUN_COUNT >= 1 )) \
  || fatal "Invalid --runs value: ${RUN_COUNT}"

[[ "${RUN_PARALLELISM}" =~ ^[0-9]+$ ]] && (( RUN_PARALLELISM >= 1 )) \
  || fatal "Invalid --parallelism value: ${RUN_PARALLELISM}"

(( RUN_PARALLELISM > RUN_COUNT )) && RUN_PARALLELISM="${RUN_COUNT}"

command -v docker >/dev/null 2>&1 \
  || fatal "docker is not available on this host"

[[ -x "${CONDA_PYTHON}" ]] \
  || fatal "Python interpreter not found: ${CONDA_PYTHON}"

[[ -d "${MBFUZZER_SRC}" ]] \
  || fatal "MBFuzzer source not found: ${MBFUZZER_SRC}"

# ─── Docker Image Check ─────────────────────────────────────────────────
if ! docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
  if docker image inspect "${DEFAULT_GCOV_IMAGE}" >/dev/null 2>&1; then
    warn "Image '${IMAGE_NAME}' not found; falling back to '${DEFAULT_GCOV_IMAGE}'"
    IMAGE_NAME="${DEFAULT_GCOV_IMAGE}"
  elif docker image inspect "${DEFAULT_PLAIN_IMAGE}" >/dev/null 2>&1; then
    warn "Image '${IMAGE_NAME}' not found; falling back to '${DEFAULT_PLAIN_IMAGE}' (no gcov)"
    IMAGE_NAME="${DEFAULT_PLAIN_IMAGE}"
  else
    fatal "Docker image '${IMAGE_NAME}' not found. Build it first:\n  docker build -f Docker/Dockerfile.mosquitto-gcov -t ${DEFAULT_GCOV_IMAGE} Docker/"
  fi
fi

IS_GCOV_IMAGE=0
if [[ "${IMAGE_NAME}" == *"gcov"* ]]; then
  IS_GCOV_IMAGE=1
fi

# ─── Docker Network Check ───────────────────────────────────────────────
if ! docker network inspect "${DOCKER_NETWORK}" >/dev/null 2>&1; then
  info "Docker network '${DOCKER_NETWORK}' not found. Creating it..."
  docker network create --subnet=172.199.0.0/16 "${DOCKER_NETWORK}" \
    || fatal "Failed to create Docker network '${DOCKER_NETWORK}'"
fi

NETWORK_SUBNET="$(docker network inspect "${DOCKER_NETWORK}" \
  -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)"
info "Network '${DOCKER_NETWORK}' subnet: ${NETWORK_SUBNET}"

# ─── Pre-Run Cleanup: Remove Stale Containers ───────────────────────────
# Kill containers from previous runs that still occupy IPs/names on the
# Docker network.  Only remove containers matching our naming convention.
stale_containers=$(docker ps -a --filter network="${DOCKER_NETWORK}" \
  --format '{{.Names}}' 2>/dev/null | grep -E '^mosquitto-worker' || true)
if [[ -n "${stale_containers}" ]]; then
  stale_count=$(echo "${stale_containers}" | wc -l)
  warn "Found ${stale_count} stale mosquitto-worker container(s) on '${DOCKER_NETWORK}'. Cleaning up..."
  echo "${stale_containers}" | xargs -r docker rm -f >/dev/null 2>&1 || true
  info "Stale containers removed."
fi

# Also clean up the standalone 'mosquitto' container if it sits on our network
if docker ps -a --filter network="${DOCKER_NETWORK}" --format '{{.Names}}' 2>/dev/null \
    | grep -qxF 'mosquitto'; then
  warn "Standalone 'mosquitto' container on '${DOCKER_NETWORK}' detected. Removing..."
  docker rm -f mosquitto >/dev/null 2>&1 || true
fi

# ─── Detect Host IP on Docker Network ───────────────────────────────────
# The mosquitto bridge needs to connect back to the host.  Detect the
# gateway/host IP on the Docker network.
if [[ -z "${HOST_BRIDGE_IP}" ]]; then
  HOST_BRIDGE_IP="$(docker network inspect "${DOCKER_NETWORK}" \
    -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null | head -1)"
fi

if [[ -z "${HOST_BRIDGE_IP}" ]]; then
  # Fallback: probe from inside a temporary container
  HOST_BRIDGE_IP="$(docker run --rm --net "${DOCKER_NETWORK}" \
    busybox ip route 2>/dev/null | awk '/default/{print $3}' | head -1)" || true
fi

if [[ -z "${HOST_BRIDGE_IP}" ]]; then
  # Last resort: use the IP from the extension config (OCP: reads gcov config, not original)
  HOST_BRIDGE_IP="$(grep -oP 'address\s+\K[0-9.]+' "${DOCKER_DIR}/conf/mosquitto-gcov.conf" | head -1)" || true
fi

[[ -n "${HOST_BRIDGE_IP}" ]] \
  || fatal "Cannot detect host IP reachable from Docker network '${DOCKER_NETWORK}'. Set HOST_BRIDGE_IP."

info "Host bridge IP: ${HOST_BRIDGE_IP}"

# ─── Artifact Root ───────────────────────────────────────────────────────
TIMESTAMP="$(date +%b-%d_%H-%M-%S)"
PARALLEL_ROOT="${SCRIPT_DIR}/artifacts/parallel-results-mosquitto_${TIMESTAMP}"
mkdir -p "${PARALLEL_ROOT}"

info "═══════════════════════════════════════════════════════════════"
info "MBFuzzer Parallel Mosquitto Campaign"
info "═══════════════════════════════════════════════════════════════"
info "Image         : ${IMAGE_NAME} (gcov=${IS_GCOV_IMAGE})"
info "Runs          : ${RUN_COUNT}"
info "Parallelism   : ${RUN_PARALLELISM}"
info "Timeout       : ${TIMEOUT_SECONDS}s ($(( TIMEOUT_SECONDS / 60 ))m)"
info "Docker network: ${DOCKER_NETWORK}"
info "Host bridge IP: ${HOST_BRIDGE_IP}"
info "Python        : ${CONDA_PYTHON}"
info "Artifact root : ${PARALLEL_ROOT}"
info "═══════════════════════════════════════════════════════════════"

# ─── Cleanup Trap ────────────────────────────────────────────────────────
declare -a ALL_CONTAINER_NAMES=()
declare -a ALL_FUZZ_PIDS=()

cleanup() {
  info "Cleaning up..."
  # Kill any remaining fuzz.py processes
  for pid in "${ALL_FUZZ_PIDS[@]}"; do
    if kill -0 "${pid}" 2>/dev/null; then
      kill -SIGINT "${pid}" 2>/dev/null || true
      sleep 2
      kill -9 "${pid}" 2>/dev/null || true
    fi
  done
  # Remove containers
  for cname in "${ALL_CONTAINER_NAMES[@]}"; do
    docker rm -f "${cname}" >/dev/null 2>&1 || true
  done
}

trap cleanup EXIT INT TERM

# ─── Port / IP Availability Helpers ──────────────────────────────────────
# Check if a TCP port is free on the host (not bound by any process).
is_port_free() {
  local port="$1"
  ! ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE "[:]${port}$"
}

# Check if a Docker network IP is free (no container currently using it).
is_docker_ip_free() {
  local ip="$1"
  local net="$2"
  # List all IPs on the network; return success if ours is absent
  ! docker network inspect "${net}" \
    -f '{{range .Containers}}{{.IPv4Address}} {{end}}' 2>/dev/null \
    | tr ' ' '\n' | grep -qF "${ip}/"
}

# Find the next free port starting from $1, stepping by 1.
find_free_port() {
  local port="$1"
  local max_attempts=100
  local attempt=0
  while (( attempt < max_attempts )); do
    if is_port_free "${port}"; then
      echo "${port}"
      return 0
    fi
    port=$(( port + 1 ))
    attempt=$(( attempt + 1 ))
  done
  fatal "Cannot find a free port starting from $1 after ${max_attempts} attempts"
}

# Find the next free Docker IP starting from prefix.<last_octet>
find_free_docker_ip() {
  local prefix="$1"
  local start_octet="$2"
  local net="$3"
  local octet="${start_octet}"
  local max_attempts=100
  local attempt=0
  while (( attempt < max_attempts && octet < 255 )); do
    local candidate="${prefix}.${octet}"
    if is_docker_ip_free "${candidate}" "${net}"; then
      echo "${candidate}"
      return 0
    fi
    octet=$(( octet + 1 ))
    attempt=$(( attempt + 1 ))
  done
  fatal "Cannot find a free Docker IP in ${prefix}.0/24 starting from octet ${start_octet}"
}

# ─── Worker Port/IP Allocation ───────────────────────────────────────────
# These arrays store the *actual* allocated values per worker index,
# populated by allocate_worker_resources() before any workers launch.
declare -A ALLOC_BROKER_IP
declare -A ALLOC_SERVER_PORT
declare -A ALLOC_CACHE_PORT

# Pre-allocate all worker resources up front so there are no races between
# parallel workers trying to claim the same port/IP.
allocate_worker_resources() {
  local prefix
  prefix="$(echo "${HOST_BRIDGE_IP}" | sed -E 's/\.[0-9]+$//')"

  local next_octet=$(( WORKER_IP_OFFSET + 1 ))
  local next_server_port="${SERVER_PORT_BASE}"
  local next_cache_port="${CACHE_PORT_BASE}"

  for (( i = 1; i <= RUN_COUNT; i++ )); do
    # --- Allocate Docker IP ---
    local ip
    ip="$(find_free_docker_ip "${prefix}" "${next_octet}" "${DOCKER_NETWORK}")"
    ALLOC_BROKER_IP[${i}]="${ip}"
    # Advance past the one we just claimed
    next_octet=$(( ${ip##*.} + 1 ))

    # --- Allocate server_module port (must be free pair: port, port+1) ---
    next_server_port="$(find_free_port "${next_server_port}")"
    ALLOC_SERVER_PORT[${i}]="${next_server_port}"
    next_server_port=$(( next_server_port + PORT_STEP ))

    # --- Allocate cache_broker port ---
    next_cache_port="$(find_free_port "${next_cache_port}")"
    ALLOC_CACHE_PORT[${i}]="${next_cache_port}"
    next_cache_port=$(( next_cache_port + PORT_STEP ))
  done
}

worker_broker_ip() {
  local idx="$1"
  echo "${ALLOC_BROKER_IP[${idx}]}"
}

worker_server_port() {
  local idx="$1"
  echo "${ALLOC_SERVER_PORT[${idx}]}"
}

worker_cache_port() {
  local idx="$1"
  echo "${ALLOC_CACHE_PORT[${idx}]}"
}

# ─── Pre-Allocate All Worker Ports & IPs ─────────────────────────────────
# Do this once up front to avoid races between parallel workers.
allocate_worker_resources
info "Resource allocation:"
for (( _dbg_i = 1; _dbg_i <= RUN_COUNT; _dbg_i++ )); do
  info "  worker$(printf '%02d' "${_dbg_i}") → IP=${ALLOC_BROKER_IP[${_dbg_i}]}  server=${ALLOC_SERVER_PORT[${_dbg_i}]}  cache=${ALLOC_CACHE_PORT[${_dbg_i}]}"
done

# ─── Prepare Per-Worker MBFuzzer Source ──────────────────────────────────
prepare_worker_source() {
  local idx="$1"
  local worker_root="$2"
  local broker_ip="$3"
  local server_port="$4"
  local cache_port="$5"
  local output_dir="$6"
  local container_name="$7"

  local src_dir="${worker_root}/mbfuzzer"

  # Copy source tree (lightweight; excludes __pycache__)
  rsync -a --exclude='__pycache__' --exclude='*.pyc' \
    "${MBFUZZER_SRC}/" "${src_dir}/"

  # ── OCP: original globals.py and fuzz.py are NOT modified ──
  # All per-worker overrides are injected via environment variables
  # and consumed by ext/globals_ext.py at runtime.  The entry point
  # fuzz_gcov.py applies the ext/ layer before calling fuzz logic.
  #
  # Write a small env file that the launch step will source.
  cat > "${worker_root}/worker_env.sh" <<ENVEOF
export MBFUZZER_OUTPUT_DIR="${output_dir}/"
export MBFUZZER_BROKER_IP="${broker_ip}"
export MBFUZZER_BROKER_NAME="${container_name}"
export MBFUZZER_BROKER_PORT=1883
export MBFUZZER_TIME_LIMIT=${TIMEOUT_SECONDS}
export MBFUZZER_SINGLE_BROKER=1
export MBFUZZER_SERVER_PORT=${server_port}
export MBFUZZER_CACHE_PORT=${cache_port}
export MBFUZZER_CONNECT_TIMEOUT=5
export MBFUZZER_RECV_TIMEOUT=0.1
ENVEOF

  info "  worker$(printf '%02d' "${idx}") source prepared → ${src_dir} (OCP: no sed patches)"
}

# ─── Prepare Per-Worker mosquitto.conf ───────────────────────────────────
prepare_worker_mosquitto_conf() {
  local worker_root="$1"
  local server_port="$2"

  local conf_dir="${worker_root}/conf"
  mkdir -p "${conf_dir}"

  # Select config template based on image tag.
  # v1.x series uses mqttv311 bridge; v2.x uses mqttv50.
  # OCP: we use mosquitto-gcov.conf (extension) for v2.x, leaving
  #      the original mosquitto.conf untouched.
  local conf_template="${DOCKER_DIR}/conf/mosquitto-gcov.conf"
  if [[ "${IMAGE_NAME}" =~ 1\.[0-9]+\.[0-9]+ ]]; then
    conf_template="${DOCKER_DIR}/conf/mosquitto-v168.conf"
  fi
  if [[ ! -f "${conf_template}" ]]; then
    fatal "Config template not found: ${conf_template}"
  fi

  # Start from the template
  cp "${conf_template}" "${conf_dir}/mosquitto.conf"

  # Patch bridge address to point to this worker's server_module port on the host
  sed -i \
    -e "s|^address .*|address ${HOST_BRIDGE_IP}:${server_port}|" \
    "${conf_dir}/mosquitto.conf"

  info "  conf template → $(basename "${conf_template}")"
  info "  bridge address → ${HOST_BRIDGE_IP}:${server_port}"
}

# ─── Start Mosquitto Container ───────────────────────────────────────────
start_mosquitto_container() {
  local container_name="$1"
  local broker_ip="$2"
  local worker_root="$3"

  local conf_path="${worker_root}/conf/mosquitto.conf"
  local coverage_dir="${worker_root}/coverage"
  mkdir -p "${coverage_dir}"

  local docker_args=(
    docker run -d
    --name "${container_name}"
    --net "${DOCKER_NETWORK}"
    --ip "${broker_ip}"
  )

  if [[ "${IS_GCOV_IMAGE}" == "1" ]]; then
    # gcov image: mount coverage output dir + custom conf
    docker_args+=(
      -v "${conf_path}:/opt/mosquitto.conf:ro"
      -v "${coverage_dir}:/coverage"
    )
  else
    # Plain image: mount conf into standard path
    docker_args+=(
      -v "${conf_path}:/mosquitto/config/mosquitto.conf:ro"
    )
  fi

  docker_args+=("${IMAGE_NAME}")

  local cid
  local docker_stderr
  docker_stderr="$(mktemp)"
  if cid="$("${docker_args[@]}" 2>"${docker_stderr}")"; then
    rm -f "${docker_stderr}"
  else
    local err_msg
    err_msg="$(<"${docker_stderr}")"
    rm -f "${docker_stderr}"
    if echo "${err_msg}" | grep -qi 'address already in use\|already exists'; then
      warn "  Container start failed (${err_msg}). Cleaning conflict and retrying..."
      # Remove any conflicting container with the same name
      docker rm -f "${container_name}" >/dev/null 2>&1 || true
      sleep 1
      cid="$("${docker_args[@]}" 2>&1)" \
        || fatal "Failed to start container '${container_name}' on retry: ${cid}"
    else
      fatal "Failed to start container '${container_name}': ${err_msg}"
    fi
  fi
  echo "${cid}" > "${worker_root}/container.id"
  ALL_CONTAINER_NAMES+=("${container_name}")

  info "  container '${container_name}' started"
  info "    Docker ID  : ${cid:0:12}"
  info "    IP         : ${broker_ip}"
  info "    Image      : ${IMAGE_NAME}"
}

# ─── Wait for Broker Ready ──────────────────────────────────────────────
wait_for_broker() {
  local broker_ip="$1"
  local port="${2:-1883}"
  local max_wait="${3:-30}"
  local elapsed=0

  while (( elapsed < max_wait )); do
    if docker run --rm --net "${DOCKER_NETWORK}" busybox \
        sh -c "echo | nc -w 1 ${broker_ip} ${port}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    elapsed=$(( elapsed + 1 ))
  done

  warn "Broker at ${broker_ip}:${port} not ready after ${max_wait}s"
  return 1
}

# ─── Coverage JSON Fallback Helper ───────────────────────────────────────
# If gcovr-summary.json is missing but coverage.xml (Cobertura) exists,
# generate a compatible JSON from XML so all downstream parsers work.
ensure_coverage_json() {
  local coverage_dir="$1"
  local summary_json="${coverage_dir}/gcovr-summary.json"
  local coverage_xml="${coverage_dir}/coverage.xml"

  # Already have JSON → nothing to do
  if [[ -s "${summary_json}" ]]; then
    return 0
  fi

  # No XML either → cannot generate
  if [[ ! -s "${coverage_xml}" ]]; then
    return 1
  fi

  # Parse Cobertura XML → generate compatible JSON
  python3 - "${coverage_xml}" "${summary_json}" <<'XMLFALLBACK' 2>/dev/null || return 1
import xml.etree.ElementTree as ET, json, sys
tree = ET.parse(sys.argv[1])
root = tree.getroot()
lr = float(root.attrib.get('line-rate', 0))
br = float(root.attrib.get('branch-rate', 0))
lv = int(root.attrib.get('lines-valid', 0))
lc = int(root.attrib.get('lines-covered', 0))
bv = int(root.attrib.get('branches-valid', 0))
bc = int(root.attrib.get('branches-covered', 0))
d = {
    'branch_percent': round(br * 100, 2),
    'branch_covered': bc,
    'branch_total': bv,
    'line_percent': round(lr * 100, 2),
    'line_covered': lc,
    'line_total': lv,
    '_source': 'coverage.xml (fallback)'
}
with open(sys.argv[2], 'w') as f:
    json.dump(d, f, indent=2)
XMLFALLBACK

  if [[ -s "${summary_json}" ]]; then
    info "  (fallback) Generated gcovr-summary.json from coverage.xml"
    return 0
  fi
  return 1
}

# ─── Collect gcov Coverage ───────────────────────────────────────────────
collect_gcov_coverage() {
  local container_name="$1"
  local worker_root="$2"
  local coverage_dir="${worker_root}/coverage"

  if [[ "${IS_GCOV_IMAGE}" != "1" ]]; then
    info "  Skipping gcov collection (non-gcov image)"
    return 0
  fi

  # Stop → flush gcda files, then restart to enable gcovr
  local cid_short=""
  [[ -f "${worker_root}/container.id" ]] && cid_short="$(head -c 12 "${worker_root}/container.id")"
  info "  Collecting gcov from '${container_name}' (id=${cid_short})..."

  # Stop → flush gcda files, then restart to enable gcovr
  info "  Stopping broker to flush .gcda files..."
  docker stop -t 15 "${container_name}" >/dev/null 2>&1 || true
  sleep 2
  docker start "${container_name}" >/dev/null 2>&1 || true
  sleep 2

  # Count gcda files
  local gcda_count
  gcda_count="$(docker exec "${container_name}" \
    find /opt/mosquitto-gcov -name '*.gcda' -type f 2>/dev/null | wc -l)" || true
  info "  .gcda files found: ${gcda_count}"

  if (( gcda_count == 0 )); then
    warn "  No .gcda files in '${container_name}'; coverage may be empty"
  fi

  # Run gcovr via the bundled script
  if docker exec "${container_name}" test -x /usr/local/bin/mosquitto_gcov_collect.sh; then
    docker exec "${container_name}" /usr/local/bin/mosquitto_gcov_collect.sh \
      > "${coverage_dir}/gcovr.log" 2>&1 || true
    info "  gcovr collection complete → ${coverage_dir}/"
  else
    warn "  mosquitto_gcov_collect.sh not found in container; skipping"
  fi

  # Copy coverage artifacts out of container (redundancy)
  docker cp "${container_name}:/coverage/." "${coverage_dir}/" >/dev/null 2>&1 || true

  # Ensure JSON summary exists (fallback: generate from coverage.xml)
  ensure_coverage_json "${coverage_dir}"

  # Parse summary JSON if available
  local summary_json="${coverage_dir}/gcovr-summary.json"
  if [[ -f "${summary_json}" ]]; then
    local branch_pct branch_covered branch_total
    branch_pct="$(python3 -c "import json; d=json.load(open('${summary_json}')); print(d.get('branch_percent', 'N/A'))" 2>/dev/null)" || branch_pct="N/A"
    branch_covered="$(python3 -c "import json; d=json.load(open('${summary_json}')); print(d.get('branch_covered', 'N/A'))" 2>/dev/null)" || branch_covered="N/A"
    branch_total="$(python3 -c "import json; d=json.load(open('${summary_json}')); print(d.get('branch_total', 'N/A'))" 2>/dev/null)" || branch_total="N/A"
    info "  Branch coverage: ${branch_pct}% (${branch_covered}/${branch_total})"
  fi
}

# ─── Launch a Single Worker ──────────────────────────────────────────────
launch_worker() {
  local idx="$1"
  local worker_label
  worker_label="worker$(printf '%02d' "${idx}")"
  local worker_root="${PARALLEL_ROOT}/${worker_label}"
  local output_dir="${worker_root}/outputs"
  local broker_ip
  local server_port
  local cache_port
  local container_name="mosquitto-${worker_label}-${TIMESTAMP//[: ]/-}"

  broker_ip="$(worker_broker_ip "${idx}")"
  server_port="$(worker_server_port "${idx}")"
  cache_port="$(worker_cache_port "${idx}")"

  mkdir -p "${worker_root}" "${output_dir}"

  info "────────────────────────────────────────────────────────────"
  info "Launching ${worker_label}"
  info "  broker IP    : ${broker_ip}"
  info "  server_module: host:${server_port}"
  info "  cache_broker : host:${cache_port}"
  info "  output dir   : ${output_dir}"
  info "  container    : ${container_name}"

  # 1. Prepare per-worker source and config
  prepare_worker_source "${idx}" "${worker_root}" "${broker_ip}" \
    "${server_port}" "${cache_port}" "${output_dir}" "${container_name}"

  prepare_worker_mosquitto_conf "${worker_root}" "${server_port}"

  # 2. Start mosquitto container
  start_mosquitto_container "${container_name}" "${broker_ip}" "${worker_root}"

  # 3. Wait for broker to become ready
  if ! wait_for_broker "${broker_ip}" 1883 30; then
    warn "${worker_label}: broker did not become ready; proceeding anyway"
  fi

  # 4. Run fuzz_gcov.py (OCP wrapper → delegates to original fuzz logic)
  local fuzz_src="${worker_root}/mbfuzzer"
  local fuzz_log="${worker_root}/fuzz.log"
  local fuzz_start_ts
  fuzz_start_ts="$(date +%s)"
  echo "${fuzz_start_ts}" > "${worker_root}/fuzz.start_ts"

  local cid_start=""
  [[ -f "${worker_root}/container.id" ]] && cid_start="$(head -c 12 "${worker_root}/container.id")"
  info "  Starting fuzz_gcov.py (timeout=${TIMEOUT_SECONDS}s, container=${cid_start}) ..."

  (
    cd "${fuzz_src}"
    # Source per-worker env overrides (OCP: no source-file patching)
    # shellcheck disable=SC1091
    source "${worker_root}/worker_env.sh"
    # PYTHONUNBUFFERED ensures print output reaches fuzz.log even on os._exit()
    PYTHONUNBUFFERED=1 PYTHONPATH="${fuzz_src}" "${CONDA_PYTHON}" fuzz_gcov.py \
      > "${fuzz_log}" 2>&1
  ) &
  local fuzz_pid=$!
  ALL_FUZZ_PIDS+=("${fuzz_pid}")
  echo "${fuzz_pid}" > "${worker_root}/fuzz.pid"

  # 5. Wait for fuzz_gcov.py to finish (it self-terminates via TIME_LIMITE_SECONDS)
  #    Add a safety margin of 5 minutes beyond the timeout.
  local hard_deadline=$(( TIMEOUT_SECONDS + 300 ))
  local waited=0
  while kill -0 "${fuzz_pid}" 2>/dev/null; do
    sleep 5
    waited=$(( waited + 5 ))
    if (( waited >= hard_deadline )); then
      warn "${worker_label}: fuzz_gcov.py exceeded hard deadline (${hard_deadline}s). Killing..."
      kill -SIGINT "${fuzz_pid}" 2>/dev/null || true
      sleep 5
      kill -9 "${fuzz_pid}" 2>/dev/null || true
      break
    fi
  done

  wait "${fuzz_pid}" 2>/dev/null
  local fuzz_exit=$?
  echo "${fuzz_exit}" > "${worker_root}/fuzz.exit_code"

  local fuzz_end_ts
  fuzz_end_ts="$(date +%s)"
  echo "${fuzz_end_ts}" > "${worker_root}/fuzz.end_ts"
  local fuzz_duration=$(( fuzz_end_ts - fuzz_start_ts ))

  info "  fuzz_gcov.py exited (code=${fuzz_exit}, duration=${fuzz_duration}s)"

  # 6. Collect gcov coverage
  collect_gcov_coverage "${container_name}" "${worker_root}"

  # 7. Stop and remove container
  local cid_full=""
  [[ -f "${worker_root}/container.id" ]] && cid_full="$(<"${worker_root}/container.id")"
  info "  Stopping container '${container_name}' (id=${cid_full:0:12})..."
  docker stop -t 5 "${container_name}" >/dev/null 2>&1 || true
  local container_exit
  container_exit="$(docker inspect "${container_name}" --format='{{.State.ExitCode}}' 2>/dev/null)" || container_exit="unknown"
  echo "${container_exit}" > "${worker_root}/container.exit_code"
  docker rm -f "${container_name}" >/dev/null 2>&1 || true

  info "${worker_label} complete ✓ (container exit=${container_exit})"
  return "${fuzz_exit}"
}

# ═══════════════════════════════════════════════════════════════════════════
# Main Execution Loop (parallelism-controlled)
# ═══════════════════════════════════════════════════════════════════════════
declare -a WORKER_ROOTS=()
running_count=0

for (( idx = 1; idx <= RUN_COUNT; idx++ )); do
  WORKER_ROOTS+=("${PARALLEL_ROOT}/worker$(printf '%02d' "${idx}")")

  (
    launch_worker "${idx}"
  ) &
  running_count=$(( running_count + 1 ))

  # Throttle by parallelism
  if (( running_count >= RUN_PARALLELISM )); then
    wait -n 2>/dev/null || true
    running_count=$(( running_count - 1 ))
  fi
done

# Wait for all remaining workers
while (( running_count > 0 )); do
  wait -n 2>/dev/null || true
  running_count=$(( running_count - 1 ))
done

# ═══════════════════════════════════════════════════════════════════════════
# Summary Generation
# ═══════════════════════════════════════════════════════════════════════════
info ""
info "═══════════════════════════════════════════════════════════════"
info "Generating Summary"
info "═══════════════════════════════════════════════════════════════"

SUMMARY_CSV="${PARALLEL_ROOT}/summary.csv"
printf 'run_index,container_name,container_id,broker_ip,server_port,cache_port,fuzz_exit_code,fuzz_duration_s,messages_sent,branch_pct,branch_covered,branch_total,line_pct,line_covered,line_total\n' \
  > "${SUMMARY_CSV}"

overall_status=0

for (( idx = 1; idx <= RUN_COUNT; idx++ )); do
  worker_label="worker$(printf '%02d' "${idx}")"
  worker_root="${PARALLEL_ROOT}/${worker_label}"
  broker_ip="$(worker_broker_ip "${idx}")"
  server_port="$(worker_server_port "${idx}")"
  cache_port="$(worker_cache_port "${idx}")"
  container_name="mosquitto-${worker_label}-${TIMESTAMP//[: ]/-}"

  # Read exit code
  fuzz_exit="unknown"
  [[ -f "${worker_root}/fuzz.exit_code" ]] && fuzz_exit="$(<"${worker_root}/fuzz.exit_code")"

  # Read duration
  fuzz_duration="N/A"
  if [[ -f "${worker_root}/fuzz.start_ts" && -f "${worker_root}/fuzz.end_ts" ]]; then
    local_start="$(<"${worker_root}/fuzz.start_ts")"
    local_end="$(<"${worker_root}/fuzz.end_ts")"
    fuzz_duration=$(( local_end - local_start ))
  fi

  # Read messages sent from fuzzing_report.txt
  messages_sent="N/A"
  report_file="${worker_root}/outputs/fuzzing_report.txt"
  if [[ -f "${report_file}" ]]; then
    messages_sent="$(grep -oP 'Fuzzing request number: \K[0-9]+' "${report_file}" 2>/dev/null)" || messages_sent="N/A"
  fi

  # Read coverage from gcovr-summary.json (with XML fallback)
  branch_pct="N/A"
  branch_covered="N/A"
  branch_total="N/A"
  line_pct="N/A"
  line_covered="N/A"
  line_total="N/A"
  ensure_coverage_json "${worker_root}/coverage" 2>/dev/null || true
  summary_json="${worker_root}/coverage/gcovr-summary.json"
  if [[ -f "${summary_json}" ]]; then
    branch_pct="$(python3 -c "import json; d=json.load(open('${summary_json}')); print(d.get('branch_percent', 'N/A'))" 2>/dev/null)" || true
    branch_covered="$(python3 -c "import json; d=json.load(open('${summary_json}')); print(d.get('branch_covered', 'N/A'))" 2>/dev/null)" || true
    branch_total="$(python3 -c "import json; d=json.load(open('${summary_json}')); print(d.get('branch_total', 'N/A'))" 2>/dev/null)" || true
    line_pct="$(python3 -c "import json; d=json.load(open('${summary_json}')); print(d.get('line_percent', 'N/A'))" 2>/dev/null)" || true
    line_covered="$(python3 -c "import json; d=json.load(open('${summary_json}')); print(d.get('line_covered', 'N/A'))" 2>/dev/null)" || true
    line_total="$(python3 -c "import json; d=json.load(open('${summary_json}')); print(d.get('line_total', 'N/A'))" 2>/dev/null)" || true
  fi

  if [[ "${fuzz_exit}" != "0" && "${fuzz_exit}" != "unknown" ]]; then
    overall_status=1
  fi

  # Read container ID
  container_id="N/A"
  [[ -f "${worker_root}/container.id" ]] && container_id="$(head -c 12 "${worker_root}/container.id")"

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "${idx}" "${container_name}" "${container_id}" "${broker_ip}" \
    "${server_port}" "${cache_port}" "${fuzz_exit}" \
    "${fuzz_duration}" "${messages_sent}" \
    "${branch_pct}" "${branch_covered}" "${branch_total}" \
    "${line_pct}" "${line_covered}" "${line_total}" \
    >> "${SUMMARY_CSV}"
done

# ─── Pretty-Print Summary ───────────────────────────────────────────────
info ""
info "┌─────────────────────────────── Results ──────────────────────────────┐"
printf "│ %-8s │ %-12s │ %-8s │ %-10s │ %-10s │ %-12s │ %-12s │\n" \
  "Worker" "Container ID" "Exit" "Duration" "Messages" "Branch Cov" "Line Cov"
info "├──────────┼──────────────┼──────────┼────────────┼────────────┼──────────────┼──────────────┤"

for (( idx = 1; idx <= RUN_COUNT; idx++ )); do
  worker_label="worker$(printf '%02d' "${idx}")"
  worker_root="${PARALLEL_ROOT}/${worker_label}"

  fuzz_exit="?"
  [[ -f "${worker_root}/fuzz.exit_code" ]] && fuzz_exit="$(<"${worker_root}/fuzz.exit_code")"

  cid_display="?"
  [[ -f "${worker_root}/container.id" ]] && cid_display="$(head -c 12 "${worker_root}/container.id")"

  fuzz_duration="?"
  if [[ -f "${worker_root}/fuzz.start_ts" && -f "${worker_root}/fuzz.end_ts" ]]; then
    local_start="$(<"${worker_root}/fuzz.start_ts")"
    local_end="$(<"${worker_root}/fuzz.end_ts")"
    fuzz_duration="$(( local_end - local_start ))s"
  fi

  messages_sent="?"
  report_file="${worker_root}/outputs/fuzzing_report.txt"
  if [[ -f "${report_file}" ]]; then
    messages_sent="$(grep -oP 'Fuzzing request number: \K[0-9]+' "${report_file}" 2>/dev/null)" || messages_sent="?"
  fi

  branch_str="N/A"
  line_str="N/A"
  ensure_coverage_json "${worker_root}/coverage" 2>/dev/null || true
  summary_json="${worker_root}/coverage/gcovr-summary.json"
  if [[ -f "${summary_json}" ]]; then
    branch_str="$(python3 -c "
import json
d=json.load(open('${summary_json}'))
print(f\"{d.get('branch_percent','?')}%\")
" 2>/dev/null)" || true
    line_str="$(python3 -c "
import json
d=json.load(open('${summary_json}'))
print(f\"{d.get('line_percent','?')}%\")
" 2>/dev/null)" || true
  fi

  printf "│ %-8s │ %-12s │ %-8s │ %-10s │ %-10s │ %-12s │ %-12s │\n" \
    "${worker_label}" "${cid_display}" "${fuzz_exit}" "${fuzz_duration}" \
    "${messages_sent}" "${branch_str}" "${line_str}"
done

info "└──────────┴──────────────┴──────────┴────────────┴────────────┴──────────────┴──────────────┘"
info ""
info "Summary CSV   : ${SUMMARY_CSV}"
info "Artifact root : ${PARALLEL_ROOT}"
info ""

# ─── Aggregate Coverage (if multiple runs) ───────────────────────────────
if (( RUN_COUNT > 1 )); then
  aggregate_json="${PARALLEL_ROOT}/aggregate_coverage.json"
  python3 - "${PARALLEL_ROOT}" "${aggregate_json}" <<'PYAGG' 2>/dev/null || true
import json, sys, os, glob
import xml.etree.ElementTree as ET

def load_coverage(worker_cov_dir):
    """Load coverage data from JSON or fall back to Cobertura XML."""
    json_path = os.path.join(worker_cov_dir, 'gcovr-summary.json')
    xml_path = os.path.join(worker_cov_dir, 'coverage.xml')
    if os.path.isfile(json_path):
        with open(json_path) as f:
            return json.load(f)
    if os.path.isfile(xml_path):
        tree = ET.parse(xml_path)
        r = tree.getroot()
        lr = float(r.attrib.get('line-rate', 0))
        br = float(r.attrib.get('branch-rate', 0))
        return {
            'branch_percent': round(br * 100, 2),
            'branch_covered': int(r.attrib.get('branches-covered', 0)),
            'branch_total': int(r.attrib.get('branches-valid', 0)),
            'line_percent': round(lr * 100, 2),
            'line_covered': int(r.attrib.get('lines-covered', 0)),
            'line_total': int(r.attrib.get('lines-valid', 0)),
            '_source': 'coverage.xml (fallback)',
        }
    return None

root = sys.argv[1]
out_path = sys.argv[2]

# Find all worker coverage directories
worker_dirs = sorted(glob.glob(os.path.join(root, "worker*/coverage")))
if not worker_dirs:
    print("[parallel] No worker coverage directories found for aggregation")
    sys.exit(0)

runs = []
for cov_dir in worker_dirs:
    d = load_coverage(cov_dir)
    if d is None:
        continue
    worker = os.path.basename(os.path.dirname(cov_dir))
    runs.append({
        "worker": worker,
        "branch_percent": d.get("branch_percent"),
        "branch_covered": d.get("branch_covered"),
        "branch_total": d.get("branch_total"),
        "line_percent": d.get("line_percent"),
        "line_covered": d.get("line_covered"),
        "line_total": d.get("line_total"),
    })

if not runs:
    print("[parallel] No coverage data found (neither JSON nor XML)")
    sys.exit(0)

branch_pcts = [r["branch_percent"] for r in runs if r["branch_percent"] is not None]
line_pcts = [r["line_percent"] for r in runs if r["line_percent"] is not None]

agg = {
    "runs": runs,
    "aggregate": {
        "num_runs": len(runs),
        "branch_percent_mean": round(sum(branch_pcts) / len(branch_pcts), 2) if branch_pcts else None,
        "branch_percent_min": min(branch_pcts) if branch_pcts else None,
        "branch_percent_max": max(branch_pcts) if branch_pcts else None,
        "line_percent_mean": round(sum(line_pcts) / len(line_pcts), 2) if line_pcts else None,
        "line_percent_min": min(line_pcts) if line_pcts else None,
        "line_percent_max": max(line_pcts) if line_pcts else None,
    },
}

with open(out_path, "w") as f:
    json.dump(agg, f, indent=2)
print(f"[parallel] Aggregate coverage → {out_path}")
PYAGG
fi

# ─── Final Status ────────────────────────────────────────────────────────
if (( overall_status == 0 )); then
  info "All ${RUN_COUNT} run(s) completed successfully."
else
  warn "Some runs finished with non-zero exit codes. Check individual fuzz.log files."
fi

# Disable cleanup trap (containers already removed in launch_worker)
trap - EXIT INT TERM

exit "${overall_status}"
