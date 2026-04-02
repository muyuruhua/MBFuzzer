# MBFuzzer: A Multi-party Protocol Fuzzer for MQTT Brokers

MBFuzzer is a multi-party black-box fuzzer for MQTT brokers.

This repository (`mbfuzzer_artifact`) is an **OCP-compliant extension** of the
original [MBFuzzer_Artifact](../MBFuzzer_Artifact/).  All 83 original source
files are preserved byte-for-byte; every new capability is delivered through
**purely additive** extension files.

---

## Table of Contents

- [Repository Structure](#repository-structure)
- [OCP Extension Architecture](#ocp-extension-architecture)
- [Original Usage (Unchanged)](#original-usage-unchanged)
- [Extended Usage: Parallel gcov Campaign](#extended-usage-parallel-gcov-campaign)
  - [Prerequisites](#prerequisites)
  - [Step 1 — Build gcov-Instrumented Docker Image](#step-1--build-gcov-instrumented-docker-image)
  - [Step 2 — Run Parallel Fuzzing Campaign](#step-2--run-parallel-fuzzing-campaign)
  - [Step 3 — Inspect Results](#step-3--inspect-results)
- [Environment Variables Reference](#environment-variables-reference)
- [Extension Files Inventory](#extension-files-inventory)
- [OCP Compliance Verification](#ocp-compliance-verification)
- [LLM-based Bug Analyzer](#llm-based-bug-analyzer)

---

## Repository Structure

```
mbfuzzer_artifact/
├── README.md                          # This file
├── run_mosquitto_parallel_docker.sh   # 🆕 Parallel orchestration script
│
├── Docker/
│   ├── Dockerfile                     # Original: multi-broker image
│   ├── Dockerfile.mosquitto-gcov      # 🆕 gcov image (v2.0.18 legacy)
│   ├── Dockerfile.mosquitto-gcov-v168 # 🆕 gcov image (v1.6.8)
│   ├── Dockerfile.mosquitto-gcov-unified # 🆕 Unified gcov image (any version)
│   ├── mosquitto_gcov_collect.sh      # 🆕 In-container gcovr collection
│   ├── broker_start.sh               # Original
│   ├── init.sh                        # Original
│   ├── run_broker.py                  # Original
│   ├── setting_config.sh             # Original
│   └── conf/
│       ├── mosquitto.conf             # Original (untouched)
│       ├── mosquitto-gcov.conf        # 🆕 v2.0.x gcov config
│       ├── mosquitto-v168.conf        # 🆕 v1.6.8 gcov config
│       └── ...                        # Other original broker configs
│
├── mbfuzzer/
│   ├── fuzz.py                        # Original entry point (untouched)
│   ├── fuzz_gcov.py                   # 🆕 OCP entry point (applies ext/ then fuzz logic)
│   ├── globals.py                     # Original (untouched)
│   ├── ext/                           # 🆕 OCP extension layer
│   │   ├── __init__.py                #     Bootstrap: apply_all()
│   │   ├── globals_ext.py             #     Env-var overrides for globals.py
│   │   ├── client_patch.py            #     Monkey-patch connect_to_broker timeout
│   │   └── report_ext.py             #     Wrapper: paper-aligned summary + JSON
│   ├── fuzzer/                        # Original (all files untouched)
│   ├── generators/                    # Original (all files untouched)
│   ├── helper_functions/              # Original (all files untouched)
│   ├── parsers/                       # Original (all files untouched)
│   ├── type/                          # Original (all files untouched)
│   └── llm-based_bug_analyzer/        # Original (all files untouched)
│
├── tools/
│   └── finalize_mosquitto_gcov_run.py # 🆕 Post-experiment helper
│
└── artifacts/                         # Output directory (git-ignored)
    └── parallel-results-mosquitto_*/
        ├── summary.csv
        ├── aggregate_coverage.json
        └── worker*/
```

Files marked with 🆕 are **new extension files** that do not exist in the
original `MBFuzzer_Artifact`.  All other files are identical to the original.

---

## OCP Extension Architecture

The [Open-Closed Principle](https://en.wikipedia.org/wiki/Open%E2%80%93closed_principle)
(OCP) states that software entities should be **open for extension but closed
for modification**.  This repository strictly follows OCP:

- **Closed for modification**: All 83 original source files from
  `MBFuzzer_Artifact` are preserved byte-for-byte (verified via `cmp -s`).
- **Open for extension**: 16 new files provide gcov coverage collection,
  parallel orchestration, and environment-variable-driven configuration.

### How It Works

```
run_mosquitto_parallel_docker.sh
  │
  ├─ writes worker_env.sh (per-worker environment variables)
  │
  └─ launches fuzz_gcov.py ──────────────────────────────────────────
       │
       ├─ import ext; ext.apply_all()
       │   ├─ globals_ext.apply()    # patches globals module via env vars
       │   ├─ client_patch.apply()   # monkey-patches connect_to_broker
       │   └─ report_ext.apply()     # wraps dump_fuzzing_info_log
       │
       └─ main()                     # reproduces fuzz.py logic with custom ports
           ├─ CacheBroker(port=EXT_CACHE_PORT)
           ├─ MQTTBroker(port=EXT_SERVER_PORT)
           └─ fuzzing loop (self-terminates via TIME_LIMITE_SECONDS)
```

The three extensions use Python's **mutable module namespace** mechanism:
- `globals_ext.py` — Sets attributes on the already-imported `globals` module
  object (e.g., `g.BROKER_IP_1 = os.environ["MBFUZZER_BROKER_IP"]`).
- `client_patch.py` — Saves a reference to the original
  `client_module.connect_to_broker`, then replaces it with a version that uses
  a longer TCP connect timeout (5 s) while preserving the original recv timeout
  (0.1 s).
- `report_ext.py` — Saves a reference to the original
  `directory_operation.dump_fuzzing_info_log`, then replaces it with a wrapper
  that calls the original first, then appends a paper-aligned summary and
  writes `paper_metrics.json`.

**Reverting to original behavior** is as simple as running `python3 fuzz.py`
instead of `python3 fuzz_gcov.py` — no file modifications needed.

---

## Original Usage (Unchanged)

The original MBFuzzer workflow (6-broker differential fuzzing) remains fully
functional.  All original instructions from the upstream `MBFuzzer_Artifact`
README apply without modification:

<details>
<summary>Click to expand original usage instructions</summary>

### Test Infrastructure Overview

* MBFuzzer Execution Environment: Ubuntu 20.04 & Python 3.8.
* Broker Deployment: Each broker as a Docker container.

### Preparatory Phase

```bash
apt install python3.8-venv
cd <parent directory of mbfuzzer> && python3 -m venv pyenv
source pyenv/bin/activate
pip3 install numpy colorama pandas openai
```

Configure Docker container IPs:
```bash
cd Docker/
./setting_config.sh <your local machine IP>
```

Build Docker image:
```bash
cd Docker/
docker build . -t mqtt_fuzzing -f Dockerfile
```

Create Docker network and start 6 broker containers:
```bash
docker network create --subnet=172.199.0.0/16 mqtt_network
docker run -itd --privileged --name=hivemq    --net mqtt_network --ip 172.199.0.2 mqtt_fuzzing bash
docker run -itd --privileged --name=vernemq   --net mqtt_network --ip 172.199.0.3 mqtt_fuzzing bash
docker run -itd --privileged --name=emqx      --net mqtt_network --ip 172.199.0.4 mqtt_fuzzing bash
docker run -itd --privileged --name=flashmq   --net mqtt_network --ip 172.199.0.5 mqtt_fuzzing bash
docker run -itd --privileged --name=nanomq    --net mqtt_network --ip 172.199.0.6 mqtt_fuzzing bash
docker run -itd --privileged --name=mosquitto --net mqtt_network --ip 172.199.0.7 mqtt_fuzzing bash
```

### Fuzzing Phase

Update `mbfuzzer/globals.py`:
```python
TIME_LIMITE_SECONDS = 1800
FUZZING_OUTPUT_DIR = "/root/fuzzing_outputs/"
```

Start MBFuzzer:
```bash
python3 ./fuzz.py
```

Start all brokers:
```bash
cd Docker/
./broker_start.sh
```

After ~30 minutes (or Ctrl+C), outputs are saved to the configured directory.

</details>

---

## Extended Usage: Parallel gcov Campaign

This section covers the **new** parallel fuzzing workflow with gcov branch
coverage collection, designed for single-broker (mosquitto) experiments that
produce coverage metrics comparable to ChatAFL.

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Docker | ≥ 20.10 | With `docker network` support |
| Python | ≥ 3.8 | For MBFuzzer + gcovr |
| rsync | any | Used by orchestrator to copy source per worker |
| ss | any | Port availability detection (from `iproute2`) |

### Step 1 — Build gcov-Instrumented Docker Image

**Unified Dockerfile (recommended)** — supports any mosquitto version:

```bash
cd Docker/

# Build v2.0.18 image
docker build -f Dockerfile.mosquitto-gcov-unified \
  --build-arg MOSQUITTO_VERSION=2.0.18 \
  -t mbfuzzer-mosquitto-gcov:2.0.18 .

# Build v1.6.8 image (ChatAFL-aligned)
docker build -f Dockerfile.mosquitto-gcov-unified \
  --build-arg MOSQUITTO_VERSION=1.6.8 \
  -t mbfuzzer-mosquitto-gcov:1.6.8 .
```

**Version-specific Dockerfiles** (alternative):

```bash
# v2.0.18 only
docker build -f Dockerfile.mosquitto-gcov -t mbfuzzer-mosquitto-gcov:2.0.18 .

# v1.6.8 only
docker build -f Dockerfile.mosquitto-gcov-v168 -t mbfuzzer-mosquitto-gcov:1.6.8 .
```

Each image includes:
- mosquitto compiled with `-fprofile-arcs -ftest-coverage` (gcov)
- `gcovr==7.2` for coverage report generation
- `mosquitto_gcov_collect.sh` for in-container coverage collection

### Step 2 — Run Parallel Fuzzing Campaign

```bash
cd /path/to/mbfuzzer_artifact

# Quick test: 2 sequential runs, 15 minutes each
./run_mosquitto_parallel_docker.sh \
  --runs 2 --parallelism 1 --timeout 15 \
  --image mbfuzzer-mosquitto-gcov:2.0.18

# Full experiment: 10 runs, 4 parallel, 60 minutes each
./run_mosquitto_parallel_docker.sh \
  --runs 10 --parallelism 4 --timeout 60 \
  --image mbfuzzer-mosquitto-gcov:2.0.18

# v1.6.8 (for ChatAFL comparison)
./run_mosquitto_parallel_docker.sh \
  --runs 3 --parallelism 3 --timeout 70 \
  --image mbfuzzer-mosquitto-gcov:1.6.8
```

**Command-line options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--runs N` | 2 | Number of independent fuzzing runs |
| `--parallelism N` | 2 | Maximum concurrent workers |
| `--timeout MINUTES` | 30 | Duration per run (accepts `Ns`, `Nm`, `Nh` suffixes) |
| `--image IMAGE` | `mbfuzzer-mosquitto-gcov:2.0.18` | Docker image for the broker |
| `--network NET` | `mqtt_network` | Docker network name |
| `--python PATH` | `/home/ckt/miniconda3/bin/python` | Python interpreter path |

**What happens per worker:**

1. **Source copy** — `rsync` copies `mbfuzzer/` (including `ext/`) to a
   worker-private directory.
2. **Environment file** — `worker_env.sh` is generated with per-worker
   `MBFUZZER_*` variables (broker IP, ports, output dir, timeout, etc.).
3. **Config template** — `mosquitto-gcov.conf` (v2.x) or `mosquitto-v168.conf`
   (v1.x) is copied and bridge address is patched via `sed`.
4. **Container launch** — A gcov-instrumented mosquitto container starts on a
   unique Docker network IP.
5. **Fuzzing** — `fuzz_gcov.py` sources the env file, applies extensions, and
   runs the fuzzing loop.
6. **Self-termination** — `fuzzing_engine_bridge_broker` checks
   `TIME_LIMITE_SECONDS` and sends `SIGINT` when the timeout is reached.
7. **Coverage collection** — `mosquitto_gcov_collect.sh` runs inside the
   container to generate gcovr reports (JSON, TXT, HTML, XML).
8. **Cleanup** — Container is stopped and removed.

### Step 3 — Inspect Results

```bash
# Results are stored under artifacts/
ls artifacts/parallel-results-mosquitto_*/

# View summary CSV
cat artifacts/parallel-results-mosquitto_*/summary.csv

# View aggregate coverage (multi-run)
cat artifacts/parallel-results-mosquitto_*/aggregate_coverage.json

# Per-worker details
ls artifacts/parallel-results-mosquitto_*/worker01/
#   outputs/          — fuzzing_report.txt, paper_metrics.json, crashes/, queue/, ...
#   coverage/         — gcovr-summary.json, coverage.xml, index.html, ...
#   fuzz.log          — stdout/stderr from fuzz_gcov.py
#   container.id      — Docker container ID
#   worker_env.sh     — Environment variables used
#   fuzz.start_ts     — Epoch timestamp of fuzzing start
#   fuzz.end_ts       — Epoch timestamp of fuzzing end
#   fuzz.exit_code    — Exit code of fuzz_gcov.py
```

**`summary.csv` columns:**

| Column | Description |
|--------|-------------|
| `run_index` | Worker number (1-based) |
| `container_name` | Docker container name |
| `container_id` | Docker container ID (first 12 chars) |
| `broker_ip` | Container IP on Docker network |
| `server_port` | Host port for `server_module` |
| `cache_port` | Host port for `cache_broker` |
| `fuzz_exit_code` | Exit code of `fuzz_gcov.py` |
| `fuzz_duration_s` | Wall-clock fuzzing duration in seconds |
| `messages_sent` | Total MQTT messages sent |
| `branch_pct` | Branch coverage percentage |
| `branch_covered` | Number of branches covered |
| `branch_total` | Total branches in mosquitto |
| `line_pct` | Line coverage percentage |
| `line_covered` | Number of lines covered |
| `line_total` | Total lines in mosquitto |

---

## Environment Variables Reference

All configuration for the extension layer is passed via environment variables.
When no variable is set, the original `globals.py` defaults are used.

| Variable | Default | Description |
|----------|---------|-------------|
| `MBFUZZER_OUTPUT_DIR` | `/root/fuzzing_outputs/` | Fuzzing output directory |
| `MBFUZZER_BROKER_IP` | `172.199.0.7` | Target broker IP |
| `MBFUZZER_BROKER_PORT` | `1883` | Target broker port |
| `MBFUZZER_BROKER_NAME` | `mosquitto` | Target broker container name |
| `MBFUZZER_TIME_LIMIT` | `1800` | Fuzzing duration in seconds |
| `MBFUZZER_SINGLE_BROKER` | *(unset)* | If `1`, shrink to single-broker mode |
| `MBFUZZER_SERVER_PORT` | `1884` | `server_module` listen port |
| `MBFUZZER_CACHE_PORT` | `1885` | `cache_broker` listen port |
| `MBFUZZER_CONNECT_TIMEOUT` | `5` | TCP connect timeout in seconds |
| `MBFUZZER_RECV_TIMEOUT` | `0.1` | Post-connect recv timeout in seconds |

---

## Extension Files Inventory

All 16 new files, grouped by purpose:

### Python Extension Layer (`mbfuzzer/ext/`)

| File | Purpose |
|------|---------|
| `ext/__init__.py` | Bootstrap: `apply_all()` calls 3 extensions in order |
| `ext/globals_ext.py` | Reads `MBFUZZER_*` env vars → patches `globals` module attributes at runtime |
| `ext/client_patch.py` | Monkey-patches `client_module.connect_to_broker` with split connect/recv timeouts |
| `ext/report_ext.py` | Wraps `dump_fuzzing_info_log`: calls original, then appends paper summary + writes `paper_metrics.json` |

### Entry Point

| File | Purpose |
|------|---------|
| `fuzz_gcov.py` | OCP entry point: `ext.apply_all()` → reproduce `fuzz.py` main logic with custom ports |

### Docker Images & Configuration

| File | Purpose |
|------|---------|
| `Dockerfile.mosquitto-gcov` | v2.0.18 gcov image (legacy) |
| `Dockerfile.mosquitto-gcov-v168` | v1.6.8 gcov image |
| `Dockerfile.mosquitto-gcov-unified` | Unified gcov image (any version via `--build-arg`) |
| `mosquitto_gcov_collect.sh` | In-container gcovr collection (JSON + TXT + HTML + XML) |
| `conf/mosquitto-gcov.conf` | v2.0.x mosquitto config (ChatAFL-aligned + bridge) |
| `conf/mosquitto-v168.conf` | v1.6.8 mosquitto config |

### Orchestration & Tools

| File | Purpose |
|------|---------|
| `run_mosquitto_parallel_docker.sh` | Parallel experiment orchestrator |
| `tools/finalize_mosquitto_gcov_run.py` | Post-experiment helper |

---

## OCP Compliance Verification

To verify that no original file has been modified:

```bash
cd /path/to/parent_directory

# Byte-level comparison of ALL shared files
find MBFuzzer_Artifact -type f \
  ! -path '*/.git/*' ! -path '*/__pycache__/*' ! -name '*.pyc' \
  ! -path '*/image/*' ! -name 'README.md' \
  | while read orig; do
    rel="${orig#MBFuzzer_Artifact/}"
    ext="mbfuzzer_artifact/${rel}"
    if [ -f "$ext" ]; then
      if cmp -s "$orig" "$ext"; then
        echo "  ✅ IDENTICAL: $rel"
      else
        echo "  🔴 DIFFERS:   $rel"
      fi
    fi
  done
```

Expected result: **83 files, all IDENTICAL, 0 differences**.

---

## LLM-based Bug Analyzer

To analyze the results using the LLM-based bug analyzer, follow these steps:

1. Extract relevant files from the fuzzing report:
```bash
cd mbfuzzer/llm-based_bug_analyzer
python3 extract_files.py /root/fuzzing_outputs/fuzzing_report.txt
```
This generates a file named `raw_list.txt` in the current directory.

2. Set the OpenAI API key as an environment variable:
```bash
export OPENAI_API_KEY=xxxx
```

3. Run the analysis script:
```bash
python3 replay_all.py raw_list.txt llm_output.txt
```

