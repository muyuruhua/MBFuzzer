# MBFuzzer: A Multi-party Protocol Fuzzer for MQTT Brokers

MBFuzzer is a multi-party black-box fuzzer for MQTT brokers.

This repository (`mbfuzzer_artifact`) is an **OCP-compliant extension** of the
original [MBFuzzer_Artifact](../MBFuzzer_Artifact/).  All 83 original source
files are preserved byte-for-byte; every new capability is delivered through
**purely additive** extension files (18 new files, ~2 336 lines).

---

## Table of Contents

- [Repository Structure](#repository-structure)
- [OCP Extension Architecture](#ocp-extension-architecture)
- [Broker Crash Resilience: gcov Flush Daemon](#broker-crash-resilience-gcov-flush-daemon)
- [Original Usage (Unchanged)](#original-usage-unchanged)
- [Extended Usage: Parallel gcov Campaign](#extended-usage-parallel-gcov-campaign)
  - [Prerequisites](#prerequisites)
  - [Step 1 — Build gcov-Instrumented Docker Image](#step-1--build-gcov-instrumented-docker-image)
  - [Step 2 — Run Parallel Fuzzing Campaign](#step-2--run-parallel-fuzzing-campaign)
  - [Step 3 — Inspect Results](#step-3--inspect-results)
- [Crash Detection & Reporting](#crash-detection--reporting)
- [Environment Variables Reference](#environment-variables-reference)
- [Extension Files Inventory](#extension-files-inventory)
- [OCP Compliance Verification](#ocp-compliance-verification)
- [LLM-based Bug Analyzer](#llm-based-bug-analyzer)

---

## Repository Structure

```
mbfuzzer_artifact/
├── README.md                            # This file
├── run_mosquitto_parallel_docker.sh     # 🆕 Parallel orchestration script (1 092 lines)
│
├── Docker/
│   ├── Dockerfile                       # Original: multi-broker image
│   ├── Dockerfile.mosquitto-gcov        # 🆕 gcov image v2.0.18 (+ flush daemon)
│   ├── Dockerfile.mosquitto-gcov-v168   # 🆕 gcov image v1.6.8
│   ├── Dockerfile.mosquitto-gcov-unified# 🆕 Unified gcov image (any version)
│   ├── gcov_flush_daemon.c              # 🆕 LD_PRELOAD library: periodic .gcda flush (123 lines)
│   ├── mosquitto-gcov-entrypoint.sh     # 🆕 ENTRYPOINT wrapper: sets LD_PRELOAD (27 lines)
│   ├── mosquitto_gcov_collect.sh        # 🆕 In-container gcovr collection (110 lines)
│   ├── broker_start.sh                  # Original
│   ├── init.sh                          # Original
│   ├── run_broker.py                    # Original
│   ├── run_broker_hivemq.py             # Original
│   ├── run.sh                           # Original
│   ├── setting_config.sh               # Original
│   └── conf/
│       ├── mosquitto.conf               # Original (untouched)
│       ├── mosquitto-gcov.conf          # 🆕 v2.0.x gcov config (bridge-aware)
│       ├── mosquitto-v168.conf          # 🆕 v1.6.8 gcov config
│       ├── emqx.conf                    # Original
│       ├── flashmq.conf                 # Original
│       ├── hivemq_config.xml            # Original
│       ├── nanomq.conf                  # Original
│       └── vernemq.conf                 # Original
│
├── mbfuzzer/
│   ├── fuzz.py                          # Original entry point (untouched)
│   ├── fuzz_gcov.py                     # 🆕 OCP entry point (123 lines)
│   ├── globals.py                       # Original (untouched)
│   ├── handle_network_response.py       # Original (untouched)
│   ├── ext/                             # 🆕 OCP extension layer
│   │   ├── __init__.py                  #     Bootstrap: apply_all() (23 lines)
│   │   ├── globals_ext.py               #     Env-var overrides (69 lines)
│   │   ├── client_patch.py              #     Monkey-patch connect timeout (59 lines)
│   │   └── report_ext.py               #     Paper-aligned summary + JSON (185 lines)
│   ├── fuzzer/                          # Original (all 7 files untouched)
│   ├── generators/                      # Original (all 17 files untouched)
│   ├── helper_functions/                # Original (all 10 files untouched)
│   ├── parsers/                         # Original (all 20 files untouched)
│   ├── type/                            # Original (all 7 files untouched)
│   └── llm-based_bug_analyzer/          # Original (all 4 files untouched)
│
├── tools/
│   └── finalize_mosquitto_gcov_run.py   # 🆕 Post-experiment helper (155 lines)
│
└── artifacts/                           # Output directory (git-ignored)
    └── parallel-results-mosquitto_*/
        ├── summary.csv
        ├── aggregate_coverage.json
        └── worker*/
            ├── outputs/                 # fuzz results (crashes, queue, report)
            ├── coverage/                # gcovr JSON/XML/HTML/TXT
            ├── fuzz.log                 # fuzzer stdout/stderr
            ├── broker_crash.status      # "true" or "false"
            ├── broker_exit_code         # container exit code
            └── ...
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
- **Open for extension**: 18 new files provide gcov coverage collection,
  crash-resilient coverage preservation, parallel orchestration, and
  environment-variable-driven configuration.

### How It Works

```
run_mosquitto_parallel_docker.sh
  │
  ├─ writes worker_env.sh (per-worker environment variables)
  │
  ├─ launches Docker container ─────────────────────────────────────
  │     └─ mosquitto-gcov-entrypoint.sh (ENTRYPOINT)
  │         ├─ export LD_PRELOAD=gcov_flush_daemon.so
  │         └─ exec mosquitto
  │             └─ [gcov_flush_daemon] background thread:
  │                   __gcov_flush() every 30s + crash signal handlers
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

The three Python extensions use Python's **mutable module namespace** mechanism:
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

## Broker Crash Resilience: gcov Flush Daemon

### Problem

When a gcov-instrumented process (e.g., mosquitto) crashes (SIGSEGV, SIGABRT,
etc.), the `atexit()` handler that normally writes `.gcda` files is **never
called**, and **ALL** coverage data accumulated since process start is lost.
This leads to 0% coverage for the entire run — a total data loss.

### Solution: `gcov_flush_daemon.so` (LD_PRELOAD)

A new C shared library (`Docker/gcov_flush_daemon.c`, 123 lines) is injected
into the mosquitto process via `LD_PRELOAD`.  It provides three layers of
protection:

| Layer | Mechanism | When It Activates |
|-------|-----------|-------------------|
| **Periodic flush** | Background pthread calls `__gcov_flush()` every N seconds | Continuously during normal operation |
| **Crash handler** | Signal handlers for SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL | On fatal crash — best-effort flush before re-raising |
| **Exit flush** | `__attribute__((destructor))` calls final flush | On normal process exit |

**GCC compatibility** (compile-time detection):

| GCC Version | API Used | Behavior |
|-------------|----------|----------|
| < 11 (e.g., 9.4 on Ubuntu 20.04) | `__gcov_flush()` | Writes `.gcda` + resets counters (gcovr merges correctly) |
| ≥ 11.1 | `__gcov_dump()` | Writes `.gcda` without resetting counters |

### Docker Integration

The flush daemon is integrated via the Docker ENTRYPOINT pattern — **no
modification to mosquitto source code**:

```
Dockerfile.mosquitto-gcov:
  1. Compiles gcov_flush_daemon.c → /usr/local/lib/gcov_flush_daemon.so
  2. Installs mosquitto-gcov-entrypoint.sh as ENTRYPOINT

mosquitto-gcov-entrypoint.sh:
  export LD_PRELOAD="/usr/local/lib/gcov_flush_daemon.so"
  export GCOV_FLUSH_INTERVAL="${GCOV_FLUSH_INTERVAL:-30}"
  exec "$@"   # → runs mosquitto
```

Container logs confirm activation:
```
[gcov_flush_daemon] Periodic gcov flush every 30s (PID=1)
```

### Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `GCOV_FLUSH_INTERVAL` | `30` | Flush interval in seconds |

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
# v2.0.18 only (includes gcov_flush_daemon.so + ENTRYPOINT)
docker build -f Dockerfile.mosquitto-gcov -t mbfuzzer-mosquitto-gcov:2.0.18 .

# v1.6.8 only
docker build -f Dockerfile.mosquitto-gcov-v168 -t mbfuzzer-mosquitto-gcov:1.6.8 .
```

Each image includes:
- mosquitto compiled with `-fprofile-arcs -ftest-coverage` (gcov)
- `gcov_flush_daemon.so` — LD_PRELOAD library for periodic `.gcda` flush and crash resilience
- `mosquitto-gcov-entrypoint.sh` — ENTRYPOINT wrapper that activates the flush daemon
- `gcovr==7.2` for coverage report generation
- `mosquitto_gcov_collect.sh` for in-container coverage collection

### Step 2 — Run Parallel Fuzzing Campaign

```bash
cd /path/to/mbfuzzer_artifact

# Quick test: 2 runs, 2 parallel, 2 minutes each
./run_mosquitto_parallel_docker.sh \
  --runs 2 --parallelism 2 --timeout 120s \
  --image mbfuzzer-mosquitto-gcov:2.0.18

# Standard: 2 runs, 15 minutes each
./run_mosquitto_parallel_docker.sh \
  --runs 2 --parallelism 2 --timeout 15 \
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
   unique Docker network IP, with `gcov_flush_daemon.so` activated via
   ENTRYPOINT.
5. **Fuzzing** — `fuzz_gcov.py` sources the env file, applies extensions, and
   runs the fuzzing loop.
6. **Self-termination** — `fuzzing_engine_bridge_broker` checks
   `TIME_LIMITE_SECONDS` and sends `SIGINT` when the timeout is reached.
7. **Crash detection** — `docker inspect` checks if container is still running
   before coverage collection.  If crashed, the crash is recorded and coverage
   is collected from flush daemon's `.gcda` files.
8. **Coverage collection** — `mosquitto_gcov_collect.sh` runs inside the
   container to generate gcovr reports (JSON, TXT, HTML, XML).
9. **Cleanup** — Container is stopped and removed.

### Step 3 — Inspect Results

```bash
# Results are stored under artifacts/
ls artifacts/parallel-results-mosquitto_*/

# View summary CSV (includes broker_crashed column)
cat artifacts/parallel-results-mosquitto_*/summary.csv

# View aggregate coverage (multi-run, with clean vs crashed breakdown)
cat artifacts/parallel-results-mosquitto_*/aggregate_coverage.json

# Per-worker details
ls artifacts/parallel-results-mosquitto_*/worker01/
#   outputs/              — fuzzing_report.txt, paper_metrics.json, crashes/, queue/, ...
#   coverage/             — gcovr-summary.json, coverage.xml, index.html, ...
#   fuzz.log              — stdout/stderr from fuzz_gcov.py
#   container.id          — Docker container ID
#   worker_env.sh         — Environment variables used
#   fuzz.start_ts         — Epoch timestamp of fuzzing start
#   fuzz.end_ts           — Epoch timestamp of fuzzing end
#   fuzz.exit_code        — Exit code of fuzz_gcov.py
#   broker_crash.status   — "true" or "false"
#   broker_exit_code      — Container exit code (e.g., 0, 137, 139)
```

**`summary.csv` columns (16 fields):**

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
| `broker_crashed` | `true` if broker crashed during fuzzing, `false` otherwise |

**Pretty-print table example** (from a 2×2 120s run):

```
┌──────────────────────────────────── Results ─────────────────────────────────────┐
│ Worker   │ Container ID │ Exit     │ Duration   │ Messages   │ Branch Cov   │ Line Cov     │ Broker    │
├──────────┼──────────────┼──────────┼────────────┼────────────┼──────────────┼──────────────┼───────────┤
│ worker01 │ ea416511d1df │ 0        │ 125s       │ 7464       │ 25.5%        │ 32.0%        │ ok        │
│ worker02 │ f47743323c2e │ 0        │ 125s       │ 13338      │ 25.5%        │ 32.0%        │ ok        │
└──────────┴──────────────┴──────────┴────────────┴────────────┴──────────────┴──────────────┴───────────┘
```

**`aggregate_coverage.json` structure** (multi-run):

```json
{
  "runs": [
    {
      "worker": "worker01",
      "branch_percent": 25.5,
      "branch_covered": 2753,
      "branch_total": 10803,
      "line_percent": 32.0,
      "line_covered": 4355,
      "line_total": 13625,
      "broker_crashed": false,
      "coverage_note": "full"
    }
  ],
  "aggregate": {
    "num_runs": 2,
    "num_broker_crashed": 0,
    "branch_percent_mean": 25.5,
    "branch_percent_min": 25.5,
    "branch_percent_max": 25.5,
    "line_percent_mean": 32.0,
    "line_percent_min": 32.0,
    "line_percent_max": 32.0
  },
  "aggregate_clean": {
    "note": "Stats excluding crashed-broker runs (if any)",
    "num_clean_runs": 2,
    "branch_percent_mean": 25.5,
    "line_percent_mean": 32.0
  }
}
```

---

## Crash Detection & Reporting

### How It Works

Before collecting coverage, the orchestrator inspects container state via
`docker inspect --format='{{.State.Running}}'`:

| Container State | Interpretation | Coverage Strategy |
|----------------|----------------|-------------------|
| `Running=true` | Broker survived the fuzzing session | Graceful stop → atexit flushes `.gcda` → **full coverage** |
| `Running=false` | Broker crashed during fuzzing | Restart container → collect `.gcda` from flush daemon → **partial coverage** |

### What Gets Recorded

| File | Content |
|------|---------|
| `broker_crash.status` | `"true"` or `"false"` |
| `broker_exit_code` | Container exit code (e.g., `139` = SIGSEGV, `134` = SIGABRT) |

### Aggregate JSON Fields

| Field | Description |
|-------|-------------|
| `broker_crashed` (per run) | Boolean: did this broker crash? |
| `coverage_note` (per run) | `"full"` or `"partial (from flush daemon)"` |
| `num_broker_crashed` (aggregate) | Count of crashed runs |
| `aggregate_clean` | Mean coverage excluding crashed runs |

### Why This Matters

Without the flush daemon, a crashed broker produces **0.0%** coverage (no
`.gcda` files).  With the flush daemon:
- `.gcda` files are written every 30 seconds
- Crash signal handlers attempt a final emergency flush
- Even a crash at minute 3 of a 15-minute run preserves ~3 minutes of coverage

---

## Environment Variables Reference

All configuration for the extension layer is passed via environment variables.
When no variable is set, the original `globals.py` defaults are used.

### Python Extension Variables (used by `fuzz_gcov.py`)

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

### Docker / gcov Variables (used inside the container)

| Variable | Default | Description |
|----------|---------|-------------|
| `GCOV_FLUSH_INTERVAL` | `30` | Periodic `.gcda` flush interval in seconds |

---

## Extension Files Inventory

All 18 new files (2 336 lines total), grouped by purpose:

### Crash Resilience (`Docker/`)

| File | Lines | Purpose |
|------|-------|---------|
| `gcov_flush_daemon.c` | 123 | LD_PRELOAD shared library: background pthread calls `__gcov_flush()` every N seconds; crash signal handlers (SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL) do best-effort flush before re-raising; constructor/destructor attributes for auto-init and final flush |
| `mosquitto-gcov-entrypoint.sh` | 27 | Docker ENTRYPOINT wrapper: sets `LD_PRELOAD` + `GCOV_FLUSH_INTERVAL`, then `exec "$@"` to run mosquitto |

### Python Extension Layer (`mbfuzzer/ext/`)

| File | Lines | Purpose |
|------|-------|---------|
| `ext/__init__.py` | 23 | Bootstrap: `apply_all()` calls 3 extensions in order |
| `ext/globals_ext.py` | 69 | Reads `MBFUZZER_*` env vars → patches `globals` module attributes at runtime |
| `ext/client_patch.py` | 59 | Monkey-patches `client_module.connect_to_broker` with split connect/recv timeouts |
| `ext/report_ext.py` | 185 | Wraps `dump_fuzzing_info_log`: calls original, then appends paper summary + writes `paper_metrics.json` |

### Entry Point

| File | Lines | Purpose |
|------|-------|---------|
| `fuzz_gcov.py` | 123 | OCP entry point: sets `PYTHONUNBUFFERED=1`, calls `ext.apply_all()`, reproduces `fuzz.py` main logic with custom ports |

### Docker Images & Configuration

| File | Lines | Purpose |
|------|-------|---------|
| `Dockerfile.mosquitto-gcov` | 69 | v2.0.18 gcov image with flush daemon + ENTRYPOINT |
| `Dockerfile.mosquitto-gcov-v168` | 97 | v1.6.8 gcov image |
| `Dockerfile.mosquitto-gcov-unified` | 123 | Unified gcov image (any version via `--build-arg`) |
| `mosquitto_gcov_collect.sh` | 110 | In-container gcovr collection (JSON + TXT + HTML + XML) |
| `conf/mosquitto-gcov.conf` | 37 | v2.0.x mosquitto config (ChatAFL-aligned + bridge) |
| `conf/mosquitto-v168.conf` | 44 | v1.6.8 mosquitto config |

### Orchestration & Tools

| File | Lines | Purpose |
|------|-------|---------|
| `run_mosquitto_parallel_docker.sh` | 1 092 | Parallel experiment orchestrator with crash detection, summary CSV/table/JSON |
| `tools/finalize_mosquitto_gcov_run.py` | 155 | Post-experiment helper |

### Early Prototype (retained for reference)

| File | Purpose |
|------|---------|
| `Docker/mosquitto_gcov_image/Dockerfile` | Early standalone gcov image prototype |
| `Docker/mosquitto_gcov_image/mosquitto_gcov_collect.sh` | Early gcovr script prototype |
| `Docker/mosquitto_gcov_image/conf/mosquitto.conf` | Early config prototype |

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

> **Note**: `hivemq-4.24.0.zip` and `vernemq.tar.gz` are tracked via Git LFS
> and may show as "DIFFERS" due to LFS pointer vs original binary.  These are
> vendor assets, not source code — the OCP guarantee applies to all 83 source
> files.

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

