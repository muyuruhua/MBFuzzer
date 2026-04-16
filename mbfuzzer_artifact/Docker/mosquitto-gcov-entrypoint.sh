#!/bin/sh
# ═══════════════════════════════════════════════════════════════════════════
# mosquitto-gcov-entrypoint.sh
#
# Entrypoint wrapper for gcov-instrumented mosquitto containers.
#
# Responsibilities:
#   1. Set LD_PRELOAD to load gcov_flush_daemon.so (periodic .gcda flush)
#   2. Run mosquitto in a SUPERVISED LOOP for crash resilience
#   3. Auto-restart on SIGSEGV / abnormal exit (up to MAX_RESTARTS)
#   4. Log restart events to /coverage/broker_restarts.log
#   5. Forward SIGTERM/SIGINT for graceful docker stop
#
# WHY: Fuzzing deliberately sends malformed input to trigger bugs.  When the
#   broker crashes (e.g. SIGSEGV in mosquitto v2.0.18), without auto-restart
#   the Docker container exits, the broker IP becomes unreachable, and the
#   fuzzer wastes all remaining time retrying dead connections.  With the
#   supervisor loop the broker is back within seconds, the fuzzer reconnects
#   via its built-in retry logic, and fuzzing continues — yielding more
#   coverage and potentially discovering additional bugs.
#
# The gcov_flush_daemon.so library ensures that:
#   - .gcda files are written every GCOV_FLUSH_INTERVAL seconds (default 30)
#   - On crash, a best-effort flush saves coverage up to the crash point
#   - Coverage data ACCUMULATES across auto-restarts (.gcda files persist)
#
# Environment variables:
#   GCOV_FLUSH_INTERVAL      – seconds between periodic flushes (default: 30)
#   MOSQUITTO_MAX_RESTARTS   – max crash restarts allowed   (default: 5)
#   MOSQUITTO_RESTART_DELAY  – seconds to wait before restart (default: 2)
#
# OCP NOTE:
#   This is a NEW extension file.  No original files are modified.
# ═══════════════════════════════════════════════════════════════════════════

# ── Configuration ─────────────────────────────────────────────────────────
export GCOV_FLUSH_INTERVAL="${GCOV_FLUSH_INTERVAL:-30}"
export LD_PRELOAD="/usr/local/lib/gcov_flush_daemon.so"

MAX_RESTARTS="${MOSQUITTO_MAX_RESTARTS:-5}"
RESTART_DELAY="${MOSQUITTO_RESTART_DELAY:-2}"

# ── State ─────────────────────────────────────────────────────────────────
RESTART_COUNT=0
CHILD_PID=0
STOP_REQUESTED=0

# Restart log: prefer /coverage (mounted volume), fall back to /tmp
if [ -d "/coverage" ] || mkdir -p /coverage 2>/dev/null; then
    RESTART_LOG="/coverage/broker_restarts.log"
else
    RESTART_LOG="/tmp/broker_restarts.log"
fi

# ── Signal handling ───────────────────────────────────────────────────────
# Forward SIGTERM/SIGINT to child for graceful docker stop.
# Sets STOP_REQUESTED flag so the loop exits cleanly after wait returns.
forward_signal() {
    STOP_REQUESTED=1
    if [ "$CHILD_PID" -ne 0 ]; then
        kill -TERM "$CHILD_PID" 2>/dev/null
    fi
}
trap forward_signal TERM INT

# ── Initialize restart log ────────────────────────────────────────────────
: > "${RESTART_LOG}" 2>/dev/null || true

echo "[gcov-entrypoint] Supervisor mode: max_restarts=${MAX_RESTARTS}, restart_delay=${RESTART_DELAY}s, flush_interval=${GCOV_FLUSH_INTERVAL}s" >&2

# ── Supervisor loop ───────────────────────────────────────────────────────
while true; do
    "$@" &
    CHILD_PID=$!

    wait "$CHILD_PID" 2>/dev/null
    EXIT_CODE=$?
    CHILD_PID=0

    # ── Graceful stop requested (docker stop → SIGTERM) ───────────────
    if [ "$STOP_REQUESTED" -eq 1 ]; then
        echo "[gcov-entrypoint] Graceful shutdown (SIGTERM received)." >&2
        exit 0
    fi

    # ── Normal exit (mosquitto exited with code 0) ────────────────────
    if [ "$EXIT_CODE" -eq 0 ]; then
        echo "[gcov-entrypoint] mosquitto exited normally (code 0)." >&2
        break
    fi

    # ── Crash detected — attempt auto-restart ─────────────────────────
    RESTART_COUNT=$((RESTART_COUNT + 1))
    TIMESTAMP="$(date '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || echo 'unknown')"

    # Decode signal name for common crash signals
    SIGNAL_INFO=""
    case "$EXIT_CODE" in
        134) SIGNAL_INFO=" (SIGABRT)" ;;
        135) SIGNAL_INFO=" (SIGBUS)"  ;;
        136) SIGNAL_INFO=" (SIGFPE)"  ;;
        139) SIGNAL_INFO=" (SIGSEGV)" ;;
        132) SIGNAL_INFO=" (SIGILL)"  ;;
    esac

    echo "${TIMESTAMP} restart=${RESTART_COUNT}/${MAX_RESTARTS} exit_code=${EXIT_CODE}${SIGNAL_INFO}" >> "${RESTART_LOG}" 2>/dev/null || true

    echo "[gcov-entrypoint] mosquitto crashed (exit ${EXIT_CODE}${SIGNAL_INFO}), auto-restart ${RESTART_COUNT}/${MAX_RESTARTS}" >&2

    if [ "$RESTART_COUNT" -ge "$MAX_RESTARTS" ]; then
        echo "[gcov-entrypoint] Max restarts reached (${MAX_RESTARTS}). Container will exit." >&2
        exit "${EXIT_CODE}"
    fi

    sleep "${RESTART_DELAY}"
done
