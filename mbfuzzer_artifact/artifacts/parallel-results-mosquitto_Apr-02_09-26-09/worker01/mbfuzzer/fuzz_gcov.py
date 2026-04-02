#!/usr/bin/env python3
"""
fuzz_gcov.py  –  OCP-compliant entry point for MBFuzzer gcov campaigns.

This thin wrapper applies all extensions from ``ext/`` and then
delegates to the **unmodified** ``fuzz.main()``.

Usage (environment variables configure the extensions):

    export MBFUZZER_OUTPUT_DIR="/path/to/outputs/"
    export MBFUZZER_BROKER_IP="172.199.0.11"
    export MBFUZZER_BROKER_NAME="mosquitto-worker01"
    export MBFUZZER_SINGLE_BROKER=1
    export MBFUZZER_TIME_LIMIT=900
    export MBFUZZER_SERVER_PORT=1884
    export MBFUZZER_CACHE_PORT=1885
    export MBFUZZER_CONNECT_TIMEOUT=5
    python fuzz_gcov.py

The original fuzz.py, globals.py, client_module.py, and
directory_operation.py are NEVER modified.
"""

import sys
import os

# Ensure the package root is on sys.path so "import globals" works.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

# ── Apply all OCP extensions BEFORE any fuzzer code runs ──────────────────
import ext                       # noqa: E402
ext.apply_all()

# ── Now import globals to inject custom ports into fuzz objects ────────────
import globals as g              # noqa: E402

# ── Override server_module / cache_broker ports (was done via sed on fuzz.py)
# We monkey-patch the module-level constants that fuzz.main() uses.
import fuzzer.server_module as _sm         # noqa: E402
import fuzzer.retain_recv_module as _rrm   # noqa: E402

_SERVER_PORT = getattr(g, "EXT_SERVER_PORT", 1884)
_CACHE_PORT  = getattr(g, "EXT_CACHE_PORT",  1885)

# ── Delegate to original fuzz.main() ─────────────────────────────────────
import fuzz                      # noqa: E402
import signal                    # noqa: E402
import helper_functions.directory_operation as do  # noqa: E402

# Re-wire the signal handler so it references the (now-patched) dump func.
_GLOBAL_Q_MODEL = None

def _handle_exit(signum, frame):
    print("Received Ctrl+C signal. Exiting...")
    do.dump_fuzzing_info_log(_GLOBAL_Q_MODEL)
    os._exit(0)


def main():
    global _GLOBAL_Q_MODEL
    signal.signal(signal.SIGINT, _handle_exit)

    import fuzzer.q_learning as QLearning
    import time

    do.create_initial_fuzzing_directory()

    Q_Model = QLearning.QLearningTable()
    _GLOBAL_Q_MODEL = Q_Model

    cacheBroker = _rrm.CacheBroker(port=_CACHE_PORT)
    cacheBroker.start()

    g.FUZZING_START_TIME = time.time()

    broker = _sm.MQTTBroker(port=_SERVER_PORT, MessageModel=Q_Model)
    broker.start()

    while broker.check_fuzzing_bridge_status() is False:
        print(f"Initial waiting for brokers (will be soon) {broker.client_sessions.keys()}")
        time.sleep(3)

    import fuzzer.fuzzing_engine as fe
    while_start_time = g.FUZZING_START_TIME

    while True:
        fe.single_fuzzing_engine_client(Q_Model)
        if g.DEBUG_FLAG_CLIENT_MSG_SENDING is True:
            break

        cur_time = time.time()
        elapsed_time = cur_time - while_start_time
        if elapsed_time >= 60:
            while_start_time = cur_time
            do.dump_fuzzing_info_log(Q_Model)

    print("Fuzzing loop finished.")
    do.dump_fuzzing_info_log(Q_Model)


if __name__ == "__main__":
    main()
