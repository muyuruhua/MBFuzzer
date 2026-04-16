"""
OCP Extension: globals overrides via environment variables.

Reads environment variables and patches the ``globals`` module at runtime.
The original ``globals.py`` is NEVER modified.

Supported environment variables
-------------------------------
MBFUZZER_OUTPUT_DIR          Override FUZZING_OUTPUT_DIR
MBFUZZER_BROKER_IP           Override BROKER_IP_1
MBFUZZER_BROKER_PORT         Override BROKER_PORT (int)
MBFUZZER_BROKER_NAME         Override BROKER_NAME_1
MBFUZZER_TIME_LIMIT          Override TIME_LIMITE_SECONDS (int)
MBFUZZER_SINGLE_BROKER       If "1", shrink all container mappings to broker #1 only
MBFUZZER_SERVER_PORT         Override server_module port (stored as EXT_SERVER_PORT)
MBFUZZER_CACHE_PORT          Override cache_broker  port (stored as EXT_CACHE_PORT)
"""

import os
import globals as g


def apply():
    # ── Output directory ──────────────────────────────────────────────────
    output_dir = os.environ.get("MBFUZZER_OUTPUT_DIR")
    if output_dir:
        if not output_dir.endswith("/"):
            output_dir += "/"
        g.FUZZING_OUTPUT_DIR = output_dir
        # Derived paths must be updated too
        g.FUZZING_OUTPUT_CRASH_DIR = g.FUZZING_OUTPUT_DIR + "crashes/"
        g.FUZZING_OUTPUT_QUEUE_DIR = g.FUZZING_OUTPUT_DIR + "queue/"
        g.FUZZING_OUTPUT_DIFF_DIR  = g.FUZZING_OUTPUT_DIR + "diffs/"
        g.FUZZING_OUTPUT_VALID_CON_DIR = g.FUZZING_OUTPUT_DIR + "valid_conn/"

    # ── Broker IP / port / name ───────────────────────────────────────────
    broker_ip = os.environ.get("MBFUZZER_BROKER_IP")
    if broker_ip:
        g.BROKER_IP_1 = broker_ip

    broker_port = os.environ.get("MBFUZZER_BROKER_PORT")
    if broker_port:
        g.BROKER_PORT = int(broker_port)

    broker_name = os.environ.get("MBFUZZER_BROKER_NAME")
    if broker_name:
        g.BROKER_NAME_1 = broker_name

    # ── Time limit ────────────────────────────────────────────────────────
    time_limit = os.environ.get("MBFUZZER_TIME_LIMIT")
    if time_limit:
        g.TIME_LIMITE_SECONDS = int(time_limit)

    # ── Single-broker mode ────────────────────────────────────────────────
    #    Shrinks the 6-broker maps to only broker #1.
    #    The original 6-broker definitions in globals.py are preserved;
    #    only the runtime *view* is narrowed.
    if os.environ.get("MBFUZZER_SINGLE_BROKER") == "1":
        g.DOCKER_CONTAINER_HOST = {g.BROKER_IP_1: g.BROKER_NAME_1}
        g.DOCKER_CONTAINER_BROKER_HOST = {g.BROKER_IP_1: g.BROKER_NAME_1}
        g.DOCKER_CONTAINER = [g.BROKER_NAME_1]
        g.DOCKER_CONTAINER_PORT = {g.BROKER_NAME_1: g.BROKER_PORT}
        # Rebuild the server-module host map so it matches the narrowed set
        g.SERVER_MODULE_HOST_OBJECT = {ip: None for ip in g.DOCKER_CONTAINER_HOST}

    # ── Extension-only attributes (not in original globals.py) ────────────
    #    These are consumed by fuzz_gcov.py to inject custom ports.
    g.EXT_SERVER_PORT = int(os.environ.get("MBFUZZER_SERVER_PORT", "1884"))
    g.EXT_CACHE_PORT  = int(os.environ.get("MBFUZZER_CACHE_PORT",  "1885"))
