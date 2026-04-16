"""
OCP Extension: socket connect() timeout monkey-patch.

The original ``client_module.connect_to_broker`` uses a 0.1 s timeout for
*both* the TCP connect() and subsequent recv().  In Docker / bridged
networking the 0.1 s connect window is often too short.

This patch:
  1. Raises the timeout to ``CONNECT_TIMEOUT`` seconds *only* for connect().
  2. Restores the original recv timeout immediately after connect() succeeds.

The original ``client_module.py`` is NEVER modified.

Environment variables
---------------------
MBFUZZER_CONNECT_TIMEOUT   TCP connect timeout in seconds  (default: 5)
MBFUZZER_RECV_TIMEOUT      Post-connect recv timeout       (default: 0.1)
"""

import os
import socket
import time

import fuzzer.client_module as cm
import helper_functions.directory_operation as do

CONNECT_TIMEOUT = float(os.environ.get("MBFUZZER_CONNECT_TIMEOUT", "5"))
RECV_TIMEOUT    = float(os.environ.get("MBFUZZER_RECV_TIMEOUT",    "0.1"))

# Keep a reference to the original function so we can delegate if needed.
_original_connect_to_broker = cm.connect_to_broker


def _patched_connect_to_broker(ip, port, max_retries=100, retry_delay=10):
    """Drop-in replacement with split connect/recv timeouts."""
    for attempt in range(max_retries):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(CONNECT_TIMEOUT)       # longer window for connect()
            sock.connect((ip, port))
            sock.settimeout(RECV_TIMEOUT)           # restore fast recv timeout
            return sock
        except socket.timeout:
            print(f"Connection attempt {attempt + 1} timed out. Retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)
        except ConnectionRefusedError:
            print(f"Connection refused by broker at {ip}:{port}. Retrying...")
            time.sleep(retry_delay)
            do.save_crash_requests()
        except Exception as e:
            print(f"An error occurred during connection: {e}. Retrying...")
            time.sleep(retry_delay)

    raise Exception(f"Failed to connect to broker at {ip}:{port} after {max_retries} attempts.")


def apply():
    """Replace ``client_module.connect_to_broker`` with the patched version."""
    cm.connect_to_broker = _patched_connect_to_broker
