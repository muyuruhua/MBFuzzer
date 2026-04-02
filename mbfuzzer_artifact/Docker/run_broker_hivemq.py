import subprocess
import psutil
import socket
import time
import os
import argparse
import binascii
import signal

def start_process(command):
    return subprocess.Popen(command, shell=True, preexec_fn=os.setsid)

def terminate_process(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
    except Exception as e:
        print(f"An error occurred: {e}")

    while True:
        time.sleep(5)
        if not any("java" in p.name() for p in psutil.process_iter()):
            break

def monitor_process(proc, host, port, path1, path2):
    while True:
        if proc.poll() is not None:
            return False

        if os.path.exists(path1) and os.path.exists(path2):
            os.remove(path1)
            os.remove(path2)
            terminate_process(proc)
            return False

        time.sleep(30) 

def main():
    parser = argparse.ArgumentParser(description="Monitor and manage an MQTT process.")
    parser.add_argument("--command", required=True, help="The command to start the target process.")
    parser.add_argument("--host", default="localhost", help="The host to check the MQTT connection on.")
    parser.add_argument("--port", type=int, default=1883, help="The port to check the MQTT connection on.")
    parser.add_argument("--path1", required=True, help="The path to the first DISABLE file.")
    parser.add_argument("--path2", required=True, help="The path to the second DISABLE file.")
    args = parser.parse_args()

    while True:
        proc = start_process(args.command)
        print("proc: ", proc)

        if not monitor_process(proc, args.host, args.port, args.path1, args.path2):
            print("Process restarted.")

if __name__ == "__main__":
    main()