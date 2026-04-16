import subprocess
import psutil
import socket
import time
import binascii
import argparse

def is_mqtt_open(host, port):
    MQTT_PING_PACKET = binascii.unhexlify("100c00044d5154540402003c0000")
    RESPONSE_TIMEOUT = 1  # seconds

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(RESPONSE_TIMEOUT)
            sock.connect((host, port))
            sock.sendall(MQTT_PING_PACKET)
            
            try:
                response = sock.recv(1024)
                return bool(response)
            except socket.timeout:
                return False
    except (socket.timeout, ConnectionRefusedError):
        return False

def start_process(command):
    return subprocess.Popen(command, shell=True)

def terminate_process(proc):
    try:
        parent_pid = proc.pid
        parent = psutil.Process(parent_pid)
        children = parent.children(recursive=True)
        
        for child in children:
            child.terminate()
        psutil.wait_procs(children, timeout=5)
        
        for child in psutil.Process(parent_pid).children(recursive=True):
            child.kill()
        
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    except Exception as e:
        print(f"An error occurred: {e}")

def monitor_process(proc, host, port):
    while True:
        if proc.poll() is not None:
            return False

        if not is_mqtt_open(host, port):
            time.sleep(3)
            if not is_mqtt_open(host, port):
                return False
        else:
            pass

        time.sleep(5)

def main():
    parser = argparse.ArgumentParser(description="Monitor and manage an MQTT process.")
    parser.add_argument("--command", required=True, help="The command to start the target process.")
    parser.add_argument("--host", default="localhost", help="The host to check the MQTT connection on.")
    parser.add_argument("--port", type=int, default=1883, help="The port to check the MQTT connection on.")
    args = parser.parse_args()

    while True:
        proc = start_process(args.command)
        
        if not monitor_process(proc, args.host, args.port):
            terminate_process(proc)
            print("Process restarted.")

if __name__ == "__main__":
    main()