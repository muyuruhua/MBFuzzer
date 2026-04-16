import datetime
import type.LimitedSizeSortedDict as LD
import helper_functions.directory_operation as do
import helper_functions.determine_message_type as dmt
import helper_functions.split_messages as sm
from parsers.parse_initializer import ParseInitializer
import helper_functions.convert_format as cf
import socket
import globals as g
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import time

class ClientFuzzer():
    def __init__(self, ip, port, socket_fd):
        self.ip = ip
        self.port = port
        self.socket_fd = socket_fd
        self.crash_occur = False
        self.forward_message = LD.LimitedSizeSortedDict(g.REQUEST_QUEUE_SIZE)
        self.response_message = None

def close_all_sockets(ClientFuzzers):
    for ClientFuzzer in ClientFuzzers.values():
        ClientFuzzer.socket_fd.close()

def connect_to_all_brokers(ClientFuzzers):
    for ip, container_name in g.DOCKER_CONTAINER_HOST.items():
        port = g.DOCKER_CONTAINER_PORT[container_name]
        try:
            socketfd = connect_to_broker(ip, port)
            clientFuzzerObject = ClientFuzzer(ip, port, socketfd)
            ClientFuzzers[container_name] = clientFuzzerObject
        except Exception as e:
            print(f"Failed to setup connection to broker {container_name} at {ip}:{port}.")

def send_and_recv_message_to_broker(message, ClientFuzzerObject):
    if isinstance(message, str):
        message = bytearray.fromhex(message)

    socket_fd = ClientFuzzerObject.socket_fd

    try:
        socket_fd.sendall(message)
        
    # Connection failed -- we found a crash!
    except ConnectionRefusedError:
        g.crash_occurred = True
        ClientFuzzerObject.crash = True
        return
    except Exception as e:
        g.client_socket_error = True
        return

    response_messages = []
    try:
        while True:
            response_msg = socket_fd.recv(1024000)
            if not response_msg:
                break
            response_messages.append(response_msg)
    except socket.timeout:
        pass
    except ConnectionResetError:
        # print("Connection closed after sending the payload")
        g.client_socket_error = True
    
    for response in response_messages:
        now = datetime.datetime.now()
        recvtime = int(now.timestamp() * 1000)
        payload = response.hex()
        
        if sm.contains_multiple_mqtt_messages(payload) == True:
            messges = sm.split_mqtt_messages(payload)  
            for message in messges: 
                mtype = dmt.determine_message_type(message)
                if mtype == g.MSG_TYPE_PUBLISH:
                    ClientFuzzerObject.forward_message.add_item(recvtime, message)
                else:
                    ClientFuzzerObject.response_message = message
        else:
            if dmt.determine_message_type(payload) == g.MSG_TYPE_PUBLISH:
                ClientFuzzerObject.forward_message.add_item(recvtime, payload)
            else:
                ClientFuzzerObject.response_message = payload
    return


def connect_to_broker(ip, port, max_retries = 100, retry_delay = 10): 
    for attempt in range(max_retries):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect((ip, port))
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


def client_close_all_broker(ClientFuzzers):
    for container_name, clientFuzzer in ClientFuzzers.items():
        clientFuzzer.socket_fd.close()
