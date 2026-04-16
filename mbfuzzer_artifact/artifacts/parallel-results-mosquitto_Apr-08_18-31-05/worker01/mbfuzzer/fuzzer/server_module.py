import socket
import threading
import fuzzer.fuzzing_engine as fe
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import datetime
import type.LimitedSizeSortedDict as LD
import helper_functions.convert_format as cf
import globals as g


def send_message_to_broker(message, cs_object):
    temp_message = message
    if isinstance(message, str):
        message = bytearray.fromhex(message)

    cs_object.client_socket.settimeout(0.2)
    try:
        cs_object.client_socket.sendall(message)

    except socket.timeout:
        return
    except Exception as e:
        cs_object.is_bridge_established = False
        return
    
    if g.broker_send_and_wait_event.get(cs_object.broker_name) != None:
        g.broker_send_and_wait_event[cs_object.broker_name].wait(timeout=0.1)
        g.broker_send_and_wait_event[cs_object.broker_name].clear()
    
class ClientSession:
    def __init__(self, ip, port, socket_fd):
        self.ip = ip
        self.port = port
        self.client_socket = socket_fd
        self.broker_name = None
        self.protocol_version = None  
        self.is_bridge_established = False      
        self.response_message = None 
        self.forward_message = LD.LimitedSizeSortedDict(g.REQUEST_QUEUE_SIZE) 
        self.crash_occurred = False   


class MQTTBroker:
    def __init__(self, host='0.0.0.0', port=1884, MessageModel=None):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.client_sessions = {} 
        self.MessageModel = MessageModel

    def clear_all_response_message(self):
        for session in self.client_sessions.values():
            if isinstance(session, ClientSession):
                session.response_message = None

    def check_fuzzing_bridge_status(self):
        if len(self.client_sessions) == len(g.DOCKER_CONTAINER_BROKER_HOST):
            for session in self.client_sessions.values():
                if not session.is_bridge_established:
                    return False
            return True
        else:
            return False

    def start(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        
        fuzzing_thread = threading.Thread(target=fe.fuzzing_engine_bridge_broker, args=(self, self.MessageModel)) 
        fuzzing_thread.start()

        server_thread = threading.Thread(target=self._handle_connections)
        server_thread.start()


    def _handle_connections(self):
        while True:
            client_socket, client_address = self.socket.accept()

            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
            client_thread.start()

    def handle_client(self, client_socket, client_address):
        while True:
            try:
                data = client_socket.recv(1024000)
                if not data:
                    break
            except Exception as e:
                break
            message_type = data[0] >> 4
            
            if message_type == 1:  # CONNECT
                self.handle_connect(data, client_socket, client_address)
            elif message_type == 3:  # PUBLISH (forward message)
                self.handle_publish(data, client_socket, client_address)
            elif message_type == 8:  # SUBSCRIBE
                self.handle_subscribe(data, client_socket, client_address)
            elif message_type == 12:    # PINGREQ
                self.handle_ping(data, client_socket, client_address)
            elif message_type == 14: # DISCONNECT
                self.handle_disconnect(data, client_socket, client_address)
            else: 
                self.handle_others(data, client_socket, client_address)
                
    def handle_disconnect(self, data, client_socket, client_address):
        pass
    
    def handle_others(self, data, client_socket, client_address):
        if g.DOCKER_CONTAINER_BROKER_HOST.get(client_address[0]) != None:
            broker_name = g.DOCKER_CONTAINER_BROKER_HOST.get(client_address[0])
            now = datetime.datetime.now()
            recvtime = int(now.timestamp() * 1000)
            payload = data.hex()
            self.client_sessions[broker_name].response_message = payload
            g.broker_send_and_wait_event[broker_name].set() 


    def handle_publish(self, data, client_socket, client_address):
        with fe.get_kv_lock(g.remove_items_locks, client_address[0]):
            broker_name = g.DOCKER_CONTAINER_BROKER_HOST[client_address[0]]
            if g.broker_to_remove_times.get(client_address[0]) != None:
                remove_time_list = g.broker_to_remove_times[client_address[0]]
                self.client_sessions[broker_name].forward_message.remove_timestamps(remove_time_list)
                g.broker_to_remove_times[client_address[0]].clear()

            now = datetime.datetime.now()
            recvtime = int(now.timestamp() * 1000)
            payload = data.hex()
            clientSession = self.client_sessions[broker_name]
            clientSession.forward_message.add_item(recvtime, payload)


    def handle_ping(self, data, client_socket, client_address):
        pingresp_msg = bytearray([0xd0, 0x00])
        client_socket.sendall(pingresp_msg)


    def handle_connect(self, data, client_socket, client_address):
        hex_data = cf.bytes_to_hex_string(data)
        protocol_version = int(hex_data[16:18], 16)
        if protocol_version >= 128:
            protocol_version = protocol_version - 128
        
        if protocol_version == 4:
            connack_msg = bytearray([
                0x20,  # CONNACK
                0x02,  # Remaining Length
                0x00,  # Connect Acknowledge Flags
                0x00,  # Connect Return Code
            ])
        elif protocol_version == 5:
            connack_msg = bytearray([
                0x20,  # CONNACK
                0x03,  # Remaining Length
                0x00,  # Connect Acknowledge Flags
                0x00,  # Connect Return Code
                0x00,  # Property Length
            ])

        try:
            client_socket.sendall(connack_msg)
            if client_address[0] not in g.DOCKER_CONTAINER_BROKER_HOST:
                exit(0)

            broker_name = g.DOCKER_CONTAINER_BROKER_HOST[client_address[0]]
            if broker_name not in self.client_sessions and client_address[0] in g.DOCKER_CONTAINER_BROKER_HOST:
                self.client_sessions[broker_name] = ClientSession(client_address[0], client_address[1], client_socket)
            self.client_sessions[broker_name].broker_name = g.DOCKER_CONTAINER_BROKER_HOST[client_address[0]]
            self.client_sessions[broker_name].protocol_version = protocol_version
            self.client_sessions[broker_name].is_bridge_established = False
            self.client_sessions[broker_name].crash_occurred = False
            g.broker_send_and_wait_event.setdefault(broker_name, threading.Event())

        except ConnectionResetError:
            client_socket.close()


    def handle_subscribe(self, data, client_socket, client_address):
        hex_data = cf.bytes_to_hex_string(data)
        packet_id = int(hex_data[4:8], 16)
        packet_id = cf.int_to_padded_hex_string(packet_id, 4)

        broker_name = g.DOCKER_CONTAINER_BROKER_HOST[client_address[0]]

        if self.client_sessions[broker_name].protocol_version == 4:
            suback_msg = "90" + "03" + packet_id + "00"
        elif self.client_sessions[broker_name].protocol_version == 5:
            suback_msg = "90" + "04" + packet_id + "0000"

        suback_msg = cf.hex_string_to_bytes(suback_msg)
        try:
            client_socket.sendall(suback_msg)
        except Exception as e:
            client_socket.close()

        self.client_sessions[broker_name].client_socket = client_socket
        self.client_sessions[broker_name].is_bridge_established = True



if __name__ == "__main__":
    broker = MQTTBroker(port=1884)
    broker.start()
