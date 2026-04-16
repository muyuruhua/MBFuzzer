import socket
import threading
import json
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import globals as g


class CacheBroker:
    def __init__(self, host='0.0.0.0', port=1885):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lock = threading.Lock()
        self.buffer = {}
        self.expected_clients = len(g.DOCKER_CONTAINER_HOST)

    def find_non_common_topics(self, brokers_dict):
        # Step 1: Find the intersection of all topic lists
        common_topics = set.intersection(*[set(topics) for topics in brokers_dict.values()])
        # Step 2: Find the union of all topic lists
        all_topics = set.union(*[set(topics) for topics in brokers_dict.values()])
        # Step 3: Find the difference between all topics and the common topics
        non_common_topics = list(all_topics - common_topics)
        # Step 4: remove some invalid
        non_common_topics_bytes = []
        for topic in non_common_topics:
            try:
                data = bytes.fromhex(topic)
                non_common_topics_bytes.append(data)
            except ValueError as e:
                continue

        return non_common_topics_bytes


    def start(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        
        cache_thread = threading.Thread(target=self._handle_connections)
        cache_thread.start()

    def _handle_connections(self):
        while True:
            client_socket, client_address = self.socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, client_address)).start()

    def handle_client(self, client_socket, client_address):

        broker_name = g.DOCKER_CONTAINER_HOST[client_address[0]]        
        buffer = ""
        while True:
            try:
                message = client_socket.recv(10240).decode('utf-8')
                if not message:
                    break
                
                buffer += message
            except (ConnectionResetError, BrokenPipeError):
                break
        
        if buffer:
            try:
                data = json.loads(buffer)
                if 'retain_topic' in data:
                    with self.lock:
                        self.buffer[broker_name] = data['retain_topic']
            except json.JSONDecodeError:
                print(f'Invalid message format: {buffer} from {broker_name}')
                return
        
        with g.Lock_RemoteRetainMessageTopic:
            if len(self.buffer) == self.expected_clients:
                g.RemoteRetainMessageTopic = self.find_non_common_topics(self.buffer)
                self.buffer = {}

        client_socket.close()


if __name__ == '__main__':
    broker = CacheBroker()
    broker.start()
