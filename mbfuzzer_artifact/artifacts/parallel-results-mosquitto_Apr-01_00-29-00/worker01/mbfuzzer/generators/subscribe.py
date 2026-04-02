from connect import Connect
from packet import Packet
from packet import packetTest
from properties import Properties
import fuzzer.mutation as fm
import random
import helper_functions.convert_format as cf
import threading
import globals as g
import string

class SubscribePayload(Packet):
    def __init__(self, protocol_version):
        super().__init__()

        self.numTopics = random.randint(0, 10)

        for i in range(self.numTopics):
            with g.Lock_RemoteRetainMessageTopic:
                if random.random() < 0.5 and len(g.RemoteRetainMessageTopic) > 0:
                    retain_topic = random.choice(g.RemoteRetainMessageTopic)
                    # retain_topic_bytes = cf.hex_string_to_bytes(retain_topic)
                    retain_topic_list = cf.bytes_to_hex_list(retain_topic)
                    topicLength = len(retain_topic_list)
                    topic = [cf.int_to_padded_hex_string(topicLength, 4), retain_topic_list]
                else:
                    topicLength = random.randint(0, 30)
                    topic = self.toEncodedString(None, topicLength) # ['0003', ['63', '6f', '34']]

            if fm.should_mutate("topic") == True and topicLength > 0:
                topic_bytes = cf.hex_list_to_bytes(topic[1])
                mutated_bytes = fm.handle_string_mutate_del_insert_replace(topic_bytes)
                mutated_list = cf.bytes_to_hex_list(mutated_bytes)
                topic_len = cf.int_to_padded_hex_string(len(mutated_list), 4)
                topic = [topic_len, mutated_list]

            if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID and g.cur_client_dependency != None:
                if len(g.cur_client_dependency) == 2:
                    if g.FIELD_TOPIC in g.cur_client_dependency["active"]["field"]:
                        g.cur_client_dependency["passive"]["field"][g.FIELD_TOPIC] = topic
                    if g.FIELD_SHARED_TOPIC in g.cur_client_dependency["active"]["field"]:
                        g.cur_client_dependency["passive"]["field"][g.FIELD_SHARED_TOPIC] = topic
                        topic_bytes = cf.hex_list_to_bytes(topic[1])
                        shared_prefix = "$share/" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + "/"
                        shared_prefix_bytes = shared_prefix.encode("utf-8")
                        topic[1] = cf.bytes_to_hex_list(shared_prefix_bytes + topic_bytes)
                        topic[0] = cf.int_to_padded_hex_string(len(topic[1]), 4)
                elif len(g.cur_client_dependency) == 1 and g.FIELD_TOPIC in g.cur_client_dependency["passive"]["field"]:
                    topic = g.cur_client_dependency["passive"]["field"][g.FIELD_TOPIC]
            elif threading.current_thread().ident == g.Broker_Fuzzing_Thread_ID and g.cur_broker_dependency != None:
                if len(g.cur_broker_dependency) == 2:
                    if g.FIELD_TOPIC in g.cur_broker_dependency["active"]["field"]:
                        g.cur_broker_dependency["passive"]["field"][g.FIELD_TOPIC] = topic
                    if g.FIELD_SHARED_TOPIC in g.cur_broker_dependency["active"]["field"]:
                        g.cur_broker_dependency["passive"]["field"][g.FIELD_SHARED_TOPIC] = topic
                        topic_bytes = cf.hex_list_to_bytes(topic[1])
                        shared_prefix = "$share/" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + "/"
                        shared_prefix_bytes = shared_prefix.encode("utf-8")
                        topic[1] = cf.bytes_to_hex_list(shared_prefix_bytes + topic_bytes)
                        topic[0] = cf.int_to_padded_hex_string(len(topic[1]), 4)
                elif len(g.cur_broker_dependency) == 1 and g.FIELD_TOPIC in g.cur_broker_dependency["passive"]["field"]:
                    topic = g.cur_broker_dependency["passive"]["field"][g.FIELD_TOPIC]

            self.payload.append(topic)

            topic_qos = random.randint(0, 2)
            no_local = random.randint(0, 1)
            retain_as_published = random.randint(0, 1)
            retain_handling = random.randint(0, 2)

            if protocol_version < 5:
                no_local = 0
                retain_as_published = 0
                retain_handling = 0
            
            subscription_options_tmp = [0b00, (retain_handling >> 1) & 1, retain_handling & 1, retain_as_published, no_local, (topic_qos >> 1) & 1, topic_qos & 1]

            subscription_options = ["%.2x" % int("".join(bin(s)[2:] for s in subscription_options_tmp), 2)] # ['02']

            if fm.should_mutate("subscription_options") == True:
                sub_opt_bytes = cf.hex_list_to_bytes(subscription_options)
                mutated_bytes = fm.handle_int_mutate_bitflip(sub_opt_bytes, 0, 8)
                mutated_list = cf.bytes_to_hex_list(mutated_bytes)
                subscription_options = mutated_list

            self.payload.append(subscription_options)

class SubscribeVariableHeader(Packet):
    def __init__(self, protocol_version):
        super().__init__()

        self.packet_identifier = self.toBinaryData(None, 2, True)
        if fm.should_mutate("packet_identifier") == True:
            packet_id = cf.hex_list_to_bytes(self.packet_identifier)
            mutated_bytes = fm.handle_int_mutate_up_downgrad_replace(packet_id)
            mutated_list = cf.bytes_to_hex_list(mutated_bytes)
            self.packet_identifier = mutated_list
        self.payload.append(self.packet_identifier)

        self.properties = Properties([0x0b, 0x26])
        if protocol_version == 5:
            self.payload.append(self.properties.toString())

class Subscribe(Packet):
    def __init__(self, protocol_version = None):
        super().__init__()

        if protocol_version is None:
            protocol_version = random.randint(3, 5)

        self.fixed_header = "82"
        self.variable_header = SubscribeVariableHeader(protocol_version)
        self.subscribe_payload = SubscribePayload(protocol_version)

        remaining_length = self.variable_header.getByteLength() + self.subscribe_payload.getByteLength()

        self.payload = [self.fixed_header, self.toVariableByte("%x" % remaining_length), self.variable_header.toString(), self.subscribe_payload.toString()]
        
if __name__ == "__main__":
    packetTest([Connect, Subscribe], 300)