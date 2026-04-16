from connect import Connect
from packet import Packet
from packet import packetTest
from properties import Properties
import random
import fuzzer.mutation as fm
import helper_functions.convert_format as cf
import threading
import globals as g
import string

class UnsubscribePayload(Packet):
    def __init__(self, protocol_version):
        super().__init__()

        self.numTopics = random.randint(0, 10)

        for i in range(self.numTopics):
            topicLength = random.randint(0, 30)
            topic = self.toEncodedString(None, topicLength) # ['0003', ['63', '6f', '34']]
            if fm.should_mutate("topic") == True and topicLength > 0:
                topic_bytes = cf.hex_list_to_bytes(topic[1])
                mutated_bytes = fm.handle_string_mutate_del_insert_replace(topic_bytes)
                mutated_list = cf.bytes_to_hex_list(mutated_bytes)
                topic_len = cf.int_to_padded_hex_string(len(mutated_list), 4)
                topic = [topic_len, mutated_list]

            if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID and g.cur_client_dependency != None:
                if len(g.cur_client_dependency) == 1 and g.FIELD_TOPIC in g.cur_client_dependency["passive"]["field"]:
                    topic = g.cur_client_dependency["passive"]["field"][g.FIELD_TOPIC]
            elif threading.current_thread().ident == g.Broker_Fuzzing_Thread_ID and g.cur_broker_dependency != None:
                if len(g.cur_broker_dependency) == 1 and g.FIELD_TOPIC in g.cur_broker_dependency["passive"]["field"]:
                    topic = g.cur_broker_dependency["passive"]["field"][g.FIELD_TOPIC]

            self.payload.append(topic)

class UnsubscribeVariableHeader(Packet):
    def __init__(self, protocol_version):
        super().__init__()

        self.packet_identifier = self.toBinaryData(None, 2, True)   # ['00', '01']
        if fm.should_mutate("packet_identifier") == True:
            packet_id = cf.hex_list_to_bytes(self.packet_identifier)
            mutated_bytes = fm.handle_int_mutate_up_downgrad_replace(packet_id)
            mutated_list = cf.bytes_to_hex_list(mutated_bytes)
            self.packet_identifier = mutated_list
        self.payload.append(self.packet_identifier)

        self.properties = Properties([0x26])
        if protocol_version == 5:
            self.payload.append(self.properties.toString())

class Unsubscribe(Packet):
    def __init__(self, protocol_version = None):
        super().__init__()

        if protocol_version is None:
            protocol_version = random.randint(3, 5)

        self.fixed_header = "a2"
        self.variable_header = UnsubscribeVariableHeader(protocol_version)
        self.unsubscribe_payload = UnsubscribePayload(protocol_version)

        remaining_length = self.variable_header.getByteLength() + self.unsubscribe_payload.getByteLength()

        self.payload = [self.fixed_header, self.toVariableByte("%x" % remaining_length), self.variable_header.toString(), self.unsubscribe_payload.toString()]
        
if __name__ == "__main__":
    packetTest([Connect, Unsubscribe], 300)