from connect import Connect
from packet import Packet
from packet import packetTest
from properties import Properties
import random
import fuzzer.mutation as fm
import helper_functions.convert_format as cf
import threading
import globals as g

class PublishFixedHeader(Packet):
    def __init__(self):
        super().__init__()

        self.dup = random.getrandbits(1)
        self.qos = min(2, random.getrandbits(2))
        self.retain = random.getrandbits(1)
        
        payload_tmp = [0b11, self.dup, (self.qos >> 1) & 1, self.qos & 1, self.retain]

        self.payload = ["%.2x" % int("".join(bin(s)[2:] for s in payload_tmp), 2)]


class PublishVariableHeader(Packet):
    def __init__(self, qos, protocol_version):
        super().__init__()

        self.topic_name_length = random.randint(0, 30)
        self.topic_name = self.toEncodedString(None, self.topic_name_length) 
        if fm.should_mutate("topic") == True and self.topic_name_length > 0:
            topic_name_bytes = cf.hex_list_to_bytes(self.topic_name[1])
            mutated_bytes = fm.handle_string_mutate_del_insert_replace(topic_name_bytes)
            self.topic_name[1] = cf.bytes_to_hex_list(mutated_bytes)
            self.topic_name[0] = cf.int_to_padded_hex_string(len(self.topic_name[1]), 4)

        if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID and g.cur_client_dependency != None:
            if len(g.cur_client_dependency) == 2 and g.FIELD_TOPIC in g.cur_client_dependency["active"]["field"]:
                    g.cur_client_dependency["passive"]["field"][g.FIELD_TOPIC] = self.topic_name
            elif len(g.cur_client_dependency) == 1:
                if g.FIELD_TOPIC in g.cur_client_dependency["passive"]["field"]:
                    self.topic_name = g.cur_client_dependency["passive"]["field"][g.FIELD_TOPIC]
                if g.FIELD_SHARED_TOPIC in g.cur_client_dependency["active"]["field"]:
                    self.topic_name = g.cur_client_dependency["passive"]["field"][g.FIELD_SHARED_TOPIC]
        elif threading.current_thread().ident == g.Broker_Fuzzing_Thread_ID and g.cur_broker_dependency != None:
            if len(g.cur_broker_dependency) == 2 and g.FIELD_TOPIC in g.cur_broker_dependency["active"]["field"]:
                g.cur_broker_dependency["passive"]["field"][g.FIELD_TOPIC] = self.topic_name
            elif len(g.cur_broker_dependency) == 1:
                if g.FIELD_TOPIC in g.cur_broker_dependency["passive"]["field"]:
                    self.topic_name = g.cur_broker_dependency["passive"]["field"][g.FIELD_TOPIC]
                if g.FIELD_SHARED_TOPIC in g.cur_broker_dependency["active"]["field"]:
                    self.topic_name = g.cur_broker_dependency["passive"]["field"][g.FIELD_SHARED_TOPIC]

        self.payload.append(self.topic_name)

        self.packet_id = self.toBinaryData(None, 2, True, 8)    # ['ba', 'dc']
        if fm.should_mutate("packet_identifier") == True:
            packet_id_bytes = cf.hex_list_to_bytes(self.packet_id)
            mutated_bytes = fm.handle_int_mutate_up_downgrad_replace(packet_id_bytes)
            self.packet_id = cf.bytes_to_hex_list(mutated_bytes)

        if qos > 0:
            self.payload.append(self.packet_id)

        self.properties = Properties([0x01, 0x02, 0x23, 0x08, 0x09, 0x26, 0x0b, 0x03])
        if protocol_version == 5:
            self.payload.append(self.properties.toString())
    

class Publish(Packet):
    def __init__(self, protocol_version = None):
        super().__init__()

        if protocol_version is None:
            protocol_version = random.randint(3, 5)

        self.fixed_header = PublishFixedHeader()            
        self.variable_header = PublishVariableHeader(self.fixed_header.qos, protocol_version)
        self.publish_message_length = random.randint(0, 100)   
        self.publish_message = self.getAlphanumHexString(self.publish_message_length) 
        
        if fm.should_mutate("message") == True:
            publish_message_bytes = cf.hex_list_to_bytes(self.publish_message)
            mutated_bytes = fm.handle_string_mutate_del_insert_replace(publish_message_bytes)
            self.publish_message = cf.bytes_to_hex_list(mutated_bytes)
            self.publish_message_length = len(self.publish_message)

        remaining_length = self.variable_header.getByteLength() + self.publish_message_length
        self.payload = [self.fixed_header.toString(), self.toVariableByte("%x" % remaining_length), self.variable_header.toString(), self.publish_message]


if __name__ == "__main__":
    packetTest([Connect, Publish], 1, True)