import random
import binascii
import string
import threading
from packet import Packet
from packet import packetTest
from properties import Properties
        
import fuzzer.mutation as fm
import helper_functions.convert_format as cf
import globals as g

class ConnectFlags(Packet):
    def __init__(self):        
        self.username_flag = random.getrandbits(1)
        self.password_flag = random.getrandbits(1)
        self.will_retain = random.getrandbits(1)
        self.will_qos = min(2, random.getrandbits(2))
        self.will_flag = random.getrandbits(1)
        self.clean_start = random.getrandbits(1)
        self.reserved = 0
        
        if self.will_flag == 0:
            self.will_qos = 0

        if self.will_flag == 0:
            self.will_retain = 0

        payload_tmp = [self.username_flag, self.password_flag, self.will_retain, self.will_qos & 1, (self.will_qos >> 1) & 1, self.will_flag, self.clean_start, self.reserved]

        self.payload = ["%.2x" % int("".join(bin(s)[2:] for s in payload_tmp), 2)]  #['02']
        if fm.should_mutate("connect_flags") == True:
            mutated_list = fm.handle_hex_mutate_bitflip(self.payload[0], 0, 8)
            self.payload = mutated_list

class ConnectVariableHeader(Packet):
    def __init__(self, protocol_version):
        if protocol_version == 3:
            self.name = self.toEncodedString(None, 6, "MQIsdp")
        else:
            self.name = self.toEncodedString(None, 4, "MQTT")
        self.protocol_version = ["%.2x" % protocol_version]
        self.flags = ConnectFlags()

        self.keepalive = self.toBinaryData(None, 2, True)   # ['27', '0c']
        if fm.should_mutate("keep_alive") == True:
            # list -> bytes
            keepalive = cf.hex_list_to_bytes(self.keepalive)
            # mutate
            mutated_bytes = fm.handle_int_mutate_up_downgrad_replace(keepalive)
            # bytes -> list
            self.keepalive = cf.bytes_to_hex_list(mutated_bytes)
        
        self.properties = Properties([0x11, 0x21, 0x27, 0x22, 0x19, 0x17, 0x26, 0x15, 0x16])

        self.payload = [self.name, self.protocol_version, self.flags.toList(), self.keepalive]

        if protocol_version == 5:
            self.payload.append(self.properties.toList())

class ConnectPayload(Packet):
    def __init__(self, header):
        self.clientid_len = random.randint(0, 30)
        self.clientid = self.toEncodedString(None, self.clientid_len)   # ["0002", ["4f", "52"]]

        if fm.should_mutate("client_id") == True and self.clientid_len > 0:
            # list -> bytes
            cliend_id_bytes = cf.hex_list_to_bytes(self.clientid[1])
            # mutate the string field
            mutated_bytes = fm.handle_string_mutate_del_insert_replace(cliend_id_bytes)
            # bytes -> list
            mutated_list = cf.bytes_to_hex_list(mutated_bytes)
            self.clientid[1] = mutated_list
            self.clientid[0] = cf.int_to_padded_hex_string(len(mutated_list), 4)
            self.clientid_len = len(mutated_list)

        if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID and g.cur_client_dependency != None:
            if len(g.cur_client_dependency) == 2 and g.FIELD_CLIENT_ID in g.cur_client_dependency["active"]["field"]:
                g.cur_client_dependency["passive"]["field"][g.FIELD_CLIENT_ID] = self.clientid
            elif len(g.cur_client_dependency) == 1 and g.FIELD_CLIENT_ID in g.cur_client_dependency["active"]["field"]:
                self.clientid = g.cur_client_dependency["passive"]["field"][g.FIELD_CLIENT_ID]
        
        
        self.will_properties = Properties([0x18, 0x01, 0x02, 0x03, 0x08, 0x09, 0x26])

        self.will_topic_length = random.randint(0, 30)
        self.will_topic = self.toEncodedString(None, self.will_topic_length)      # ["0002", ["4f", "52"]]
        if fm.should_mutate("will_topic") == True and self.will_topic_length > 0:
            # list -> bytes
            will_topic_bytes = cf.hex_list_to_bytes(self.will_topic[1])
            # mutate the string field
            mutated_bytes = fm.handle_string_mutate_del_insert_replace(will_topic_bytes)
            # bytes -> list
            mutated_list = cf.bytes_to_hex_list(mutated_bytes)
            self.will_topic[1] = mutated_list
            self.will_topic[0] = cf.int_to_padded_hex_string(len(mutated_list), 4)
            self.will_topic_length = len(mutated_list)

        self.will_payload_length = random.randint(0, 30)
        self.will_payload = self.toEncodedString(None, self.will_payload_length)  # ["0002", ["4f", "52"]]
        if fm.should_mutate("will_payload") == True and self.will_payload_length > 0:
            # list -> bytes
            will_payload_bytes = cf.hex_list_to_bytes(self.will_payload[1])
            # mutate the string field
            mutated_bytes = fm.handle_string_mutate_del_insert_replace(will_payload_bytes)
            # bytes -> list
            mutated_list = cf.bytes_to_hex_list(mutated_bytes)
            self.will_payload[1] = mutated_list
            self.will_payload[0] = cf.int_to_padded_hex_string(len(mutated_list), 4)
            self.will_payload_length = len(mutated_list)

        self.username_length = random.randint(0, 30)
        self.username = self.toEncodedString(None, self.username_length)  # ["0002", ["4f", "52"]]
        if fm.should_mutate("username") == True and self.username_length > 0:
            # list -> bytes
            username_bytes = cf.hex_list_to_bytes(self.username[1])
            # mutate the string field
            mutated_bytes = fm.handle_string_mutate_del_insert_replace(username_bytes)
            # bytes -> list
            mutated_list = cf.bytes_to_hex_list(mutated_bytes)
            self.username[1] = mutated_list
            self.username[0] = cf.int_to_padded_hex_string(len(mutated_list), 4)
            self.username_length = len(mutated_list)

        self.password_length = random.randint(0, 30)
        self.password = self.toEncodedString(None, self.password_length)
        if fm.should_mutate("password") == True and self.password_length > 0:
            # list -> bytes
            password_bytes = cf.hex_list_to_bytes(self.password[1])
            # mutate the string field
            mutated_bytes = fm.handle_string_mutate_del_insert_replace(password_bytes)
            # bytes -> list
            mutated_list = cf.bytes_to_hex_list(mutated_bytes)
            self.password[1] = mutated_list
            self.password[0] = cf.int_to_padded_hex_string(len(mutated_list), 4)
            self.password_length = len(mutated_list)

        self.payload = [self.clientid]

        if header.flags.will_flag == 1 or (header.flags.will_flag == 0 and fm.should_mutate("connect_flags") == True):
            if int(header.protocol_version[0]) == 5:
                self.payload.append(self.will_properties.toList())

            self.payload.append(self.will_topic)
            self.payload.append(self.will_payload)
            
        if header.flags.username_flag == 1 or (header.flags.username_flag == 0 and fm.should_mutate("connect_flags") == True):
            self.payload.append(self.username)
        
        if header.flags.password_flag == 1 or (header.flags.password_flag == 0 and fm.should_mutate("connect_flags") == True):
            self.payload.append(self.password)

class Connect(Packet):
    def __init__(self, protocol_version = None):
        super().__init__()

        if protocol_version is None:
            protocol_version = random.randint(3, 5)

        self.protocol_version = protocol_version

        self.fixed_header = ["%.2x" % 0b10000]
        self.variable_header = ConnectVariableHeader(protocol_version)
        self.connect_payload = ConnectPayload(self.variable_header)

        remaining_length = self.variable_header.getByteLength() + self.connect_payload.getByteLength()
        
        self.payload = [self.fixed_header, self.toVariableByte("%x" % remaining_length), self.variable_header.toList(), self.connect_payload.toList()]
        
        if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID:
            g.PLATEAU_CONNECT_OBJECT.version = protocol_version
            g.PLATEAU_CONNECT_OBJECT.connect_flags = "".join(str(item) for item in self.variable_header.flags.payload)
            g.PLATEAU_CONNECT_OBJECT.client_id = True if self.connect_payload.clientid_len != 0 else g.PLATEAU_CONNECT_OBJECT.client_id
            g.PLATEAU_CONNECT_OBJECT.will_topic = True if self.connect_payload.will_topic_length != 0 else g.PLATEAU_CONNECT_OBJECT.will_topic
            g.PLATEAU_CONNECT_OBJECT.will_payload = True if self.connect_payload.will_payload_length != 0 else g.PLATEAU_CONNECT_OBJECT.will_payload
            for property in self.connect_payload.will_properties.payload:
                if type(property) is list:
                    if property[0] == "01":
                        g.PLATEAU_CONNECT_OBJECT.payload_format_indicator = True
                    elif property[0] == "08":
                        g.PLATEAU_CONNECT_OBJECT.response_topic = True
                    elif property[0] == "18":
                        g.PLATEAU_CONNECT_OBJECT.will_delay_inteval = True


if __name__ == "__main__":
    packetTest([Connect], 10)