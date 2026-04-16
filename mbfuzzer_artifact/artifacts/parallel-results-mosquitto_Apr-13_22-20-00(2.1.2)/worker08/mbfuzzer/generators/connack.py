from packet import Packet
from packet import packetTest
from connect import Connect 
from properties import Properties
import random
import fuzzer.mutation as fm
import helper_functions.convert_format as cf

class ConnackVariableHeader(Packet):
    def __init__(self, protocol_version):
        super().__init__()

        # self.acknowledgement_flags = self.toBinaryData(None, 1, True, 1)    #['00']
        self.acknowledgement_flags = ['00']
        if fm.should_mutate("acknowledgement_flags") == True:
            ack_flags_int = cf.hex_list_to_integer(self.acknowledgement_flags)
            ack_flags_bytes = cf.int_to_bytes(ack_flags_int)
            mutated_bytes = fm.handle_int_mutate_bitflip(ack_flags_bytes, 0, 8)
            mutated_list = cf.bytes_to_hex_list(mutated_bytes)
            self.acknowledgement_flags = mutated_list

        self.payload.append(self.acknowledgement_flags)

        # self.return_code = self.toBinaryData(None, 1, True)   # ['00']
        candidate_return_code = ['00', '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8A', '8C', '90', '95', '97', '99', '9A', '9B', '9C', '9D', '9F']
        self.return_code = random.choice(candidate_return_code)
        if fm.should_mutate("return_code") == True:
            return_code_bytes = cf.hex_list_to_bytes(self.return_code)
            mutated_bytes = fm.handle_int_mutate_up_downgrad_replace(return_code_bytes)
            mutated_list = cf.bytes_to_hex_list(mutated_bytes)
            self.return_code = mutated_list
            
        self.payload.append(self.return_code)

        self.connack_properties = Properties([0x11, 0x21, 0x24, 0x25, 0x27, 0x12, 0x22, 0x26, 0x28, 0x29, 0x21, 0x13, 0x1a, 0x1c, 0x15, 0x16])
        if protocol_version == 5:
            self.payload.append(self.connack_properties.toList())

class Connack(Packet):
    def __init__(self, protocol_version = None):
        super().__init__()

        if protocol_version is None:
            protocol_version = random.randint(3, 5)

        self.fixed_header = ['20']
        self.variable_header = ConnackVariableHeader(protocol_version)
        remaining_length = self.toVariableByte("%x" % self.variable_header.getByteLength())

        self.payload = [self.fixed_header, remaining_length, self.variable_header.toList()]

if __name__ == "__main__":
    packetTest([Connect, Connack], 300)