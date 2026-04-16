from packet import Packet
from packet import packetTest
from connect import Connect
from properties import Properties
import random
import fuzzer.mutation as fm
import helper_functions.convert_format as cf

class DisconnectVariableHeader(Packet):
    def __init__(self, protocol_version):
        super().__init__()

        auth_reason_code = random.choice([0x00, 0x04, 0x80, 0x81, 0x82, 0x83, 0x87, 0x89, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2])
        self.reason_code = [cf.int_to_hex_string(auth_reason_code)]   # e.g., ["18"], ["19"]

        if True:
            print("choice_code: ", self.reason_code)
            choice_code = cf.hex_list_to_bytes(self.reason_code)
            mutated_bytes = fm.handle_int_mutate_up_downgrad_replace(choice_code)
            mutated_string = cf.bytes_to_hex_string(mutated_bytes)
            self.reason_code = [mutated_string]

        if protocol_version == 5:
            self.payload.append(self.reason_code)

        self.properties = Properties([0x11, 0x1f, 0x26, 0x1c])
        if protocol_version == 5:
            self.payload.append(self.properties.toString())
    

class Disconnect(Packet):
    def __init__(self, protocol_version = None):
        super().__init__()

        if protocol_version is None:
            protocol_version = random.randint(3, 5)

        self.fixed_header = ['e0']
        self.variable_header = DisconnectVariableHeader(protocol_version)

        remaining_length = self.variable_header.getByteLength()

        self.payload = [self.fixed_header, self.toVariableByte("%x" % remaining_length), self.variable_header.toString()]

if __name__ == "__main__":
    packetTest([Connect, Disconnect], 250)