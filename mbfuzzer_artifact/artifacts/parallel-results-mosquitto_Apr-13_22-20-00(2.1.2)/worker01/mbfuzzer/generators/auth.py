from connect import Connect
from packet import Packet
from packet import packetTest
from properties import Properties
import random
import fuzzer.mutation as fm
import helper_functions.convert_format as cf

class AuthVariableHeader(Packet):
    def __init__(self):
        super().__init__()

        # self.reason_code = self.toBinaryData(None, 1, True)
        auth_reason_code = random.choice([0x18, 0x19])
        self.reason_code = [cf.int_to_hex_string(auth_reason_code)]   # e.g., "18", "19"

        # mutate field "reason_code"
        if fm.should_mutate("reason_code") == True:
            choice_code = cf.hex_string_to_bytes(self.reason_code[0])
            mutated_bytes = fm.handle_int_mutate_up_downgrad_replace(choice_code)
            mutated_string = cf.bytes_to_hex_string(mutated_bytes)
            self.reason_code = [mutated_string]

        self.payload.append(self.reason_code)

        self.properties = Properties([0x15, 0x16, 0x1f, 0x26])
        self.payload.append(self.properties.toString())

class Auth(Packet):
    def __init__(self, protocol_version = None):
        super().__init__()

        self.fixed_header = "f0"
        self.variable_header = AuthVariableHeader()
        remaining_length = self.variable_header.getByteLength()
        self.payload = [self.fixed_header, self.toVariableByte("%x" % remaining_length), self.variable_header.toString()]
        
if __name__ == "__main__":
    packetTest([Connect, Auth], 300)