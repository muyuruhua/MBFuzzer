from connect import Connect
from packet import Packet
from packet import packetTest
from properties import Properties
import random
import fuzzer.mutation as fm
import helper_functions.convert_format as cf

class PubackVariableHeader(Packet):
    def __init__(self, protocol_version):
        super().__init__()

        self.packet_identifier = self.toBinaryData(None, 2, True)   # ["01", "7e"]
        if fm.should_mutate("packet_identifier") == True:
            packet_id = cf.hex_list_to_bytes(self.packet_identifier)
            mutated_bytes = fm.handle_int_mutate_up_downgrad_replace(packet_id)
            mutated_list = cf.bytes_to_hex_list(mutated_bytes)
            self.packet_identifier = mutated_list

        self.payload.append(self.packet_identifier)

        self.reason_code = [random.choice(['00', '10', '80', '83', '87', '90', '91', '97', '99'])]
        if fm.should_mutate("reason_code") == True:
            reason_code = cf.hex_list_to_bytes(self.reason_code)
            mutated_bytes = fm.handle_int_mutate_up_downgrad_replace(reason_code)
            mutated_list = cf.bytes_to_hex_list(mutated_bytes)
            self.reason_code = mutated_list
        if protocol_version == 5:
            self.payload.append(self.reason_code)

        self.properties = Properties([0x1f, 0x26])
        if protocol_version == 5:
            self.payload.append(self.properties.toString())

class Puback(Packet):
    def __init__(self, protocol_version = None):
        super().__init__()
        
        if protocol_version is None:
            protocol_version = random.randint(3, 5)

        self.fixed_header = "40"
        self.variable_header = PubackVariableHeader(protocol_version)
        remaining_length = self.variable_header.getByteLength()

        self.payload = [self.fixed_header, self.toVariableByte("%x" % remaining_length), self.variable_header.toString()]

if __name__ == "__main__":
    packetTest([Connect, Puback], 300)