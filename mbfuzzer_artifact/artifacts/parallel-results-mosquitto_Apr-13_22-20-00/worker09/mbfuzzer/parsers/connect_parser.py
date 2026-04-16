from parsers.protocol_parser import ProtocolParser as Parser
import sys
sys.path.append("generators")

# from connect import Connect
# from disconnect import Disconnect

from type.VersionError import VersionError


class ConnectParser(Parser):

    def getUserNameFlag(self, connect_flags):
        bit_values = [int(bit) for bit in format(connect_flags, '08b')]
        return bit_values[0]

    def getPasswordFlag(self, connect_flags):
        bit_values = [int(bit) for bit in format(connect_flags, '08b')]
        return bit_values[1]

    def getWillRetainFlag(self, connect_flags):
        bit_values = [int(bit) for bit in format(connect_flags, '08b')]
        return bit_values[2]

    def getQosVersion(self, connect_flags):
        bit_values = [int(bit) for bit in format(connect_flags, '08b')]
        bit_list = bit_values[4:6]
        binary_string = ''.join(str(bit) for bit in bit_list)
        qos_value = int(binary_string, 2)
        return qos_value

    def getWillFlag(self, connect_flags):
        bit_values = [int(bit) for bit in format(connect_flags, '08b')]
        return bit_values[5]

    def getCleanSessionFlag(self, connect_flags):
        bit_values = [int(bit) for bit in format(connect_flags, '08b')]
        return bit_values[6]

    def getReservedFlag(self, connect_flags):
        bit_values = [int(bit) for bit in format(connect_flags, '08b')]
        return bit_values[7]

    def __init__(self, payload, protocol_version = 3, only_version = False):
        super().__init__(payload, protocol_version)

        self.index = self.insertStringNoIdentifier("protocol name", payload, self.index, False)
        # print("self.index: ", self.index)

        self.index = self.insertSingleByte("version", payload, self.index, False)
        if self.H_fields["version"]:
           self.protocol_version = int(self.H_fields["version"], 16) 
        #    print("self.protocol_version: ", self.protocol_version)
           if only_version is not False:
                return
        
        self.index = self.insertSingleByte("connect flags", payload, self.index, False)
        if self.H_fields["connect flags"]:
            connect_flags = int(self.H_fields["connect flags"], 16)
            self.H_fields["username flag"] = self.getUserNameFlag(connect_flags)
            self.H_fields["password flag"] = self.getPasswordFlag(connect_flags)
            self.H_fields["will retain"] = self.getWillRetainFlag(connect_flags)
            self.H_fields["qos"] = self.getQosVersion(connect_flags)
            self.H_fields["will flag"] = self.getWillFlag(connect_flags)
            self.H_fields["clean session flag"] = self.getCleanSessionFlag(connect_flags)
            self.H_fields["reserved flag"] = self.getReservedFlag(connect_flags)
        
        self.index = self.insertTwoBytesNoIdentifier("keep alive", payload, self.index, False)

        if self.protocol_version == 5:
            try:
                self.parseProperties() 
            except VersionError:
                self.H_fields["invalid property"] = ""
        
        self.index = self.insertStringNoIdentifier("client id", payload, self.index, False)

        if self.H_fields["will flag"]:
            if self.protocol_version == 5:
                try:
                    self.parseProperties()
                except VersionError:
                    self.H_fields["invalid property"] = ""
            self.index = self.insertStringNoIdentifier("will topic", payload, self.index, False)
            self.index = self.insertStringNoIdentifier("will message", payload, self.index, False)
        if self.H_fields["username flag"]:
            self.index = self.insertStringNoIdentifier("username", payload, self.index, False)
        if self.H_fields["password flag"]:
            self.index = self.insertStringNoIdentifier("password", payload, self.index, False)

def test():
    payload = "10e00100044d51545405bc5da7212600157a70454b71536869437136363534783054415336710007486d62355a5937000065010102637e6548080017634c6b54364f50563450416b696f67306d74593734414709001cd22a7d8cf563fd65a0eeffb1128054c654f201406d1d6751e6cd92bd2600106861434350366c6b4f7732454c694944001072723478366367706430327047456d69001e7542424270396c755563436f6a5747314b434f6b375a71447774684b774c00125539735266453077334f49314d796d76456a00166c4a78435379744a424f7539353443566b4769377848  "
    parser = ConnectParser(payload, 4)

    print(parser.G_fields)
    print(parser.H_fields)
    print(parser.I_fields_count)

if __name__ == "__main__":
    test()