
from parsers.protocol_parser import ProtocolParser as Parser
import sys
sys.path.append("generators")
from type.VersionError import VersionError


class PublishParser(Parser):

    # Given the fixed header, return the QoS version, defined by bits 1 and 2.
    def getQoSVersion(self, fixed_header):
        return int(bin(fixed_header)[-3:-1], 2)

    def __init__(self, payload, protocol_version):
        super().__init__(payload, protocol_version)

        self.index = self.insertStringNoIdentifier(
            "topic name", payload, self.index, False)

        fixed_header = int(self.G_fields["fixed header"], 16)
        # print("fixed_header:\n",fixed_header,"\nG_fields[fixed header]:\n",self.G_fields["fixed header"])
        if self.getQoSVersion(fixed_header) > 0:
            self.index = self.insertTwoBytesNoIdentifier(
                "packet identifier", payload, self.index, False)

        if protocol_version == 5:
            try:
                self.parseProperties()
            except VersionError:
                raise VersionError("The version of the protocol is not supported.")

        message_length = (self.remainingLengthToInteger() * 2) + \
            2 + len(self.remaining_length) - self.index
        self.H_fields["message"] = payload[self.index:self.index+message_length]

def test():
    protocol_version = 5
    payload = "352a00008f4c1e010002941213b208000c346b354f59686339584656500bf7e3970723c4955a77584a355354"
    # sendToBroker("localhost", 1883, connect.toString() + payload.toString())
    parser = PublishParser(payload, protocol_version)
    print(parser.G_fields)
    print(parser.H_fields)

    # print("Publish:\n",payload.toString())


if __name__ == "__main__":
    test()
