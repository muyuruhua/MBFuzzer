from parsers.protocol_parser import ProtocolParser as Parser
import sys
sys.path.append("generators")
from type.VersionError import VersionError

import random

class SubackParser(Parser):
    def __init__(self, payload, protocol_version):
        super().__init__(payload, protocol_version)

        self.index = self.insertTwoBytesNoIdentifier("packet identifier", payload, self.index, False)

        if protocol_version == 5:
            try:
                self.parseProperties()
            except VersionError:
                raise VersionError("The version of the protocol is not supported.")

        while self.index < len(payload):
            self.index = self.insertByteListNoIdentifier("return code (Granted QoS)", payload, self.index, True)
