from parsers.protocol_parser import ProtocolParser as Parser
import sys
sys.path.append("generators")
from type.VersionError import VersionError

import random

class PubrecParser(Parser):
    def __init__(self, payload, protocol_version):
        super().__init__(payload, protocol_version)

        self.index = self.insertTwoBytesNoIdentifier("packet identifier", payload, self.index, False)

        if protocol_version == 5:
            self.index = self.insertByteNoIdentifier("reason code", payload, self.index, True)
            try:
                self.parseProperties()
            except VersionError:
                raise VersionError("The version of the protocol is not supported.")