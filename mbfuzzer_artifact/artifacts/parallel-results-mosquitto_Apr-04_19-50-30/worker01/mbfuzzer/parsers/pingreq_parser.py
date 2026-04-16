from parsers.protocol_parser import ProtocolParser as Parser
import sys
sys.path.append("generators")

import random

class PingreqParser(Parser):
    def __init__(self, payload, protocol_version):
        super().__init__(payload, protocol_version)