# This file will receive the payload and decide which parser to pass it to, 
# based on the first byte in the fixed header.

from parsers.protocol_parser import ProtocolParser
from parsers.connect_parser import ConnectParser
from parsers.connack_parser import ConnackParser
from parsers.publish_parser import PublishParser
from parsers.disconnect_parser import DisconnectParser
from parsers.puback_parser import PubackParser
from parsers.pubrec_parser import PubrecParser
from parsers.pubrel_parser import PubrelParser
from parsers.pubcomp_parser import PubcompParser
from parsers.subscribe_parser import SubscribeParser
from parsers.suback_parser import SubackParser
from parsers.unsubscribe_parser import UnsubscribeParser
from parsers.unsuback_parser import UnsubackParser
from parsers.pingreq_parser import PingreqParser
from parsers.pingresp_parser import PingrespParser
from parsers.auth_parser import AuthParser
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import helper_functions.determine_message_type as dmt
from type.VersionError import VersionError
import signal
import threading
import globals as g

class ParseInitializer:
    def __init__(self, payload, protocol_version):
        assert type(payload) == str
        packetDict = {
            '1': ConnectParser,
            '2': ConnackParser, 
            '3': PublishParser,
            '4': PubackParser,
            '5': PubrecParser,
            '6': PubrelParser,
            '7': PubcompParser,
            '8': SubscribeParser,
            '9': SubackParser,
            'a': UnsubscribeParser,
            'b': UnsubackParser,
            'c': PingreqParser,
            'd': PingrespParser,
            'e': DisconnectParser,
            'f': AuthParser}

        
        if len(payload) > 0:
            try:
                self.parser = packetDict[payload[0]](payload, protocol_version)

            # KeyError means that the payload is not a valid MQTT packet, so we create 
            # a "fake" Parser object (from an empty string a protocol version 0)
            except KeyError:
                self.parser = ProtocolParser("", 0)
            except VersionError:
                raise VersionError("The version of the protocol is not supported.")
        else:
            self.parser = None

# Determine what version of the protocol is being used 
def determine_protocol_version(packet):
    if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID:
        # with threading.Lock():
        return g.client_protocol_version
    elif threading.current_thread().ident == g.Broker_Fuzzing_Thread_ID:
        # with threading.Lock():
        return g.broker_protocol_version

def return_publish_parser(message):
    version = determine_protocol_version(message)
    return PublishParser(message, version)

def process_any_disconnect_multiple_packets(hex_string):
    hex_string = hex_string.lower()
    length = len(hex_string)
    e0_positions = [i for i in range(length) if hex_string.startswith('e0', i)]
    
    for pos in e0_positions:
        msg_length_hex = hex_string[pos+2:pos+4]
        if msg_length_hex == '':
            continue
        msg_length = int(msg_length_hex, 16) * 2
        
        end_pos = pos + 4 + msg_length
        
        if end_pos == length and (end_pos - pos - 4) == msg_length:
            return hex_string[:pos], pos 
    
    return hex_string, None

def parse_remaining_length(data):
    remaining_length = 0
    multiplier = 1
    byte = data[0]
    offset = 1
    
    while True:
        current_bits = byte & 0b01111111
        remaining_length += current_bits * multiplier
        
        if byte & 0b10000000:
            multiplier *= 128
            if offset >= len(data):
                break
            byte = data[offset]
            offset += 1
        else:
            break
    
    return remaining_length, offset

def assert_msg_length(data):
    data = bytes.fromhex(data)
    if len(data) < 2:
        return False
    
    fixed_header = data[0]
    remaining_length, offset = parse_remaining_length(data[1:]) # FIXME: Index out of range in some cases
    if (remaining_length + offset + 1) > len(data):
        return False
    return True

def check_for_multiple_messages(hex_data):
    data = bytes.fromhex(hex_data)
    
    if len(data) < 2:
        return False
    fixed_header = data[0]
    remaining_length, offset = parse_remaining_length(data[1:])
    max_length_bytes = 4  

    if offset > max_length_bytes:
        return True 
    
    total_length_first_msg = 2 + offset + remaining_length  
    
    if len(data) > total_length_first_msg and total_length_first_msg < len(data):
        return True 
    else:
        return False 

def get_conn_proto_version(message):
    # MQIsdp => 4D5149736470. version 3
    if "4d5149736470" in message[:20]:
        return 3
    else:
        temp_parser = ConnectParser(message, 4, True)
        return temp_parser.protocol_version
    
# 
def return_packet_parser(message, conn_proto_version = None):
    original_message = message
    updated_hex_string, e0_position = process_any_disconnect_multiple_packets(message)
    if e0_position is not None and e0_position != 0:
        message = updated_hex_string

    if message.startswith('0'):
        return None

    if len(message) > 3 and check_for_multiple_messages(message):
        print(f"strange error by check_for_multiple_messages: {original_message}")
        return None

    if assert_msg_length(message) == False:
        return None
    
    index = 0
    parser = None
    temp_version = conn_proto_version
    while index < len(message):
        try:
            if temp_version == None:
                temp_version = determine_protocol_version(message)
                parser = ParseInitializer(message[index:], temp_version)
            else:
                parser = ParseInitializer(message[index:], temp_version)
            index +=  2 * (parser.parser.remainingLengthToInteger()) + 2 + len(parser.parser.remaining_length)

        except ValueError:
            index += 2
        except VersionError:
            if dmt.determine_message_type(message) == g.MSG_TYPE_CONNACK:
                parser = ParseInitializer(message, 4)
            else:
                if temp_version != None:
                    if temp_version == 5:
                        temp_version = temp_version - 1
                        continue
                print(f"strange error: {original_message}")
                raise VersionError("The version of the protocol is not supported.") 
            break

    return parser

if __name__ == "__main__":
    payload = "05111e02ffff7af677677747686f4966447639"

    parser = return_packet_parser(payload, 5)
    print("G.fields:\n",parser.parser.G_fields)
    print("H.fields:\n",parser.parser.H_fields)