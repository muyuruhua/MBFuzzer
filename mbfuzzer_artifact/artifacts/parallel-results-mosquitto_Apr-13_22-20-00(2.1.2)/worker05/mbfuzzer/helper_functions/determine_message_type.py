import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import globals as g


# Determine what message type of the protocol is being used 
def determine_message_type(packet):
    if len(packet) == 0:
        return None
    
    if packet[0] == "1":
        return g.MSG_TYPE_CONNECT
    elif packet[0] == "2":
        return g.MSG_TYPE_CONNACK
    elif packet[0] == "3":
        return g.MSG_TYPE_PUBLISH
    elif packet[0] == "4":
        return g.MSG_TYPE_PUBACK
    elif packet[0] == "5":
        return g.MSG_TYPE_PUBREC
    elif packet[0] == "6":
        return g.MSG_TYPE_PUBREL
    elif packet[0] == "7":
        return g.MSG_TYPE_PUBCOMP
    elif packet[0] == "8":
        return g.MSG_TYPE_SUBSCRIBE
    elif packet[0] == "9":
        return g.MSG_TYPE_SUBACK
    elif packet[0] == str("a"):
        return g.MSG_TYPE_UNSUBSCRIBE
    elif packet[0] == str("b"):
        return g.MSG_TYPE_UNSUBACK
    elif packet[0] == str("c"):
        return g.MSG_TYPE_PINGREQ
    elif packet[0] == str("d"):
        return g.MSG_TYPE_PINGRESP
    elif packet[0] == str("e"):
        return g.MSG_TYPE_DISCONNECT
    elif packet[0] == str("f"):
        return g.MSG_TYPE_AUTH