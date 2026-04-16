
from itertools import combinations
from collections import defaultdict
import helper_functions.directory_operation as do
import helper_functions.determine_message_type as dmt
import hashlib
import json
import datetime
import globals as g
# import fuzzer.fuzzing_engine as fe
# import parsers.protocol_parser as pp
import parsers.parse_initializer as pi
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import threading
from parsers.connack_parser import ConnackParser


class DiffResponseInfo():
    def __init__(self, diff_type):
        self.id = None
        self.protocol_version = None
        self.diff_type = diff_type
        self.field_name = None
        self.diff_range_broker = []
        self.msg_type = None
        self.client_msg_path = None
        self.broker_msg_path = None
        self.direction = None   # client, broker, both
        self.capture_time = None
        self.msg_path = None
        self.pub_msg = None

    def hash_value(self):
        data = {
            "protocol_version": self.protocol_version,
            "diff_type": self.diff_type,
            "field_name": self.field_name,
            "diff_range_broker": sorted(list(set(self.diff_range_broker))),
            "msg_type": self.msg_type,
            "direction": self.direction,
        }
        data = {k: v for k, v in data.items() if v is not None}
        json_data = json.dumps(data, sort_keys=True)
        hash_value = hashlib.md5(json_data.encode()).hexdigest()
        return hash_value
    
    
    def to_string(self):
        result = ""
        if self.protocol_version is not None:
            result += f"protocol_version: {self.protocol_version}, "
        if self.diff_type == g.DIFF_FIELD_DIFFERENT:
            result += "type: {Field Different}, "
        elif self.diff_type == g.DIFF_FIELD_MISSING:
            result += "type: {Field Missing}, "
        elif self.diff_type == g.DIFF_FIELD_UNEXPECTED:
            result += "type: {Field Unexpected}, "
        elif self.diff_type == g.DIFF_MESSAGE_DIFFERENT:
            result += "type: {Message Different}, "
        elif self.diff_type == g.DIFF_MESSAGE_MISSING:
            result += "type: {Message Missing}, "
        elif self.diff_type == g.DIFF_MESSAGE_UNEXPECTED:
            result += "type: {Message Unexpected}, "
        
        if self.field_name is not None:
            result += f"field: {self.field_name}, "
        
        if len(self.diff_range_broker) > 0:
            self.diff_range_broker = list(set(self.diff_range_broker))
            result += f"diff_range_broker: {self.diff_range_broker}, "
        
        if self.msg_type is not None:
            result += f"msg_type: {self.msg_type}, "
        
        if self.direction is not None:
            result += f"direction: {self.direction}, "
        
        if self.client_msg_path is not None:
            result += f"file_path: {self.client_msg_path}, "
        
        if self.broker_msg_path is not None:
            result += f"file_path: {self.broker_msg_path}, "
        
        if self.msg_path is not None:
            result += f"file_path: {self.msg_path}, "
        
        if self.capture_time is not None:
            result += f"capture_time: {self.capture_time}, "
        
        return result.rstrip(", ")


def handle_network_response(request_tuple, ClientFuzzers):
    all_response_state = {}

    msg_type = request_tuple[0]
    msg_content = request_tuple[1]
    for clientFuzzer in ClientFuzzers.values():
        res_message = clientFuzzer.response_message

        if res_message == None:
            continue

        parser = pi.return_packet_parser(res_message)
        if parser is None:
            continue

        response_hash = parser.parser.retGHFieldsHash()

        if response_hash not in g.FUZZING_NETWORK_RESPONSE_LOG:
            g.FUZZING_NETWORK_RESPONSE_LOG[response_hash] = True
            g.FUZZING_CLIENT_PLATEAU = 0  
            filepath = do.save_interesting_message_to_queue(msg_type, msg_content)
            protocol_version = g.broker_protocol_version
            if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID:
                protocol_version = g.client_protocol_version
            g.FUZZING_NETWORK_RESPONSE_CORPUS.setdefault(msg_type, {}).setdefault(protocol_version, []).append(filepath)            

        response_state = parser.parser.retQTableState()
        if response_state not in all_response_state:
            all_response_state[response_state] = 1
        else:
            all_response_state[response_state] += 1

    if len(all_response_state) == 0:
        if msg_type == g.MSG_TYPE_PUBLISH:
            return g.STATE_PUBLISH_QOS0
        else:
            return g.STATE_NONE
    else:
        max_state = max(all_response_state, key=all_response_state.get)
        return max_state

def differential_response_fields(container_name1, parser1, container_name2, parser2, response_field_diff, endtime=None):

    G_fields1 = parser1.parser.G_fields
    G_fields2 = parser2.parser.G_fields
    G_fields_key_diff = set(G_fields1.keys()) ^ set(G_fields2.keys())

    for field_name in G_fields_key_diff:
        if field_name in G_fields1:
            response_field_diff.setdefault(field_name, {}).setdefault("Missing", {})
            response_field_diff[field_name]["Missing"].setdefault("range broker", []).append(container_name2)
            response_field_diff.setdefault(field_name, {}).setdefault("Unexpected", {})
            response_field_diff[field_name]["Unexpected"].setdefault("range broker", []).append(container_name1)
            if endtime is not None:
                response_field_diff[field_name]["Missing"]["first_time"] = endtime
                response_field_diff[field_name]["Unexpected"]["first_time"] = endtime
        else:
            response_field_diff.setdefault(field_name, {}).setdefault("Missing", {})
            response_field_diff[field_name]["Missing"].setdefault("range broker", []).append(container_name1)
            response_field_diff.setdefault(field_name, {}).setdefault("Unexpected", {})
            response_field_diff[field_name]["Unexpected"].setdefault("range broker", []).append(container_name2)
            if endtime is not None:
                response_field_diff[field_name]["Missing"]["first_time"] = endtime
                response_field_diff[field_name]["Unexpected"]["first_time"] = endtime

        response_field_diff[field_name]["Missing"]["range broker"] = sorted(list(set(response_field_diff[field_name]["Missing"]["range broker"])))
        response_field_diff[field_name]["Unexpected"]["range broker"] = sorted(list(set(response_field_diff[field_name]["Unexpected"]["range broker"])))


    G_fields_common_keys = set(G_fields1.keys()) & set(G_fields2.keys())
    for field_name in G_fields_common_keys:
        if G_fields1[field_name] != G_fields2[field_name]:
            response_field_diff.setdefault(field_name, {}).setdefault("Different", {})
            response_field_diff[field_name]["Different"].setdefault("range broker", []).append(container_name1)
            response_field_diff[field_name]["Different"]["range broker"].append(container_name2)
            if endtime is not None:
                response_field_diff[field_name]["Different"]["first_time"] = endtime

    H_fields1 = parser1.parser.H_fields
    H_fields2 = parser2.parser.H_fields
    H_fields_key_diff = set(H_fields1.keys()) ^ set(H_fields2.keys())

    for field_name in H_fields_key_diff:
        if field_name in H_fields1:
            response_field_diff.setdefault(
                field_name, {}).setdefault("Missing", {})
            response_field_diff[field_name]["Missing"].setdefault("range broker", []).append(container_name2)
            response_field_diff.setdefault(field_name, {}).setdefault("Unexpected", {})
            response_field_diff[field_name]["Unexpected"].setdefault("range broker", []).append(container_name1)
            if endtime is not None:
                response_field_diff[field_name]["Missing"]["first_time"] = endtime
                response_field_diff[field_name]["Unexpected"]["first_time"] = endtime
        else:
            response_field_diff.setdefault(field_name, {}).setdefault("Missing", {})
            response_field_diff[field_name]["Missing"].setdefault("range broker", []).append(container_name1)
            response_field_diff.setdefault(field_name, {}).setdefault("Unexpected", {})
            response_field_diff[field_name]["Unexpected"].setdefault("range broker", []).append(container_name2)
            if endtime is not None:
                response_field_diff[field_name]["Missing"]["first_time"] = endtime
                response_field_diff[field_name]["Unexpected"]["first_time"] = endtime
        response_field_diff[field_name]["Missing"]["range broker"] = sorted(list(set(response_field_diff[field_name]["Missing"]["range broker"])))
        response_field_diff[field_name]["Unexpected"]["range broker"] = sorted(list(set(response_field_diff[field_name]["Unexpected"]["range broker"])))


def differetial_analysis_for_response(ClientFuzzers, message_type, message_payload, flags):
    newResults = False
    response_msg_diff = {}  
    response_field_diff = {}  

    for container_name1, cfobj1 in ClientFuzzers.items():    # ClientFuzzers:{'mosquitto': <object1>, 'naonmq': <object2>, ...}
        for container_name2, cfobj2 in ClientFuzzers.items():
            if container_name1 != container_name2:
                if (cfobj1.response_message is None and cfobj2.response_message is not None) or (cfobj1.response_message is not None and cfobj2.response_message is None):
                    if cfobj1.response_message is None:
                        response_msg_diff.setdefault("Missing", {}).setdefault("range broker", []).append(container_name1)
                        response_msg_diff.setdefault("Unexpected", {}).setdefault("range broker", []).append(container_name2)
                    elif cfobj2.response_message is None:
                        response_msg_diff.setdefault("Missing", {}).setdefault("range broker", []).append(container_name2)
                        response_msg_diff.setdefault("Unexpected", {}).setdefault("range broker", []).append(container_name1)
                elif cfobj1.response_message is not None and cfobj2.response_message is not None:
                    msg1 = cfobj1.response_message
                    msg2 = cfobj2.response_message
                    parser1 = pi.return_packet_parser(msg1)
                    parser2 = pi.return_packet_parser(msg2)

                    if parser1 is not None and parser2 is not None:
                        differential_response_fields(container_name1, parser1, container_name2, parser2, response_field_diff)
    if response_msg_diff:
        response_msg_diff["Missing"]["range broker"] = sorted(list(set(response_msg_diff["Missing"]["range broker"])))
        response_msg_diff["Unexpected"]["range broker"] = sorted(list(set(response_msg_diff["Unexpected"]["range broker"])))

    if response_msg_diff:
        diffInfo = DiffResponseInfo(g.DIFF_MESSAGE_MISSING)
        if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID:
            diffInfo.protocol_version = g.client_protocol_version
        else:
            diffInfo.protocol_version = g.broker_protocol_version

        diffInfo.msg_type = message_type
        diffInfo.direction = flags
        diffInfo.capture_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

        if len(response_msg_diff["Missing"]["range broker"]) > len(response_msg_diff["Unexpected"]["range broker"]):
            diffInfo.diff_range_broker = response_msg_diff["Unexpected"]["range broker"]
            diffInfo.diff_type = g.DIFF_MESSAGE_UNEXPECTED
        else:
            diffInfo.diff_range_broker = response_msg_diff["Missing"]["range broker"]
            diffInfo.diff_type = g.DIFF_MESSAGE_MISSING

        diff_hash_value = diffInfo.hash_value()
        if diff_hash_value not in g.DIFFERENTIAL_RESULTS_SET:
            filename = None
            if type(message_payload) == bytes:
                message_hash = hashlib.md5(message_payload).hexdigest()
            else:
                message_hash = hashlib.md5(message_payload.encode()).hexdigest()
            if g.diff_seed_dict.get(message_hash) is None:
                filename = do.save_diff_req_message(flags)
                g.diff_seed_dict[message_hash] = filename
            else:
                filename = g.diff_seed_dict[message_hash]
            
            diffInfo.client_msg_path = filename
            diffInfo.id = g.DifferenceNumber
            g.DifferenceNumber += 1
            g.DIFFERENTIAL_RESULTS_SET.add(diff_hash_value)
            g.DIFFERENTIAL_RESULTS.append(diffInfo)
            newResults = True
        else:
            g.CLIENT_DIFF_OLD_RESULTS = True

    if response_field_diff:
        for field_name, diff_info in response_field_diff.items():
            diffInfo = DiffResponseInfo(g.DIFF_FIELD_MISSING)
            if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID:
                diffInfo.protocol_version = g.client_protocol_version
            else:
                diffInfo.protocol_version = g.broker_protocol_version
            diffInfo.msg_type = message_type
            diffInfo.direction = flags
            diffInfo.capture_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            diffInfo.field_name = field_name

            if diff_info.get("Missing") and len(diff_info["Missing"]["range broker"]) > len(diff_info["Unexpected"]["range broker"]):
                diffInfo.diff_type = g.DIFF_FIELD_UNEXPECTED
                diffInfo.diff_range_broker = diff_info["Unexpected"]["range broker"]
            elif diff_info.get("Missing") and len(diff_info["Missing"]["range broker"]) <= len(diff_info["Unexpected"]["range broker"]):
                diffInfo.diff_type = g.DIFF_FIELD_MISSING
                diffInfo.diff_range_broker = diff_info["Missing"]["range broker"]
            if diff_info.get("Different"):
                diffInfo.diff_type = g.DIFF_FIELD_DIFFERENT
                diffInfo.diff_range_broker = diff_info["Different"]["range broker"]

            diff_hash_value = diffInfo.hash_value()
            if diff_hash_value not in g.DIFFERENTIAL_RESULTS_SET:
                message_hash = hashlib.md5(
                    message_payload.encode()).hexdigest()
                filename = None
                if g.diff_seed_dict.get(message_hash) is None:
                    filename = do.save_diff_req_message(flags) 
                    g.diff_seed_dict[message_hash] = filename
                else:
                    filename = g.diff_seed_dict[message_hash]

                diffInfo.client_msg_path = filename
                diffInfo.id = g.DifferenceNumber
                g.DifferenceNumber += 1
                g.DIFFERENTIAL_RESULTS_SET.add(diff_hash_value)
                g.DIFFERENTIAL_RESULTS.append(diffInfo)
                newResults = True
            else:
                g.CLIENT_DIFF_OLD_RESULTS = True

    return newResults

def get_time_windows_range(start_index, target_list):
    start_time = target_list[start_index][0]
    end_time = start_time + g.TIME_WINDOWS_SIZE
    end_index = None

    for i in range(start_index, len(target_list)):
        time_stamp, _ = target_list[i]
        if time_stamp > end_time:
            end_index = i
            break
    if end_index is not None and end_index > 0:
        end_index -= 1
    return (start_index, end_index)


def find_common_element_indexes(lists_dict):
    intersection = set.intersection(*map(set, lists_dict.values()))
    indexes = defaultdict(list)
    for element in intersection:
        for name, lst in lists_dict.items():
            indexes[name].append(lst.index(element))

    return indexes

def locate_element_inwhich_broker(ClientFuzzerDict, msg_hash):
    results = []
    for c_name, tuple_list in ClientFuzzerDict.items():
        for _, _, _, hash_value, _ in tuple_list:
            if hash_value == msg_hash:
                results.append(c_name)
    return results

def find_message_first_time(ClientFuzzerDict, msg_hash):
    first_time = None
    msg_payload = None
    for c_name, tuple_list in ClientFuzzerDict.items():
        for abs_time, _, msg, hash_value, _ in tuple_list:
            if hash_value == msg_hash:
                if first_time == None:
                    first_time = abs_time
                    msg_payload = msg
                else:
                    first_time = min(first_time, abs_time)
    return (first_time, msg_payload)

def find_target_message_item(ClientFuzzerDict, msg_hash):
    for c_name, tuple_list in ClientFuzzerDict.items():
        for abs_time, _, msg, hash_value, _ in tuple_list:
            if hash_value == msg_hash:
                return (c_name, abs_time, msg)
    return None

def differetial_analysis_for_forward_pro(ClientFuzzers):
    newResults = False
    ClientFuzzerDict = {}
    for cf in ClientFuzzers.values():
        c_name = g.DOCKER_CONTAINER_HOST[cf.ip]     
        c_list = cf.forward_message.get_sorted_items()  # list[(time, msg), ...]
        for abs_time, pub_msg in c_list:
            parser = pi.return_packet_parser(pub_msg)
            if parser is None:
                continue

            topic_hash = None
            pub_msg_hash = None
            if parser.parser.H_fields.get("topic name") is not None:
                topic_hash = hashlib.md5(parser.parser.H_fields["topic name"].encode()).hexdigest()
            if parser.parser.H_fields.get("message") is not None:
                pub_msg_hash = hashlib.md5(parser.parser.H_fields["message"].encode()).hexdigest()
            
            if topic_hash is not None or pub_msg_hash is not None:
                msg_hash = topic_hash + pub_msg_hash
            elif topic_hash is not None:
                msg_hash = topic_hash
            elif pub_msg_hash is not None:
                msg_hash = pub_msg_hash
            
            ClientFuzzerDict.setdefault(c_name, {})
            ClientFuzzerDict[c_name][msg_hash] = parser # store {broker_name: {topic+payload1: pub_msg1, topic+payload2: pub_msg2}}
    
    PubCountMsgs = {}
    for c_name, msg_dict in ClientFuzzerDict.items():
        for msg_hash in msg_dict.keys():
            PubCountMsgs.setdefault(msg_hash, []).append(c_name)
            PubCountMsgs[msg_hash] = list(set(PubCountMsgs[msg_hash]))


    for msg_hash, broker_list in PubCountMsgs.items():
        forward_field_diff = {} 
        forward_msg_diff = {}  

        if len(broker_list) == len(ClientFuzzerDict):
            for pair in combinations(ClientFuzzerDict.keys(), 2):
                c_name1, c_name2 = pair
                parser1 = ClientFuzzerDict[c_name1].get(msg_hash)
                parser2 = ClientFuzzerDict[c_name2].get(msg_hash)
                res1_hash = parser1.parser.retGHFieldsHash()
                res2_hash = parser2.parser.retGHFieldsHash()
                if res1_hash != res2_hash:
                    differential_response_fields(c_name1, parser1, c_name2, parser2, forward_field_diff)

        elif len(broker_list) > 0 and len(broker_list) < len(ClientFuzzerDict)//2:
            UnexpectedBroker = broker_list
            forward_msg_diff.setdefault(msg_hash, {}).setdefault("type", "Unexpected")
            forward_msg_diff[msg_hash].setdefault("range broker", UnexpectedBroker)

        elif len(broker_list) >= len(ClientFuzzerDict)//2 and len(broker_list) < len(ClientFuzzerDict):
            MissingBroker = list(set(g.DOCKER_CONTAINER) - set(broker_list))
            forward_msg_diff.setdefault(msg_hash, {}).setdefault("type", "Missing")
            forward_msg_diff[msg_hash].setdefault("range broker", MissingBroker)

        with g.diff_pub_msg_queue_lock:
            g.diff_pub_msg_queue[msg_hash] = True  

        if forward_msg_diff:
            if save_forward_msg_diff_results(forward_msg_diff):
                newResults = True

        if forward_field_diff:
            if save_forward_field_diff_results(forward_field_diff):
                newResults = True
    
    return newResults


def differetial_analysis_for_forward(ClientFuzzers):
    newResults = False
    ClientFuzzerDict = {}
    for cf in ClientFuzzers.values():
        c_name = g.DOCKER_CONTAINER_HOST[cf.ip]     
        c_list = cf.forward_message.get_sorted_items()  # list[(time, msg), ...]
        c_start_time = None
        for abs_time, pub_msg in c_list:
            if c_start_time is None:
                c_start_time = abs_time
            rel_time = abs_time - c_start_time
            parser = pi.return_packet_parser(pub_msg)
            if parser is None:
                continue

            msg_hash = parser.parser.retGHFieldsHash()
            if parser.parser.H_fields.get("message") is not None:
                payload = parser.parser.H_fields["message"] # keyError
            else:
                payload = ""

            item_tuple = (abs_time, rel_time, pub_msg, msg_hash, payload)
            ClientFuzzerDict.setdefault(c_name, []).append(item_tuple)

    MsgCountDict = defaultdict(int)
    MsgTupleDict = {}  

    for c_name1, seq1 in ClientFuzzerDict.items():
        seq1_count = set()
        for i, (abs_time1, rel_time1, msg1, msg_hash1, payload1) in enumerate(seq1):
            if msg_hash1 not in seq1_count:
                seq1_count.add(msg_hash1)
                MsgCountDict[msg_hash1] += 1
                MsgTupleDict.setdefault(msg_hash1, []).append((abs_time1, rel_time1, msg1, msg_hash1, payload1))
            for c_name2, seq2 in ClientFuzzerDict.items():
                if c_name1 == c_name2:
                    continue
                seq2_count = set()
                for j, (abs_time2, rel_time2, msg2, msg_hash2, payload2) in enumerate(seq2):
                    time_diff = abs(rel_time1 - rel_time2) 
                    if time_diff < g.TIME_WINDOWS_SIZE:
                        if msg_hash2 not in seq2_count:
                            seq2_count.add(msg_hash2)
                            MsgCountDict[msg_hash2] += 1
                            MsgTupleDict.setdefault(msg_hash2, []).append((abs_time2, rel_time2, msg2, msg_hash2, payload2))
        break

    for msg_hash, count in MsgCountDict.items():
        if count == len(ClientFuzzerDict):
            for c_name, msg_list in ClientFuzzerDict.items():
                msg_list_new = [x for x in msg_list if x not in MsgTupleDict[msg_hash]]
                ClientFuzzerDict[c_name] = msg_list_new

    MsgLevelDiff_CountDict = defaultdict(int) 
    if len(set(len(ClientFuzzerDict[c_name]) for c_name in ClientFuzzerDict)) != 1:
        for c_values in ClientFuzzerDict.values():
            seen_values = set()
            for _, _, _, msg_hash, _ in c_values:
                if msg_hash not in seen_values:
                    MsgLevelDiff_CountDict[msg_hash] += 1
                    seen_values.add(msg_hash)
        threshold = len(ClientFuzzerDict) // 2  
        forward_msg_diff = {}
        
        for msg_hash, value in MsgLevelDiff_CountDict.items():
            if value >= threshold and value < len(ClientFuzzerDict):
                forward_msg_diff.setdefault(msg_hash, {}).setdefault("type", "Missing")
                range_broker_list = locate_element_inwhich_broker(ClientFuzzerDict, msg_hash)
                forward_msg_diff[msg_hash].setdefault("range broker", range_broker_list)
                first_time, pub_msg = find_message_first_time(ClientFuzzerDict, msg_hash)   

                forward_msg_diff[msg_hash]["first_time"] = first_time
                forward_msg_diff[msg_hash]["message"] = pub_msg
                parser = pi.return_packet_parser(pub_msg)
                if parser is not None and parser.parser.H_fields.get("message") != None:
                    pub_payload_hash = hashlib.md5(parser.parser.H_fields["message"].encode()).hexdigest()
                    with g.diff_pub_msg_queue_lock:
                        g.diff_pub_msg_queue[pub_payload_hash] = True  
            elif value < threshold and value > 0:
                forward_msg_diff.setdefault(msg_hash, {}).setdefault("type", "Unexpected")
                range_broker_list = locate_element_inwhich_broker(ClientFuzzerDict, msg_hash)
                forward_msg_diff[msg_hash].setdefault("range broker", range_broker_list)
                first_time, pub_msg = find_message_first_time(ClientFuzzerDict, msg_hash) 

                forward_msg_diff[msg_hash]["first_time"] = first_time
                forward_msg_diff[msg_hash]["message"] = pub_msg
                parser = pi.return_packet_parser(pub_msg)
                if parser is not None and parser.parser.H_fields.get("message") != None:
                    pub_payload_hash = hashlib.md5(parser.parser.H_fields["message"].encode()).hexdigest()
                    with g.diff_pub_msg_queue_lock:
                        g.diff_pub_msg_queue[pub_payload_hash] = True

        for msg_hash, objects in forward_msg_diff.items():
            diff_type = None
            if objects["type"] == "Missing":
                diff_type = g.DIFF_MESSAGE_MISSING
            else:
                diff_type = g.DIFF_MESSAGE_UNEXPECTED
            diffInfo = DiffResponseInfo(diff_type)
            if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID:
                diffInfo.protocol_version = g.client_protocol_version
            else:
                diffInfo.protocol_version = g.broker_protocol_version
            diffInfo.diff_range_broker = objects["range broker"]
            endtime = forward_msg_diff[msg_hash]["first_time"]
            diffInfo.direction = "both"

            if diffInfo.hash_value not in g.DIFFERENTIAL_RESULTS_SET:
                diffInfo.id = g.DifferenceNumber
                diffInfo.msg_path = do.save_publish_for_forward_diff_message() 
                g.DifferenceNumber += 1
                g.DIFFERENTIAL_RESULTS_SET.add(diffInfo.hash_value)
                g.DIFFERENTIAL_RESULTS.append(diffInfo) 
                newResults = True
            else:
                g.CLIENT_DIFF_OLD_RESULTS = True

    forward_field_diff = {}  # field-level difference
    for pair in combinations(ClientFuzzerDict.keys(),2):
        c_name1, c_name2 = pair
        for item1 in ClientFuzzerDict[c_name1]:
            msg1, msg_hash1, payload1 = item1[2], item1[3], item1[4]

            for item2 in ClientFuzzerDict[c_name2]:
                msg2, msg_hash2, payload2 = item2[2], item2[3], item2[4]
                if payload1 == payload2 and msg_hash1 != msg_hash2:
                    parser1 = pi.return_packet_parser(msg1)
                    parser2 = pi.return_packet_parser(msg2)
                    if parser1 is not None and parser2 is not None:
                        msg1_recv_time = find_target_message_item(ClientFuzzerDict, msg_hash1)[1]
                        msg2_recv_time = find_target_message_item(ClientFuzzerDict, msg_hash2)[1]
                        end_time = min(msg1_recv_time, msg2_recv_time)
                        differential_response_fields(c_name1, parser1, c_name2, parser2, forward_field_diff, end_time)
    
    if forward_field_diff:
        for field_name, diff_info in forward_field_diff.items():
            diffInfo = DiffResponseInfo(g.DIFF_MESSAGE_MISSING)
            if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID:
                diffInfo.protocol_version = g.client_protocol_version
            else:
                diffInfo.protocol_version = g.broker_protocol_version
            diffInfo.field_name = field_name
            diffInfo.msg_type = g.MSG_TYPE_PUBLISH
            diffInfo.direction = "both"
            endtime = None

            if diff_info.get("Missing") and len(diff_info["Missing"]["range broker"]) > len(diff_info["Unexpected"]["range broker"]):
                diffInfo.diff_type = g.DIFF_FIELD_UNEXPECTED
                diffInfo.diff_range_broker = diff_info["Unexpected"]["range broker"]
                endtime = diff_info["Unexpected"]["first_time"]
            elif diff_info.get("Missing") and len(diff_info["Missing"]["range broker"]) <= len(diff_info["Unexpected"]["range broker"]):
                diffInfo.diff_type = g.DIFF_FIELD_MISSING
                diffInfo.diff_range_broker = diff_info["Missing"]["range broker"]
                endtime = diff_info["Missing"]["first_time"]
            if diff_info.get("Different"):
                diffInfo.diff_type = g.DIFF_FIELD_DIFFERENT
                diffInfo.diff_range_broker = diff_info["Different"]["range broker"]
                endtime = diff_info["Different"]["first_time"]

            diff_hash_value = diffInfo.hash_value()

            if diff_hash_value not in g.DIFFERENTIAL_RESULTS_SET:
                diffInfo.id = g.DifferenceNumber
                g.DifferenceNumber += 1
                g.DIFFERENTIAL_RESULTS_SET.add(diff_hash_value)
                g.DIFFERENTIAL_RESULTS.append(diffInfo)
                diffInfo.msg_path = do.save_publish_for_forward_diff_message()
                newResults = True
            else:
                g.CLIENT_DIFF_OLD_RESULTS = True
    return newResults

def update_diff_publish(MessageModel):
    learned = False
    pub_msg_hash_del = []
    with g.diff_pub_msg_queue_lock:
        for pub_msg_hash in g.diff_pub_msg_queue:
            if pub_msg_hash in g.updated_pubmsg_hash:
                pub_msg_hash_del.append(pub_msg_hash)
                continue
            if pub_msg_hash in g.publish_request_queue:
                cur_state = g.publish_request_queue[pub_msg_hash][0]
                next_state = g.publish_request_queue[pub_msg_hash][1]
                MessageModel.learn(cur_state, g.MSG_TYPE_PUBLISH, 1, next_state)
                pub_msg_hash_del.append(pub_msg_hash)
                g.updated_pubmsg_hash.add(pub_msg_hash)
                learned = True

        for pub_msg_hash in pub_msg_hash_del:
            g.diff_pub_msg_queue.delete(pub_msg_hash)
    
    return learned

def validate_connack_message(ClientFuzzers):
    reason_codes = {}

    for broker_name, clientFuzzer in ClientFuzzers.items():
        res_message = clientFuzzer.response_message

        if res_message is None:
            continue

        parser = pi.return_packet_parser(res_message)
        if parser is None or type(parser.parser) is not ConnackParser:
            continue
        
        if parser.parser.G_fields.get("reason code") is not None:
            reason_codes[broker_name] = parser.parser.G_fields["reason code"]

    all_zeros = all(value == '00' for value in reason_codes.values())
    if all_zeros and len(reason_codes) == len(ClientFuzzers):
        return True

    return False

def save_forward_field_diff_results(forward_field_diff):
    newResults = False
    for field_name, diff_info in forward_field_diff.items():
        diffInfo = DiffResponseInfo(g.DIFF_MESSAGE_MISSING)
        if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID:
            diffInfo.protocol_version = g.client_protocol_version
        else:
            diffInfo.protocol_version = g.broker_protocol_version
        diffInfo.field_name = field_name
        diffInfo.msg_type = g.MSG_TYPE_PUBLISH
        diffInfo.direction = "both"
        if diff_info.get("Missing") and len(diff_info["Missing"]["range broker"]) > len(diff_info["Unexpected"]["range broker"]):
            diffInfo.diff_type = g.DIFF_FIELD_UNEXPECTED
            diffInfo.diff_range_broker = diff_info["Unexpected"]["range broker"]
        elif diff_info.get("Missing") and len(diff_info["Missing"]["range broker"]) <= len(diff_info["Unexpected"]["range broker"]):
            diffInfo.diff_type = g.DIFF_FIELD_MISSING
            diffInfo.diff_range_broker = diff_info["Missing"]["range broker"]
        if diff_info.get("Different"):
            diffInfo.diff_type = g.DIFF_FIELD_DIFFERENT
            diffInfo.diff_range_broker = diff_info["Different"]["range broker"]

        diff_hash_value = diffInfo.hash_value()

        if diff_hash_value not in g.DIFFERENTIAL_RESULTS_SET:
            diffInfo.id = g.DifferenceNumber
            g.DifferenceNumber += 1
            g.DIFFERENTIAL_RESULTS_SET.add(diff_hash_value)
            g.DIFFERENTIAL_RESULTS.append(diffInfo)
            diffInfo.msg_path = do.save_publish_for_forward_diff_message()
            newResults = True
        else:
            g.CLIENT_DIFF_OLD_RESULTS = True
    
    return newResults

def save_forward_msg_diff_results(forward_msg_diff):
    newResults = False
    for msg_hash, objects in forward_msg_diff.items():
        diff_type = None
        if objects["type"] == "Missing":
            diff_type = g.DIFF_MESSAGE_MISSING
        else:
            diff_type = g.DIFF_MESSAGE_UNEXPECTED
        diffInfo = DiffResponseInfo(diff_type)
        if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID:
            diffInfo.protocol_version = g.client_protocol_version
        else:
            diffInfo.protocol_version = g.broker_protocol_version
        diffInfo.diff_range_broker = objects["range broker"]
        diffInfo.direction = "both"

        if diffInfo.hash_value not in g.DIFFERENTIAL_RESULTS_SET:
            diffInfo.id = g.DifferenceNumber
            diffInfo.msg_path = do.save_publish_for_forward_diff_message() 
            g.DifferenceNumber += 1
            g.DIFFERENTIAL_RESULTS_SET.add(diffInfo.hash_value)
            g.DIFFERENTIAL_RESULTS.append(diffInfo) 
            newResults = True
        else:
            g.CLIENT_DIFF_OLD_RESULTS = True
    
    return newResults