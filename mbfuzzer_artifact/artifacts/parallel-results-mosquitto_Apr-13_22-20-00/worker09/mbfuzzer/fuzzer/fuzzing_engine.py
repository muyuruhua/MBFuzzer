import hashlib
import helper_functions.directory_operation as do
import fuzzer.handle_network_response as hnr
import threading
import fuzzer.client_module as client_module
import fuzzer.server_module as server_module
import fuzzer.mutation as fm
import globals as g
from generators.connect import Connect
from generators.auth import Auth
from generators.disconnect import Disconnect
from generators.pingreq import Pingreq
from generators.pingresp import Pingresp
from generators.puback import Puback
from generators.pubcomp import Pubcomp
from generators.publish import Publish
from generators.pubrec import Pubrec
from generators.pubrel import Pubrel
from generators.suback import Suback
from generators.subscribe import Subscribe
from generators.unsuback import Unsuback
from generators.unsubscribe import Unsubscribe
from generators.connack import Connack
import type.ConnectClass as ConnectClass

import parsers.parse_initializer as pi
import time
import random
from collections import Counter

import globals as g
import os
import signal
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from queue import Queue
import helper_functions.determine_message_type as dmt


def get_kv_lock(kv_locks, key):
    if key not in kv_locks:
        kv_locks[key] = threading.Lock()
    return kv_locks[key]


def generate_message(message_type):
    protocol_version = g.broker_protocol_version
    if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID:
        # with threading.Lock():
        with g.client_protocol_version_lock:
            if g.client_protocol_version == None:
                protocol_version = random.randint(3, 5)
                g.client_protocol_version = protocol_version
            else:
                protocol_version = g.client_protocol_version

    # protocol_version = random.randint(3, 5)
    message_mapping = {
        g.MSG_TYPE_AUTH: Auth,
        g.MSG_TYPE_CONNECT: Connect,
        g.MSG_TYPE_CONNACK: Connack,
        g.MSG_TYPE_DISCONNECT: Disconnect,
        g.MSG_TYPE_PINGREQ: Pingreq,
        g.MSG_TYPE_PINGRESP: Pingresp,
        g.MSG_TYPE_PUBLISH: Publish,
        g.MSG_TYPE_PUBACK: Puback,
        g.MSG_TYPE_PUBCOMP: Pubcomp,
        g.MSG_TYPE_PUBREC: Pubrec,
        g.MSG_TYPE_PUBREL: Pubrel,
        g.MSG_TYPE_SUBSCRIBE: Subscribe,
        g.MSG_TYPE_SUBACK: Suback,
        g.MSG_TYPE_UNSUBSCRIBE: Unsubscribe,
        g.MSG_TYPE_UNSUBACK: Unsuback,
    }

    message_class = message_mapping.get(message_type) 
    if message_class:
        return message_class(protocol_version).toString()
    else:
        return None    

def select_message_from_corpus(message_type, protocol_version):
    filepath = random.choice(g.FUZZING_NETWORK_RESPONSE_CORPUS[message_type][protocol_version])
    message = None
    with open(filepath, 'r') as f:
        message = f.read()
    return message
    
def select_valid_conn_message(protocol_version):
    filepath = random.choice(g.PLATEAU_CONNECT_OBJECT_DICT[protocol_version])
    message = None
    with open(filepath, 'r') as f:
        message = f.read()
    return message
    

def single_fuzzing_engine_client(MessageModel):

    response_state = g.STATE_CLIENT_INITIAL
    ClientFuzzers = {}
    g.Client_Fuzzing_Thread_ID = threading.current_thread().ident
    g.client_protocol_version = None
    g.PLATEAU_CONNECT_OBJECT = ConnectClass.ConnectClass() 
    ValidConnectMsg = False
    client_module.connect_to_all_brokers(ClientFuzzers)

    loop_break = True

    if g.CLOG_NUM % 100 == 0:
        print("client fuzzing")
    g.CLOG_NUM += 1


    MSG_QUEUE = Queue()
    if g.DEBUG_FLAG_CLIENT_MSG_SENDING == True:
        MessageModel.check_state_exist(response_state)
        with open(g.TEST_CASE_FILE, 'r') as f:
            for line in f:
                MSG_QUEUE.put(line.strip())

    while loop_break:

        if g.DEBUG_FLAG_CLIENT_MSG_SENDING == False:
            mtype_schedule_probability = random.random()
            dependency_exist = g.dependency_event.has_dependency_with_flag("client") or g.dependency_event.has_dependency_with_flag("both")
            if dependency_exist and mtype_schedule_probability >= 0.5:  
                with g.dependency_event_lock:
                    if g.dependency_event.has_dependency_with_flag("client") and mtype_schedule_probability >= 0.5:
                        dependency = g.dependency_event.get_dependencies_with_flag("client")
                        message_type = dependency["passive"]["mtype"]
                    elif g.dependency_event.has_dependency_with_flag("both"):
                        dependency = g.dependency_event.get_dependencies_with_flag("both")
                        message_type = dependency["passive"]["mtype"]
            else:
                message_type = MessageModel.choose_next_action(response_state)
                if message_type in g.all_client_dependency and mtype_schedule_probability >= 0.5:
                    g.cur_client_dependency = random.choice(g.all_client_dependency[message_type]) 

            cur_random_num = random.random()
            if response_state == g.STATE_CLIENT_INITIAL and message_type == g.MSG_TYPE_CONNECT and g.DUPLICATE_DIFF_CONNECT_NUM > g.FUZZING_CONNECT_MAX_PLATEAU and cur_random_num < 0.8:
                protocol_version = g.broker_protocol_version
                if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID:
                    if g.client_protocol_version == None:
                        protocol_version = random.randint(4, 5)
                        g.client_protocol_version = protocol_version
                    else:
                        protocol_version = g.client_protocol_version

                if g.PLATEAU_CONNECT_OBJECT_DICT.get(protocol_version) and len(g.PLATEAU_CONNECT_OBJECT_DICT[protocol_version]) > 0:
                    message = select_valid_conn_message(protocol_version)
                    ValidConnectMsg = True
                else:
                    message = generate_message(message_type) 
                    g.CLIENT_SELECT_CORPUS_FLAG = False

            elif g.FUZZING_CLIENT_PLATEAU > g.FUZZING_MAX_PLATEAU and cur_random_num < 0.5 and message_type in g.FUZZING_NETWORK_RESPONSE_CORPUS:
                protocol_version = g.broker_protocol_version
                if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID:
                    protocol_version = g.client_protocol_version

                if g.FUZZING_NETWORK_RESPONSE_CORPUS[message_type].get(protocol_version) != None and len(g.FUZZING_NETWORK_RESPONSE_CORPUS[message_type][protocol_version]) > 0:
                    message = select_message_from_corpus(message_type, protocol_version)
                    message = fm.handle_message_mutation(message)
                    g.CLIENT_SELECT_CORPUS_FLAG = True
                else:
                    message = generate_message(message_type)
                    g.CLIENT_SELECT_CORPUS_FLAG = False
            else:
                message = generate_message(message_type)
                g.CLIENT_SELECT_CORPUS_FLAG = False
        
            if g.cur_client_dependency != None and len(g.cur_client_dependency) == 2:
                flag = g.cur_client_dependency["passive"]["flag"]
                new_dict = {"passive": g.cur_client_dependency["passive"]}
                with g.dependency_event_lock:
                    g.dependency_event.add_dependency(flag, new_dict) 
        else:
            if not MSG_QUEUE.empty():
                message = MSG_QUEUE.get()
                message_type = dmt.determine_message_type(message)
            else:
                os.kill(os.getpid(), signal.SIGINT)

        if message_type == g.MSG_TYPE_CONNECT and response_state == g.STATE_CLIENT_INITIAL:
            g.DUPLICATE_DIFF_CONNECT_NUM += 1

        threads = []
        for clientFuzzer in ClientFuzzers.values():
            clientFuzzer.response_message = None
            thread = threading.Thread(target = client_module.send_and_recv_message_to_broker, args=(message, clientFuzzer))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        do.push_queue(g.client_request_queue, message)
        g.client_request_queue_list.push(message)
        g.CLIENT_SENT_MESSAGE[message_type] += 1
        g.FUZZING_CLIENT_PLATEAU += 1

        if g.crash_occurred:
            g.crash_occurred = False
            loop_break = False
            affect_brokers_str = "_".join([g.DOCKER_CONTAINER_HOST[clientFuzzer.ip]
                                          for clientFuzzer in ClientFuzzers.values() if clientFuzzer.crash_occurred])
            do.save_crash_requests(affect_brokers_str)
            break
        
        if g.client_socket_error == True:
            g.client_socket_error = False
            loop_break = False

        if response_state == g.STATE_CLIENT_INITIAL and message_type == g.MSG_TYPE_CONNECT:
            if hnr.validate_connack_message(ClientFuzzers) == True:
                hashId = g.PLATEAU_CONNECT_OBJECT.hash()
                if g.PLATEAU_CONNECT_OBJECT_DICT.get(hashId) == None:
                    g.PLATEAU_CONNECT_OBJECT_DICT[hashId] = 1
                    filepath = do.save_valid_connect_message_to_queue(message, g.client_protocol_version)
                    g.PLATEAU_CONNECT_OBJECT_DICT.setdefault(g.client_protocol_version, []).append(filepath)

        new_response_state = hnr.handle_network_response((message_type, message), ClientFuzzers)  # check state if interesting

        if response_state != g.STATE_CLIENT_INITIAL and message_type == g.MSG_TYPE_PUBLISH and g.CLIENT_SELECT_CORPUS_FLAG == False:
            parser = pi.return_publish_parser(message)
            if parser.H_fields.get("packet identifier") == None:
                pub_msg_topic_hash = hashlib.md5(parser.H_fields["topic name"].encode()).hexdigest()
                pub_msg_hash = hashlib.md5(parser.H_fields["message"].encode()).hexdigest()
                msg_hash = pub_msg_topic_hash + pub_msg_hash
                g.publish_request_queue[msg_hash] = (response_state, response_state)

        if new_response_state is not None:
            diff_response_res = hnr.differetial_analysis_for_response(ClientFuzzers, message_type, message, "client")
            diff_forward_res = hnr.differetial_analysis_for_forward_pro(ClientFuzzers)
            
            if diff_response_res == True or diff_forward_res == True:
                print(f"[+] New client diff_response_res ({len(g.DIFFERENTIAL_RESULTS)} found) in {message_type}.")
                g.FUZZING_CLIENT_PLATEAU = 0
                loop_break = False
                MessageModel.learn(response_state, message_type, 1, new_response_state)

            if diff_response_res == True:
                filepath = do.save_interesting_message_to_queue(message_type, message)
                g.FUZZING_NETWORK_RESPONSE_CORPUS.setdefault(message_type, {}).setdefault(g.client_protocol_version, []).append(filepath)
                if response_state == g.STATE_CLIENT_INITIAL and message_type == g.MSG_TYPE_CONNECT:
                    g.DUPLICATE_DIFF_CONNECT_NUM = 0

            if diff_forward_res == True:
                hnr.update_diff_publish(MessageModel) 

        if g.CLIENT_DIFF_OLD_RESULTS == True and ValidConnectMsg == False:
            g.CLIENT_DIFF_OLD_RESULTS = False
            g.CLIENT_DIFF_OLD_RESULTS_NUM[message_type] += 1
            loop_break = False

        response_state = new_response_state

    if loop_break == False:
        client_module.close_all_sockets(ClientFuzzers)
        g.client_socket_error = False
        with g.client_broker_request_queue_lock:
            g.client_request_queue.clear()

def fuzzing_engine_bridge_broker(MQTTBroker, MessageModel):
    while True:
        if time.time() - g.FUZZING_START_TIME >= g.TIME_LIMITE_SECONDS:
            print("Broker time limit reached. Exiting...")
            os.kill(os.getpid(), signal.SIGINT)
            break

        if MQTTBroker.check_fuzzing_bridge_status() == True:
            if g.BLOG_NUM % 100 == 0:
                print("broker fuzzing...")
            g.BLOG_NUM += 1

            bridge_broker_single_fuzzing_loop(MQTTBroker, MessageModel)
        else:
            time.sleep(1)

def bridge_broker_single_fuzzing_loop(MQTTBroker, MessageModel):
    response_state = g.STATE_BRIDGE_STATE
    g.Broker_Fuzzing_Thread_ID = threading.current_thread().ident

    mtype_schedule_probability = random.random()
    dependency_exist = g.dependency_event.has_dependency_with_flag("both")
    if dependency_exist and mtype_schedule_probability >= 0.5:
        if g.dependency_event.has_dependency_with_flag("both"):
            with g.dependency_event_lock:
                dependency = g.dependency_event.get_dependencies_with_flag("both")
                message_type = dependency["passive"]["mtype"]
    else:
        message_type = MessageModel.choose_next_action(response_state)
        if message_type in g.all_broker_dependency and mtype_schedule_probability >= 0.5:
            g.cur_broker_dependency = random.choice(g.all_broker_dependency[message_type])

    if g.FUZZING_BROKER_PLATEAU > g.FUZZING_MAX_PLATEAU and random.random() < 0.5 and message_type in g.FUZZING_NETWORK_RESPONSE_CORPUS:
        protocol_version = g.broker_protocol_version
        if g.FUZZING_NETWORK_RESPONSE_CORPUS[message_type].get(protocol_version) != None and len(g.FUZZING_NETWORK_RESPONSE_CORPUS[message_type][protocol_version]) > 0:
            message = select_message_from_corpus(message_type, protocol_version)
            message = fm.handle_message_mutation(message)
            g.BROKER_SELECT_CORPUS_FLAG = True
        else:
            message = generate_message(message_type)
            g.BROKER_SELECT_CORPUS_FLAG = False
    else:
        message = generate_message(message_type)
        g.BROKER_SELECT_CORPUS_FLAG = False

    if g.cur_broker_dependency != None and len(g.cur_broker_dependency) == 2:
        flag = g.cur_broker_dependency["passive"]["flag"]
        new_dict = {"passive": g.cur_broker_dependency["passive"]}
        with g.dependency_event_lock:
            g.dependency_event.add_dependency(flag, new_dict)

    MQTTBroker.clear_all_response_message()
    threads = []
    for addr, cs_object in MQTTBroker.client_sessions.items():
        thread = threading.Thread(target=server_module.send_message_to_broker, args = (message, cs_object))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    do.push_queue(g.broker_request_queue, message)
    g.broker_request_queue_list.push(message)
    g.FUZZING_BROKER_PLATEAU += 1
    g.BROKER_SENT_MESSAGE[message_type] += 1

    if g.crash_occurred:
        affect_brokers_str = "_".join([cs_object.broker_name for cs_object in MQTTBroker.client_sessions.values() if cs_object.crash_occurred])
        do.save_crash_requests(affect_brokers_str)
        return

    if message_type == g.MSG_TYPE_PUBLISH and g.BROKER_SELECT_CORPUS_FLAG == False:
        parser = pi.return_publish_parser(message)
        if parser.H_fields.get("packet identifier") == None:
            pub_msg_topic_hash = hashlib.md5(parser.H_fields["topic name"].encode()).hexdigest()
            pub_msg_hash = hashlib.md5(parser.H_fields["message"].encode()).hexdigest()
            msg_hash = pub_msg_topic_hash + pub_msg_hash
            g.publish_request_queue[msg_hash] = (response_state, response_state)

    diff_response_res = hnr.differetial_analysis_for_response(MQTTBroker.client_sessions, message_type, message, "broker")
    
    if diff_response_res == True:
        print(f"[+] New broker diff_response_res ({len(g.DIFFERENTIAL_RESULTS)} found) in {message_type}")
        MessageModel.learn(response_state, message_type, 1, response_state)
        filepath = do.save_interesting_message_to_queue(message_type, message)
        g.FUZZING_NETWORK_RESPONSE_CORPUS.setdefault(message_type, {}).setdefault(g.broker_protocol_version, []).append(filepath)
        g.FUZZING_BROKER_PLATEAU = 0
    
    client_sessions = MQTTBroker.client_sessions
    lengths = [value.forward_message.get_queue_length() for value in client_sessions.values()]
    length_counts = Counter(lengths)
    most_common_length = length_counts.most_common(1)[0][0]

    if most_common_length != 0:
        ClientFuzzers = {}      
        for addr, cs_object in client_sessions.items():
            newcfobject= client_module.ClientFuzzer(cs_object.ip, cs_object.port, None)
            cs_object.forward_message.assign_top_n_to_self(most_common_length, newcfobject.forward_message)
            ClientFuzzers[addr] = newcfobject
            with get_kv_lock(g.remove_items_locks, addr):
                g.broker_to_remove_times[addr] = cs_object.forward_message.get_top_n_timestamps(most_common_length)
        
        diff_forward_res = hnr.differetial_analysis_for_forward_pro(ClientFuzzers)
        
        if diff_forward_res == True:
            hnr.update_diff_publish(MessageModel)
            g.FUZZING_BROKER_PLATEAU = 0
    
    g.broker_request_queue.clear()