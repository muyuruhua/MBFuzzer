import os
import sys
import threading
# sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import globals as g
import hashlib
import datetime
import binascii
# import parsers.parse_initializer as pi
import helper_functions.determine_message_type as dmt
import helper_functions.convert_format as cf
import time

def create_initial_fuzzing_directory():
    for directory in [g.FUZZING_OUTPUT_DIR, g.FUZZING_OUTPUT_CRASH_DIR, g.FUZZING_OUTPUT_QUEUE_DIR, g.FUZZING_OUTPUT_DIFF_DIR, g.FUZZING_OUTPUT_VALID_CON_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)

    for important_dir in [g.FUZZING_OUTPUT_CRASH_DIR, g.FUZZING_OUTPUT_DIFF_DIR]:
        if os.listdir(important_dir):
            print(f"Important data exists in {important_dir}. Please handle it first.")
            exit()

    for queue_file in os.listdir(g.FUZZING_OUTPUT_QUEUE_DIR):
        file_path = os.path.join(g.FUZZING_OUTPUT_QUEUE_DIR, queue_file)
        if os.path.isfile(file_path):
            os.remove(file_path)

    for valid_file in os.listdir(g.FUZZING_OUTPUT_VALID_CON_DIR):
        file_path = os.path.join(g.FUZZING_OUTPUT_VALID_CON_DIR, valid_file)
        if os.path.isfile(file_path):
            os.remove(file_path)


def save_valid_connect_message_to_queue(message_content, version):
    version = str(version)
    valid_msg_dir = os.path.join(g.FUZZING_OUTPUT_VALID_CON_DIR)
    if not os.path.exists(valid_msg_dir):
        os.makedirs(valid_msg_dir)
    
    file_path = os.path.join(valid_msg_dir, "valid-" + str(version) + "-id_" + str(g.VALID_CONNECT_NUM) + ".raw")
    g.VALID_CONNECT_NUM += 1
    with open(file_path, "w") as file:
        file.write(message_content) 
    return file_path


def save_interesting_message_to_queue(msg_type, message_content):
    msg_type_dir = os.path.join(g.FUZZING_OUTPUT_QUEUE_DIR, msg_type)
    if not os.path.exists(msg_type_dir):
        os.makedirs(msg_type_dir)

    hash_value = hashlib.md5(message_content.encode()).hexdigest()

    file_path = os.path.join(msg_type_dir, hash_value)

    with open(file_path, "w") as file:
        file.write(message_content) 

    return file_path

def save_diff_req_message(flags):
    msg_type_dir = os.path.join(g.FUZZING_OUTPUT_DIFF_DIR)
    if not os.path.exists(msg_type_dir):
        os.makedirs(msg_type_dir)
    
    filename = g.FUZZING_OUTPUT_DIFF_DIR + "/diff-" + str(g.diff_number) + "-" + str(flags) + ".raw"
    g.diff_number += 1
    f = open(filename, "w")
    request_queue = g.client_request_queue
    if flags == "broker":
        request_queue = g.broker_request_queue
        
    for req in request_queue.get_sorted_items():
        f.write(req[1] + "\n")
    f.close()

    return filename


def merge_two_queue_by_time(list1, list2, endtime, msg_constraint=None):
    merge_list = []
    i = 0
    j = 0
    while i < len(list1) and j < len(list2):
        if list1[i][0] <= list2[j][0]:
            if list1[i][0] <= endtime:
                content = "client:\n" + list1[i][1]
                if msg_constraint is None or dmt.determine_message_type(list1[i][1]) in msg_constraint:
                    merge_list.append(content)
                i += 1
            else:
                break
        else:
            if list2[j][0] <= endtime:
                content = "broker:\n" + list2[j][1]
                if msg_constraint is None or dmt.determine_message_type(list2[j][1]) in msg_constraint:
                    merge_list.append(content)
                j += 1
            else:
                break
    while i < len(list1) and list1[i][0] <= endtime:
        content = "client:\n" + list1[i][1]
        if msg_constraint is None or dmt.determine_message_type(list1[i][1]) in msg_constraint:
            merge_list.append(content)
        i += 1
    while j < len(list2) and list2[j][0] <= endtime:
        content = "broker:\n" + list2[j][1]
        if msg_constraint is None or dmt.determine_message_type(list2[j][1]) in msg_constraint:
            merge_list.append(content)
        j += 1

    return merge_list


def save_crash_requests(affect_brokers="connect"):
    client_empty_flag = g.client_request_queue_list.is_empty()
    broker_empty_flag = g.broker_request_queue_list.is_empty()
    # skip if both queues are empty
    if client_empty_flag and broker_empty_flag:
        return

    filename = g.FUZZING_OUTPUT_CRASH_DIR + "/crash-" + str(g.crash_number) + "-" + affect_brokers
    g.crash_number += 1
    f = open(filename, "w")

    client_msgs = g.client_request_queue_list.print_queue()
    if client_msgs != None:
        f.write("client:\n")
        f.write(client_msgs + "\n")
        g.client_request_queue_list.clear()
    
    broker_msgs = g.broker_request_queue_list.print_queue()
    if broker_msgs != None:
        f.write("broker:\n")
        f.write(broker_msgs + "\n")
        g.broker_request_queue_list.clear()

    f.close()

def save_crash_req_message(affect_brokers, flags):
    endtime = 0
    if flags == "client":
        endtime = g.client_request_queue.get_last_timestamp()
    else:
        endtime = g.broker_request_queue.get_last_timestamp()

    client_queue = g.client_request_queue.get_sorted_items()
    broker_queue = g.broker_request_queue.get_sorted_items()
    merget_message_list = merge_two_queue_by_time(client_queue, broker_queue, endtime)

    if len(merget_message_list) == 0:
        return
        
    # dt = str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"))
    filename = g.FUZZING_OUTPUT_CRASH_DIR + "/crash-" + str(g.crash_number) + "-" + affect_brokers
    g.crash_number += 1
    f = open(filename, "w")
    for line in merget_message_list:
        f.write(line + "\n")
    f.close()


def save_publish_for_forward_diff_message():
    client_queue = None
    broker_queue = None

    with g.client_broker_request_queue_lock:
        client_queue = g.client_request_queue.get_sorted_items()
        broker_queue = g.broker_request_queue.get_sorted_items()

    filename = g.FUZZING_OUTPUT_DIFF_DIR + "/diff_forward-" + str(g.diff_number) + "-both.raw"
    g.diff_number += 1
    f = open(filename, "w")
    if len(client_queue) > 0:
        f.write("client:\n")
        for req in client_queue:
            f.write(req[1] + "\n")
    if len(broker_queue) > 0:
        f.write("broker:\n")
        for req in broker_queue:
            f.write(req[1] + "\n")
    f.close()
    return filename


def save_forward_diff_req_message(flags, endtime):
    client_queue = None
    broker_queue = None
    with g.client_broker_request_queue_lock:
        client_queue = g.client_request_queue.get_sorted_items()
        broker_queue = g.broker_request_queue.get_sorted_items()
    merget_message_list = merge_two_queue_by_time(client_queue, broker_queue, endtime, [g.MSG_TYPE_CONNECT, g.MSG_TYPE_SUBSCRIBE, g.MSG_TYPE_PUBLISH])
    if len(merget_message_list) == 0:
        return
    filename = g.FUZZING_OUTPUT_DIFF_DIR + "/diff_forward-" + str(g.diff_number) + "-" + str(flags) + ".raw"
    g.diff_number += 1
    f = open(filename, "w")
    for line in merget_message_list:
        f.write(line + "\n")
    f.close()
    return filename


def push_queue(queue, request):
    if type(request) != str:
        request = binascii.hexlify(request).decode()
    now = datetime.datetime.now()
    timestamp = int(now.timestamp() * 1000)
    queue.add_item(timestamp, request)  # FIXME: max size

def total_messages_sent(message_dict):
    return sum(message_dict.values())

def dict_to_string(message_dict):
    return "\n".join([f"\t{key}: {value}" for key, value in message_dict.items()])


def dump_fuzzing_info_log(Model = None):

    endtime = time.time()

    log_content =  "Fuzzing Start Time: " + datetime.datetime.fromtimestamp(g.FUZZING_START_TIME).strftime("%Y-%m-%d %H:%M:%S") + "\n"
    log_content += "Fuzzing End Time: " + datetime.datetime.fromtimestamp(endtime).strftime("%Y-%m-%d %H:%M:%S") + "\n"
    log_content += "Fuzzing request number: " + str(total_messages_sent(g.CLIENT_SENT_MESSAGE) + total_messages_sent(g.BROKER_SENT_MESSAGE)) + "\n"
    log_content += "Crash Number: " + str(g.crash_number) + "\n"
    log_content += "Diff Number: " + str(g.diff_number) + "\n"
    log_content += "Duplicate Diff Number: " + str(total_messages_sent(g.CLIENT_DIFF_OLD_RESULTS_NUM)) + "\n"
    if len(g.CLIENT_DIFF_OLD_RESULTS_NUM.keys()) > 0:
        log_content += dict_to_string(g.CLIENT_DIFF_OLD_RESULTS_NUM) + "\n"

    if len(g.DIFFERENTIAL_RESULTS) > 0:
        log_content += "\nDifferential Report:\n"
        for diff_object in g.DIFFERENTIAL_RESULTS:
            log_content += diff_object.to_string() + "\n"

    file_path = os.path.join(g.FUZZING_OUTPUT_DIR, "fuzzing_report.txt")
    with open(file_path, "w") as f:
        f.write(log_content)
    