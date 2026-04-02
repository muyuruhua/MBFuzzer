import os
import sys
import threading
import json
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


def count_output_files(directory):
    if not os.path.exists(directory):
        return 0

    total = 0
    for _, _, files in os.walk(directory):
        total += len(files)
    return total


def parse_existing_report_metrics():
    file_path = os.path.join(g.FUZZING_OUTPUT_DIR, "fuzzing_report.txt")
    metrics = {}

    if not os.path.exists(file_path):
        return metrics

    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("Fuzzing Start Time: "):
                metrics["start_time"] = line.split(": ", 1)[1]
            elif line.startswith("Fuzzing End Time: "):
                metrics["end_time"] = line.split(": ", 1)[1]
            elif line.startswith("Fuzzing request number: "):
                value = line.split(": ", 1)[1]
                try:
                    metrics["messages_sent"] = int(value)
                except ValueError:
                    pass

    return metrics


def build_paper_aligned_summary(endtime):
    existing_metrics = parse_existing_report_metrics()
    messages_sent = total_messages_sent(g.CLIENT_SENT_MESSAGE) + total_messages_sent(g.BROKER_SENT_MESSAGE)
    if messages_sent == 0:
        messages_sent = existing_metrics.get("messages_sent", 0)

    queue_files = count_output_files(g.FUZZING_OUTPUT_QUEUE_DIR)
    valid_conn_files = count_output_files(g.FUZZING_OUTPUT_VALID_CON_DIR)
    diff_files = count_output_files(g.FUZZING_OUTPUT_DIFF_DIR)
    crash_files = count_output_files(g.FUZZING_OUTPUT_CRASH_DIR)
    single_broker_mode = len(g.DOCKER_CONTAINER) < 2

    runtime_seconds = int(max(0, endtime - g.FUZZING_START_TIME)) if g.FUZZING_START_TIME else 0
    if runtime_seconds == 0 and existing_metrics.get("start_time") and existing_metrics.get("end_time"):
        try:
            start_time = datetime.datetime.strptime(existing_metrics["start_time"], "%Y-%m-%d %H:%M:%S")
            finish_time = datetime.datetime.strptime(existing_metrics["end_time"], "%Y-%m-%d %H:%M:%S")
            runtime_seconds = int(max(0, (finish_time - start_time).total_seconds()))
        except ValueError:
            pass

    notes = [
        "The paper reports messages sent, branch coverage, and unique bug discovery results.",
        "Branch coverage requires a gcov-instrumented C/C++ broker build and is not collected in the current local run.",
        "Paper bug counts are unique reported/confirmed/fixed bugs after analysis, not raw seed-file counts.",
    ]

    if single_broker_mode:
        notes.append("This local run used single-broker mode, so non-compliance bug discovery is not directly comparable to the paper's six-broker differential setup.")

    summary = {
        "subjects": list(g.DOCKER_CONTAINER),
        "runtime_seconds": runtime_seconds,
        "messages_sent": messages_sent,
        "paper_metric_scope": {
            "coverage_metric": "branch coverage",
            "coverage_value": None,
            "coverage_status": "unavailable in current local run",
            "memory_bug_reported": None,
            "memory_bug_confirmed": None,
            "memory_bug_fixed": None,
            "non_compliance_bug_reported": None,
            "non_compliance_bug_confirmed": None,
            "non_compliance_bug_fixed": None,
        },
        "local_artifacts": {
            "crash_seed_files": crash_files,
            "diff_seed_files": diff_files,
            "queue_corpus_files": queue_files,
            "valid_connect_seed_files": valid_conn_files,
        },
        "paper_comparability": {
            "single_broker_mode": single_broker_mode,
            "coverage_comparable": False,
            "bug_discovery_comparable": not single_broker_mode,
        },
        "notes": notes,
    }
    return summary


def paper_summary_to_text(summary):
    paper_scope = summary["paper_metric_scope"]
    local_artifacts = summary["local_artifacts"]
    comparability = summary["paper_comparability"]

    lines = [
        "Paper-aligned Local Summary:",
        "Subject: " + ", ".join(summary["subjects"]),
        "Runtime Seconds: " + str(summary["runtime_seconds"]),
        "Messages Sent: " + str(summary["messages_sent"]),
        "Coverage Metric (Paper): " + paper_scope["coverage_metric"],
        "Coverage Value: unavailable in current local run",
        "Memory Bug (Report/Confirmed/Fixed): unavailable from raw local artifacts",
        "Non-Compliance Bug (Report/Confirmed/Fixed): unavailable from raw local artifacts",
        "Crash Seed Files (Local): " + str(local_artifacts["crash_seed_files"]),
        "Diff Seed Files (Local): " + str(local_artifacts["diff_seed_files"]),
        "Queue Corpus Files (Local): " + str(local_artifacts["queue_corpus_files"]),
        "Valid Connect Seed Files (Local): " + str(local_artifacts["valid_connect_seed_files"]),
        "Single Broker Mode: " + str(comparability["single_broker_mode"]),
        "Coverage Comparable to Paper: " + str(comparability["coverage_comparable"]),
        "Bug Discovery Comparable to Paper: " + str(comparability["bug_discovery_comparable"]),
        "Notes:",
    ]

    for note in summary["notes"]:
        lines.append("- " + note)

    return "\n".join(lines)


def resolve_report_header(endtime, existing_metrics):
    messages_sent = total_messages_sent(g.CLIENT_SENT_MESSAGE) + total_messages_sent(g.BROKER_SENT_MESSAGE)

    if g.FUZZING_START_TIME and messages_sent > 0:
        start_time_text = datetime.datetime.fromtimestamp(g.FUZZING_START_TIME).strftime("%Y-%m-%d %H:%M:%S")
        end_time_text = datetime.datetime.fromtimestamp(endtime).strftime("%Y-%m-%d %H:%M:%S")
        return start_time_text, end_time_text, messages_sent

    start_time_text = existing_metrics.get("start_time")
    end_time_text = existing_metrics.get("end_time")
    messages_sent = existing_metrics.get("messages_sent", messages_sent)

    if start_time_text is None:
        start_time_text = datetime.datetime.fromtimestamp(endtime).strftime("%Y-%m-%d %H:%M:%S")
    if end_time_text is None:
        end_time_text = datetime.datetime.fromtimestamp(endtime).strftime("%Y-%m-%d %H:%M:%S")

    return start_time_text, end_time_text, messages_sent


def dump_fuzzing_info_log(Model = None):

    endtime = time.time()
    existing_metrics = parse_existing_report_metrics()
    start_time_text, end_time_text, messages_sent = resolve_report_header(endtime, existing_metrics)

    log_content =  "Fuzzing Start Time: " + start_time_text + "\n"
    log_content += "Fuzzing End Time: " + end_time_text + "\n"
    log_content += "Fuzzing request number: " + str(messages_sent) + "\n"
    log_content += "Crash Number: " + str(g.crash_number) + "\n"
    log_content += "Diff Number: " + str(g.diff_number) + "\n"
    log_content += "Duplicate Diff Number: " + str(total_messages_sent(g.CLIENT_DIFF_OLD_RESULTS_NUM)) + "\n"
    if len(g.CLIENT_DIFF_OLD_RESULTS_NUM.keys()) > 0:
        log_content += dict_to_string(g.CLIENT_DIFF_OLD_RESULTS_NUM) + "\n"

    if len(g.DIFFERENTIAL_RESULTS) > 0:
        log_content += "\nDifferential Report:\n"
        for diff_object in g.DIFFERENTIAL_RESULTS:
            log_content += diff_object.to_string() + "\n"

    paper_summary = build_paper_aligned_summary(endtime)
    log_content += "\n" + paper_summary_to_text(paper_summary) + "\n"

    file_path = os.path.join(g.FUZZING_OUTPUT_DIR, "fuzzing_report.txt")
    with open(file_path, "w") as f:
        f.write(log_content)

    paper_json_path = os.path.join(g.FUZZING_OUTPUT_DIR, "paper_metrics.json")
    with open(paper_json_path, "w") as f:
        json.dump(paper_summary, f, indent=2)
    