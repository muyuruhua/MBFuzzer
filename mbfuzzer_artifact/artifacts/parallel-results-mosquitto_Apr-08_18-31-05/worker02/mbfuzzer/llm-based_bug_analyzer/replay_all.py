import socket
import threading
from typing import List, Tuple
import sys
import os
import llm_prompt as llmp
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import helper_functions.determine_message_type as dmt
import parsers.parse_initializer as pi
import globals as g

DOCKER_CONTAINER_HOST = {"172.199.0.7": "mosquitto", "172.199.0.6": "nanomq", "172.199.0.5": "flashmq", "172.199.0.4": "emqx", "172.199.0.3":"vernemq", "172.199.0.2": "hivemq"}
LOG_PATH = None

def merge_two_dicts(dict1, dict2):
    merged_dict = {**dict1, **dict2}
    return merged_dict

def filter_dict_by_value(input_dict):
    return {key: value for key, value in input_dict.items() if int(value) > 1}

def parse_packets(packet_hex_string, protocl_version = None):
    msg_type = dmt.determine_message_type(packet_hex_string)
    parser = pi.return_packet_parser(packet_hex_string, protocl_version)
    if msg_type == g.MSG_TYPE_CONNECT:
        protocl_version = parser.parser.protocol_version
        parser = pi.return_packet_parser(packet_hex_string, protocl_version)
    msg_dict = merge_two_dicts(parser.parser.G_fields, parser.parser.H_fields)
    msg_description = {"message_type": msg_type, "fields": msg_dict, "fields_count": filter_dict_by_value(parser.parser.I_fields_count)}
    msg_description = llmp.transform_message_format(msg_description)
    return msg_description, protocl_version


def send_recv_packets_to_broker(ip, port, packet_hex_strings, timeout = 0.5, protocol_version = None, LLM_PROMPT = None):
    broker_name = DOCKER_CONTAINER_HOST[ip]
    response_descriptions = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
        except Exception as e:
            return

        for packet_hex in packet_hex_strings:
            try:
                sock.sendall(bytes.fromhex(packet_hex))

                try:
                    while True:
                        response = sock.recv(2048)
                        if not response:
                            response_descriptions.append("None response")
                            break
                        response = response.hex()
                        msg_description = parse_packets(response, protocol_version)[0]
                        response_descriptions.append(msg_description)
                except socket.timeout:
                    pass
                except Exception as e:
                    pass
            except BrokenPipeError:
                break
    
    if LLM_PROMPT is not None:
        LLM_PROMPT[broker_name] = response_descriptions


def send_to_multiple_to_brokers(ips, port, packet_hex_strings, timeout = 0.5):
    LLM_PROMPT = {}
    REQUEST_MESSAGE_INFO = {}
    request_index = 0
    conn_proto_version = None
    for packet in packet_hex_strings:
        if len(packet) == 0:
            continue

        msg_type = dmt.determine_message_type(packet)
        if msg_type == g.MSG_TYPE_CONNECT:
            conn_proto_version = pi.get_conn_proto_version(packet)

        parser = pi.return_packet_parser(packet, conn_proto_version)
        msg_dict = merge_two_dicts(parser.parser.G_fields, parser.parser.H_fields)
        
        REQUEST_MESSAGE_INFO[request_index] = {"message_type": msg_type, "fields": msg_dict, "fields_count": filter_dict_by_value(parser.parser.I_fields_count)}
        LLM_PROMPT.setdefault('request', []).append(llmp.transform_message_format(REQUEST_MESSAGE_INFO[request_index]))
        request_index += 1
    
    LLM_PROMPT.setdefault('response', {})
    threads = []
    for ip in ips:
        thread = threading.Thread(target=send_recv_packets_to_broker, args=(ip, port, packet_hex_strings, timeout, conn_proto_version, LLM_PROMPT['response']))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()

    llm_prompt_dict = llmp.store_LLM_prompt(LLM_PROMPT, DOCKER_CONTAINER_HOST)
    return llm_prompt_dict


def read_packet_hex_strings_from_file(file_path: str) -> List[str]:
    packet_hex_strings = []
    with open(file_path, 'r') as file:
        for line in file:
            stripped_line = line.strip()
            if not stripped_line.startswith("client:"):
                packet_hex_strings.append(stripped_line)
        return packet_hex_strings


def ask_for_llm_model_chatgpt(prompt, model="gpt-4o"):
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not set")
    
    response = llmp.get_chat_response(api_key, prompt, model)
    
    if response is None:
        return None
    return str(response)


def save_information_to_file(content, append=False):
    global LOG_PATH
    try:
        if append:
            with open(LOG_PATH, 'a') as file:
                file.write(content)
        else:
            with open(LOG_PATH, 'w') as file:
                file.write(content)
    except FileNotFoundError:
        print(f"Error: File '{LOG_PATH}' not found.")
        sys.exit(1)

def remove_empty_lines(s):
    lines = s.split('\n')
    non_empty_lines = [line for line in lines if line.strip()]
    return '\n'.join(non_empty_lines)

def ask_for_llm_diff_info(filename, llm_prompt, model= "gpt-4o"):
    prompt = f"(1) Followings are a sequence of MQTT requests sent by the client.\n {llm_prompt['request']}\n"
    prompt += f"(2) Followings are the sequence of responses from several brokers.\n {llm_prompt['response']}\n"
    prompt += f"(3) Now you are an expert in the MQTT protocol, please describe what the differences between these brokers in responding to handle such request.\nPlease provide the detail description of the analysis.\n\n"
    if model.startswith("gpt"):
        response = ask_for_llm_model_chatgpt(prompt, model)

    response = remove_empty_lines(response)
    llm_prompt["llm_broker_diff"] = response
    save_information_to_file(f"Process [{filename}]\nStep 1.\n" + prompt + "\n[LLM Response]:\n" + response + "\n", append=True)
    return response

def ask_for_llm_final_info(llm_prompt, model="gpt-4o"):
    prompt = "(1) Followings are protocol violations related to several MQTT messages.\n"
    prompt += llm_prompt["augment"] 
    prompt += f"(2) Followings are a sequence of MQTT requests sent by the client.\n {llm_prompt['request']}\n"
    prompt += f"(3) The processing of the above requests by each broker has the following differences:\n {llm_prompt['llm_broker_diff']}\n"
    prompt += f"(4) Now that you are an MQTT protocol expert, determine whether the client request violates the protocol violations listed in (1) based on the response differences.\n"
    prompt += f"Answer in such format: first gives the analysis process, starting with '# Analysis Process.'. Then gives the final conclusion, if there is an explicit violation, response with 'Protocol Violation Found!' or 'No violation!'\n"
    if model.startswith("gpt"):
        response = ask_for_llm_model_chatgpt(prompt, model)

    response = remove_empty_lines(response)
    llm_prompt["llm_final"] = response
    save_information_to_file("Step 2.\n"+ prompt + "LLM Response:\n" + response + "\n", append=True)
    return response

def filter_filename(seeds, filename):
    for seed in seeds:
        if seed in filename:
            print(f"{seed} vs {filename} matched!")
            return True
    print(f"{seed} vs {filename} not matched!")
    return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <file_with_paths.txt> <llm_output.txt>")
        sys.exit(1)
    
    paths_file_path = sys.argv[1]
    LOG_PATH = sys.argv[2]

    try:
        with open(paths_file_path, 'r') as file:
            files_list = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(f"Error: File '{paths_file_path}' not found.")
        sys.exit(1)


    target_ips = ["172.199.0.2", "172.199.0.3", "172.199.0.4", "172.199.0.5", "172.199.0.6", "172.199.0.7"]  # List of IP addresses to send packets to
    target_port = 1883  # Port number
   
    limited_number = 0
    for file_path in files_list:
        limited_number += 1
        packet_hex_strings = read_packet_hex_strings_from_file(file_path)
        print(f"Reading No_{limited_number}.{file_path} \n")
        llm_prompt = send_to_multiple_to_brokers(target_ips, target_port, packet_hex_strings)
        response1 = ask_for_llm_diff_info(file_path, llm_prompt, model="gpt-4o") 
        response2 = ask_for_llm_final_info(llm_prompt, model="gpt-4o")   
        print(response2, "\n")