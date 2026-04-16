
import os
from contextlib import contextmanager
from openai import OpenAI
import augment_prompt as ap

MSG_TYPE = ["DISCONNECT", "CONNECT", "PUBLISH", "UNSUBSCRIBE", "SUBSCRIBE", "PINGREQ", "CONNACK", "PUBACK", "PUBREC","PUBREL", "PUBCOMP", "UNSUBACK", "SUBACK", "PINGRESP", "AUTH"]

@contextmanager
def use_proxy(http_proxy, https_proxy):
    original_http_proxy = os.environ.get("http_proxy")
    original_https_proxy = os.environ.get("https_proxy")
    
    os.environ["http_proxy"] = http_proxy
    os.environ["https_proxy"] = https_proxy
    
    try:
        yield
    finally:
        if original_http_proxy is not None:
            os.environ["http_proxy"] = original_http_proxy
        else:
            del os.environ["http_proxy"]
        
        if original_https_proxy is not None:
            os.environ["https_proxy"] = original_https_proxy
        else:
            del os.environ["https_proxy"]

def get_chat_response(api_key, message, model="gpt-3.5-turbo"):
    client = OpenAI(api_key=api_key)
    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": message,
            }
        ],
        model=model,
    )
    return chat_completion.choices[0].message.content

def hex_to_utf8_or_mark_if_invalid(hex_str):
    try:
        utf8_str = bytes.fromhex(hex_str).decode('utf-8')
    except UnicodeDecodeError:
        utf8_str = hex_str + " (Note: non-UTF-8 encoding)"

    if utf8_str == '':
        return 'NULL'
    return utf8_str

def hex_to_binary(hex_str):
    decimal_value = int(hex_str, 16)
    binary_str = bin(decimal_value)[2:]
    return f"0b{binary_str.zfill(8)}" 

def transform_message_format(log_entry):
    message_type = log_entry.get('message_type')
    fields = log_entry.get('fields', {})
    fields_count = log_entry.get('fields_count', {})

    message_parts = []
    Properties = []
    Comments = None

    for key, value in fields.items():
        if 'user property' in key:
            value = hex_to_utf8_or_mark_if_invalid(value)
            Properties.append(f"{key}={value}")
        elif key == 'response topic':
            response_topic_utf8 = hex_to_utf8_or_mark_if_invalid(value)
            Properties.append(f"Response Topic={response_topic_utf8}")
        elif key == 'reason string':
            reason_string_utf8 = hex_to_utf8_or_mark_if_invalid(value)
            Properties.append(f"Reason String={reason_string_utf8}")
        elif key == 'authentication method':
            auth_method_utf8 = hex_to_utf8_or_mark_if_invalid(value)
            Properties.append(f"Authentication Method={auth_method_utf8}")
        elif key == 'content type':
            content_type_utf8 = hex_to_utf8_or_mark_if_invalid(value)
            Properties.append(f"Content Type={content_type_utf8}")
        elif key == 'server reference':
            server_ref_utf8 = hex_to_utf8_or_mark_if_invalid(value)
            Properties.append(f"Server Reference={server_ref_utf8}")
        elif key == 'assigned client identifier':
            client_id_utf8 = hex_to_utf8_or_mark_if_invalid(value)
            Properties.append(f"Assigned Client Identifier={client_id_utf8}")
        elif key == 'message expiry interval':
            expiry_interval = int(value, 16)
            Properties.append(f"Message Expiry Interval={expiry_interval}")
        elif key == 'session expiry interval':
            expiry_interval = int(value, 16)
            Properties.append(f"Session Expiry Interval={expiry_interval}")
        elif key == 'server keep alive':
            keep_alive_value = int(value, 16)
            Properties.append(f"Server Keep Alive={keep_alive_value}")
        elif key == 'will delay interval':
            delay_interval = int(value, 16)
            Properties.append(f"Will Delay Interval={delay_interval}")
        elif key == 'receive maximum':
            receive_max = int(value, 16)
            Properties.append(f"Receive Maximum={receive_max}")
        elif key == 'topic alias maximum':
            topic_alias_max = int(value, 16)
            Properties.append(f"Topic Alias Maximum={topic_alias_max}")
        elif key == 'topic alias':
            topic_alias = int(value, 16)
            Properties.append(f"Topic Alias={topic_alias}")
        elif key == 'maximum qos':
            max_qos = int(value, 16)
            Properties.append(f"Maximum QoS={max_qos}")
        elif key == 'subscription identifier':
            sub_id = int(value, 16)
            Properties.append(f"Subscription Identifier={sub_id}")
        elif key == 'maximum packet size':
            max_packet_size = int(value, 16)
            Properties.append(f"Maximum Packet Size={max_packet_size}")
        elif key == 'shared subscription available':
            shared_sub_avail = int(value, 16)
            Properties.append(f"Shared Subscription Available={shared_sub_avail}")
        elif key == 'subscription identifier available':
            sub_id_avail = int(value, 16)
            Properties.append(f"Subscription Identifier Available={sub_id_avail}")
        elif key == 'wildcard subscription available':
            wildcard_sub_avail = int(value, 16)
            Properties.append(f"Wildcard Subscription Available={wildcard_sub_avail}")
        elif key == 'retain available':
            retain_avail = int(value, 16)
            Properties.append(f"Retain Available={retain_avail}")
        elif key == 'request response information':
            req_resp_info = int(value, 16)
            Properties.append(f"Request Response Information={req_resp_info}")
        elif key == 'request problem information':
            req_prob_info = int(value, 16)
            Properties.append(f"Request Problem Information={req_prob_info}")
        elif key == 'payload format indicator':
            payload_format = int(value, 16)
            Properties.append(f"Payload Format Indicator={payload_format}")
        elif key == 'packet identifier':
            message_parts.append(f"Message Identifier={int(value, 16)}")
        elif key == 'client id':
            client_id_utf8 = hex_to_utf8_or_mark_if_invalid(value)
            message_parts.append(f"Client ID={client_id_utf8}")
        elif key == 'protocol name':
            protocol_name_utf8 = hex_to_utf8_or_mark_if_invalid(value)
            message_parts.append(f"Protocol Name={protocol_name_utf8}")
        elif key.startswith('subscription options'):
            value = ['0x' + hex_str.zfill(2) for hex_str in value]
            message_parts.append(f"Subscription Options={value}")
        elif key == 'username':
            username_utf8 = hex_to_utf8_or_mark_if_invalid(value)
            message_parts.append(f"Username={username_utf8}")
        elif key == 'topic':
            topics_utf8 = [hex_to_utf8_or_mark_if_invalid(t) for t in value]
            message_parts.append(f"topic={topics_utf8}")
        elif key == 'topic name':
            topic_name_utf8 = hex_to_utf8_or_mark_if_invalid(value)
            message_parts.append(f"Topic Name={topic_name_utf8}")
        elif key == 'message':
            message_utf8 = hex_to_utf8_or_mark_if_invalid(value)
            message_parts.append(f"Message={message_utf8}")
        elif key == 'will topic':
            will_topic_utf8 = hex_to_utf8_or_mark_if_invalid(value)
            message_parts.append(f"Will Topic={will_topic_utf8}")
        elif key == 'will message':
            will_message_utf8 = hex_to_utf8_or_mark_if_invalid(value)
            message_parts.append(f"Will Message={will_message_utf8}")
        elif key == 'keep alive':
            keep_alive_value = int(value, 16)
            message_parts.append(f"Keep Alive={keep_alive_value}")
        elif key == 'reason code':
            if isinstance(value, list):
                value = [f"0x{element}" for element in value]
                message_parts.append(f"Reason Code={value}")
            else:
                if len(value) > 0:
                    message_parts.append(f"Reason Code=0x{value}")
                else:
                    message_parts.append(f"Reason Code=NULL")
        elif key == 'fixed header':
            message_parts.append(f"Fixed Header=0x{value}")
        elif key == 'acknowledge flags':
            message_parts.append(f"Acknowledge Flags=0x{value}")
        elif key == 'connect flags':
            message_parts.append(f"Connect Flags=0x{value}")
        
        else:
            if key in ['message']:
                message_parts.append(f"{key}={value[:10]}")
            else:
                message_parts.append(f"{key}={value}")

    if fields_count:
        Comments = ', including' + ','.join([f" {k} {v} times".format(k=k, v=v) for k, v in fields_count.items()]) + '.'
    
    message_parts.append(f"Properties={Properties}")

    if Comments:
        return f'{message_type}: [' + ', '.join(message_parts) + ']' + Comments
    return f'{message_type}: [' + ', '.join(message_parts) + ']'

def store_LLM_prompt(LLM_PROMPT_pre, brokers_name):
    protocol_version = 5
    MATCH_MSG_TYPE = []
    LLM_AUGMENT = ""
    LLM_PROMPT_res = {}

    for item in LLM_PROMPT_pre["request"]:
        mtype = ""
        for msg_type in MSG_TYPE:
            if msg_type in item:
                mtype = msg_type
                break
        
        if mtype in MATCH_MSG_TYPE:
            continue
        else:
            MATCH_MSG_TYPE.append(mtype)
        
        if ("version=05" not in item) and (msg_type == "CONNECT"):
            protocol_version = 4

        if protocol_version == 5 and ap.Version5.get(mtype) is not None:
            LLM_AUGMENT += f"  Message {mtype} has following relevant violation definitions:"
            LLM_AUGMENT += f"{ap.Version5[mtype]}\n"
        elif protocol_version == 4 and ap.Version311.get(mtype) is not None:
            LLM_AUGMENT += f"  Message {mtype} has following relevant violation definitions:"
            LLM_AUGMENT += f"{ap.Version311[mtype]}\n"
    LLM_PROMPT_res["augment"] = LLM_AUGMENT

    LLM_PROMPT_REQUEST = ""
    index = 1
    for request_item in LLM_PROMPT_pre['request']:
        LLM_PROMPT_REQUEST += f"  Req_{index}. {request_item}\n"
        index += 1
    LLM_PROMPT_res["request"] = LLM_PROMPT_REQUEST 

    LLVM_PROMPT_RESPONSE = "Server received responses are as follows.\n"
    for broker_name, response_list in LLM_PROMPT_pre['response'].items():
        LLVM_PROMPT_RESPONSE += f" {broker_name}:\n"
        index = 1
        for response_item in response_list:
            LLVM_PROMPT_RESPONSE += f"  Resp_{index}. {response_item}\n"
            index += 1
    LLM_PROMPT_res["response"] = LLVM_PROMPT_RESPONSE 

    return LLM_PROMPT_res


def construct_LLM_prompt(LLM_PROMPT_pre, brokers_name):
    protocol_version = 5

    # Followings are the descriptions of MQTT message:
    MATCH_MSG_TYPE = []

    LLM_PROMPT_REQUEST = "Part 1. Followings are the protocol violations in specifications.\n"
    for item in LLM_PROMPT_pre["request"]:
        mtype = ""
        for msg_type in MSG_TYPE:
            # print(msg_type, " vs ", item)
            if msg_type in item:
                mtype = msg_type
                break
        
        if mtype in MATCH_MSG_TYPE:
            continue
        else:
            MATCH_MSG_TYPE.append(mtype)
        
        if "version=05" not in item:
            protocol_version = 4

        if protocol_version == 5 and ap.Version5.get(mtype) is not None:
            LLM_PROMPT_REQUEST += f"  Message {mtype} has following relevant violation definitions:"
            LLM_PROMPT_REQUEST += f"{ap.Version5[mtype]}\n"
        elif protocol_version == 4 and ap.Version311.get(mtype) is not None:
            LLM_PROMPT_REQUEST += f"  Message {mtype} has following relevant violation definitions:"
            LLM_PROMPT_REQUEST += f"{ap.Version311[mtype]}\n"

    LLM_PROMPT_REQUEST += f"Part 2. Following are the communication history with {len(brokers_name)} MQTT brokers ({', '.join(brokers_name.values())}).\n"
    LLM_PROMPT_REQUEST += "Client transmited requests are as follows. \n"
    index = 1
    for request_item in LLM_PROMPT_pre['request']:
        LLM_PROMPT_REQUEST += f"  Req_{index}. {request_item}\n"
        index += 1
    
    LLVM_PROMPT_RESPONSE = "Server received responses are as follows.\n"
    for broker_name, response_list in LLM_PROMPT_pre['response'].items():
        LLVM_PROMPT_RESPONSE += f" {broker_name}:\n"
        index = 1
        for response_item in response_list:
            LLVM_PROMPT_RESPONSE += f"  Resp_{index}. {response_item}\n"
            index += 1
    
    LLM_PROMPT_QUESTION = "Please analyze whether there is a protocol violation in the client transmited request strictly based on the protocol violation defined in Part 1, combined with the feedback provided in the server received response in Part 2.\n"
    LLM_PROMPT_QUESTION += "If it doesn't match any description listed in Part 1, please answer \"No inconsistency or uncertainty.\""
    LLM_PROMPT_QUESTION += "The format of the answer is as follows.\n"
    LLM_PROMPT_QUESTION += "* No inconsistency or uncertainty. or * The request violates the content of specifications: xxxxx in Part 1, because xxxxx."
    LLM_PROMPT = LLM_PROMPT_REQUEST + LLVM_PROMPT_RESPONSE + LLM_PROMPT_QUESTION

    print(LLM_PROMPT)

    return LLM_PROMPT


if __name__ == '__main__':
    log_entry = {
        'message_type': 'SUBSCRIBE',
        'fields': {
            'fixed header': '82',
            'subscription options': ['25', '29'],
            'packet identifier': '8b4a',
            'user property key': '436b34304d4b697a57394664',
            'user property value': '4a46504e79543971475372794d55394d55316b7151366a39',
            'topic': ['5732617a6948335875547a', '58']
        },
        'fields_count': {'fixed header': 2, 'topic': 3}
    }

    converted_message = transform_message_format(log_entry)
    print(converted_message)