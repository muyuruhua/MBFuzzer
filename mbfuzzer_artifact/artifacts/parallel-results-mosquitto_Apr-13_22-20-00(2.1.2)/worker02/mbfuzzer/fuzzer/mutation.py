import binascii
import helper_functions.print_verbosity as pv
import helper_functions.convert_format as cf
import globals as g
import random
import threading
import copy


def flatten_and_concatenate(lst):
    copied_lst = copy.deepcopy(lst)  
    flattened_lst = lst + copied_lst 
    return flattened_lst

def should_mutate(field_name):
    probability = g.Field_Mutation_Scheduler.get_mutation_probability(field_name)
    results = random.random() <= probability
    if results == True:
        if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID:
            g.Client_Field_Mutation_Record[field_name] += 1
        elif threading.current_thread().ident == g.Broker_Fuzzing_Thread_ID:
            g.Broker_Field_Mutation_Record[field_name] += 1
    return results


# Delete some bytes from the payload
def handle_string_mutate_delete(payload):
    if len(payload) <= 2:
        return

    del_len = random.randint(1, len(payload))

    for d in range(del_len):
        del_from = random.randint(0, len(payload) - 1)
        payload = payload[:del_from] + payload[del_from + 1:]

    payload_bytes = payload.encode() if isinstance(payload, str) else payload
    pv.debug_print("Fuzzed payload now (deleted %d bytes): %s" % (del_len, binascii.hexlify(payload_bytes)))


def handle_int_mutate_bitflip(payload, start_bit, length):
    byte_value = int.from_bytes(payload, byteorder='little')

    for i in range(start_bit, start_bit + length):
        if random.random() < 0.50:
            byte_value ^= 1 << i 

    byte_value_len = length//4 
    mutated_payload = byte_value.to_bytes(byte_value_len, byteorder='little')
    pv.debug_print("Fuzzed payload now (bitflip): %s" % binascii.hexlify(mutated_payload))

    return mutated_payload

def handle_int_mutate_up_downgrad_replace(payload):

    payload_intval = int.from_bytes(payload, byteorder='little')
    max_value = 2**(len(payload) * 8) - 1

    opt = random.randint(0, 1)
    if opt == 0:
        mutation_amount = random.randint(-payload_intval, payload_intval)
        payload_intval += mutation_amount
        payload_intval = min(max(payload_intval, 0), max_value)
        payload = payload_intval.to_bytes(len(payload), byteorder='little')
        pv.debug_print("Fuzzed payload now (mutated integer add/decr random): %s" % binascii.hexlify(payload))

    else:
        if random.random() < 0.5: # only for test
            if len(payload) == 1:
                INTERESTING_SETS = g.INTERSTING_VALUES_8
            elif len(payload) > 1 and len(payload) < 4:
                INTERESTING_SETS = g.INTERSTING_VALUES_8 + g.INTERSTING_VALUES_16
            elif len(payload) >= 4:
                INTERESTING_SETS = g.INTERSTING_VALUES_8 + \
                    g.INTERSTING_VALUES_16 + g.INTERSTING_VALUES_32

            INTERESTING_VALUE = random.choice(INTERESTING_SETS)

            payload = INTERESTING_VALUE.to_bytes(len(payload), byteorder='little')

            pv.debug_print("Fuzzed payload now (mutated integer replace interesting): %s" % binascii.hexlify(payload))
        # Just a random one
        else:
            Random_value = random.randint(0, max_value)
            payload = Random_value.to_bytes(len(payload), byteorder='little')
            pv.debug_print("Fuzzed payload now (mutated integer replace random): %s" % binascii.hexlify(payload))
    return payload

def handle_string_mutate_del_insert_replace(payload):
    mutated_payload = payload
    mutation_type = random.randint(1, 3)
    payload_length = len(payload)
    if mutation_type == 1:
        if payload_length >= 1:
            insert_pos = random.randint(0, payload_length)

            if random.random() < 0.5:
                insert_value = random.choice(g.INTERESTING_STRING)
                mutated_payload = payload[:insert_pos] + insert_value + payload[insert_pos:]
            else:
                insert_len = random.randint(1, payload_length) 

                insert_value = random.getrandbits(insert_len * 8).to_bytes(insert_len, byteorder='little')
                mutated_payload = payload[:insert_pos] + insert_value + payload[insert_pos:]

            pv.debug_print("Fuzzed payload now (insert): %s" % (mutated_payload))

    elif mutation_type == 2:
        if payload_length >= 1:
            delete_pos = random.randint(0, payload_length - 1)
            delete_len = random.randint(1, min(payload_length - delete_pos, 10))
            mutated_payload = payload[:delete_pos] + payload[delete_pos + delete_len:]

            pv.debug_print("Fuzzed payload now (delete): %s" % (mutated_payload))

    elif mutation_type == 3:
        if payload_length >= 1:
            replace_pos = random.randint(0, payload_length - 1)

            if random.random() < 0.5:
                replace_value = random.choice(g.INTERESTING_STRING)
                mutated_payload = payload[:replace_pos] + \
                    replace_value + payload[replace_pos + 1:]
            else:
                replace_len = random.randint(1, payload_length - replace_pos)
                replace_value = random.getrandbits(replace_len * 8).to_bytes(replace_len, byteorder='little')
                mutated_payload = payload[:replace_pos] + \
                    replace_value + payload[replace_pos + replace_len:]

            pv.debug_print("Fuzzed payload now (replace): %s" % (mutated_payload))

    return mutated_payload


def handle_property_list_mutate(field_list, list_type):
    if list_type == "integer":
        field_key = field_list[0] 
        field_value_list = field_list[1]   

        if random.random() >= 0.20:
            field_value_bytes = cf.hex_list_to_bytes(field_value_list)
            mutated_value_bytes = handle_int_mutate_up_downgrad_replace(field_value_bytes)
            mutated_list = cf.bytes_to_hex_list(mutated_value_bytes)
            mutated_field_list = [field_key, mutated_list]
        else:
            mutated_field_list = flatten_and_concatenate(field_list)
    elif list_type == "string" or list_type == "binary":
        field_key = field_list[0] 
        field_value_length = field_list[1] 
        field_value_list = field_list[2] 

        if random.random() >= 0.20:
            field_value_bytes = cf.hex_list_to_bytes(field_value_list)
            mutated_value_bytes = handle_string_mutate_del_insert_replace(field_value_bytes)
            mutated_value_list = cf.bytes_to_hex_list(mutated_value_bytes)  
            mutated_value_length = cf.int_to_padded_hex_string(len(mutated_value_list), 4)
            mutated_field_list = [field_key, mutated_value_length, mutated_value_list]
        else:
            mutated_field_list = flatten_and_concatenate(field_list)
    elif list_type == "string_pair":
        field_key = field_list[0]
        field_value_list1 = field_list[2]
        field_value_list2 = field_list[4]
        if random.random() >= 0.20:
            field_value_bytes1 = cf.hex_list_to_bytes(field_value_list1)
            field_value_bytes2 = cf.hex_list_to_bytes(field_value_list2)
            mutated_value_bytes1 = handle_string_mutate_del_insert_replace(field_value_bytes1)
            mutated_value_bytes2 = handle_string_mutate_del_insert_replace(field_value_bytes2)
            mutated_value_list1 = cf.bytes_to_hex_list(mutated_value_bytes1)
            mutated_value_list2 = cf.bytes_to_hex_list(mutated_value_bytes2)
            mutated_value_len1 = cf.int_to_padded_hex_string(len(mutated_value_list1), 4)
            mutated_value_len2 = cf.int_to_padded_hex_string(len(mutated_value_list2), 4)
            mutated_field_list = [field_key, mutated_value_len1, mutated_value_list1, mutated_value_len2, mutated_value_list2]
        else:
            mutated_field_list = flatten_and_concatenate(field_list)

    return mutated_field_list

def handle_hex_mutate_bitflip(hex_payload, start_bit, length):
    payload = bytes.fromhex(hex_payload)

    assert len(payload) == 1, "Payload must be a single-byte represented as a hexadecimal string."

    byte_value = int.from_bytes(payload, byteorder='little')

    for i in range(start_bit, start_bit + length):
        if random.random() < 0.50:
            byte_value ^= 1 << i

    mutated_payload = byte_value.to_bytes(1, byteorder='little')
    mutated_hex_payload = binascii.hexlify(mutated_payload).decode('utf-8')
    return [mutated_hex_payload]

# Mutate some bytes in the payload
def handle_mutate_message(message):
    if isinstance(message, str):
        message = bytes.fromhex(message)
        
    maxlen = len(message) * g.FUZZING_INTENSITY

    mutate_len = random.randint(1, max(1, round(maxlen)))
    mutate_payload = random.getrandbits(8 * mutate_len).to_bytes(mutate_len, 'little')

    for p in mutate_payload:
        index = random.randint(0, len(message))
        message = message[:index] + p.to_bytes(1, 'little') + message[index + 1:] 

    pv.debug_print("Fuzzed payload now (mutated %d bytes): %s" % (mutate_len, binascii.hexlify(message)))

    return message

# Remove some bytes from the payload
def handle_delete_message(message):
    if isinstance(message, str):
        message = bytes.fromhex(message)

    if len(message) <= 2:
        return

    maxlen = len(message) * g.FUZZING_INTENSITY
    delete_len = random.randint(1, max(1, round(maxlen)))

    for d in range(delete_len):
        index = random.randint(0, len(message) - 1)
        message = message[:index] + message[index + 1:]

    pv.debug_print("Fuzzed payload now (deleted %d bytes): %s" % (delete_len, binascii.hexlify(message)))

    return message

# Inject some bytes into the payload
def handle_nonbof_message(message):
    if isinstance(message, str):
        message = bytes.fromhex(message)

    if len(message) >= g.MAXIMUM_PAYLOAD_LENGTH:
        return

    maxlen = len(message) * g.FUZZING_INTENSITY
    inject_len = random.randint(1, max(1, round(maxlen)))
    inject_payload = random.getrandbits(8 * inject_len).to_bytes(inject_len, 'little')  

    for p in inject_payload:
        index = random.randint(0, len(message))
        message = message[:index] + p.to_bytes(1, 'little') + message[index:] 

    pv.debug_print("Fuzzed payload now (injected %d bytes): %s" % (inject_len, binascii.hexlify(message)))
    
    return message

# Inject many bytes into the payload
# Default behavior is to inject between 1 and 10 times the length
# of the payload, up to a defined maximum payload length 
def handle_bof_message(message):
    if isinstance(message, str):
        message = bytes.fromhex(message)

    if len(message) >= g.MAXIMUM_PAYLOAD_LENGTH:
        return

    minlen = max(1, (1 + g.FUZZING_INTENSITY) * len(message))
    maxlen = max(minlen, 5 * (1 + g.FUZZING_INTENSITY) * len(message))
    inject_len = random.randint(round(minlen), round(maxlen))
    inject_payload = random.getrandbits(8 * inject_len).to_bytes(inject_len, 'little')
    
    for p in inject_payload:
        index = random.randint(0, len(message))
        message = message[:index] + p.to_bytes(1, 'little') + message[index:] 

    pv.debug_print("Fuzzed payload now (injected %d bytes): %s" % (inject_len, binascii.hexlify(message)))
    return message



def handle_message_mutation(message):
    MUTATION_METHODS = {
        1: handle_bof_message,
        2: handle_nonbof_message,
        3: handle_delete_message,
        4: handle_mutate_message,
    }

    mutation_count = 0
    current_message = message
    last_current_message = current_message
    at_least_once = False
    while mutation_count < g.MAX_MUTATIONS:
        mutation_count += 1
        if not at_least_once:
            random_method = random.randint(1, 4)
            current_message = MUTATION_METHODS[random_method](current_message)
            if current_message is None:
                current_message = last_current_message
                break
            else:
                last_current_message = current_message
            at_least_once = True
        else:
            if random.random() < g.MUTATION_PROBABILITY and current_message is not None:
                random_method = random.randint(1, 4)
                current_message = MUTATION_METHODS[random_method](current_message)
                if current_message is None:
                    current_message = last_current_message
                    break
                else:
                    last_current_message = current_message

    if isinstance(current_message, bytes):
        current_message = binascii.hexlify(current_message).decode("utf-8")
    return current_message




if __name__ == "__main__":
    data_val = cf.hex_list_to_integer(['00'])
    data_bytes = cf.int_to_bytes(data_val)
    payload = data_bytes
    print("Original payload: ", payload)
    dd = handle_int_mutate_bitflip(payload, 0, 8)
    print("mutate payload: ", dd)