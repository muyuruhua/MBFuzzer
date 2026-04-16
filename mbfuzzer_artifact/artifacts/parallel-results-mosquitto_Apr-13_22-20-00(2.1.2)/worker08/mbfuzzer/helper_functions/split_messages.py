def decode_remaining_length(data):
    multiplier = 1
    value = 0
    index = 0
    while True:
        if index >= len(data):
            break
        encoded_byte = data[index]  # FIXME: IndexError: index out of range?
        index += 1
        value += (encoded_byte & 127) * multiplier
        if (encoded_byte & 128) == 0:
            break
        multiplier *= 128
    return value, index

def contains_multiple_mqtt_messages(data):
    if type(data) == str:
        data = bytes.fromhex(data)

    index = 0
    data_length = len(data)
    
    while index < data_length:
        if index + 1 >= data_length:
            return False
        
        fixed_header = data[index]
        index += 1
        
        remaining_length, length_bytes = decode_remaining_length(data[index:])
        index += length_bytes
        
        index += remaining_length
        
        if index < data_length:
            return True
        
    return False

def split_mqtt_messages(data):
    if type(data) == str:
        data = bytes.fromhex(data)

    index = 0
    data_length = len(data)
    messages = []
    
    while index < data_length:
        if index + 1 >= data_length:
            break
        
        start_index = index
        
        fixed_header = data[index]
        index += 1
        
        remaining_length, length_bytes = decode_remaining_length(data[index:])  # BUG: IndexError: index out of range
        index += length_bytes
        
        total_length = 1 + length_bytes + remaining_length
        
        message = data[start_index: start_index + total_length]
        messages.append(message.hex())
        
        index = start_index + total_length
        
    return messages

if __name__ == "__main__":
    hex_data = "3155000c72657461696e5f746f706963007373737373737373737373737373737373737373737373737373737373737373737373737373737373737373737373787831313131313131313131313131323331323331313131200008746f7069633132330031313131313131313131313131323331323331313131120006746f706963320031323331323331313131130007746f706963323300313233313233313131"# 4 publish
    hex_data = "523478395a614c4465366733764942747a526d79900832cf020202020202" # reserved
    data = bytes.fromhex(hex_data)

    print("Contains multiple MQTT messages:", contains_multiple_mqtt_messages(data))

    messages = split_mqtt_messages(data)
    for i, msg in enumerate(messages):
        print(f"Message {i + 1}: {msg}")
