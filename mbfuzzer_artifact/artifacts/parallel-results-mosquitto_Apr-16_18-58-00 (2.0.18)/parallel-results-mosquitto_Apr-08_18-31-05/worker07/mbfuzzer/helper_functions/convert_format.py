
def bytes_to_hex_string(data):
    hex_string = ''.join(['{:02x}'.format(byte) for byte in data])
    return hex_string


def hex_string_to_int(hex_string):
    return int(hex_string, 16)

def hex_string_to_bytes(data):
    return bytes.fromhex(data)

def int_to_hex_string(integer, prefix='0x'):
    hex_str = f"{prefix}{integer:02x}"
    return hex_str[2:]

def int_to_padded_hex_string(integer, total_length=4):
    unpadded_hex_string = hex(integer)[2:]
    while len(unpadded_hex_string) < total_length:
        unpadded_hex_string = '0' + unpadded_hex_string
    return unpadded_hex_string

def int_to_bytes(integer):
    return integer.to_bytes((integer.bit_length() + 7) // 8, byteorder='little')

def bytes_to_int(byte_str):
    return int.from_bytes(byte_str, byteorder='little')


def hex_list_to_integer(hex_list):
    integer_value = int(''.join(hex_list), 16)
    return integer_value

def bytes_to_hex_list(byte_value):
    hex_string = byte_value.hex()
    hex_list = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    return hex_list



def integer_to_hex_list(integer_value):
    hex_string = hex(integer_value)[2:]
    hex_list = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    return hex_list

def bytes_to_hex_list(byte_data):
    hex_str = byte_data.hex() 
    return [hex_str[i:i+2] for i in range(0, len(hex_str), 2)] 

def hex_list_to_bytes(hex_list):
    hex_str = ''.join(hex_list) 
    return bytes.fromhex(hex_str) 


if __name__ == "__main__":
    data = b''  
    hex_string = bytes_to_hex_string(data)
    print(hex_string) 
