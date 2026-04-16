import sys
import os
import re

def parse_file(file_path, special_content = None):
    broker_raw_list = []
    client_raw_list = []
    both_raw_list = []

    pattern = re.compile(r'.*file_path:\s(.*\.raw).*')

    with open(file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                file_path = match.group(1)
                if '-broker.raw' in file_path and file_path not in broker_raw_list:
                    broker_raw_list.append(file_path)
                elif '-client.raw' in file_path and file_path not in client_raw_list:
                    if special_content is not None and line.find(special_content) != -1:
                        client_raw_list.append(file_path)
                    elif special_content is None:
                        client_raw_list.append(file_path)
                elif '-both.raw' in file_path and file_path not in both_raw_list:
                    both_raw_list.append(file_path)

    return broker_raw_list, client_raw_list, both_raw_list

def save_list_to_file(file_list, file_name):
    with open(file_name, 'w') as file:
        for item in file_list:
            file.write(f"{item}\n")

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print(f"File not found: {file_path}")
        sys.exit(1)

    broker_raw_list, client_raw_list, both_raw_list = parse_file(file_path, "{Message")

    save_list_to_file(client_raw_list, 'raw_list.txt')
    print(f"Done! broker_raw_list: {len(broker_raw_list)}, client_raw_list: {len(client_raw_list)}, both_raw_list: {len(both_raw_list)}")

if __name__ == "__main__":
    main()