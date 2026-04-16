import hashlib
import json

class ConnectClass:
    def __init__(self):
        self.version = None
        self.connect_flags = None
        self.client_id = False
        self.will_topic = False
        self.will_payload = False
        # self.username = False
        # self.password = False
        # will property
        self.will_delay_inteval = False # 18
        self.payload_format_indicator = False   # 01
        # self.message_expiry_interval = False    # 02
        # self.content_type = False   # 03
        self.response_topic = False  # 08
        # self.correlation_data = False   # 09

    def hash(self):
        attr_values = {attr_name: getattr(self, attr_name) 
                       for attr_name in dir(self) 
                       if not attr_name.startswith("__") and not callable(getattr(self, attr_name)) and getattr(self, attr_name) is not None}

        json_str = json.dumps(attr_values, sort_keys=True)
        md5_hash = hashlib.md5(json_str.encode('utf-8')).hexdigest()
        return md5_hash

if __name__ == "__main__":
    connect = ConnectClass()
    print(connect.hash())