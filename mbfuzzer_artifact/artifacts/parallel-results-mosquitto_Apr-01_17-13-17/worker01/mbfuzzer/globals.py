import type.LimitedSizeSortedDict as LD
import type.LimitedDict as LDD
import type.LimitedSizeList as LSL
import type.FieldMutationClass as FMC
import type.ConnectClass as CC
import hashlib
from collections import defaultdict
import type.DependencyQueue as DQ
import threading

# =============================================USER DEFINE VARIABLE=============================================


# Time limit (seconds)
TIME_LIMITE_SECONDS = 900

# Output Directory
FUZZING_OUTPUT_DIR = "/home/ckt/Documents/000_2026_test_dev/mbfuzzer_artifact/artifacts/parallel-results-mosquitto_Apr-01_17-13-17/worker01/outputs/"

# Broker IP and Port
BROKER_IP_1 = "172.199.0.11"
BROKER_PORT = 1883

BROKER_NAME_1 = "mosquitto-worker01-Apr-01_17-13-17"

# ================================================================================================================

DOCKER_CONTAINER_HOST = {BROKER_IP_1: BROKER_NAME_1}
DOCKER_CONTAINER_BROKER_HOST = {BROKER_IP_1: BROKER_NAME_1}
DOCKER_CONTAINER = [BROKER_NAME_1]

DOCKER_CONTAINER_PORT = {BROKER_NAME_1: BROKER_PORT}

# Definition: Message Type
MSG_TYPE_CONNECT = "CONNECT"
MSG_TYPE_CONNACK = "CONNACK"
MSG_TYPE_PUBLISH = "PUBLISH"
MSG_TYPE_PUBACK = "PUBACK"
MSG_TYPE_PUBREC = "PUBREC"
MSG_TYPE_PUBREL = "PUBREL"
MSG_TYPE_PUBCOMP = "PUBCOMP"
MSG_TYPE_SUBSCRIBE = "SUBSCRIBE"
MSG_TYPE_SUBACK = "SUBACK"
MSG_TYPE_UNSUBSCRIBE = "UNSUBSCRIBE"
MSG_TYPE_UNSUBACK = "UNSUBACK"
MSG_TYPE_PINGREQ = "PINGREQ"
MSG_TYPE_PINGRESP = "PINGRESP"
MSG_TYPE_DISCONNECT = "DISCONNECT"
MSG_TYPE_AUTH = "AUTH"
# MSG_TYPE_INVALID = "INVALID"

# Q-Learning parameters
ACTIONS = [
    MSG_TYPE_CONNECT, MSG_TYPE_CONNACK, MSG_TYPE_PUBLISH, MSG_TYPE_PUBACK, MSG_TYPE_PUBREC, MSG_TYPE_PUBREL, MSG_TYPE_PUBCOMP, MSG_TYPE_SUBSCRIBE, MSG_TYPE_SUBACK, MSG_TYPE_UNSUBSCRIBE, MSG_TYPE_UNSUBACK, MSG_TYPE_PINGREQ, MSG_TYPE_PINGRESP, MSG_TYPE_AUTH
]
N_STATES = 15  # the number of states (protocol states)
EPSILON = 0.9  # greedy police
ALPHA = 0.1  # learning rate
GAMMA = 0.9  # discount factor
protocol_version = 0
TAU = 0.5  # medium temperature parameter for the function "choose_next_action"

FUZZING_OUTPUT_CRASH_DIR = FUZZING_OUTPUT_DIR + "crashes/" 
FUZZING_OUTPUT_QUEUE_DIR = FUZZING_OUTPUT_DIR + "queue/" 
FUZZING_OUTPUT_DIFF_DIR = FUZZING_OUTPUT_DIR + "diffs/" 
FUZZING_OUTPUT_VALID_CON_DIR = FUZZING_OUTPUT_DIR + "valid_conn/"

SERVER_MODULE_HOST_OBJECT = {ip: None for ip in DOCKER_CONTAINER_HOST.keys()}


FUZZING_Client_SOCKET_TIMEOUT_USECS = 1000

FUZZING_NETWORK_RESPONSE_CORPUS = {} 
FUZZING_NETWORK_RESPONSE_LOG = {}

FUZZING_MAX_PLATEAU = 1024   
FUZZING_CLIENT_PLATEAU = 0   
FUZZING_BROKER_PLATEAU = 0   

CLIENT_SELECT_CORPUS_FLAG = False  
BROKER_SELECT_CORPUS_FLAG = False

BLOG_NUM = 0
CLOG_NUM = 0

FUZZING_CONNECT_MAX_PLATEAU = 512  
DUPLICATE_DIFF_CONNECT_NUM = 0       
PLATEAU_CONNECT_OBJECT = CC.ConnectClass()  
PLATEAU_CONNECT_OBJECT_DICT = {} 
VALID_CONNECT_NUM = 1

client_protocol_version = None
broker_protocol_version = 5
client_protocol_version_lock = threading.Lock()

# Differential testing
DifferenceNumber = 0
DIFF_MESSAGE_MISSING = 1
DIFF_MESSAGE_UNEXPECTED = 2
DIFF_MESSAGE_DIFFERENT = 3
DIFF_FIELD_MISSING = 4
DIFF_FIELD_UNEXPECTED = 5
DIFF_FIELD_DIFFERENT = 6

DIFFERENTIAL_RESULTS = [] 
DIFFERENTIAL_RESULTS_SET = set()  

TIME_WINDOWS_SIZE = 100  

diff_number = 0 
crash_number = 0  
crash_occurred = False
client_socket_error = False
FUZZING_START_TIME = 0  
FUZZING_REQUEST_COUNT = 0 

client_recv_disconnect = False 

broker_to_remove_times = {} 
remove_items_locks = {}
broker_send_and_wait_event = {} 

CLIENT_DIFF_OLD_RESULTS = False  
CLIENT_DIFF_OLD_RESULTS_NUM = defaultdict(int) 

FUZZING_INTENSITY = 0.1

# message queue size
REQUEST_QUEUE_SIZE = 100

client_request_queue = LD.LimitedSizeSortedDict(REQUEST_QUEUE_SIZE)  # queue for client send request, format: {timestamp: message_payload}
broker_request_queue = LD.LimitedSizeSortedDict(REQUEST_QUEUE_SIZE)
client_broker_request_queue_lock = threading.Lock()
client_request_queue_list = LSL.LimitedSizeList(REQUEST_QUEUE_SIZE)
broker_request_queue_list = LSL.LimitedSizeList(REQUEST_QUEUE_SIZE)
RemoteRetainMessageTopic = []
Lock_RemoteRetainMessageTopic = threading.Lock()
diff_seed_dict = {}

# Q-Learning
updated_pubmsg_hash = set() 
publish_request_queue = LDD.LimitedDict(max_size=10000) 
diff_pub_msg_queue = LDD.LimitedDict(max_size=1000)
diff_pub_msg_queue_lock = threading.Lock()

# Special State
STATE_CLIENT_INITIAL = hashlib.md5("CLIENT_INITIAL_STATE".encode()).hexdigest()
STATE_BRIDGE_STATE = hashlib.md5("BRIDGE_STATE".encode()).hexdigest()
STATE_BRIDGE_END_STATE = hashlib.md5("BRIDGE_END_STATE".encode()).hexdigest()
STATE_NONE = hashlib.md5("None".encode()).hexdigest()
STATE_PUBLISH_QOS0 = hashlib.md5("PUBLISH_NO_RESPONSE".encode()).hexdigest()

# Mutation
INTERSTING_VALUES_8 = [0, 1, 16, 32, 64, 100, 127]
INTERSTING_VALUES_16 = [128, 255, 256, 512, 1000, 1024, 4096, 32767]
INTERSTING_VALUES_32 = [32768, 65535, 65536, 100663045, 2147483647]

INTERESTING_STRING = [b"\x00", b"\xff", b"<", b"+", b"#", b"/"]

mqtt_fields = [
    # bits
    'message_type',
    'dup_flag',
    'qos_level',
    'retain',
    'username_flag',
    'password_flag',
    'will_retain',
    'will_qos',
    'will_flag',
    'clean_session_flag',
    'no_local',
    'retain_as_published',
    'retain_handling',
    'acknowledgement_flags',
    'connect_flags',
    'fixed_header_flags',
    'subscription_options',
    # int
    'keep_alive',
    'assigned_client_identifier',
    'server_keepalive',
    'packet_identifier',
    'return_code',
    'reason_code',
    'payload_format_indicator',
    'message_expiry_interval',
    'subscription_identifier',
    'session_expiry_interval',
    'request_problem_information',
    'will_delay_interval',
    'receive_maximum',
    'topic_alias_maximum',
    'topic_alias',
    'maximum_qos',
    'retain_available',
    'maximum_packet_size',
    'wildcard_subscription_available',
    'subscription_identifiers_available',
    'shared_subscription_available',
    # string
    'authentication_method',
    'authentication_data',
    'protocol_name',
    'protocol_version',
    'topic',
    'client_id',
    'username',
    'password',
    'will_topic',
    'will_payload',
    'message',
    'content_type',
    'response_topic',
    'auth_method',
    'response_information',
    'request_response_information',
    'server_reference',
    'reason_string',
    'user_property',
    # binary
    'correlation_data',
    'auth_data',
]
mutation_initial_probability = 0.1
mutation_learning_rate = 0.1
Field_Mutation_Scheduler = FMC.FieldMutationScheduler(fields=mqtt_fields, initial_probability=mutation_initial_probability, learning_rate=mutation_learning_rate)

Client_Field_Mutation_Record = defaultdict(int)
Broker_Field_Mutation_Record = defaultdict(int)

MAXIMUM_PAYLOAD_LENGTH = 10000
MAX_MUTATIONS = 10
MUTATION_PROBABILITY = 0.5

# Dependency
FIELD_TOPIC = 1
FIELD_SHARED_TOPIC = 2
FIELD_CLIENT_ID = 3
FIELD_TOPIC_ALIAS = 4

Dependency_Subscribe_1 = {  
    "active":  {"flag": "client", "mtype": MSG_TYPE_SUBSCRIBE, "field": {FIELD_TOPIC: None} },
    "passive": {"flag": "both", "mtype": MSG_TYPE_PUBLISH, "field": {FIELD_TOPIC: None} }
}
Dependency_Subscribe_2 = {  
    "active":  {"flag": "client", "mtype": MSG_TYPE_SUBSCRIBE, "field": {FIELD_SHARED_TOPIC: None} },
    "passive": {"flag": "both", "mtype": MSG_TYPE_PUBLISH, "field": {FIELD_SHARED_TOPIC: None} }
}
Dependency_Subscribe_3 = { 
    "active":  {"flag": "client", "mtype": MSG_TYPE_SUBSCRIBE, "field": {FIELD_TOPIC: None} },
    "passive": {"flag": "client", "mtype": MSG_TYPE_UNSUBSCRIBE, "field": {FIELD_TOPIC: None} }
}
Dependency_Publish_1 = { 
    "active":  {"flag": "both", "mtype": MSG_TYPE_PUBLISH, "field": {FIELD_TOPIC: None}, "persistent": True },
    "passive": {"flag": "client", "mtype": MSG_TYPE_SUBSCRIBE, "field": {FIELD_TOPIC: None}, "persistent": True }
}
Dependency_Publish_2 = {  
    "active":  {"flag": "both", "mtype": MSG_TYPE_PUBLISH, "field": {FIELD_TOPIC_ALIAS: None} },
    "passive": {"flag": "both", "mtype": MSG_TYPE_PUBLISH, "field": {FIELD_TOPIC_ALIAS: None} }
}
Dependency_Connect_1 = {  
    "active":  {"flag": "client", "mtype": MSG_TYPE_CONNECT, "field": {FIELD_CLIENT_ID: None}, "persistent": True },
    "passive": {"flag": "client", "mtype": MSG_TYPE_CONNECT, "field": {FIELD_CLIENT_ID: None}, "persistent": True }
}

all_client_dependency = {
    MSG_TYPE_CONNECT: [Dependency_Connect_1],
    MSG_TYPE_SUBSCRIBE: [Dependency_Subscribe_1, Dependency_Subscribe_2, Dependency_Subscribe_3],
    MSG_TYPE_PUBLISH: [Dependency_Publish_1, Dependency_Publish_2]
}
all_broker_dependency = {
    MSG_TYPE_PUBLISH: [Dependency_Publish_1, Dependency_Publish_2]
}

dependency_event = DQ.DependencyQueue() 
dependency_event_lock = threading.Lock()

cur_client_dependency = None    
cur_broker_dependency = None

Client_Fuzzing_Thread_ID = None
Broker_Fuzzing_Thread_ID = None

#

CLIENT_SENT_MESSAGE = {
    MSG_TYPE_CONNECT: 0,
    MSG_TYPE_CONNACK: 0,
    MSG_TYPE_PUBLISH: 0,
    MSG_TYPE_PUBACK: 0,
    MSG_TYPE_PUBREC: 0,
    MSG_TYPE_PUBREL: 0,
    MSG_TYPE_PUBCOMP: 0,
    MSG_TYPE_SUBSCRIBE: 0,
    MSG_TYPE_SUBACK: 0,
    MSG_TYPE_UNSUBSCRIBE: 0,
    MSG_TYPE_UNSUBACK: 0,
    MSG_TYPE_PINGREQ: 0,
    MSG_TYPE_PINGRESP: 0,
    MSG_TYPE_DISCONNECT: 0,
    MSG_TYPE_AUTH: 0
}

BROKER_SENT_MESSAGE = {
    MSG_TYPE_CONNECT: 0,
    MSG_TYPE_CONNACK: 0,
    MSG_TYPE_PUBLISH: 0,
    MSG_TYPE_PUBACK: 0,
    MSG_TYPE_PUBREC: 0,
    MSG_TYPE_PUBREL: 0,
    MSG_TYPE_PUBCOMP: 0,
    MSG_TYPE_SUBSCRIBE: 0,
    MSG_TYPE_SUBACK: 0,
    MSG_TYPE_UNSUBSCRIBE: 0,
    MSG_TYPE_UNSUBACK: 0,
    MSG_TYPE_PINGREQ: 0,
    MSG_TYPE_PINGRESP: 0,
    MSG_TYPE_DISCONNECT: 0,
    MSG_TYPE_AUTH: 0
}

# Debug parameters
DEBUG_FLAG_CLIENT_MSG_SENDING = False
TEST_CASE_FILE = "diff-4-client.raw"
VERBOSITY = 1   # debug level