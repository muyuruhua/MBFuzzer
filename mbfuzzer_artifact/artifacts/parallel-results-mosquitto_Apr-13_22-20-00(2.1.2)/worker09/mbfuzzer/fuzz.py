import sys
import fuzzer.fuzzing_engine as fe
import helper_functions.directory_operation as do
import fuzzer.q_learning as QLearning
import globals as g
import signal
import time
import os
import fuzzer.server_module as server_module
import fuzzer.retain_recv_module as retain_recv_module


def handle_exit(signum, frame):
    print("Received Ctrl+C signal. Exiting...")
    do.dump_fuzzing_info_log(GLOBAL_Q_MODEL) 
    os._exit(0)

def main():
    global GLOBAL_Q_MODEL
    # Set up signal handler
    signal.signal(signal.SIGINT, handle_exit)

    # Create fuzzing directory 
    do.create_initial_fuzzing_directory()

    Q_Model = QLearning.QLearningTable()
    GLOBAL_Q_MODEL = Q_Model
    
    cacheBroker = retain_recv_module.CacheBroker(port=1885)
    cacheBroker.start()

    g.FUZZING_START_TIME = time.time()
    # Start mqtt broker fuzzers
    broker = server_module.MQTTBroker(port=1884, MessageModel = Q_Model)
    broker.start()

    while broker.check_fuzzing_bridge_status() == False:
        print(f"Initial waiting for brokers (will be soon) {broker.client_sessions.keys()}")
        time.sleep(3)

    while_start_time = g.FUZZING_START_TIME

    # Run client fuzzing loop
    while True:
        fe.single_fuzzing_engine_client(Q_Model) 
        if g.DEBUG_FLAG_CLIENT_MSG_SENDING == True:
            break
        
        cur_time = time.time()
        elapsed_time = cur_time - while_start_time
        if elapsed_time >= 60:
            while_start_time = cur_time
            do.dump_fuzzing_info_log(Q_Model)
    
    print("Fuzzing loop finished.")
    do.dump_fuzzing_info_log(Q_Model)


if __name__ == "__main__":
    main()
