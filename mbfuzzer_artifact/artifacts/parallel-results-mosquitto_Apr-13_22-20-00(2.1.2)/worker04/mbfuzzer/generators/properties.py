from packet import Packet
import random
import helper_functions.convert_format as cf 
import fuzzer.mutation as fm
import binascii
import globals as g 
import threading

class Properties(Packet):

    def conditionalAppend(self, whitelist, code, packet):
        if whitelist is None or code in whitelist:
            self.appendPayloadRandomly(packet)

    def __init__(self, whitelist = None):
        super().__init__()

        self.payload_format_indicator = ['01', [random.choice(['00', '01'])]]
        if fm.should_mutate("payload_format_indicator") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.payload_format_indicator, "integer")
            self.payload_format_indicator = mutated_field_list
        self.conditionalAppend(whitelist, 0x01, self.payload_format_indicator)

        self.message_expiry_interval = self.toBinaryData(0x02, 4, True) # ['02', ['97', '55', '92', '4d']]
        if fm.should_mutate("message_expiry_interval") == True: 
            mutated_field_list = fm.handle_property_list_mutate(self.message_expiry_interval, "integer")
            self.message_expiry_interval = mutated_field_list
        self.conditionalAppend(whitelist, 0x02, self.message_expiry_interval)

        self.content_type_length = random.randint(0, 30)
        self.content_type = self.toEncodedString(0x03, self.content_type_length)
        if fm.should_mutate("content_type") == True:        # ['03', '0001', ['7a']]
            mutated_field_list = fm.handle_property_list_mutate(self.content_type, "string")
            self.content_type = mutated_field_list
        self.conditionalAppend(whitelist, 0x03, self.content_type)

        self.response_topic_length = random.randint(0, 30)
        self.response_topic = self.toEncodedString(0x08, self.response_topic_length)
        if fm.should_mutate("response_topic") == True:      # ['03', '0001', ['7a']]
            mutated_field_list = fm.handle_property_list_mutate(self.response_topic, "string")
            self.response_topic = mutated_field_list
        self.conditionalAppend(whitelist, 0x08, self.response_topic)

        self.correlation_data_length = random.randint(0, 30)
        self.correlation_data = self.toBinaryData(0x09, self.correlation_data_length)
        if fm.should_mutate("correlation_data") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.correlation_data, "binary")
            self.correlation_data = mutated_field_list
        self.conditionalAppend(whitelist, 0x09, self.correlation_data)

        self.subscription_identifier_value = random.randint(0, 268435455)
        if fm.should_mutate("subscription_identifier") == True:
            sub_id_bytes = cf.int_to_bytes(self.subscription_identifier_value)
            mutated_bytes = fm.handle_int_mutate_up_downgrad_replace(sub_id_bytes)
            self.subscription_identifier_value = cf.bytes_to_int(mutated_bytes)
        self.subscription_identifier = "0b" + self.toVariableByte("%x" % self.subscription_identifier_value)    # 0bc2b2d447
        # print("subscription_identifier: ", self.subscription_identifier)
        self.conditionalAppend(whitelist, 0x0b, self.subscription_identifier)

        self.session_expiry_interval = self.toBinaryData(0x11, 4, True)
        if fm.should_mutate("session_expiry_interval") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.session_expiry_interval, "integer")
            self.session_expiry_interval = mutated_field_list
        # print("session_expiry_interval: ", self.session_expiry_interval)
        self.conditionalAppend(whitelist, 0x11, self.session_expiry_interval)

        self.assigned_client_identifier_length = random.randint(0, 30)
        self.assigned_client_identifier = self.toEncodedString(0x12, self.assigned_client_identifier_length)
        if fm.should_mutate("assigned_client_identifier") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.assigned_client_identifier, "string")
            self.assigned_client_identifier = mutated_field_list
        self.conditionalAppend(whitelist, 0x12, self.assigned_client_identifier)

        self.server_keepalive = self.toBinaryData(0x13, 2, True)
        if fm.should_mutate("server_keepalive") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.server_keepalive, "integer")
            self.server_keepalive = mutated_field_list
        self.conditionalAppend(whitelist, 0x13, self.server_keepalive)

        self.authentication_method_len = random.randint(0, 30)
        self.authentication_method = self.toEncodedString(0x15, self.authentication_method_len)
        if fm.should_mutate("authentication_method") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.authentication_method, "string")
            self.authentication_method = mutated_field_list
        self.conditionalAppend(whitelist, 0x15, self.authentication_method)

        self.authentication_data_len = random.randint(0, 30)
        self.authentication_data = self.toEncodedString(0x16, self.authentication_data_len) # ['16', '001e', ['35', ...]]
        if fm.should_mutate("authentication_data") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.authentication_data, "string")
            self.authentication_data = mutated_field_list
        self.conditionalAppend(whitelist, 0x16, self.authentication_data)

        self.request_problem_information = self.toBinaryData(0x17, 1, True, 1)  # ['17', ['01']]
        if fm.should_mutate("request_problem_information") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.request_problem_information, "integer")
            self.request_problem_information = mutated_field_list
        self.conditionalAppend(whitelist, 0x17, self.request_problem_information)

        self.will_delay_interval = self.toBinaryData(0x18, 4, True)
        if fm.should_mutate("will_delay_interval") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.will_delay_interval, "integer")
            self.will_delay_interval = mutated_field_list
        self.conditionalAppend(whitelist, 0x18, self.will_delay_interval)

        self.request_response_information = self.toBinaryData(0x19, 1, True, 1)
        if fm.should_mutate("request_response_information") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.request_response_information, "integer")
            self.request_response_information = mutated_field_list
        self.conditionalAppend(whitelist, 0x19, self.request_response_information)

        self.response_information_length = random.randint(1, 30)
        self.response_information = self.toEncodedString(0x1a, self.response_information_length)
        if fm.should_mutate("response_information") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.response_information, "string")
            self.response_information = mutated_field_list
        self.conditionalAppend(whitelist, 0x1a, self.response_information)

        self.server_reference_length = random.randint(1, 30)
        self.server_reference = self.toEncodedString(0x1c, self.server_reference_length)
        if fm.should_mutate("server_reference") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.server_reference, "string")
            self.server_reference = mutated_field_list
        self.conditionalAppend(whitelist, 0x1c, self.server_reference)

        self.reason_string_length = random.randint(1, 30)
        self.reason_string = self.toEncodedString(0x1f, self.reason_string_length)
        if fm.should_mutate("reason_string") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.reason_string, "string")
            self.reason_string = mutated_field_list
        self.conditionalAppend(whitelist, 0x1f, self.reason_string)

        self.receive_maximum = self.toBinaryData(0x21, 2, True, 8, 1)
        if fm.should_mutate("receive_maximum") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.receive_maximum, "integer")
            self.receive_maximum = mutated_field_list
        self.conditionalAppend(whitelist, 0x21, self.receive_maximum)

        self.topic_alias_maximum = self.toBinaryData(0x22, 2, True)
        if fm.should_mutate("topic_alias_maximum") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.topic_alias_maximum, "integer")
            self.topic_alias_maximum = mutated_field_list
        self.conditionalAppend(whitelist, 0x22, self.topic_alias_maximum)

        self.topic_alias = self.toBinaryData(0x23, 2, True)
        if fm.should_mutate("topic_alias") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.topic_alias, "integer")
            self.topic_alias = mutated_field_list

        if threading.current_thread().ident == g.Client_Fuzzing_Thread_ID and g.cur_client_dependency != None:
            if len(g.cur_client_dependency) == 2 and g.FIELD_TOPIC_ALIAS in g.cur_client_dependency["active"]["field"]:
                g.cur_client_dependency["passive"]["field"][g.FIELD_TOPIC_ALIAS] = self.topic_alias
            elif len(g.cur_client_dependency) == 1 and g.FIELD_TOPIC_ALIAS in g.cur_client_dependency["passive"]["field"]:
                self.topic_alias = g.cur_client_dependency["passive"]["field"][g.FIELD_TOPIC_ALIAS]
        elif threading.current_thread().ident == g.Broker_Fuzzing_Thread_ID and g.cur_broker_dependency != None:
            if len(g.cur_broker_dependency) == 2 and g.FIELD_TOPIC_ALIAS in g.cur_broker_dependency["active"]["field"]:
                g.cur_broker_dependency["passive"]["field"][g.FIELD_TOPIC_ALIAS] = self.topic_alias
            elif len(g.cur_broker_dependency) == 1 and g.FIELD_TOPIC_ALIAS in g.cur_broker_dependency["passive"]["field"]:
                self.topic_alias = g.cur_broker_dependency["passive"]["field"][g.FIELD_TOPIC_ALIAS]

        self.conditionalAppend(whitelist, 0x23, self.topic_alias)

        self.maximum_qos = self.toBinaryData(0x24, 1, True, 1)  #  ['24', ['00']] or  ['24', ['01']]
        if fm.should_mutate("maximum_qos") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.maximum_qos, "integer")
            self.maximum_qos = mutated_field_list
        self.conditionalAppend(whitelist, 0x24, self.maximum_qos)

        self.retain_available = self.toBinaryData(0x25, 1, True, 1)
        if fm.should_mutate("retain_available") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.retain_available, "integer")
            self.retain_available = mutated_field_list
        self.conditionalAppend(whitelist, 0x25, self.retain_available)

        self.user_property_name_length = random.randint(1, 30)
        self.user_property_value_length = random.randint(1, 30)
        self.user_property = self.toEncodedStringPair(0x26, self.user_property_name_length, self.user_property_value_length) # ['26', '0001', ['38'], '0002', ['39']
        if fm.should_mutate("user_property") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.user_property, "string_pair")
            self.user_property = mutated_field_list
        self.conditionalAppend(whitelist, 0x26, self.user_property)

        self.maximum_packet_size = self.toBinaryData(0x27, 4, True, 8, 1)
        if fm.should_mutate("maximum_packet_size") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.maximum_packet_size, "integer")
            self.maximum_packet_size = mutated_field_list
        self.conditionalAppend(whitelist, 0x27, self.maximum_packet_size)

        self.wildcard_subscription_available = self.toBinaryData(0x28, 1, True, 1)
        if fm.should_mutate("wildcard_subscription_available") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.wildcard_subscription_available, "integer")
            self.wildcard_subscription_available = mutated_field_list
        self.conditionalAppend(whitelist, 0x28, self.wildcard_subscription_available)

        self.subscription_identifiers_available = self.toBinaryData(0x29, 1, True, 1)
        if fm.should_mutate("subscription_identifiers_available") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.subscription_identifiers_available, "integer")
            self.subscription_identifiers_available = mutated_field_list
        self.conditionalAppend(whitelist, 0x29, self.subscription_identifiers_available)

        self.shared_subscription_available = self.toBinaryData(0x2a, 1, True, 1)
        if fm.should_mutate("shared_subscription_available") == True:
            mutated_field_list = fm.handle_property_list_mutate(self.shared_subscription_available, "integer")
            self.shared_subscription_available = mutated_field_list
        self.conditionalAppend(whitelist, 0x2a, self.shared_subscription_available)

        self.prependPayloadLength()