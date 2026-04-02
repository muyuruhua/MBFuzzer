import sys
sys.path.append("parsers/")

from parsers.parse_initializer import ParseInitializer
import helper_functions.determine_protocol_version as hpv
import helper_functions.print_verbosity as pv
import globals as g
import helper_functions.compare_parser as hcp
import json

# Handle the network response -- log the request if 
# the response was unique.
# A response is unique if its G field has never been seen before.
def handle_network_response(recv):
    if len(recv) == 0:
        return

    if g.protocol_version == 0:
        g.protocol_version = hpv.determine_protocol_version(recv.hex())
        
    index = 0
    while index < len(recv.hex()):
        try:
            parser = ParseInitializer(recv.hex()[index:], g.protocol_version)

            # Log G fields
            G_fields = str(parser.parser.G_fields)
            # G_fields = str(parser.parser.G_fields) + str(parser.parser.H_fields)
            if G_fields not in g.network_response_log.keys():
                g.network_response_log[G_fields] = g.payload
                pv.normal_print("Found new network response (%d found)" % len(g.network_response_log.keys()))

            index +=  2 * (parser.parser.remainingLengthToInteger()) + 2 + len(parser.parser.remaining_length)

        # If the parser throws a ValueError, chances are that the payload
        # is malformed. In that case, we skip the current byte and hope for 
        # the best.
        except ValueError:
            index += 2


def difftest(recvs):
    DifferenceFlag_GField = False
    DifferenceFlag_HField = False
    Differential_Results = {}

    dict_parser = {}    # key: "Broker1_Client", value: parser object
    dict_parser_g_fields_hash = {}  # key: "Broker1_Client", value: hash of g_fields
    dict_parser_h_fields_hash = {}  # key: "Broker1_Client", value: hash of h_fields
    # step1. 
    # transform the response message into a parser object and 
    # then get the hash values of G_fields and H_fields in the parser object, 
    # and next store the above two results in a dictionary

    for key, value in recvs.items():
        if len(value) == 0 and dict_parser.get(key) is None:
            dict_parser[key] = None # no response, no parser object, thus using None
            continue

        if g.protocol_version == 0:
            g.protocol_version = hpv.determine_protocol_version(value.hex())
        index = 0
        while index < len(value.hex()):
            try:
                parser = ParseInitializer(value.hex()[index:], g.protocol_version)
                if dict_parser.get(key) is None:
                    dict_parser[key] = parser.parser    # store parser object
                    dict_parser_g_fields_hash[key], dict_parser_h_fields_hash[key] = parser.parser.retDiffTestingRespHash() # store hash of g_fields and h_fields
                index +=  2 * (parser.parser.remainingLengthToInteger()) + 2 + len(parser.parser.remaining_length)
            except ValueError:
                index += 2

    dict_classified_G_hash = {} # key: hash, value: ["Broker1_Client", "Broker2_Client"]
    # step2.
    # classify the parser object based on the hash of G_fields, i.e., figure out which brokers have the same G_fields and which ones are different

    for key, value in dict_parser_g_fields_hash.items():    # key: "Broker1_Client", value: hash
        if value not in dict_classified_G_hash:
            dict_classified_G_hash[value] = []
        dict_classified_G_hash[value].append(key)   # store the broker name in the list of the same hash value

    # if length of hash beyond 1, then analyze the difference of G_Fields
    if len(dict_classified_G_hash.keys()) > 1:
        DifferenceFlag_GField = True
        # Found difference
        for i in range(len(dict_classified_G_hash.keys())):
            hash1 = list(dict_classified_G_hash.keys())[i]
            parser1_name = dict_classified_G_hash[hash1][0]
            parser1 = dict_parser[parser1_name] 

            if i == len(dict_classified_G_hash.keys()) - 1:
                break

            for j in range(i+1, len(dict_classified_G_hash.keys())):
                hash2 = list(dict_classified_G_hash.keys())[j]
                parser2_name = dict_classified_G_hash[hash2][0]
                parser2 = dict_parser[parser2_name]

                hcp.compare_g_fields(parser1, parser2, parser1_name, parser2_name,Differential_Results)


    # step3
    # classify the parser object based on the hash of H_fields, i.e., figure out which brokers have the same H_fields and which ones are different
    # we only consider the key of H_fields
    dict_classified_H_hash = {}
    for key, value in dict_parser_h_fields_hash.items():
        if value not in dict_classified_H_hash:
            dict_classified_H_hash[value] = []
        dict_classified_H_hash[value].append(key)
    if len(dict_classified_H_hash.keys()) > 1:
        DifferenceFlag_HField = True
        # Found difference
        for i in range(len(dict_classified_H_hash.keys())):
            hash1 = list(dict_classified_H_hash.keys())[i]
            parser1_name = dict_classified_H_hash[hash1][0] 
            parser1 = dict_parser[parser1_name]  

            if i == len(dict_classified_H_hash.keys()) - 1:
                break

            for j in range(i+1, len(dict_classified_H_hash.keys())):
                hash2 = list(dict_classified_H_hash.keys())[j]
                parser2_name = dict_classified_H_hash[hash2][0]
                parser2 = dict_parser[parser2_name]

                # compare the H_fields of parser1 and parser2, save the difference to Differential_Results
                hcp.compare_h_fields(parser1, parser2, parser1_name, parser2_name,Differential_Results)

    # step4: clean data
    if DifferenceFlag_GField == True or DifferenceFlag_HField == True:
        pv.normal_print(f"Found new ({len(g.DIFFERENTIAL_RESULTS)} found)  network response difference")
    elif DifferenceFlag_GField == False and DifferenceFlag_HField == False:
        # pv.normal_print("No new network response difference")
        pass
    # deduplicate the Differential_Results (json formats)
    Differential_Results = hcp.deduplicate_json(Differential_Results)
    print(json.dumps(Differential_Results, indent=2, sort_keys=True))


if __name__ == "__main__":
    recvs = {
        "Broker1_Client": bytes.fromhex("320f0006746f7069633100313233313233"),
        "Broker2_Client": bytes.fromhex("340f0006746f7069633100313233313233"),
        "Broker3_Client": bytes.fromhex("300f0006746f7069633100313233313233"),
    }
    print("recvs: ", recvs)
    difftest(recvs)

    

