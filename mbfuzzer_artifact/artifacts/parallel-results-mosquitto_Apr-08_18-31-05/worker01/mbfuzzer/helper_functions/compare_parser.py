
def compare_g_fields(parser1,parser2,parser1_name,parser2_name,diff_info):    #paser1: paser.g_field (type: dict), paser2: paser.g_field
    """compare two parser's g_fields (including fields and values), and save the difference to diff_info

    Args:
        parser1 (object): parser1 of response message (may be None)
        parser2 (object): parser2 of response message
        parser1_name (str): parser1 name
        parser2_name (str): parser2 name
        diff_info (json): store the difference 

    Returns:
        _type_: _description_
    """
    Difference = False

    # if one of the parser is None, means no response received, save the difference to diff_info
    if (parser1 is None and parser2 is not None):
        diff_info["response"].setdefault(key, {})
        diff_info["response"].setdefault("have", []).append(parser2_name)
        diff_info["response"].setdefault("no", []).append(parser1_name)
        # diff_info.append(f"{parser1_name} NO response!\n")
        return True
    if (parser1 is not None and parser2 is None):
        diff_info["response"].setdefault(key, {})
        diff_info["response"].setdefault("have", []).append(parser1_name)
        diff_info["response"].setdefault("no", []).append(parser2_name)
        # diff_info.append(f"{parser2_name} NO response!\n")
        return True

    # if both parsers are not None, compare the g_fields
    parser1_G_fields = parser1.G_fields
    parser2_G_fields = parser2.G_fields

    for key, value1 in parser1_G_fields.items():
        if key not in parser2_G_fields:
            diff_info.setdefault("fields", {})
            diff_info["fields"].setdefault(key, {})
            diff_info["fields"][key].setdefault("no", []).append(parser2_name)
            diff_info["fields"][key].setdefault("have", []).append(parser1_name)
            Difference = True
        else:
            value2 = parser2_G_fields[key]
            if value1 != value2:
                diff_info.setdefault("fields", {})
                diff_info["fields"].setdefault(key, {})
                diff_info["fields"][key].setdefault("values", {})
                diff_info["fields"][key]["values"].setdefault(value2, []).append(parser2_name)
                diff_info["fields"][key]["values"].setdefault(value1, []).append(parser1_name)
                Difference = True
            del parser2_G_fields[key]

    for key, value2 in parser2_G_fields.items():
        diff_info.setdefault("fields", {})
        diff_info["fields"].setdefault(key, {})
        diff_info["fields"][key].setdefault("no", []).append(parser1_name)
        diff_info["fields"][key].setdefault("have", []).append(parser2_name)
        Difference = True

    return Difference

# similar to compare_g_fields, but this function only used to compare the fields of h_fields, rather than the values
def compare_h_fields(parser1,parser2,parser1_name,parser2_name,diff_info):
    Difference = False
    
    if (parser1 is None and parser2 is not None):
        diff_info["response"].setdefault(key, {})
        diff_info["response"].setdefault("have", []).append(parser2_name)
        diff_info["response"].setdefault("no", []).append(parser1_name)
        # diff_info.append(f"{parser1_name} NO response!\n")
        return True
    if (parser1 is not None and parser2 is None):
        diff_info["response"].setdefault(key, {})
        diff_info["response"].setdefault("have", []).append(parser1_name)
        diff_info["response"].setdefault("no", []).append(parser2_name)
        # diff_info.append(f"{parser2_name} NO response!\n")
        return True

    keys1 = set(parser1.H_fields.keys())
    keys2 = set(parser2.H_fields.keys())
    
    if keys1 == keys2:
        return Difference
    else:
        extra_keys1 = keys1 - keys2
        extra_keys2 = keys2 - keys1
        
        if extra_keys1:
            for key in extra_keys1:
                diff_info.setdefault("fields", {})
                diff_info["fields"].setdefault(key, {})
                diff_info["fields"][key].setdefault("no", []).append(parser2_name)
                diff_info["fields"][key].setdefault("have", []).append(parser1_name)
                Difference = True
        if extra_keys2:
            for key in extra_keys2:
                diff_info.setdefault("fields", {})
                diff_info["fields"].setdefault(key, {})
                diff_info["fields"][key].setdefault("no", []).append(parser1_name)
                diff_info["fields"][key].setdefault("have", []).append(parser2_name)
                Difference = True
        
        return Difference


# recursively removes duplicate elements from a JSON data structure, particularly focusing on lists.
def deduplicate_json(json_data):
    if isinstance(json_data, dict):
        new_dict = {}
        for key, value in json_data.items():
            new_dict[key] = deduplicate_json(value)
        return new_dict
    elif isinstance(json_data, list):
        new_list = []
        for item in json_data:
            new_list.append(deduplicate_json(item))
        return list(set(new_list)) 
    else:
        return json_data