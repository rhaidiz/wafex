#!/usr/local/bin/python3.5

"""
This module provides parsing methods
"""
import os
import re
import json
import config
import requests
import linecache
import itertools
import modules.utils as utils
import modules.wrapper.wfuzz as fuzzer

from modules.logger import logger


"""
Understands filesystem attacks on the message sequence chart.
msc_table: is the message sequence chart table
extended: is a JSON structure that extendes the msc_table for concretizing
            attacks
"""
def filesystem(msc_table,extended):
    logger.info("Looking for file-system attacks")
    fs = []

    # regexp
    r_write_no_sqli  = re.compile("([a-zA-Z]*?)\.s\.evil_file(?:.*?)")
    r_path_injection = re.compile("([a-zA-Z]*?)\.s\.path_injection(?:.*?)")
    r_file           = re.compile("([a-z]*?)\.s\.e_file\((.*?)\)")
    r_evil_file      = re.compile("^evil_file")
    r_e_file         = re.compile("e_file\((.*)\)")

    for idx, row in enumerate(msc_table):
        tag = row[0]
        step = row[1]
        sender = step[0]
        receiver = step[1]
        msg = step[2]
        entry = None

        if sender not in config.receiver_entities:
            # since in presence of a query the attacker always perform
            # a SQLi, it might be that he wants to perform an upload file
            # but he also need a SQLi bypass in order to proceed. So we give
            # a low priority to SQLi bypass and we check it again for other
            # attacks.
            if extended[tag]["attack"] != 10 and extended[tag]["attack"] != -1:
                continue
            # is a message from the intruder
            debugMsg = "processing {}".format(msg)
            logger.debug(debugMsg)
            params = r_write_no_sqli.search(msg)
            if params:
                # is a malicious file-write (upload)
                #entry = {"attack":5,"params":{params.group(1):"evil_file"}}
                debugMsg = "Unrestricted file upload {}".format(tag)
                logger.debug(debugMsg)

                params = utils.__get_parameters(msg)
                entry = { "attack" : 5, "params" : params }

                extended[tag]["attack"] = 5
            else:
                if r_evil_file.match(msg):
                    debugMsg = "Exploiting evil_file {}".format(tag)
                    logger.debug(debugMsg)

                    params = utils.__get_parameters(msg)
                    entry = { "attack" : 9, "params" : params }
                    extended[tag]["attack"] = 9

                # inj_point = r_path_injection.search(msg)
                # if "evil_file" not in msg and inj_point:
                #     # is a file-include with payload path_injection
                #     #entry = { "attack" : 4, "params" : { params.group(1) : "?" } }
                #     params = utils.__get_parameters(msg)
                #     extended[tag]["attack"] = 4
                #     extended[tag]["inj_point"] = inj_point.group(1)
                # else:
                #     # The intruder is sending something
                #     # function of file(). Find where
                #     # the file-name was previously used and, if we
                #     # marked the action as normal request (-1), change
                #     # it as file inclusion (4)
                payload = r_file.search(msg)
                current_attack_number = extended[tag]["attack"]
                if payload and current_attack_number == -1:
                    for _tag in extended:
                        attack = extended[_tag]
                        for k,v in attack["params"].items():
                            if _tag != tag and payload.group(2) in v and extended[_tag]["attack"] == -1:
                                extended[_tag]["attack"] = 4

                                debugMsg = "File inclusion vulnerability {}".format(tag)
                                logger.debug(debugMsg)

                    params = utils.__get_parameters(msg)
                    extended[tag]["attack"] = 7
                    extended[tag]["inj_point"] = {payload.group(1):payload.group(2)}

                    debugMsg = "Exploit file extracted {}".format(tag)
                    logger.debug(debugMsg)
                else:
                    if tag not in extended and tag != "tag":
                        # this is a normal request
                        params = utils.__get_parameters(msg)
                        entry = { "attack" : -1, "params" : params }
                        extended[tag]["attack"] = -1

                        debugMsg = "Normal request: {} params {}".format(tag, params)
                        logger.debug(debugMsg)
        else:
            # we are in the receiving part
            msg_result = msg.split(",")[1]
            payload = r_e_file.search(msg_result)
            # check if something function of file is sent back to the intruder
            if payload:
                for _tag in extended:
                    attack = extended[_tag]
                    for k,v in attack["params"].items():
                        if _tag != tag and payload.group(1) in v and extended[_tag]["attack"] == -1:
                            
                            debugMsg = "File inclusion vulnerability {}".format(_tag)
                            logger.debug(debugMsg)
                            
                            extended[_tag]["attack"] = 4
                            extended[_tag]["read"] = payload.group(1)




def execute_wfuzz(fuzzer_details):
    # set default parameters
    fuzzer.set_param("--basic","regis:password")
    fuzzer.set_param("-o","json")
    if fuzzer_details["ss"] != None:
        fuzzer.set_param("--ss",fuzzer_details["ss"])
    # we need to write a file with the payload to pass to wfuzz
    f = open("wfuzz_payloads","w")
    for p in fuzzer_details["payloads"]:
        f.write(p+"\n")
    f.close()
    payloads_path = os.path.join(os.getcwd(),"wfuzz_payloads")
    fuzzer.set_param("-w",payloads_path)
    url = fuzzer_details["url"]
    method = fuzzer_details["method"]
    params = fuzzer_details["params"]
    get_params = ""
    if method == "GET":
        for k,v in params.items():
            if v == "?":
                v = "FUZZ"
            get_params = get_params + k + "=" + v + "&"
        #TODO: missing the POST method branch
    get_url = url+"?"+get_params
    out = fuzzer.run_wfuzz(get_url)
    return out



def save_extracted_file(name,text):
    filepath = os.path.join(config.WFAST_EXTRACTED_FILES_DIR,name)
    try:
        f = open(filepath,"w")
        f.write(text)
    except Exception as e:
        criticalMsg = "Error {}\n in saving the file {}, aborting execution!".format(e, filepath)
        logger.critical(criticalMsg)
        exit(0)
    f.close()
    return filepath

"""
Given a filename, this function returns a list of payloads that needs to be tested for performin
a directory traversal attack.
"""
def payloadgenerator(fname,depth=6):
    dots = "../"
    return [dots*i+fname for i in range(depth) ]
