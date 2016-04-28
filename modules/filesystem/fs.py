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
import modules.wrapper.wfuzz as fuzzer

from modules.logger import logger


"""
Understands filesystem attacks on the message sequence chart.
msc_table: is the message sequence chart table
extended: is a JSON structure that extendes the msc_table for concretizing
            attacks
"""
def filesystem(msc_table,extended):
    logger.debug("Starting extend_trace_filesystem")
    fs = []
    logger.debug(extended)

    # regexp
    r_write_no_sqli  = re.compile("([a-zA-Z]*?)\.s\.evil_file(?:.*?)")
    r_path_injection = re.compile("([a-zA-Z]*?)\.s\.path_injection(?:.*?)")
    r_file           = re.compile("(?:[a-z]*?)\.s\.e_file\(([a-z]*?)\)")

    for idx, row in enumerate(msc_table):
        tag = row[0]
        step = row[1]
        sender = step[0]
        receiver = step[1]
        msg = step[2]

        if sender not in config.receiver_entities:
            # is a message from the intruder
            debugMsg = "processing {}".format(msg)
            logger.debug(debugMsg)
            params = r_write_no_sqli.search(msg)
            if "sqli" not in msg and params:
                # is a malicious file-write (upload)
                entry = {"attack":5,"params":{params.group(1):"evil_file"}}
                extended[tag] = entry
                logger.debug("1")
            else:
                params = r_path_injection.search(msg)
                if "sqli" not in msg and params:
                    # is a file-include with payload path_injection
                    entry = {"attack":4,"params":{params.group(1):"?"}}
                    extended[tag] = entry
                    logger.debug("2 {}".format(params))
                else:
                    payload = r_file.search(msg)
                    if payload:
                        # I've found the intruder is sending somthing
                        # function of file(). So I'm looking where I've
                        # seen the file being send and I mark it as an
                        # attack
                        logger.debug("3")
                        for tag,attack in extended:
                            for k,v in attack["params"]:
                                if payload in v:
                                    extended[tag]["attack"] = 4
                    else:
                        logger.debug("4")
                        if tag not in extended and tag != "tag":
                            # this is a normal request
                            tmp = ["?" if idx%2 else k for idx,k in enumerate(msg.split(".s."))]
                            params = dict(itertools.zip_longest(*[iter(tmp)] * 2, fillvalue=""))
                            debugMsg = "Normal request: {} params {}".format(tag, params)
                            logger.debug(debugMsg)

                            extended[tag] = {"attack":-1,"params":params}
                            logger.debug("normal request")
                            fs.append(["n",0])



def execute_wfuzz(fuzzer_details):
    # set default parameters
    fuzzer.set_param("--basic","regis:password")
    fuzzer.set_param("-o","json")
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
    if method == "GET":
        get_params = ""
        for k,v in params.items():
            if v == "?":
                v = "FUZZ"
            get_params = get_params + k + "=" + v + "&"
    #TODO: missing the POST method branch
    get_url = url+"?"+get_params
    out = fuzzer.run_wfuzz(get_url)
    return out

"""
Given a filename, this function returns a list of payloads that needs to be tested for performin
a directory traversal attack.
"""
def payloadgenerator(fname,depth=6):
    dots = "../"
    return [dots*i+fname for i in range(depth) ]
