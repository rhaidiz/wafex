#!/usr/local/bin/python3.5

"""
This module provides parsing methods
"""

import re
import config
import requests
import linecache
import json
from modules.logger import cprint


"""
Understands filesystem attacks on the message sequence chart.
msc_table: is the message sequence chart table
extended: is a JSON structure that extendes the msc_table for concretizing
            attacks
"""
def filesystem(msc_table,extended):
    cprint("Starting extend_trace_filesystem","D")
    entities = {"webapplication","filesystem","database","<webapplication>","<filesystem>","<database>"}
    fs = []
    for idx, row in enumerate(msc_table):
        tag = row[0]
        message = row[1]
        if message and len(message) == 3:
            sender = message[0]
            receiver = message[1]
            msg = message[2]
            # message is valid
            if(message[0] not in entities):
                cprint(message,"D")
                # message is a request:
                # - evil_file is a fileupload (without sqli)
                # - path_injection is a fileinclude
                if "evil_file" in msg and "sqli" not in msg:
                    # file upload, get the parameters
                    cprint(msg,"D")
                    p = re.search("([a-zA-Z]*)\.evil_file",msg)
                    if p != None:
                        entry = {"attack":5,"params":{p.group(1):"evil_file"}}
                        extended[tag] = entry
                        fs.append(["u",p.group(1)])
                elif "path_injection" in msg:
                    p = re.search("([a-zA-Z]*)\.path_injection",msg)
                    if p != None:
                        entry = {"attack":4,"params":{p.group(1):"?"}}
                        fs.append(["r",p.group(1)])
                elif "f_file(" in msg:
                    # there's a request that sends something function of file
                    p = re.findall("f_file\(([a-zA-Z]*)\)",msg)
                    fs.append(["e",p])
                    for idx2,row2 in enumerate(msc_table):
                        # when we find that f_file(?) is used, we should loop from the
                        # beginning until now and check where we should retrieve this
                        # file (which is completely different from SQLi)
                        tag2 = row2[0]
                        message2 = row2[1]
                        if message2 and len(message2) == 3 and idx2 < idx:
                            sender = message2[0]
                            receiver = message2[1]
                            msg = message2[2]
                            # message is valid
                            if(message2[0] not in entities):
                                for v in p:
                                    k_v = re.search("([a-zA-Z]*)\.htpwd",msg)
                                    entry = {"attack":4,"params":{k_v.group(1),v}}
                                    extended[tag2] = entry
                                    fs[idx2] = ["r",v]

                else:
                        if tag not in extended:
                            extended[tag] = {"attack":-1}
                            cprint("normal request","D")
                            fs.append(["n",0])
                    # this is a read attack
    cprint("filesystem matrix","D")
    cprint(fs,"D")
