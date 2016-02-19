#!/usr/local/bin/python3.5

"""
This module provides parsing methods
"""

import re
import config
import requests
import linecache
import json

from modules.logger import logger


"""
Understands filesystem attacks on the message sequence chart.
msc_table: is the message sequence chart table
extended: is a JSON structure that extendes the msc_table for concretizing
            attacks
"""
def filesystem(msc_table,extended):
    logger.debug("Starting extend_trace_filesystem")
    entities = {"webapplication","filesystem","database","<webapplication>","<filesystem>","<database>"}
    fs = []
    for idx, row in enumerate(msc_table):
        tag = row[0]
        message = row[1]
        sender = message[0]
        receiver = message[1]
        msg = message[2]
        if message and len(message) == 3:
            # message is a request
            if(sender not in entities):
                logger.debug(message)
                # message is a request:
                # - evil_file is a fileupload (without sqli)
                # - path_injection is a fileinclude
                if "evil_file" in msg and "sqli" not in msg:
                    # file upload, get the parameters
                    logger.debug(msg)
                    p = re.search("([a-zA-Z]*)\.evil_file",msg)
                    if p != None:
                        entry = {"attack":5,"params":{p.group(1):"evil_file"}}
                        extended[tag] = entry
                        fs.append(["u",p.group(1)])
                # this is an indefined path injection, access a not specified file
                # in the filesystem
                elif "path_injection" in msg:
                    p = re.search("([a-zA-Z]*)\.path_injection",msg)
                    if p != None:
                        entry = {"attack":4,"params":{p.group(1):"?"}}
                        extended[tag] = entry
                        fs.append(["r",p.group(1)])
                elif "f_file(" in msg:
                    # there's a request that sends something function of file
                    abfilename = re.findall("f_file\(([a-zA-Z]*)\)",msg)
                    fs.append(["e",abfilename])
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
                            if(message2[0] not in entities and not "sqli" in msg ):
                                for v in abfilename:
                                    k_v = re.search("([a-zA-Z]*)\."+abfilename,msg)
                                    entry = {"attack":4,"params":{k_v.group(1),v}}
                                    extended[tag2] = entry
                                    fs[idx2] = ["r",v]

                else:
                        if tag not in extended:
                            extended[tag] = {"attack":-1}
                            logger.debug("normal request")
                            fs.append(["n",0])
            else:
                # check eveytime there is a message from webapplication to
                # filesystem right alter a message sent from the intruder to webapp
                # if that is the case, possible path traversal
                if sender == "webapplication" and receiver == "<i>":
                    prev_row = msc_table[idx-1]
                    prev_tag = prev_row[0]
                    prev_message = prev_row[1]
                    prev_msg = prev_message[2]
                    logger.debug("qui")
                    logger.debug(msg)
                    read_file_regexp = re.search("f_file\((.*)\)",msg)
                    if read_file_regexp != None:
                        payload = read_file_regexp.group(1)
                        if payload in prev_msg:
                            logger.debug("we have a possible traversal in ..")
                            logger.debug(prev_tag)

