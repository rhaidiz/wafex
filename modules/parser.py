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
Takes as input an msc and returns one array with requests 
and responses in order of execution.
For each step, add the corresponding tag number.
[ (tag#,(actor1,actor2,message)), ... ]
"""
def msc(aat):
    cprint("starting MSC","D")
    msc = aat.replace(" ","")
    lines = msc.split("\n")
    result = []
    request_regexp = re.compile(r'(.*?)\*->\*(.*?):(?:.*?).http_request\((.*)\)\.tag([0-9]*)')
    response_regexp = re.compile(r'(.*?)\*->\*(.*?):http_response\((.*?)\)')
    line_num = 0
    tag = "tag"
    for line in lines:
        if line:
            cprint(line,"D")
            tmp_request = request_regexp.match(line)
            tmp_response = None
            #if not tmp_request: # not a request
            #    # search for a response
            #    tmp_response = response_regexp.match(line)
            if tmp_request:
                # we have found a request
                cprint("request found","D")
                cprint(tmp_request,"D")
                result.append((tag + tmp_request.group(4),(tmp_request.group(1),tmp_request.group(2),tmp_request.group(3))))
            else:
                tmp_response = response_regexp.match(line)
                if tmp_response:
                    # we have found a response
                    cprint("response found","D")
                    cprint(tmp_response,"D")
                    result.append((tag,(tmp_response.group(1),tmp_response.group(2),tmp_response.group(3))))
    if config.DEBUG:
        cprint(__name__ + " result","D")
        cprint(result,"D")
        cprint("################","D")
    return result




# --==[ SQL Injection ]==--
# 1: whenever I find a sqli somewhere, look for i -> webapp : tuple(of_the_same_sqli)
#    if found, data extraction is performed and thus inside the sqli array I'll have
#    and entry [a,idx] where idx is the line where the injection should be performed
# 2: if I don't perform a data extraction, a 0 should appear
# 3: sqli.lfi identifies a sql-injection for reading
# 4: sqli.evil_file identifies a sql-injection for writing
# 

# --==[ Filesystem ]==--
#TODO: TBA


# Matrix form:
# [ ['a',[( tag_where_to_exploit, [ parameters_to_exploit ])]],
#         ['n',0]
#         ['e',0] ]
# Where  a: attack
#        n: normal request
#        e: exploit
"""
Understands sql-injection attacks on the message sequence chart.
msc_table: is the message sequence chart table
extended: is a JSON structure that extendes the msc_table for concretizing
            attacks
"""
def sqli(msc_table,extended):
    cprint("Starting extend_trace_sqli","D")
    sqli = []
    injection_point = ""
    for idx, message in enumerate(msc_table):
        cprint(message,"D")
        tag = message[0]
        message = message[1]
        if message and len(message) == 3:
            # read message and check if it's a request and require an SQLi
            if (not message[0] == "webapplication") and "sqli" in message[len(message)-1] and not "tuple" in message[len(message)-1]:
                cprint("there is a sqli","D")
                cprint(message,"D")
                cprint("---------------","D")
                # now we should check what kind of sqli isa
                # is sqli is followed by evil_file, is a writing
                if( "sqli.evil_file" in message[len(message)-1] ):
                    entry = {"attack":2}
                    extended[tag] = entry
                    sqli.append(["w",0])
                # if is not a writing we check if sqli is followed by anything that starts with a lower-case letter
                elif( re.search('sqli\.[a-z]',message[len(message)-1]) != None ):
                    entry = {"attack":1}
                    extended[tag] = entry
                    sqli.append(["r",0])
                # otherwise is "standard" sqli
                else:
                    entry = {"attack":0}
                    extended[tag] = entry
                    sqli.append(["a",[]])
                injection_point = idx
            # we are exploiting a sqli, find the column that should be retrieved
            # .([a-z]*?).tuple
            elif "webapplication" in message[1] and "tuple" in message[len(message)-1] and "sqli" in message[len(message)-1]:
                #param_regexp = re.compile(r'(.*?).tuple\(')
                param_regexp = re.compile(r'\.?([a-zA-Z]*?)\.tuple')
                params = param_regexp.findall(message[len(message)-1])
                cprint("exploiting sqli here","D")
                cprint("Message:","D")
                cprint(message,"D")
                cprint("Params: ","D")
                cprint(params,"D")
                cprint(tag,"D")
                cprint("--------------------","D")
                # create a multiple array with params from different lines
                t = msc_table[injection_point][0]
                extended[t]["params"] = {tag:params}
                extended[tag] = {"attack": 6}
                sqli[injection_point][1].append((tag,params))
                sqli.append(["e",injection_point])
            else:
                if tag not in extended:
                    extended[tag] = {"attack":-1}
                    sqli.append(["n",0])
    cprint(sqli,"D")
    return sqli


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



"""
Return a JSON structure

{ "url":"http",
  "method" : "GET",
  "params" : [{"key":"value","key":"?"} ],
  "data"   : ["users.username","users.password"]
}
"""
