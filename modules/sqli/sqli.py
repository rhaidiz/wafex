
#!/usr/local/bin/python3.5

"""
This module provides sql-injection extension
"""
import re
import config
import requests
import linecache
import json
from modules.logger import cprint

# --==[ SQL Injection ]==--
# 1: whenever I find a sqli somewhere, look for i -> webapp : tuple(of_the_same_sqli)
#    if found, data extraction is performed and thus inside the sqli array I'll have
#    and entry [a,idx] where idx is the line where the injection should be performed
# 2: if I don't perform a data extraction, a 0 should appear
# 3: sqli.lfi identifies a sql-injection for reading
# 4: sqli.evil_file identifies a sql-injection for writing
# 


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


