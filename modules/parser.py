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



"""
Return a JSON structure

{ "url":"http",
  "method" : "GET",
  "params" : [{"key":"value","key":"?"} ],
  "data"   : ["users.username","users.password"]
}
"""
