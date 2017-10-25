#!/usr/local/bin/python3.5

"""
This module executes an http request
"""

import config
import requests

from modules.logger import logger
# parameters for configuring the requests maker:
# Requests group
# - basic authentication params
# - SSL verification: True, False, CA path
# - proxy
# - proxy-cred
# - sqlmap usage

# request = {url, method, params, cookies, files}

def execute_request(s,request):
    url = request["url"]
    if "method" in request:
        method = request["method"]
    else:
        method = "GET"
    try:
        logger.debug(request["params"])
        for k,v in request["params"].items():
            if v == "?":
                inputMsg = "Provide value for: {}\n".format(k)
                new_value = input(inputMsg)
                request["params"][k] = new_value
        params = request["params"]
    except KeyError:
        params = []
    try:
        cookies = request["cookies"]
    except KeyError:
        cookies = []
    #cookies = {'8c7a5a8dc980f43a35da380d188606dd': 'my-app/0.0.1'}
    try:
        files = request["files"]
    except KeyError:
        files = {}


    logger.debug("Execute request")
    debugMsg = "url: {}".format(url)
    logger.debug(debugMsg)
    debugMsg = "method: {}".format(method)
    logger.debug(debugMsg)
    debugMsg = "params: {}".format(params)
    logger.debug(debugMsg)
    debugMsg = "cookies: {}".format(cookies)
    logger.debug(debugMsg)
    debugMsg = "files: {}".format(files)
    logger.debug(debugMsg)
    #url = 'https://157.27.244.25/chained'
    if config.proxy != None:
        proxies = {"http" : "http://"+config.proxy,"https":"https://"+config.proxy}
    r = None
    if method == "GET":
        if config.proxy != None:
            r = s.get(url,proxies=proxies,params=params, cookies=cookies, verify=False, auth=('regis','password'))
        else:
            r = s.get(url,params=params, verify=False, cookies=cookies,auth=('regis','password'))
    else:
        if config.proxy != None:
            r = s.post(url,proxies=proxies, data = params, files=files, cookies=cookies,verify=False, auth=('regis','password'))
        else:
            r = s.post(url, data = params, verify=False, files=files, cookies=cookies,auth=('regis','password'))

    logger.debug(r.text)
    return r

"""
output format: { table { columns : [values]}}
"""
