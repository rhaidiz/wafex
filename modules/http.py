#!/usr/local/bin/python3.5

"""
This module executes an http request
"""

import requests
import config

from modules.logger import cprint
# parameters for configuring the requests maker:
# Requests group
# - basic authentication params
# - SSL verification: True, False, CA path
# - proxy
# - proxy-cred
# - sqlmap usage

def execute_request(s,request):
    url = request["url"]
    method = request["method"]
    try:
        params = request["params"]
    except KeyError:
        params = []
    try:
        cookies = request["cookies"]
    except KeyError:
        cookies = []
    #cookies = {'8c7a5a8dc980f43a35da380d188606dd': 'my-app/0.0.1'}

    cprint("Execute request","V")
    cprint(url,"V")
    cprint(method,"V")
    cprint(params,"V")
    cprint(cookies,"V")
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
            r = s.post(url,proxies=proxies, data = params, cookies=cookies,verify=False, auth=('regis','password'))
        else:
            r = s.post(url, data = params, verify=False, cookies=cookies,auth=('regis','password'))

    #r = requests.get(url, cookies=cookies, proxies=proxy, verify=False, auth=('regis','password'))
    cprint(r.text,"D")
    return r

"""
output format: { table { columns : [values]}}
"""
