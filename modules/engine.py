#!/usr/local/bin/python3.5

"""
This module executes a trace
"""


import re
import config
import requests
import linecache
import parser
import modules.wrapper.sqlmap as sqlmap
import json
import threading
import itertools
import atexit
import modules.filesystem.fs 
import modules.sqli.sqli

from modules.logger import cprint
# disable warnings when making unverified HTTPS requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from os import listdir
from os.path import isfile, join, expanduser, dirname, realpath
from modules.sqli.sqli import sqlmap_parse_data_extracted
from modules.sqli.sqli import sqli_init
from modules.sqli.sqli import execute_sqlmap
from modules.sqli.sqli import execute_bypass


# global request
s = None

# global attack domain
attack_domain = ""
    
# specific for executing sqlmap
data_to_extract = []

def exitcleanup():
    print("exiting "+__name__)

# takes an attack trace and an extension matrix, and execute the attack
def execute_attack(msc_table,concretization_json,file_aslanpp):
    global s
    global attack_domain
    cprint("Executing the attack trace")


    atexit.register(exitcleanup)

    # general fields for sperforming an HTTP request
    url = None
    method = None
    params = None
    mapping = None
    abstract_param_to_real = None

    # sqlmap output
    sqlmap_output = None
    
    # request session object for performing subsequent HTTP requests
    s = requests.Session()
        
    # current response
    response = None

    # load the concretization file
    with open(config.concretization,"r") as data_file:
         concretization_data = json.load(data_file)
    attack_domain = concretization_data["domain"]

    __got_cookie = False

    # loop the msc_table, the main execution loop
    for idx, message in enumerate(msc_table):
        
        if "<i" in message[1][0]:
            # intruder step
            tag = message[0]
            m = message[1]
            concretization_details = concretization_json[tag]

            attack = concretization_details["attack"]
            params = None
            try:
                params = concretization_details["params"]
            except KeyError:
                pass

            # if we have the keep-cookie option, we make a first empty request to
            # get the initial set-cookie
            # TODO: request creation should be improved considering also the 
            # parameters and the cookies
            if config.keep_cookie and not __got_cookie:
               #msc_table[
               cprint("executing first request for getting cookie","D")
               first_request = {}
               first_request["url"] = concretization_data[tag]["url"]
               first_request["method"] = concretization_data[tag]["method"]
               r = __execute_request(first_request)
               s.cookies.clear()
               config.cookies = r.cookies
               __got_cookie = True


            # continue?
            cprint(message[1])
            c = __ask_yes_no("Executing step, continue?")
            if not c:
                exit(0)

            # SQL-injection filesystem READ
            if attack == 1:
                cprint(" SQLI Filesystem read attack!",color="y")
                _init = sqli_init(message,concretization_details,concretization_data,idx)
                execute_sqlmap(_init)
                # extracted files can be found in ~/.sqlmap/output/<attacked_domani>/files/
                # list extracted file content
                #__list_extracted_files()
                continue
            
            # SQL-injection filesystem WRITE
            if attack == 2:
                _init = sqli_init(message,concretization_details,concretization_data,idx)
                execute_sqlmap(_init)
                continue


            # SQL-injection 
            if attack == 0:
                # data extraction 
                if params != None:
                   cprint("Data extraction attack!",color="y") 
                   # data extraction, execute sqlmap
                   _init = sqli_init(message,concretization_details,concretization_data,idx)
                   # for the execution we need (url,method,params,data_to_extract)
                   # data_to_extract => table.column
                   # sqlmap_output = execute_sqlmap(url,method,params,data_to_extract)
                   output = execute_sqlmap(_init)
                   sqlmap_output = sqlmap_parse_data_extracted(output)
                   cprint(sqlmap_output,"D")
                   if not sqlmap_output:
                       cprint("No data extracted from the database","W")
                       exit()
                # authentication bypass
                else:
                   cprint("Authentication bypass attack!",color="y") 
                   tag = message[0]
                   req = {}
                   req["url"] = concretization_data[tag]["url"]
                   req["method"] = concretization_data[tag]["method"]
                   # now create the params
                   params = {}
                   for k,v in concretization_data[tag]["params"].items():
                       tmp = v.split("=")
                       params[tmp[0]] = tmp[1]
                   req["params"] = params
                   
                   pages = msc_table[idx+1][1][2].split(".")
                   check = concretization_data[pages[0]] # baaad, we assume that position 0 is always the page we're looking for
                   is_bypass = execute_bypass(s,req,check)
                   if is_bypass:
                       cprint("bypass success",color="g")
                   else:
                       cprint("bypass error, abort execution",color="r")
                       exit(0)

            # exploit the sqli here, which is also a normal request where we use
            # the result from sqlmap
            elif attack == 6:
                cprint("exploit sqli here, crafted request","D")
                
                tag = message[0]

                req = {}
                req["url"] = concretization_data[tag]["url"]
                req["method"] = concretization_data[tag]["method"]
                # generate all possible combination of parameters to try
                params = {}
                req_params = []
                for k,v in concretization_data[tag]["params"].items():
                    tmp = v.split("=")
                    param_pair = []
                    if tmp[1] == "?":
                       # we need to provide something from the output of sqlmap
                       table = concretization_data[tag]["tables"][tmp[0]].split(".")
                       for v in sqlmap_output[table[0]][table[1]]:
                           param_pair.append(tmp[0]+"="+v)
                       cprint(param_pair,"D")
                       req_params.append(param_pair)
                       cprint(req_params,"D")
                    else:
                        param_pair.append(tmp[0] + "=" + tmp[1])
                        req_params.append(param_pair)

                # generate all possible combination of cookies to try
                cookies = {}
                req_cookies = []
                try:
                    for k,v in concretization_data[tag]["cookies"].items():
                        tmp = v.split("=")
                        cookies_pair = []
                        if tmp[1] == "?":
                           # we need to provide something from sqlmap output
                           table = concretization_data[tag]["tables"][tmp[0]].split(".")
                           for v in sqlmap_output[table[0]][table[1]]:
                               cookies_pair.append(tmp[0]+"="+v)
                           cprint(cookies_pair,"D")
                           req_cookies.append(cookies_pair)
                           cprint(req_cookies,"D")
                        else:
                            cookies_pair.append(tmp[0] + "=" + tmp[1])
                            req_cookies.append(cookies_pair)
                except KeyError:
                    pass
                cprint(req,"D")
                # I used the %26 (encode of &) because it might happen that the password has a &
                # and when I split, I split wrong
                params_perm = []
                cookies_perm = []
                if len(req_params) > 0:
                    params_perm = ["%26".join(str(y) for y in x) for x in itertools.product(*req_params)]
                if len(req_cookies) > 0:
                    cookies_perm = ["%26".join(str(y) for y in x) for x in itertools.product(*req_cookies)]
                cprint("params perm","D")
                cprint(params_perm,"D")
                cprint("cookies perm","D")
                cprint(cookies_perm,"D")

                found = False
                # loop on all the possibile params and cookies combination and try to exploit the result
                if len(params_perm) == 0 and len(cookies_perm) > 0:
                    # we only have cookies
                    for header in cookies_perm:
                        if not found:
                            cprint("Attempt to exploit sqli","D")
                            cprint(header,"D")
                            req["cookies"] = dict( item.split("=") for item in header.split("%26") )
                            response = __execute_request(req)
                            found = __check_response(idx,msc_table,concretization_data,response)
                elif len(params_perm) > 0 and len(cookies_perm) == 0:
                    # we only have params
                    for param in params_perm:
                        if not found:
                            cprint("Attempt to exploit sqli","D")
                            cprint(param,"D")
                            req["params"] = dict( item.split("=") for item in param.split("%26") )
                            response = __execute_request(req)
                            found = __check_response(idx,msc_table,concretization_data,response)
                elif len(params_perm) > 0 and len(cookies_perm) > 0:
                    # we have params and cookies values
                    for param in params_perm:
                        req["params"] = dict( item.split("=") for item in param.split("%26") )
                        for header in cookies_perm:
                            if not found:
                                cprint("Attempt to exploit sqli","D")
                                cprint(param,D)
                                req["cookies"] = dict( item.split("=") for item in header.split("%26") )
                                response = __execute_request(req)
                                found = __check_response(idx,msc_table,concretization_data,response)
                
                if not found:
                    # we coulan'td procede in the trace, abort
                    cprint("Exploitation failed, abort trace execution",color="r")
                    exit(0)
                else:
                    cprint("Exploitation succceded",color="g")

            # normal http request
            elif attack == -1:
                cprint(msc_table[idx][0],"D")

                tag = message[0]

                req = {}
                req["url"] = concretization_data[tag]["url"]
                req["method"] = concretization_data[tag]["method"]
                # now create the params
                params = {}
                for k,v in concretization_data[tag]["params"].items():
                    tmp = v.split("=")
                    params[tmp[0]] = tmp[1]
                req["params"] = params
                response = __execute_request(req)
                # check if reponse is valid based on the MSC
                # pages contain the right side of a response
                pages = msc_table[idx+1][1][2].split(".")
                for p in pages:
                        cprint(concretization_data[p],"D")
                        if response == None or not( concretization_data[p] in response.text):
                           cprint("Exploitation failed, abort trace execution",color="r")
                           exit(0)
                        else:
                           cprint("Step succceded",color="g")
    cprint("Trace ended",color="g")
                             
def __check_response(idx,msc_table,concretization_data,response):
    pages = msc_table[idx+1][1][2].split(".")
    for p in pages:
           cprint(concretization_data[p],"D")
           try:
                   if response != None and concretization_data[p] in response.text:
                       cprint("valid request","D")
                       cprint(concretization_data[p],"D")
                       return True
                       break;
           except Exception:
                    return False
                    cprint("NO ","D")
    return False

# parameters for configuring the requests maker:
# Requests group
# - basic authentication params
# - SSL verification: True, False, CA path
# - proxy
# - proxy-cred
# - sqlmap usage

def __execute_request(request):
    global s
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

    cprint("Execute request")
    cprint(url)
    cprint(method)
    cprint(params)
    cprint(cookies)
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

def __ask_yes_no(msg,default="y"):
    prompt = " [Y/n]"
    ret = True
    if default == "n":
        prompt = " [n/Y]"
        ret = False
    s = input(msg + prompt)
    if s == "":
        return ret
    if s == "Y" or s == "y":
        return True
    elif s == "N" or s == "n":
        return False
    else:
        print("Invalid input");
        return __ask_yes_no(msg,default)



    

if __name__ == "__main__":
    execute_normal_request("c")

