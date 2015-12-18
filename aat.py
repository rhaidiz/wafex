#!/usr/local/bin/python3.5

"""
This module provides functionalities for parsing a
Message Sequence Chart attack trace in Alice and Bob motation.
"""


import re
import global_var
import requests
import linecache
import parser
from my_print import cprint
# disable warnings when making unverified HTTPS requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import wrapper.sqlmap
import json
import threading
import itertools

# global request
s = None

# takes an attack trace and an extension matrix, and execute the attack
def execute_attack(msc_table,extension_sqli,file_aslanpp):
    global s
    cprint("Executing the attack trace","INFO")

    # general fields for sperforming an HTTP request
    url = None
    method = None
    params = None
    mapping = None
    abstract_param_to_real = None
    
    # specific for executing sqlmap
    data_to_extract = []

    # sqlmap output
    sqlmap_output = None
    
    # request session object for performing subsequent HTTP requests
    s = requests.Session()
        
    # current response
    response = None

    # loop the msc_table and find when to perform a sqli attack
    for idx, message in enumerate(msc_table):
        if "webapplication" in msc_table[idx][1][0]:
                # is a response, check if we got it right
                cprint("Check if response is valid","DEBUG")
                pages = msc_table[idx][1][2].split(".")
                cprint(pages,"DEBUG")
                with open("chained_concretization.txt","r") as data_file:
                     data = json.load(data_file)
                for p in pages:
                        try:
                                # we now check if the obtained response is valid.
                                # if is not valid, and the previous request was a 
                                # normal request, we ask to modify the previous 
                                # request.
                                # if is not valid and the previous request was
                                # an exploitation, try a different combination of
                                # parameters.
                                # if the request was valid, procede with next operation
                                if response != None and data[p] in response.text:
                                    cprint("valid request","DEBUG")
                                    cprint(data[p],"DEBUG")
                        except Exception:
                                cprint("NO ","DEBUG")
                                
                     

        if not "webapplication" in msc_table[idx][1][0]:
             if "a" in extension_sqli[idx][0]:
                 cprint("sqli attack","DEBUG")
                 cprint(message,"DEBUG")
                 cprint(extension_sqli[idx],"DEBUG")
                 tag = message[0]
                 #parser.request_details(msc_table,message[0])

                 sqli_init = {}
                 with open("chained_concretization.txt","r") as data_file:
                     data = json.load(data_file)
                 sqli_init["url"] = data[tag]["url"]
                 sqli_init["method"] = data[tag]["method"]
                 # now create the params
                 params = {}
                 for k,v in data[tag]["params"].items():
                     tmp = v.split("=")
                     params[tmp[0]] = tmp[1]
                 sqli_init["params"] = params
                 # data to extract
                 extract = []
                 exploitations = extension_sqli[idx][1]
                 cprint("Exploitations","DEBUG")
                 cprint(exploitations,"DEBUG")
                 for row in exploitations:
                       tag = row[0]
                       exploit_points = row[1]
                       for k in exploit_points:
                                tmp_map = data[tag]["params"][k].split("=")[0]
                                tmp_table = data[tag]["tables"][tmp_map]
                                extract.append(tmp_table)
                 sqli_init["extract"] = extract
                 if not extract:
                     cprint("No valid data to be extracred from the database","WARNING")
                 else:
                    # for the execution we need (url,method,params,data_to_extract)
                    # data_to_extract => table.column
                    #sqlmap_output = execute_sqlmap(url,method,params,data_to_extract)
                    sqlmap_output = execute_sqlmap(sqli_init)
                    cprint(sqlmap_output,"DEBUG")
                    if not sqlmap_output:
                        cprint("No data extracted from the database","WARNING")
                        exit()
             elif "e" in extension_sqli[idx][0]:
                 # exploit the sqli here, which is also a normal request where we use
                 # the result from sqlmap
                 cprint("exploit sqli here, crafted request","DEBUG")
                 
                 tag = message[0]

                 req = {}
                 with open("chained_concretization.txt","r") as data_file:
                     data = json.load(data_file)
                 req["url"] = data[tag]["url"]
                 req["method"] = data[tag]["method"]
                 # now create the params
                 params = {}
                 tmp_dyn_params = []
                 for k,v in data[tag]["params"].items():
                     tmp = v.split("=")
                     tmp_a = []
                     if tmp[1] == "?":
                        # we need to provide something from the output of sqlmap
                        table = data[tag]["tables"][tmp[0]].split(".")
                        #TODO here we are using one of the possibile output, we shoule 
                        #loop and be sure to try all possibile combinations
                        params[tmp[0]] = sqlmap_output[table[0]][table[1]][0]
                        for v in sqlmap_output[table[0]][table[1]]:
                            tmp_a.append(tmp[0]+"="+v)
                        cprint(tmp_a,"DEBUG")
                        tmp_dyn_params.append(tmp_a)
                        cprint("CCCCCCCCCCCCCCCCCCCCCC","DEBUG")
                        cprint(tmp_dyn_params,"DEBUG")
                     else:
                         tmp_a.append(tmp[0] + "=" + tmp[1])
                         tmp_dyn_params.append(tmp_a)
                         params[tmp[0]] = tmp[1]
                 req["params"] = params
                 cprint(req,"DEBUG")
                 tmp_pp = None
                 if len(tmp_dyn_params) > 1:
                     # I used the %26 because it might happen that the password has a &
                     tmp_pp = ["%26".join(str(y) for y in x) for x in itertools.product(*tmp_dyn_params)]
                 cprint(tmp_pp,"DEBUG")
                 # loop on all the possibile params combination and try to exploit the result
                 found = False
                 for param in tmp_pp:
                    if not found:
                        cprint("attempt to exploit sqli results","DEBUG")
                        cprint(param,"DEBUG")
                        # I used the %26 because it might happen that the password has a &
                        req["params"] = dict( item.split("=") for item in param.split("%26") )
                        cprint(req,"DEBUG")
                        response = execute_request(req)
                        pages = msc_table[idx+1][1][2].split(".")
                        with open("chained_concretization.txt","r") as data_file:
                             data = json.load(data_file)
                        for p in pages:
                                cprint(data[p],"DEBUG")
                                try:
                                        if response != None and data[p] in response.text:
                                            cprint("valid request","DEBUG")
                                            cprint(data[p],"DEBUG")
                                            found = True
                                            break;
                                except Exception:
                                        cprint("NO ","DEBUG")

             elif "n" in extension_sqli[idx][0]:
                 # normal http request
                 cprint(msc_table[idx][0],"DEBUG")

                 tag = message[0]

                 req = {}
                 with open("chained_concretization.txt","r") as data_file:
                     data = json.load(data_file)
                 req["url"] = data[tag]["url"]
                 req["method"] = data[tag]["method"]
                 # now create the params
                 params = {}
                 for k,v in data[tag]["params"].items():
                     tmp = v.split("=")
                     params[tmp[0]] = tmp[1]
                 req["params"] = params
                 response = execute_request(req)

# parameters for configuring the requests maker:
# Requests group
# - basic authentication params
# - SSL verification: True, False, CA path
# - proxy
# - proxy-cred
# - sqlmap usage

def execute_request(request):
    global s
    url = request["url"]
    method = request["method"]
    params = request["params"]

    cprint("Execute request", "DEBUG")
    cprint(url,"DEBUG")
    cprint(method,"DEBUG")
    cprint(params,"DEBUG")
    #url = 'https://157.27.244.25/chained'
    headers = {'user-agent': 'my-app/0.0.1'}
    proxy = {"http" : "http://127.0.0.1:8080","https":"https://127.0.0.1:8080"}
    r = None
    if method == "GET":
        r = s.get(url,proxies=proxy,params=params, verify=False, auth=('regis','password'))
    else:
        r = s.post(url,proxies=proxy, data = params, verify=False, auth=('regis','password'))
    #r = requests.get(url, headers=headers, proxies=proxy, verify=False, auth=('regis','password'))
    cprint(r.text,"DEBUG")
    return r

"""
output format: { table { columns : [values]}}
"""

def execute_sqlmap(sqlmap_details):
    print(sqlmap_details)
    url = sqlmap_details["url"]
    method = sqlmap_details["method"]
    params = sqlmap_details["params"]
    data_to_extract = sqlmap_details["extract"]

    cprint("Execute sqlmap","DEBUG")
    wrapper.sqlmap.run_api_server()
    task = wrapper.sqlmap.new_task()
    wrapper.sqlmap.set_option("authType","Basic",task)
    wrapper.sqlmap.set_option("authCred","regis:password",task)

    url_params = ""
    for k,v in params.items():
        url_params = url_params+"&"+k+"="+v
    if method == "GET":
        wrapper.sqlmap.set_option("url",url+"/"+url_params,task)
    elif method == "POST":
        wrapper.sqlmap.set_option("url",url,task)
        wrapper.sqlmap.set_option("data",url_params,task)
    wrapper.sqlmap.set_option("dumpTable","true",task)
    for tblcol in data_to_extract:
        tbl_list = tblcol.split(".")
        cprint(tbl_list[0],"DEBUG")
        wrapper.sqlmap.set_option("tbl",tbl_list[0],task)

    #wrapper.sqlmap.set_option("data","username=?&password=?",task)
    #wrapper.sqlmap.set_option("tbl","users",task)

    wrapper.sqlmap.start_scan(url,task)
    cprint(url,"DEBUG")
    cprint(method,"DEBUG")
    cprint(params,"DEBUG")
    cprint(data_to_extract,"DEBUG")

    stopFlag = threading.Event()
    sqlmap_output = ""
    while not stopFlag.wait(5):
        r = wrapper.sqlmap.get_status(task)
        if "terminated" in r:
            cprint("Analysis terminated","DEBUG")
            sqlmap_output = wrapper.sqlmap.get_data(task)
            stopFlag.set()
        else:
            cprint("Analysis in progress ... ","DEBUG")
    
    # Let's parse the data extracted
    cprint(sqlmap_output,"DEBUG")
    extracted_values = {}
    #TODO: check errors in the sqlmap_output
    for tblcol in data_to_extract:
        tbl_list = tblcol.split(".")
        cprint(tbl_list[1],"DEBUG")
        tmp_table = tbl_list[0]
        tmp_column = tbl_list[1]
        try:
            extracted_values[tmp_table]
        except KeyError:
            extracted_values[tmp_table] = {}
        try:
            extracted_values[tmp_table][tmp_column] = sqlmap_output["data"][2]["value"][tmp_column]["values"]
        except Exception:
            cprint("error in the sqlmap output","ERROR")
            wrapper.sqlmap.kill
            cprint(sqlmap_output,"DEBUG")
            exit()
        cprint("Ending sqlmap extraction","DEBUG") 
        wrapper.sqlmap.kill()
    return extracted_values

if __name__ == "__main__":
    execute_normal_request("c")

