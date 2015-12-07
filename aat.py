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




# takes an attack trace and an extension matrix, and execute the attack
def execute_attack(msc_table,extension_sqli,file_aslanpp):
    cprint("Executing the attack trace","INFO")

    # loop the msc_table and find when to perform an attack
    for idx, message in enumerate(msc_table):
        if not "webapplication" in msc_table[idx][1][0]:
             if "a" in extension_sqli[idx][0]:
                 cprint("sqli attack","DEBUG")
                 url = None
                 method = None
                 params = []
                 data_to_extract = []
                 url, method, params, data_to_extract = parser.sqli_details(idx,msc_table, extension_sqli, file_aslanpp)
                 # for the execution we need (url,method,params,data_to_extract)
                 # data_to_extract => table.column
                 execute_sqlmap(url,method,params,data_to_extract)
             elif "e" in extension_sqli[idx][0]:
                 # exploit the sqli here, which is also a normal request where we use
                 # the result from sqlmap
                 cprint("exploit sqli here","DEBUG")
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

def execute_normal_request(request):
    url = 'https://157.27.244.25/chained'
    headers = {'user-agent': 'my-app/0.0.1'}
    proxy = {"http" : "http://127.0.0.1:8080","https":"https://127.0.0.1:8080"}

    r = requests.get(url, headers=headers, proxies=proxy, verify=False, auth=('regis','password'))
    print(r.status_code)


def execute_sqlmap(url,method,params,data_to_extract):
    cprint("Execute sqlmap","DEBUG")
    cprint(url,"DEBUG")
    cprint(method,"DEBUG")
    cprint(params,"DEBUG")
    cprint(data_to_extract,"DEBUG")

if __name__ == "__main__":
    execute_normal_request("c")

