#!/usr/local/bin/python3.5

"""
This module will provide functionality for parsing an
ASLAn++ attack trace in the Alice and Bob motation.
"""


import re
import global_var
import requests
import linecache
from my_print import cprint
# disable warnings when making unverified HTTPS requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# how to execute sqlmap for injection:
# possibilities:
#  1) data extraction used somewhere else
#  2) authentication bypass
#  
# 1: whenever I find a sqli somewhere, look for i -> webapp : tuple(of_the_same_sqli)
#    if found, data extraction is performed and thus inside the sqli array I'll have
#    and entry [a,idx] where idx is the line where the injection should be performed
#    I should also save the list of columns over which the sqli should be performed
# 2: if I don't perform a data extraction, a 0 should appear

# --------
# uname_s = error_sqli(uname)     <?>           ->*   webapplication  : i.e_request(article_page.errorsql.sqli)
#                                 webapplication   ->*  <i>          : response(errorPage.tuple(errorsql.sqli))
# execute with uname_s            <i>           ->*   webapplication  : e_request(login_page.users.uname.tuple(errorsql.sqli))
#                                 webapplication   ->*  <i>          : response(secureFolder)



# takes as input the output of mc.py.parse_aat
# This function outputs a matrix representing where a sqli occurs and where it should
# be exploited.
# Matrix form:
# [ ['a',[( step_where_to_exploit, [ parameters_to_exploit ])]],
#         ['n',0]
#         ['e',0] ]
# Where  a: attack
#        n: normal request
#        e: exploit

def extend_trace_sqli(trace):
    if global_var.DEBUG:
        cprint("Starting extend_trace_sqli","DEBUG")
    # there should be only one sqli injection point in our traces
    # but we create an array for further extension
    sqli = []
    injection_point = ""
    for idx, message in enumerate(trace):
        message = message[1]
        if message and len(message) == 3:
            # read message and check if it's a request and require an SQLi
            if (not message[0] == "webapplication") and "sqli" in message[len(message)-1] and not "tuple" in message[len(message)-1]:
                if global_var.DEBUG:
                    cprint("there is a sqli","DEBUG")
                    cprint(message,"DEBUG")
                    cprint("---------------","DEBUG")
                injection_point = idx
                sqli.append(["a",[]])
            # we are exploiting a sqli, find the column that should be retrieved
            # .([a-z]*?).tuple
            elif "webapplication" in message[1] and "tuple" in message[len(message)-1] and "sqli" in message[len(message)-1]:
                param_regexp = re.compile(r'(.*?).tuple\(')
                params = param_regexp.findall(message[len(message)-1])
                if global_var.DEBUG:
                   cprint("exploiting sqli here","DEBUG")
                   cprint("Message:","DEBUG")
                   cprint(message,"DEBUG")
                   cprint("Params: ","DEBUG")
                   cprint(params,"DEBUG")
                   cprint("--------------------","DEBUG")
                # create a multiple array with params from different lines
                sqli[injection_point][1].append((idx,params))
                sqli.append(["e",injection_point])
            else:
                sqli.append(["n",0])
    cprint(sqli,"DEBUG")
    return sqli

# takes an attack trace and an extension matrix, and execute the attack
def execute_attack(aat,extension_sqli):
    cprint("Executing the attack trace","INFO")

    # loop the aat and find when to perform an attack
    for idx, message in enumerate(aat):
        if not "webapplication" in aat[idx][1][0]:
             if "a" in extension_sqli[idx][0]:
                 #TODO: move this code in a different location, maybe inside a parser module?
                 # we need to execute a sql injection
                 # parameters for executing sqlmap
                 url = None
                 method = None
                 params = []
                 data_to_extract = []
                 # perform an sqli attack here, which means run sqlmap
                 # retrieve attack details
                 line_num = aat[idx][0]
                 line = linecache.getline("Joomla_nd.aslan++", line_num)
                 # get parameter list first (not sure if I need this list)
                 params_list = re.compile(r'http_request\((.*?)\)')
                 model_params = params_list.search(line.strip()).group(1).split(".")
                 cprint(params,"DEBUG")
                 # next line is the URL
                 line_num += 1
                 line = linecache.getline("Joomla_nd.aslan++", line_num)
                 url_exp = re.compile(r'%@ (.*)')
                 url = url_exp.search(line).group(1)
                 cprint(url,"DEBUG")
                 # next line is the method
                 line_num += 1
                 line = linecache.getline("Joomla_nd.aslan++", line_num)
                 method_exp = re.compile(r'%@ (.*)')
                 method = method_exp.search(line).group(1)
                 cprint(method,"DEBUG")
                 # now retrieve the real parameters needed for the request
                 line_num +=1
                 line = linecache.getline("Joomla_nd.aslan++", line_num)
                 while line.strip().startswith("%@"):
                     par_exp = re.compile(r'->(.*)=(.*)')
                     par = par_exp.search(line.strip())
                     params.append((par.group(1),par.group(2)))
                     cprint(params,"DEBUG")
                     line_num += 1
                     line = linecache.getline("Joomla_nd.aslan++", line_num)
                 # once we have this info we need the info of the table to be extracted
                 # using sqlmap
                 exploitation_points = extension_sqli[idx][1]
                 for idx2, param in exploitation_points:
                     exploitation_step = exploitation_points[idx][0]
                     exploitation_params = exploitation_points[idx][1]
                     # now for each params in exploitation_params I have to search
                     # for the corresponding mapping, and we can start from where that
                     # step starts
                     cprint(aat[exploitation_step][0],"DEBUG")
                     line_num = aat[exploitation_step][0] + 1
                     line = linecache.getline("Joomla_nd.aslan++", line_num)
                     while line.strip().startswith("%@"):
                         for exp_par in exploitation_params:
                            str_tmp = "M_"+exp_par
                            if str_tmp in line:
                                par_exp = re.compile(str_tmp+'->(.*)')
                                line = line.replace(" ","")
                                table_column_tmp = par_exp.search(line)
                                cprint(table_column_tmp.group(1),"DEBUG")
                                data_to_extract.append(table_column_tmp.group(1))
                         line_num += 1
                         line = linecache.getline("Joomla_nd.aslan++", line_num)

                 cprint("sqli attack","DEBUG")
                 # for the execution we need (url,method,params,data_to_extract)
                 # data_to_extract => table.column
                 execute_sqlmap(url,method,params,data_to_extract)
             elif "e" in extension_sqli[idx][0]:
                 # exploit the sqli here, which is also a normal request where we use
                 # the result from sqlmap
                 cprint("exploit sqli here","DEBUG")
             elif "n" in extension_sqli[idx][0]:
                 # normal http request
                 
                 cprint(aat[idx][0],"DEBUG")

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

