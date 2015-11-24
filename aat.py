#!/usr/local/bin/python3.5

"""
This module will provide functionality for parsing an
ASLAn++ attack trace in the Alice and Bob motation.
"""


import re

DEBUG = 1

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


# takes as input an array of trace to be executed in the Alice -> Bob notation
# [(A , B , message)]
def extend_trace_sqli(trace):
    DEBUG = 1
    # there should be only one sqli injection point in our traces
    # but we create an array for further extension
    sqli = []
    injection_point = ""
    for idx, message in enumerate(trace):
        if message and len(message) == 3:
            # read message and check if it's a request and require an SQLi
            if (not message[0] == "webapplication") and "sqli" in message[len(message)-1] and not "tuple" in message[len(message)-1]:
                if DEBUG:
                    print("there is a sqli")
                    print(message)
                    print("---------------")
                injection_point = idx
                sqli.append(["a",[]])
            # we are exploiting a sqli, find the column that should be retrieved
            # .([a-z]*?).tuple
            elif "webapplication" in message[1] and "tuple" in message[len(message)-1] and "sqli" in message[len(message)-1]:
                param_regexp = re.compile(r'(.*?).tuple\(')
                params = param_regexp.findall(message[len(message)-1])
                if DEBUG:
                    print("exploiting sqli here")
                    print("Message:")
                    print(message)
                    print("Params: ")
                    print(params)
                    print("--------------------")
                # create a multiple array with params from different lines
                sqli[injection_point][1].append((idx,params))
                sqli.append(["e",injection_point])
            else:
                sqli.append(["n",0])
    if DEBUG:
        print(sqli)
    return sqli

# takes an attack trace and an extension matrix, and execute the attack
def execute_attack(aat,extension_sqli):
    print("Executing the attack trace")
    # loop the aat and find when to perform an attack
    for idx, message in enumerate(aat):
        if "a" in extension_sqli[idx][0]:
            # perform an sqli attack here
            print("sqli attack")
        elif "e" in extension_sqli[idx][0]:
            # exploit the sqli here
            print("exploit sqli here")
        elif "n" in extension_sqli[idx][0]:
            # normal http request
            print("normal request")




