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




# --==[ SQL Injection ]==--
# 1: whenever I find a sqli somewhere, look for i -> webapp : tuple(of_the_same_sqli)
#    if found, data extraction is performed and thus inside the sqli array I'll have
#    and entry [a,idx] where idx is the line where the injection should be performed
# 2: if I don't perform a data extraction, a 0 should appear
# 3: sqli.lfi identifies a sql-injection for reading
# 4: sqli.evil_file identifies a sql-injection for writing
# 

# --==[ Filesystem ]==--
#TODO: TBA


# Matrix form:
# [ ['a',[( tag_where_to_exploit, [ parameters_to_exploit ])]],
#         ['n',0]
#         ['e',0] ]
# Where  a: attack
#        n: normal request
#        e: exploit
"""
Understands the sql-injection points
"""
def sqli(msc_table):
    if config.DEBUG:
        cprint("Starting extend_trace_sqli","D")
    # there should be only one sqli injection point in our traces
    # but we create an array for further extension
    sqli = []
    injection_point = ""
    for idx, message in enumerate(msc_table):
        tag = message[0]
        message = message[1]
        if message and len(message) == 3:
            # read message and check if it's a request and require an SQLi
            if (not message[0] == "webapplication") and "sqli" in message[len(message)-1] and not "tuple" in message[len(message)-1]:
                if config.DEBUG:
                    cprint("there is a sqli","D")
                    cprint(message,"D")
                    cprint("---------------","D")
                injection_point = idx
                sqli.append(["a",[]])
            # we are exploiting a sqli, find the column that should be retrieved
            # .([a-z]*?).tuple
            elif "webapplication" in message[1] and "tuple" in message[len(message)-1] and "sqli" in message[len(message)-1]:
                #param_regexp = re.compile(r'(.*?).tuple\(')
                param_regexp = re.compile(r'\.?([a-zA-Z]*?)\.tuple')
                params = param_regexp.findall(message[len(message)-1])
                cprint("exploiting sqli here","D")
                cprint("Message:","D")
                cprint(message,"D")
                cprint("Params: ","D")
                cprint(params,"D")
                cprint(tag,"D")
                cprint("--------------------","D")
                # create a multiple array with params from different lines
                sqli[injection_point][1].append((tag,params))
                sqli.append(["e",injection_point])
            else:
                sqli.append(["n",0])
    cprint(sqli,"D")
    return sqli


"""
Return a JSON structure

{ "url":"http",
  "method" : "GET",
  "params" : [{"key":"value","key":"?"} ],
  "data"   : ["users.username","users.password"]
}
"""
#def request_details(msc_table,tag):     
#
#    print(sqli_init)
    
    



"""
Extracts the information needed to perform a sqli.
idx             : current step in msc_table
msc_table       : the msc table extended with src_line
sqli_matrix     : sqli support matrix
file_aslanpp    : model source
"""
#def old_request_details(idx,msc_table, file_aslanpp, sqli_matrix = None):
#    cprint("Start sqli_details","D")
#    # we need to execute a sql injection
#    # parameters for executing sqlmap
#    url = None
#    method = None
#    abstract_param_to_real = {}
#    params = []
#    mapping = {}
#    data_to_extract = []
#    # perform an sqli attack here, which means run sqlmap
#    # retrieve attack details
#    line_num = msc_table[idx][0]
#    line = linecache.getline(file_aslanpp, line_num)
#    # get parameter list first (not sure if I need this list)
#    abstract_params_exp = re.compile(r'http_request\((.*?)\)')
#    cprint(line.strip().replace(" ",""),"D")
#    model_params = abstract_params_exp.search(line.strip().replace(" ","")).group(1).split(".")
#    cprint(model_params,"D")
#    # next line is the URL
#    line_num += 1
#    line = linecache.getline(file_aslanpp, line_num)
#    url_exp = re.compile(r'%@ (.*)')
#    url = url_exp.search(line).group(1)
#    cprint(url,"D")
#    # next line is the method
#    line_num += 1
#    line = linecache.getline(file_aslanpp, line_num)
#    method_exp = re.compile(r'%@ (.*)')
#    method = method_exp.search(line).group(1)
#    cprint(method,"D")
#    # now retrieve the real parameters needed for the request
#    # and the mapping params -> table.column
#    line_num +=1
#    line = linecache.getline(file_aslanpp, line_num)
#    while line.strip().startswith("%@"):
#        cprint(line,"D")
#        if re.match(r'%@ (?!M)',line.strip()):
#            # parameters
#            par_exp = re.compile(r'%@(.*?)->(.*)=(.*)')
#            trimmed_line = line.replace(" ","")
#            par = par_exp.search(trimmed_line)
#            param_abstract = par.group(1)
#            param_key = par.group(2)
#            param_value = par.group(3)
#            abstract_param_to_real[param_abstract] = param_key
#            params.append((param_key,param_value))
#            cprint(params,"D")
#        else:
#            # table mapping
#            par_exp = re.compile(r'M_(.*?)->(.*)')
#            par = par_exp.search(line.replace(" ",""))
#            mapping[par.group(1)] = par.group(2)
#            cprint(mapping,"D")
#            
#        line_num += 1
#        line = linecache.getline(file_aslanpp, line_num)
#
#
#    # retrieve column.table mapping
#
#    if sqli_matrix == None:
#        return url, method, params, abstract_param_to_real, mapping
#    
#    # once we have the real parameters for performing the request,  we need to know
#    # which data to extract
#    exploitation_points = sqli_matrix[idx][1]
#    cprint("retrieve data to extract","D")
#    cprint(sqli_matrix[idx],"D")
#
#    for idx2, param in exploitation_points:
#        exploitation_step = exploitation_points[idx][0]
#        exploitation_params = exploitation_points[idx][1]
#        # now for each params in exploitation_params I have to search
#        # for the corresponding mapping, and we can start from where that
#        # step starts
#        cprint(msc_table[exploitation_step][0],"D")
#        line_num = msc_table[exploitation_step][0] + 1
#        line = linecache.getline(file_aslanpp, line_num)
#        while line.strip().startswith("%@"):
#            for exp_par in exploitation_params:
#               str_tmp = "M_"+exp_par
#               if str_tmp in line:
#                   par_exp = re.compile(str_tmp+'->(.*)')
#                   line = line.replace(" ","")
#                   table_column_tmp = par_exp.search(line)
#                   cprint("to extract","D")
#                   cprint(table_column_tmp.group(1),"D")
#                   data_to_extract.append(table_column_tmp.group(1))
#            line_num += 1
#            line = linecache.getline(file_aslanpp, line_num)
#    cprint("Data to extract","D")
#    cprint(data_to_extract,"D")
#    return url, method, params, data_to_extract
    

#def __get_line_number(file_descriptor,rule):
#    # search for the line code
#    found_line = False
#    for line in file_descriptor:
#        if line.startswith(str(rule)+" %"):
#            found_line = True
#        if found_line & line.startswith("  RULES"):
#            line_regexp = re.compile(r'step_(?:.*?)__line_([0-9]*)')
#            line_num = line_regexp.findall(line)
#            if config.DEBUG:
#                #cprint("line number: " + line,"D")
#                cprint(line_num,"D")
#            return line_num
#