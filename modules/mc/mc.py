#!/usr/local/bin/python3.5

"""
This module implements methods wrapping
the AVANTSSAR platform.
"""

import re
import json
import config
import os.path
import subprocess

from sys import platform
from modules.logger import logger
from abstrac_http import AbstractHttpRequest
from abstrac_http import AbstractHttpResponse

# external software
if platform == "linux" or platform == "linux2":
    CLATSE = "modules/mc/cl-atse_i686"
elif platform == "darwin":
    CLATSE = "modules/mc/cl-atse_x86_64-mac"
elif platform == "win32":
    CLATSE = "modules/mc/cl-atse_i686-windows.exe"


# default value for the connector
connector = config.CONNECTOR_1_4_9

"""
Generates the message sequence chart
from an attack trace file and the ASLan model
"""
def generate_msc(file_attack_trace,file_aslan_model):
    
    r_time = re.compile("STATISTICS TIME (.*)")
    r_tested = re.compile("TESTED (.*)")
    r_reached = re.compile("REACHED (.*)")
    r_reading = re.compile("READING (.*)")
    r_analyze = re.compile("ANALYSE (.*)")
    r_unused = re.compile("UNUSED: { (.*)")
    r_goal = re.compile("GOAL: (.*)")
    r_end_unused = re.compile("(.*) }")
    unused_flag = 0
    
    tmp_attack_trace = ""
    p1 = subprocess.Popen(["java","-jar",connector,"-ar",file_attack_trace,file_aslan_model],universal_newlines=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        out,err = p1.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        p1.kill()
        logger.critical("MSC creation timed out")
        exit()
    if config.verbosity:
        # print the generated output on a file
        msc_verbose = open("tmp_msc.txt","w")
        msc_verbose.write(out)
        msc_verbose.close()
    f = open(file_attack_trace)
    msc = ""
    comments = False
    for line in f.readlines():
        line = line.strip()
        if "SUMMARY ATTACK_FOUND" in line:
            # we found an attack, so return the generated MSC
            i = out.find("MESSAGES:")
            msc = out[i+9:]
            logger.info("Abstract Attack Trace found:")
            print(msc)
        elif "SUMMARY NO_ATTACK_FOUND" in line:
            # no attack found, we don't need the MSC
            logger.warning("NO ATTACK FOUND")
        else:
            goal = r_goal.search(line)
            if goal:
                infoMsg = "GOAL: {}".format(goal.group(1))
                logger.info(infoMsg)
                continue
            if "COMMENTS" in line:
                comments = True
                logger.info("COMMENTS")
                continue
            if "STATISTICS TIME" in line:
                comments = False
                continue
            if comments == True:
                print(line)
                continue
            tested = r_tested.search(line)
            if tested:
                infoMsg = "TESTED: {}".format(tested.group(1))
                logger.info(infoMsg)
                continue
            reached = r_reached.search(line)
            if reached:
                infoMsg = "REACHED: {}".format(reached.group(1))
                logger.info(infoMsg)
                continue
            analyze = r_analyze.search(line)
            if analyze:
                infoMsg = "ANALYZE: {}".format(analyze.group(1))
                logger.info(infoMsg)
                # I return here because if I reached ANALYZE, I don't care of 
                # reading the remaning part of the output
                return msc
            unused = r_unused.search(line)
            if unused:
                logger.debug("UNUSED:")
                logger.debug(unused.group(1))
                unused_flag = 1
                continue
            else: 
                last_line_unused = r_end_unused.search(line)
                if unused_flag == 1 and last_line_unused:
                    # last line of the unused
                    logger.debug(last_line_unused.group(1))
                    unused_flag = 0
                    continue
                elif unused_flag == 1:
                    # keep reading next files
                    logger.debug(line)
                    continue
    # this return is for safety reason. Theoretically it should always
    # return when ANALYZE is found
    return msc

"""
Execute the CL-Atse model checker locally
"""
def local_cl_atse(file_aslan,options=[]):
    global CLATSE
    logger.info("Executing CL-Atse locally")
    atse_output = os.path.splitext(file_aslan)[0] + ".atse"
    atse_output_descriptor = open(atse_output,"w")
    atse_execution_array = [CLATSE] + options + [file_aslan]
    logger.debug(atse_execution_array)
    p1 = subprocess.Popen(atse_execution_array,universal_newlines=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        out,err = p1.communicate(timeout=config.mc_timeout)
    except subprocess.TimeoutExpired:
        p1.kill()
        logger.critical("Model checker timed out")
        exit()
    atse_output_descriptor.write(out)
    atse_output_descriptor.close()
    return atse_output

"""
Generate an ASLan file from an ASLan++ file.
"""
def aslanpp2aslan(file_aslanpp):
    #connector = config.connector
    # get the filename without extension
    debugMsg = "file aslanpp: {}".format(file_aslanpp)
    logger.debug(debugMsg)
    basename = os.path.splitext(os.path.basename(file_aslanpp))[0]
    translator_output_file = "tmp_"+basename+".aslan"

    logger.info("Generating ASlan model")
    debugMsg = "{} on {} out-file {}".format(connector,file_aslanpp,translator_output_file)
    logger.debug(debugMsg)

    p1 = subprocess.Popen(["java","-jar",connector,file_aslanpp,"-o",translator_output_file],universal_newlines=True,stderr=subprocess.PIPE)

    try:
        out,err = p1.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        p1.kill()
        criticalMsg = "Error: {} timed out."
        logger.critical(criticalMsg)
        exit()


    # check if an error has been generated from the translator
    if "FATAL" in err or "ERROR" in err:
        # there was an error in executing the translator
        logger.critical("Translator generated an error")
        logger.critical(err)
        exit()

    if config.verbosity and "WARNING" in err:
        logger.debug(err.strip())
    logger.info("ASlan model generated")
    return translator_output_file, err


"""
Parses a Message Sequence Charts and returns a list of AbstractHttpRequests.
"""
def parse_msc(aat):
    # remove the < > chars
    # WARNING: by removing > I also remove the arrow in the messages *->* will become *-*
    aat = re.sub("<|>","",aat)
    aat = re.sub("},{","}.{",aat)

    # remove unnecessary messages and duplicates
    # and insert the remainig lines in reverse inside reverse_aat
    lines_seen = set()
    reverse_aat = []
    for line in aat.split("\n"):
        line = line.replace(" ","")
        if not "i*-*honest" in line and not "honest*-*i" in line and not "database" in line and not "filesystem" in line:
            if line and line not in lines_seen:
                reverse_aat.insert(0,line)
                lines_seen.add(line)

    # order the sequence
    tag_regexp = re.compile(r'tag(?P<tag>[0-9]*)')
    aat = []
    tag_seen = set()
    for line1 in reverse_aat:
        current_tag = tag_regexp.search(line1).group("tag")
        for line2 in reverse_aat:
            tag = tag_regexp.search(line2).group("tag")
            if tag not in tag_seen and tag == current_tag:
                aat.insert(0,line2)
        tag_seen.add(current_tag)

    request_regexp =  re.compile(r'(?P<sender>.*?)\*-\*(?P<receiver>.*?):(?:.*?)http_request\((?P<page>.*)\,(?P<params>.*)\,(?P<cookies>.*)\)\.tag(?P<tag>[0-9]*)')
    response_regexp = re.compile(r'(?P<sender>.*?)\*-\*(?P<receiver>.*?):http_response\((?P<page>.*)\,(?P<content>.*)\,(?P<cookies>.*)\)\.tag(?P<tag>[0-9]*)')

    # load the concretization file
    concretization_data = ""
    print(config.concretization)
    with open(config.concretization,"r") as data_file:
         concretization_data = json.load(data_file)
         data_file.close()

    # is an array containing AbstractHttpRequest
    msc = []
    # aat is a list containing [request, response, ...] where every request
    # is followed by a response. We get an iterator and iterate every two
    # elemements of the list
    aat_iterator = iter(aat)
    for line_request in aat_iterator:
        try:
            line_response = next(aat_iterator)
        except StopIteration as e:
            # it means the was response to the request, it can
            # happen if the goal is reaced without the need
            # of sending the response. We set line_response to an empty string
            line_response = ""

        # parse the request
        request_match = request_regexp.match(line_request)
        ab_http_request = AbstractHttpRequest()
        if request_match:
            ab_http_request.sender = request_match.group("sender")
            ab_http_request.receiver = request_match.group("receiver")
            ab_http_request.page = request_match.group("page")
            params = request_match.group("params")
            ab_http_request.params = _get_params(params)
            cookies = request_match.group("cookies")
            ab_http_request.cookies = _get_params(cookies)
            tag = request_match.group("tag")
            ab_http_request.tag = tag

            # get the concrete parameter for this request
            tagstr = "tag{}".format(tag)
            ab_http_request.url = concretization_data[tagstr]["url"]
            ab_http_request.method = concretization_data[tagstr]["method"]
            ab_http_request.get_params = concretization_data[tagstr]["get_params"]
            ab_http_request.post_params = concretization_data[tagstr]["post_params"]
            ab_http_request.cookies = concretization_data[tagstr]["cookies"]

        # parse the response
        response_match = response_regexp.match(line_response)
        if response_match:
            ab_http_response = AbstractHttpResponse()
            ab_http_response.sender = response_match.group("sender")
            ab_http_response.receiver = response_match.group("receiver")
            ab_http_response.page = response_match.group("page")
            content = response_match.group("content")
            ab_http_response.content = content
            cookies = response_match.group("cookies")
            ab_http_response.cookies = cookies.split(".")
            ab_http_response.tag = response_match.group("tag")
            ab_http_request.response = ab_http_response

        # identify the action assosiated with this AbstractHttpRequest
        action, params = _identify_action(ab_http_request)
        ab_http_request.action = action
        ab_http_request.action_params = params
        # append the HTTP request
        msc.append(ab_http_request)

    return msc



# 1) sqli_bypass : sqli for login bypassing
# 2) sqli_write : sqli for writing a file
# 3) sqli_read : sqli for reading a file
# 4) sqli : dump the entire db
# 5) path_injection : use Wfuzz
# 6) xss : steal the user's session
# else) normal request

def _identify_action(ab_request):
    """ Returns action code and an array of parameters required for the action. """
    if "i" == ab_request.sender and "webapplication" == ab_request.receiver:
        for c in ab_request.params:
            key = c
            value = ab_request.params[c]
            if "sqli_read" in value:
                # this is a SQLi for reading a file
                file_to_read_regexp = re.compile(r'file\((?P<file>.*)\)')
                file_to_read = file_to_read_regexp.search(ab_request.response.content)
                return 0, [key, file_to_read.group("file")]
            elif "sqli_write" in value:
                # this is a SQLi for writing a file
                file_to_write_regexp = re.compile(r'sqli_write\.(?P<file>.*)\.')
                file_to_write = file_to_write_regexp.search(value)
                return 1, [key, file_to_write.group("file")]
            elif "sqli_bypass" in value:
                # this is a SQLi to create a tautology
                return 2, [key]
            elif "xss" in value:
                # this is a stored XSS since the intruder is comunicating with
                # the webapplication
                return 3, [key]
            elif "path_injection" in value or "_file" in value:
                # this is a file inclusion
                file_to_read_regexp = re.compile(r'file\((?P<file>.*)\)')
                file_to_read = file_to_read_regexp.search(ab_request.response.content)
                return 4, [key, file_to_read.group("file")]
            elif "sqli" in value:
                # this is a SQLi for dumping the database
                return 5, [key]
    elif "honest" == ab_request.sender and "webapplication" == ab_request.receiver:
        for c in ab_request.params:
            key = c
            value = ab_request.params[c]
            if "xss" in value:
                # this is a reflected XSS since the honest entity is
                # communicating with the webapplication
                return 6,[key]
    elif "webapplication" == ab_request.response.sender and "honest" == ab_request.response.sender:
        # this is the response to the request
        if xss in ab_request.response.content:
            # this is an XSS response to the honest
            return 7,[None]
    return -1, [None]

def _get_params(line):
    # parses the parameters line and creates a dictionary
    # (probably there is a more pythonic way of doing this)
    ret = dict()
    if line == "none":
        return ret
    for c in [c.split(".eq.") for c in line.split(".emp.")]:
        ret[c[0]] = c[1]
    return ret


