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

from modules.logger import logger

# external software
CLATSE = "modules/mc/cl-atse_x86_64-mac"

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
        out,err = p1.communicate(timeout=600)
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
Takes as input an msc and returns one array with requests
and responses in order of execution.
For each step, add the corresponding tag number.
[ (tag#,(actor1,actor2,message)), ... ]
"""
def parse_msc(aat):
    logger.info("Parsing the Message Sequence Chart")
    msc = aat.replace(" ","")
    lines = msc.split("\n")
    result = []
    request_regexp = re.compile(r'(.*?)\*->\*(.*?):(?:.*?).http_request\((.*)\)\.tag([0-9]*)')
    response_regexp = re.compile(r'(.*?)\*->\*(.*?):http_response\((.*)\)')
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
                result.append((tag + tmp_request.group(4),(tmp_request.group(1),tmp_request.group(2),tmp_request.group(3))))
            else:
                tmp_response = response_regexp.match(line)
                if tmp_response:
                    # we have found a response
                    result.append((tag,(tmp_response.group(1),tmp_response.group(2),tmp_response.group(3))))
    return result
