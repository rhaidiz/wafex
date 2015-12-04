#!/usr/local/bin/python3.5

"""
This module provides the specific model checking methods.
It provides methods for generating the attack trace and
for parsing the attack trace, generating an array of tuple
representing the MSC.
"""

import os.path
import subprocess
import re

# custom import
import global_var
from my_print import cprint

# external software
CONNECTOR_1_4 = "connector/aslanpp-connector-1.4.1.jar"
CLATSE = "mc/cl-atse_x86_64-mac"

# global variables
connector = CONNECTOR_1_4

def generate_msc(attack_trace_file,aslan_model):
    tmp_attack_trace = ""
    p1 = subprocess.Popen(["java","-jar",connector,"-ar",attack_trace_file,aslan_model],universal_newlines=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    out,err = p1.communicate(timeout=10)
    f = open(attack_trace_file)
    for line in f.readlines():
        if "SUMMARY ATTACK_FOUND" in line:
            # we found an attack, so we generate the MSC
            i = out.find("MESSAGES:")
            msc = out[i+9:]
            cprint("Abstract Attack Trace found:","INFO")
            if global_var.verbosity:
                print(out)
            else:
                print(msc)
            return msc
        elif "SUMMARY NO_ATTACK_FOUND" in line:
            # no attack found, we don't need the MSC
            if global_var.verbosity:
                print(out)
            else:    
               cprint("NO ATTACK FOUND","INFO") 
            return ""


def local_cl_atse(aslan):
    global CLATSE
    cprint("Executing CL-Atse locally","INFO")
    atse_output = os.path.splitext(aslan)[0] + ".atse"
    atse_output_descriptor = open(atse_output,"w")
    p1 = subprocess.Popen([CLATSE,aslan],universal_newlines=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        out,err = p1.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        p1.kill()
        cprint("Model checker timed out","ERROR")
        exit()
    atse_output_descriptor.write(out)
    atse_output_descriptor.close()
    return atse_output


def translator(model):
    global connector
    # get the filename without extension
    basename = os.path.splitext(os.path.basename(model))[0]
    translator_output_file = "tmp_"+basename+".aslan"
    if global_var.verbosity:
        cprint("Executing translator " + connector + " on "+model + " output file " + translator_output_file,"VERBOSITY")
    else:
        cprint("Executing the translator","INFO")
    p1 = subprocess.Popen(["java","-jar",connector,model,"-o",translator_output_file],universal_newlines=True,stderr=subprocess.PIPE)

    try:
        out,err = p1.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p1.kill()
        cprint("Error: " + connector + " timed out.","INFO")
        exit()

    if "FATAL" in err or "ERROR" in err:
        # there was an error in executing the translator
        cprint("Translator generated an error","ERROR")
        print(err)
        exit()

    if global_var.verbosity and "WARNING" in err:
        print(err)

    return translator_output_file


# returns one array with requests and responses in order of execution
# [ (src_line,(line)), ... ]


def parse_aat(aat,attack_trace_file):
    aat = aat.replace(" ","")
    lines = aat.split("\n")
    result = []
    request_regexp = re.compile(r'(.*?)\*->\*(.*?):(?:.*?).http_request\((.*)\)')
    response_regexp = re.compile(r'(.*?)\*->\*(.*?):http_response\((.*?)\)')
    rule = 2
    atse_output_descriptor = open(attack_trace_file,"r")
    line_num = 0
    for line in lines:
        if line:
            tmp_request = request_regexp.findall(line)
            tmp_response = None
            if not tmp_request: # not a request
                # search for a response
                tmp_response = response_regexp.findall(line)
            if len(tmp_request) == 1:
                print(tmp_request)
                # we have found a request
                line_num = __get_line_number(atse_output_descriptor,rule)
                if line_num:
                    line_num = line_num[0]
                    result.append((int(line_num),tmp_request[0]))
            elif len(tmp_response) == 1:
                # we have found a response
                line_num = __get_line_number(atse_output_descriptor,rule)
                if line_num:
                    line_num = line_num[0]
                    result.append((int(line_num),tmp_response[0]))
            rule += 1
    if global_var.DEBUG:
        cprint(__name__ + " result","DEBUG")
        cprint(result,"DEBUG")
        cprint("################","DEBUG")
    return result


def __get_line_number(file_descriptor,rule):
    # search for the line code
    found_line = False
    for line in file_descriptor:
        if line.startswith(str(rule)+" %"):
            found_line = True
        if found_line & line.startswith("  RULES"):
            line_regexp = re.compile(r'step_(?:.*?)__line_([0-9]*)')
            line_num = line_regexp.findall(line)
            if global_var.DEBUG:
                cprint("line number: " + line,"DEBUG")
                cprint(line_num,"DEBUG")
            return line_num
