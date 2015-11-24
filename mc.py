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

# external software
CONNECTOR_1_4 = "connector/aslanpp-connector-1.4.1.jar"
CLATSE = "mc/cl-atse_x86_64-mac"

# global variables
connector = CONNECTOR_1_4

def generate_msc(attack_trace_file,aslan_model):
    tmp_attack_trace = ""
    f = open(attack_trace_file)
    for line in f.readlines():
        if "SUMMARY ATTACK_FOUND" in line:
            # we found an attack, so we generate the MSC
            p1 = subprocess.Popen(["java","-jar",connector,"-ar",attack_trace_file,aslan_model],universal_newlines=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            out,err = p1.communicate(timeout=10)
            i = out.find("MESSAGES:")
            msc = out[i+9:]
            if global_var.verbosity:
                print(msc)
            return msc
        elif "SUMMARY NO_ATTACK_FOUND" in line:
            # no attack found, we don't need the MSC
            print("NO ATTACK FOUND")
            return ""


def local_cl_atse(aslan):
    global CLATSE
    atse_output = os.path.splitext(aslan)[0] + ".atse"
    atse_output_descriptor = open(atse_output,"w")
    p1 = subprocess.Popen([CLATSE,aslan],universal_newlines=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        out,err = p1.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        p1.kill()
        print("Error: model checker timed out")
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
        print("Executing translator " + connector + " on "+model + " output file " + translator_output_file)
    p1 = subprocess.Popen(["java","-jar",connector,model,"-o",translator_output_file],universal_newlines=True,stderr=subprocess.PIPE)

    try:
        out,err = p1.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p1.kill()
        print("Error: " + connector + " timed out.")
        exit()

    if "FATAL" in err or "ERROR" in err:
        # there was an error in executing the translator
        print("# ---- Error translator ---- #")
        print(err)
        print("# -------------------------- #")
        exit()

    if global_var.verbosity and "WARNING" in err:
        print(err)

    return translator_output_file


# returns one array with requests and responses in order of execution
def parse_aat(aat):
    DEBUG = 0

    aat = aat.replace(" ","")
    lines = aat.split("\n")
    result = []
    for line in lines:
        if line:
            request_regexp = re.compile(r'(.*?)->\*(.*?):(?:.*?).http_request\((.*)\)')
            response_regexp = re.compile(r'(.*?)->\*(.*?):http_response\((.*?)\)')
            tmp = request_regexp.findall(line)
            if not tmp:
                tmp = response_regexp.findall(line)
            if len(tmp) == 1:
                result.append(tmp[0])
    if DEBUG:
        print(__name__ + " result")
        print(result)
        print("################")
    return result
