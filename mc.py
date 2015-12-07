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

def generate_msc(file_attack_trace,file_aslan_model):
    tmp_attack_trace = ""
    p1 = subprocess.Popen(["java","-jar",connector,"-ar",file_attack_trace,file_aslan_model],universal_newlines=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        out,err = p1.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        p1.kill()
        cprint("MSC creation timed out","ERROR")
        exit()
    f = open(file_attack_trace)
    for line in f.readlines():
        if "SUMMARY ATTACK_FOUND" in line:
            # we found an attack, so return the generated MSC
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


def local_cl_atse(file_aslan):
    global CLATSE
    cprint("Executing CL-Atse locally","INFO")
    atse_output = os.path.splitext(file_aslan)[0] + ".atse"
    atse_output_descriptor = open(atse_output,"w")
    p1 = subprocess.Popen([CLATSE,file_aslan],universal_newlines=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        out,err = p1.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        p1.kill()
        cprint("Model checker timed out","ERROR")
        exit()
    atse_output_descriptor.write(out)
    atse_output_descriptor.close()
    return atse_output

"""
Executes the translator on the given ASLan++ file 
"""
def translator(file_model):
    global connector
    # get the filename without extension
    basename = os.path.splitext(os.path.basename(file_model))[0]
    translator_output_file = "tmp_"+basename+".aslan"
    if global_var.verbosity:
        cprint("Executing translator " + connector + " on "+file_model + " output file " + translator_output_file,"VERBOSITY")
    else:
        cprint("Executing the translator","INFO")
    p1 = subprocess.Popen(["java","-jar",connector,file_model,"-o",translator_output_file],universal_newlines=True,stderr=subprocess.PIPE)

    try:
        out,err = p1.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p1.kill()
        cprint("Error: " + connector + " timed out.","INFO")
        exit()


    return translator_output_file, err



