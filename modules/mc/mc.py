#!/usr/local/bin/python3.5

"""
This module implements methods wrapping
the AVANTSSAR platform.
"""

import os.path
import subprocess
import re
import config
from modules.logger import cprint

# external software
CLATSE = "modules/mc/cl-atse_x86_64-mac"

# default value for the connector
connector = config.CONNECTOR_1_4_1

"""
Generates the message sequence chart 
from an attack trace file and the ASLan model
"""
def generate_msc(file_attack_trace,file_aslan_model):
    tmp_attack_trace = ""
    p1 = subprocess.Popen(["java","-jar",connector,"-ar",file_attack_trace,file_aslan_model],universal_newlines=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        out,err = p1.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        p1.kill()
        cprint("MSC creation timed out","E")
        exit()
    if config.verbosity:
        # print the generated output on a file
        msc_verbose = open("tmp_msc.txt","w")
        msc_verbose.write(out)
        msc_verbose.close()
    f = open(file_attack_trace)
    for line in f.readlines():
        if "SUMMARY ATTACK_FOUND" in line:
            # we found an attack, so return the generated MSC
            i = out.find("MESSAGES:")
            msc = out[i+9:]
            cprint("Abstract Attack Trace found:","I")
            print(msc)
            return msc
        elif "SUMMARY NO_ATTACK_FOUND" in line:
            # no attack found, we don't need the MSC
            cprint("NO ATTACK FOUND","I") 
            return ""

"""
Execute the CL-Atse model checker locally
"""
def local_cl_atse(file_aslan):
    global CLATSE
    cprint("Executing CL-Atse locally","I")
    atse_output = os.path.splitext(file_aslan)[0] + ".atse"
    atse_output_descriptor = open(atse_output,"w")
    p1 = subprocess.Popen([CLATSE,file_aslan],universal_newlines=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        out,err = p1.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        p1.kill()
        cprint("Model checker timed out","E")
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
    basename = os.path.splitext(os.path.basename(file_aslanpp))[0]
    translator_output_file = "tmp_"+basename+".aslan"

    cprint("Generating ASlan model","I")
    cprint(connector + " on "+file_aslanpp + " output file " + translator_output_file,"V")

    p1 = subprocess.Popen(["java","-jar",connector,file_aslanpp,"-o",translator_output_file],universal_newlines=True,stderr=subprocess.PIPE)

    try:
        out,err = p1.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p1.kill()
        cprint("Error: " + connector + " timed out.","E")
        exit()


    # check if an error has been generated from the translator
    if "FATAL" in err or "ERROR" in err:
        # there was an error in executing the translator
        cprint("Translator generated an error","E")
        cprint(err,"E")
        exit()

    if config.verbosity and "WARNING" in err:
        cprint(err.strip(),"V")
    cprint("ASlan model generated","I")    
    return translator_output_file, err


