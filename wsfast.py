#!/usr/local/bin/python3.5

import argparse
import subprocess
import os.path

# external software
CONNECTOR_1_4 = "connector/aslanpp-connector-1.4.1.jar"
CLATSE = "mc/cl-atse_x86_64-mac"

# global variables
verbosity = None
connector = CONNECTOR_1_4

def main():
    global verbosity
    # command line parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("model",help="The model written in ASLAn++")
    parser.add_argument("--verbose", help="Increase the output verbosity",action="store_true")
    args = parser.parse_args()
    load_model = args.model

    # check if file exists
    if not os.path.isfile(load_model):
        print("Error: " + load_model + " file not found")
        exit()
    verbosity = args.verbose 
    

    # first thing is to run the translator, by default we use version 1.4.1
    aslan_model = translator(load_model)

    # we can now run the model checker, by default we use Cl-Atse in local mode
    attack_trace_file = local_cl_atse(aslan_model)

    tmp_attack_trace = ""
    f = open(attack_trace_file)
    for line in f.readlines():
        if "SUMMARY ATTACK_FOUND" in line:
        # we found an attack, so we generate the MSC
            generate_msc(attack_trace_file,aslan_model)
            break
        elif "SUMMARY NO_ATTACK_FOUND" in line:
        # no attack found, we don't need the MSC
            print("NO ATTACK FOUND")
            break


def local_cl_atse(aslan):
    global verbosity
    global CLATSE
    atse_output = os.path.splitext(aslan)[0] + ".atse"
    atse_output_descriptor = open(atse_output,"w")
    p1 = subprocess.Popen([CLATSE,aslan],universal_newlines=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        out,err = p1.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        p1.kill()
        print("Error: model checker timed out")
    atse_output_descriptor.write(out)
    atse_output_descriptor.close()
    return atse_output
    
def generate_msc(attack_file,aslan_model):
    global verbosity
    global connector
    p1 = subprocess.Popen(["java","-jar",connector,"-ar",attack_file,aslan_model],universal_newlines=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    out,err = p1.communicate(timeout=10)
    i = out.find("MESSAGES:")
    print(out[i+9:])

def translator(model):
    global verbosity
    global connector
    # get the filename without extension
    basename = os.path.splitext(os.path.basename(model))[0]
    translator_output_file = "tmp_"+basename+".aslan"
    if verbosity:
        print("Executing translator " + connector + " on "+model)
    p1 = subprocess.Popen(["java","-jar",connector,model,"-o",translator_output_file],universal_newlines=True,stderr=subprocess.PIPE, stdout=subprocess.DEVNULL)

    try:
        out,err = p1.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p1.kill()
        print("Error: " + connector + " timed out.")
    if "FATAL" in err:
        # there was a FATAL error in executing the translator
        if verbosity:
            print(err)
        else:
            print("Error translator")
        exit()

    return translator_output_file

if __name__ == "__main__":
    main()
