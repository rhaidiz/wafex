#!/usr/local/bin/python3.5

import argparse
import os.path

# custom import
import aat
import mc
import global_var


def main():
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
    global_var.verbosity = args.verbose 
    

    # first thing is to run the translator, by default we use version 1.4.1
    aslan_model = mc.translator(load_model)

    print("Executing model checker")
    # we can now run the model checker, by default we use Cl-Atse in local mode
    attack_trace_file = mc.local_cl_atse(aslan_model)


    # we now check the generated file
    msc = mc.generate_msc(attack_trace_file,aslan_model)

    # read the output and parse it
    tracia = mc.parse_aat(msc)

    sqli_matrix = aat.extend_trace_sqli(tracia)

    aat.execute_attack(tracia,sqli_matrix)


    
#def generate_msc(attack_file,aslan_model):
#    global verbosity
#    global connector
#    p1 = subprocess.Popen(["java","-jar",connector,"-ar",attack_file,aslan_model],universal_newlines=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)
#    out,err = p1.communicate(timeout=10)
#    i = out.find("MESSAGES:")
#    print(out[i+9:])


if __name__ == "__main__":
    main()
