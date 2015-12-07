#!/usr/local/bin/python3.5

import argparse
import os.path

# custom import
import aat
import mc
import parser
import global_var


def main():
    # command line parsing
    cmd = argparse.ArgumentParser()
    cmd.add_argument("model",help="The model written in ASLAn++")
    cmd.add_argument("--debug",help="Print debug messages",action="store_true")
    cmd.add_argument("--mc-only",help="Run the model-checker only",action="store_true")
    cmd.add_argument("--verbose", help="Increase the output verbosity",action="store_true")
    args = cmd.parse_args()
    load_model = args.model

    # check if file exists
    if not os.path.isfile(load_model):
        print("Error: " + load_model + " file not found")
        exit()
    global_var.verbosity = args.verbose
    global_var.DEBUG = args.debug
    

    # first thing is to run the translator, by default we use version 1.4.1
    file_aslan_model, err = mc.translator(load_model)

    # check if an error has been generated from the translator
    if "FATAL" in err or "ERROR" in err:
        # there was an error in executing the translator
        cprint("Translator generated an error","ERROR")
        print(err)
        exit()

    if global_var.verbosity and "WARNING" in err:
        print(err)


    # we can now run the model checker, by default we use Cl-Atse locally 
    file_attack_trace = mc.local_cl_atse(file_aslan_model)


    # translate the attack trace in msc 
    msc_output = mc.generate_msc(file_attack_trace,file_aslan_model)

    if not args.mc_only:
         # read the output and parse it
         msc_table = parser.msc(msc_output,file_attack_trace)

         sqli_matrix = parser.sqli(msc_table)

         aat.execute_attack(msc_table,sqli_matrix,load_model)


    


if __name__ == "__main__":
    main()
