#!/usr/local/bin/python3.5

"""
WSFAST main file
"""

import argparse
import os.path
import engine
from mc import mc
import parser
import global_var
from my_print import cprint
import atexit

def main():
    # command line parsing
    cmd = argparse.ArgumentParser()
    cmd.add_argument("model",help="The model written in ASLAn++")
    cmd.add_argument("concret",help="The concretization details written in JSON")
    cmd.add_argument("--debug",help="Print debug messages",action="store_true")
    cmd.add_argument("--mc-only",help="Run the model-checker only",action="store_true")
    cmd.add_argument("--verbose", help="Increase the output verbosity",action="store_true")
    translator = cmd.add_argument_group('Translator')
    translator_versions = ["1.4.1","1.4.9","1.3"]
    translator.add_argument("--translator",help="Specify a jar translator to use. Allowed values are "+", ".join(translator_versions)+". Default (1.4.1)", metavar='',choices=translator_versions)
    
    requests = cmd.add_argument_group("Requests")
    requests.add_argument("--proxy",help="Use an HTTP proxy when executing requests")
    
    args = cmd.parse_args()
    load_model = args.model

    # check if file exists
    if not os.path.isfile(load_model):
        print("Error: " + load_model + " file not found")
        exit()
    # check if file exists
    if not os.path.isfile(args.concret):
        print("Error: " + args.concret + " file not found")
        exit()

    # register exiting cleanup function
    atexit.register(exitcleanup)
    
    # set global variables 
    global_var.verbosity = args.verbose
    global_var.DEBUG = args.debug
    global_var.proxy = args.proxy
    global_var.concretization = args.concret
    if args.translator == "1.4.9":
        mc.connector = global_var.CONNECTOR_1_4_9
    if args.translator == "1.3":
        mc.connector = global_var.CONNECTOR_1_3
    

    # first thing is to confert the ASLan++ model in ASLan
    file_aslan_model, err = mc.aslanpp2aslan(load_model)

    # check if an error has been generated from the translator
    if "FATAL" in err or "ERROR" in err:
        # there was an error in executing the translator
        cprint("Translator generated an error","E")
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
         msc_table = parser.msc(msc_output)
         sqli_matrix = parser.sqli(msc_table)

         # execute the attack trace
         engine.execute_attack(msc_table,sqli_matrix,load_model)


    
def exitcleanup():
    print("exiting")


if __name__ == "__main__":
    main()
