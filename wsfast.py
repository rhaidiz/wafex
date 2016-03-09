#!/usr/bin/env python3.5

"""
WSFAST main file
"""

import glob
import shutil
import atexit
import config
import os.path
import argparse
import logging

from modules.filesystem.fs import filesystem
from modules.sqli.sqli import sqli
from modules.engine import execute_attack
from modules.logger import logger
from modules.mc import mc
from modules.filemerger import merger



def main():
    # command line parsing
    cmd = argparse.ArgumentParser()
    cmd.add_argument("model",help="The model written in ASLAn++")
    cmd.add_argument("--c",metavar="concre_file",help="The concretization file, needed for executing the whole trace")
    cmd.add_argument("--debug",help="Print debug messages",action="store_true")
    cmd.add_argument("--mc-only",help="Run the model-checker only",action="store_true")
    cmd.add_argument("--merger",help="Use the specified file as a base file to merge with the given model",metavar="merger")
    cmd.add_argument("--verbose", help="Increase the output verbosity",action="store_true")
    translator = cmd.add_argument_group('Translator')
    translator_versions = ["1.4.1","1.4.9","1.3"]
    translator.add_argument("--translator",help="Specify a jar translator to use. Allowed values are "+", ".join(translator_versions)+". Default (1.4.1)", metavar='',choices=translator_versions)

    requests = cmd.add_argument_group("HTTP(S) options")
    requests.add_argument("--proxy",help="Use an HTTP proxy when executing requests")
    requests.add_argument("--keep-set-cookie",help="Keep Set-Cookie header from response",action="store_true")

    args = cmd.parse_args()
    load_model = args.model

    # check if model file exists
    if not os.path.isfile(load_model):
        logger.critical("Error: " + load_model + " file not found")
        exit()
    # check if concretization file exists only if --mc-only hasn't been specified
    if args.c == None and not args.mc_only:
        logger.critical("Concretization file not specified")
        exit()
    elif not args.mc_only and not os.path.isfile(args.c):
        logger("Error: " + args.c + " file not found")
        exit()
    elif not args.mc_only and args.c != None and  os.path.isfile(args.c):
        config.concretization = args.c

    # register exiting cleanup function
    atexit.register(exitcleanup)

    # set global variables
    config.verbosity = args.verbose
    config.DEBUG = args.debug

    if config.DEBUG:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    config.proxy = args.proxy
    config.keep_cookie = args.keep_set_cookie
    if args.translator == "1.4.9":
        mc.connector = config.CONNECTOR_1_4_9
    if args.translator == "1.3":
        mc.connector = config.CONNECTOR_1_3

    if args.merger:
        base_model = args.merger
        webapp = load_model
        load_model = "out.aslan++"
        # merge the files
        merger(webapp,base_model,load_model)

    # first thing is to confert the ASLan++ model in ASLan
    file_aslan_model, err = mc.aslanpp2aslan(load_model)

    # we can now run the model checker, by default we use Cl-Atse locally
    file_attack_trace = mc.local_cl_atse(file_aslan_model)

    # translate the attack trace in msc
    msc_output = mc.generate_msc(file_attack_trace,file_aslan_model)

    if not args.mc_only:
         # read the output and parse it
         msc_table = mc.parse_msc(msc_output)
         concretization_json = {}
         sqli_matrix = sqli(msc_table,concretization_json)
         fs_matrix = filesystem(msc_table,concretization_json)
         logger.info(concretization_json)

         # execute the attack trace
         execute_attack(msc_table,concretization_json,load_model)



def exitcleanup():
    # remove temporary files
    logger.info("Exiting wsfast..., removing temporary files!")
    for fl in glob.glob("./tmp_*"):
        os.remove(fl)
    logger.info("Bye!")


if __name__ == "__main__":
    main()
