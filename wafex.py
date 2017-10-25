#!/usr/bin/env python3

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
import modules.utils as utils

from modules.filesystem.fs import filesystem
from modules.sqli.sqli import sqli
from modules.engine import execute_attack
from modules.logger import logger
from modules.mc import mc
from modules.filemerger import merger
from abstrac_http import AbstractHttpRequest
from abstrac_http import AbstractHttpResponse



def main():
    # command line parsing
    cmd = argparse.ArgumentParser()
    cmd.add_argument("model",help="An ASLAn++ model")
    cmd.add_argument("--c",metavar="concre_file",help="The concretization file, needed for executing Abstract Attack Trace")
    cmd.add_argument("--debug",help="Print debug messages",action="store_true")
    cmd.add_argument("--mc-only",help="Run the model-checker only and exit",action="store_true")
    cmd.add_argument("--interactive", help="Ask input of every parameter", action="store_true")
    #cmd.add_argument("--merger",help="Use the specified file as a base file to merge with the given model", metavar="basefile")
    cmd.add_argument("--verbose", help="Increase the output verbosity",action="store_true")
    translator = cmd.add_argument_group('Translator')
    translator_versions = ["1.4.1","1.4.9","1.3"]
    translator.add_argument("--translator",help="Specify a jar translator to use. Allowed values are "+", ".join(translator_versions)+". Default (1.4.1)", metavar='',choices=translator_versions)

    requests = cmd.add_argument_group("HTTP(S) options")
    requests.add_argument("--proxy", metavar="ip:port", help="Use an HTTP proxy when executing requests")

    model_checker = cmd.add_argument_group("Cl-Atse options")
    model_checker.add_argument("--mc-options",help="String representing the options to pass to Cl-Atse. For more information on the available options check Cl-Atse manual")
    model_checker.add_argument("--mc-timeout", metavar="T", help="If Cl-Atse runs more than T seconds, abort (default: 600)", type=int)

    args = cmd.parse_args()
    load_model = args.model


    mc_options = args.mc_options.split(" ") if args.mc_options else []
    if args.mc_timeout:
        config.mc_timeout = args.mc_timeout

    # check if model file exists
    if not os.path.isfile(load_model):
        criticalMsg = "Error {} file not found".format(load_model)
        logger.critical(criticalMsg)
        exit()
    # check if concretization file exists only if --mc-only hasn't been specified
    if args.c == None and not args.mc_only:
        logger.critical("Concretization file not specified")
        exit()
    elif not args.mc_only and not os.path.isfile(args.c):
        criticalMsg = "Error: {} file not found".format(args.c)
        logger.critical(criticalMsg)
        exit()
    elif not args.mc_only and args.c != None and  os.path.isfile(args.c):
        config.concretization = args.c

    print(config.BANNER.format(config.VERSION,config.SITE))

    # register exiting cleanup function
    atexit.register(exitcleanup)

    # set global variables
    config.verbosity = args.verbose
    config.DEBUG = args.debug

    # create folders if they do not exists
    if not os.path.isdir(config.WFAST_HOME):
        logger.info("Creating {} home folder".format(config.TOOL_NAME))
        os.makedirs(config.WFAST_HOME)
    if not os.path.isdir(config.WFAST_EXTRACTED_FILES_DIR):
        logger.info("Creating {} extracted files folder".format(config.TOOL_NAME))
        os.makedirs(config.WFAST_EXTRACTED_FILES_DIR)

    if config.DEBUG:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if args.proxy:
        proxy = args.proxy.split(":")
        if proxy[0] and proxy[1].isdigit():
            config.proxy_ip = proxy[0]
            config.proxy_port = proxy[1]
            print(config.proxy_ip)
            print(config.proxy_port)
        else:
            criticalMsg = "Invalid proxy format {}".format(args.proxy)
            logger.error(criticalMsg)
            exit(-1)
    if args.translator == "1.4.9":
        mc.connector = config.CONNECTOR_1_4_9
    if args.translator == "1.3":
        mc.connector = config.CONNECTOR_1_3

    # if args.merger:
    #     base_model = args.merger
    #     webapp = load_model
    #     load_model = "out.aslan++"
    #     # merge the files
    #     merger(webapp,base_model,load_model)

    # first thing is to confert the ASLan++ model in ASLan
    file_aslan_model, err = mc.aslanpp2aslan(load_model)

    # we can now run the model checker, by default we use Cl-Atse locally
    file_attack_trace = mc.local_cl_atse(file_aslan_model,mc_options)

    # translate the attack trace in msc
    msc_output = mc.generate_msc(file_attack_trace,file_aslan_model)


    if not args.mc_only:

        # read the output and parse it
        msc = mc.parse_msc(msc_output)

        logger.debug("Parsed MSC")
        for msg in msc:
            debugMsg = "{} {}:{}:{} {} > tag{}".format(msg.sender , msg.receiver, msg.params, msg.action, msg.action_params, msg.tag)
            logger.debug(debugMsg)

        # execute the attack trace
        execute_attack(msc)



def exitcleanup():
    # remove temporary files
    logger.info("Exiting wsfast...")
    if not config.DEBUG:
        logger.info("removing temporary files!")
        for fl in glob.glob("./tmp_*"):
            os.remove(fl)
    logger.info("Bye!")


if __name__ == "__main__":
    main()
