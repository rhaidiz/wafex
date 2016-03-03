#!/usr/bin/env python3.5


"""
This library provides convenient methods for executing wfuzz
NOTE: Only tested with python3.5
"""
import time
import json
import atexit
import shutil
import os.path
import requests
import threading
import subprocess

from modules.logger import logger


WFUZZ          = ["./wfuzz.py"]
wfuzz_process      = None



"""
Configure the command line parameters
"""
def set_param(k,v=""):
    global WFUZZ
    WFUZZ.append(k)
    if v != "":
        WFUZZ.append(v)

"""
Execute the fuzzer and get the json back
"""

def run_wfuzz(url):
    global WFUZZ
    WFUZZ.append(url)
    logger.debug(WFUZZ)
    p1 = subprocess.Popen(WFUZZ,cwd="./wfuzz/",universal_newlines=True,stderr=subprocess.PIPE,stdout=subprocess.PIPE)
    try:
        out, err = p1.communicate(timeout=10)
        return json.loads(out)
    except subprocess.TimeoutExpired:
        p1.kill()
        logger.critical("Error: wfuzz timed out.")
        exit()


if __name__ == "__main__":
    set_param("-w","prova.txt")
    set_param("--basic","regis:password")
    set_param("-o","json")
    set_param("--ss","root")
    o = run_wfuzz("https://157.27.244.25/chained/chained/index.php?file=FUZZ")
    print(o)


