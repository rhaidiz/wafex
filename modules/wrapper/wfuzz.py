#!/usr/bin/env python3.5

import time
import json
import atexit
import shutil
import os.path
import requests
import threading
import subprocess

from modules.logger import logger

class Wfuzz:
    """
    This class provides a python wrapper for running wfuzz
    NOTE: Only tested with python3.5
    """

    def __init__(self):
        self._wfuzz_cmd = ["./wfuzz.py"]
        self._wfuzz_path = "./wfuzz/"

    def set_param(self, k, v):
        """
        Sets a parameter for executing Wfuzz.
        :param k: flag paramenter
        :param v: value of the flag
        """
        if k and v:
            # extend if both k and v are given
            self._wfuzz_cmd.extend([k,v])
        elif k:
            # append if only k is give (a boolean flag)
            self._wfuzz_cmd.append(k)


    def run_wfuzz(self, url):
        """
        Executes Wfuzz and returns a list of files retrieved during the fuzzing.
        :param url: the url of the target
        """
        self._wfuzz_cmd.append(url)
        debugMsg = "executing WFUZZ {}".format(self._wfuzz_cmd)
        logger.debug(debugMsg)
        p1 = subprocess.Popen(self._wfuzz_cmd, cwd=self._wfuzz_path, universal_newlines=True,stderr=subprocess.PIPE,stdout=subprocess.PIPE)
        try:
            out, err = p1.communicate(timeout=10)
            debugMsg = "wfuzz out {}".format(out)
            logger.debug(debugMsg)
            # return a list containing the successful URL
            urls = []
            json_out = json.loads(out)
            for req in json_out:
                urls.append(req["url"])
            return urls
        except subprocess.TimeoutExpired:
            p1.kill()
            logger.critical("Error: wfuzz timed out.")
            exit()
    

