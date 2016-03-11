#!/usr/bin/env python3.5

"""
This library provides convenient methods for executing
and accessing sqlmap APIs.
NOTE: Only tested with python3.5
"""


import time
import json
import atexit
import shutil
import pexpect
import os.path
import requests
import threading
import subprocess

from modules.logger import logger


SQLMAP_API          = "./sqlmapapi.py -s"
SQLMAP_SERVER_IP    = "127.0.0.1"
SQLMAP_SERVER_PORT  = "8775"
SQLMAP_BASE_URL     = "http://"+SQLMAP_SERVER_IP+":"+SQLMAP_SERVER_PORT
sqlmap_process      = None


""" Run the api as a web server """
def run_api_server():
    global sqlmap_process
    atexit.register(exiting)
    logger.info("starting sqlmap APIs")
    # NOTE: when executing sqlmapapi.py the working directory must be ./sqlmap/ otherwise when the analysis
    # is started, it raises a not file execeptio 'cause it cannot find sqlmap.py
    sqlmap_process = subprocess.Popen(SQLMAP_API.split(" "),stderr=subprocess.PIPE, stdout=subprocess.PIPE,cwd="./sqlmap/")
    while True:
        line = sqlmap_process.stdout.readline()
        if "REST-JSON API server connected to IPC database" in line.decode('utf-8'):
            # the webserver is up and running
            return True
    raise Exception()
    return False

""" Kill sqlmap API process """
def kill():
    sqlmap_process.kill()

""" Set a value for a specified task_id """
def set_option(option,value,task_id):
    url = SQLMAP_BASE_URL+"/option/"+task_id+"/set"
    params = { option : value }
    debugMsg = "task {} setting {} to {}".format(task_id, option, value)
    logger.debug(debugMsg)
    r = requests.post(url,json=params)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        logger.critical("JSON decoder error")
        exit()
    if json_result['success'] == True:
        return True
    else:
        return False


""" Create a new task """
def new_task():
    #time.sleep(1)
    url = SQLMAP_BASE_URL+"/task/new"
    try:
        r = requests.get(url)
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        logger.critical("JSON decoder error")
        exit()
    except Exception as e:
        criticalMsg = "Somethin bad happened {}".format(e)
        logger.critical(criticalMsg)
    if json_result['success'] == True:
        return json_result['taskid']
    else:
        return False

""" Delete a task """
def del_task(task_id):
    url = SQLMAP_BASE_URL+"/task/"+task_id+"/delete"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        logger.critical("JSON decoder error")
        exit()
    return json_result['success']

""" Start scanning """
def start_scan(url_to_scan,task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/start"
    params = { "url" : url_to_scan }
    r = requests.post(url,json=params)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        logger.critical("JSON decoder error")
        exit()
    if json_result['success'] == True:
        return json_result['engineid']
    else:
        return False

""" Retrive sqlmap status """
def get_status(task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/status"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        logger.critical("JSON decoder error")
        exit()
    return json_result['status']

""" Retrieve sqlmap log """
def get_log(task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/log"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        logger.critical("JSON decoder error")
        exit()
    return json_result['log']

""" Get result data """
def get_data(task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/data"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        logger.critical("JSON decoder error")
        exit()
    return json_result

""" Kill a specified task """
def kill_task(task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/kill"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        logger.critical("JSON decoder error")
        exit()
    if json_result['success'] == True:
        return json_result
    else:
        return False

""" Exiting """
def exiting():
    kill()
    logger.debug("Done!")

if __name__ == "__main__":
    #---------------------#
    # Testing the library #
    #---------------------#
    run_api_server()
    task = new_task()
    print("Created a new task " + task)

    ## configuring the scanner for testing the chained attack case
    print(set_option("authType","Basic",task))
    print(set_option("authCred","regis:password",task))
    print(set_option("data","username=a&password=0",task))
    print(set_option("getTables","true",task))

    # starting the scan
    print(start_scan(task,"https://157.27.244.25/chained/chained/index.php"))

    stopFlag = threading.Event()

    # blocking code that checks when sqlmap ends
    while not stopFlag.wait(5):
        print("my thread")
        r = get_status(task)
        if "terminated" in r:
            print("Analysis terminated")
            print(get_data(task))
            stopFlag.set()
            kill()
        else:
            print("Analysis in progress ... ")



