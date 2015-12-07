#!/usr/local/bin/python3.5

"""
Wrapper around the sqlmap tool. This wrapper provides 
convenient methods for executing sqlmap and returning 
its output.
"""
#import ../global_var
import subprocess
import pexpect
from sys import platform as _platform

import time
import requests
import json
#from threading import Thread # This is the right package name
#from threading import Event # This is the right package name
import threading

SQLMAP_API = "./sqlmapapi.py -s"

SQLMAP_SERVER_IP = "127.0.0.1"
SQLMAP_SERVER_PORT = "8775"
SQLMAP_BASE_URL = "http://"+SQLMAP_SERVER_IP+":"+SQLMAP_SERVER_PORT

sqlmap_process = ""

def run_api_server():
    global sqlmap_process
    print("Executing")
    # NOTE: when executing sqlmapapi.py the working directory must be ./sqlmap/ otherwise when the analysis
    # is started, it raises an not fil execptio 'cause it cannot find sqlmap.py
    sqlmap_process = subprocess.Popen(SQLMAP_API.split(" "),stderr=subprocess.PIPE, stdout=subprocess.PIPE,cwd="./sqlmap/")
    print("""
     _____  _____ _                             
    /  ___||  _  | |                            
    \ `--. | | | | |      _ __ ___   __ _ _ __  
     `--. \| | | | |     | '_ ` _ \ / _` | '_ \ 
     /\__/ /\ \/' / |____ | | | | | | (_| | |_) |
     \____/  \_/\_\_____/ |_| |_| |_|\__,_| .__/ 
                                  | |      API    
                                  |_|""")
    while True:
        line = sqlmap_process.stdout.readline()
        if "REST-JSON API server connected to IPC database" in line.decode('utf-8'):
            # the webserver is up and running
            return
        if not line: break
    print("done")

def kill():
    global sqlmap_process
    sqlmap_process.kill()


# set a value for an option to a task_id
def set_option(option,value,task_id):
    url = SQLMAP_BASE_URL+"/option/"+task_id+"/set"
    params = { option : value }
    print("task " + task_id +" setting " + option + " to " + value )
    r = requests.post(url,json=params)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        print("JSON decoder error")
        exit()
    #print(json_result)
    if json_result['success'] == True:
        return True
    else:
        return False

def new_task():
    url = SQLMAP_BASE_URL+"/task/new"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        print("JSON decoder error")
        exit()
    if json_result['success'] == True:
        return json_result['taskid']
    else:
        return False

def del_task(task_id):
    url = SQLMAP_BASE_URL+"/task/"+task_id+"/delete"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        print("JSON decoder error")
        exit()
    return json_result['success']

# when sqlmap dumps something, it is saved in ~/.sqlmap/output/<target>/dump/
def sqlmap_result():
        print("reading result")


def start_scan(url_to_scan,task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/start"
    params = { "url" : url_to_scan }
    r = requests.post(url,json=params)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        print("JSON decoder error")
        print(str(e))
        #print(e)
        exit()
    if json_result['success'] == True:
        return json_result['engineid']
    else:
        return False

def get_status(task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/status"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        print("JSON decoder error")
        exit()
    return json_result['status']


def get_log(task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/log"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        print("JSON decoder error")
        exit()
    return json_result['log']


def get_data(task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/data"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        print("JSON decoder error")
        exit()
    return json_result


def kill_task(task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/kill"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        print("JSON decoder error")
        exit()
    if json_result['success'] == True:
        return json_result
    else:
        return False


class MyThread(threading.Thread):
    def __init__(self, event,task):
        threading.Thread.__init__(self)
        self.stopped = event
        self.task = task

    def run(self):
        while not self.stopped.wait(5):
            print("my thread")
            r = sqlmap_get_status(self.task)
            if "terminated" in r:
                print("Analysis terminated")
                self.stopped.set()
            else:
                print("Analysis in progress ... ")
            # call a function


if __name__ == "__main__":
    #---------------------#
    # Testing the wrapper #
    #---------------------#
    sqlmap_run_api_server()
    task = sqlmap_new_task()
    print("Created a new task " + task)

    ## configuring the scanner for testing the chained attack case
    print(sqlmap_option_set("authType","Basic",task))
    print(sqlmap_option_set("authCred","regis:password",task))
    print(sqlmap_option_set("data","username=a&password=0",task))
    print(sqlmap_option_set("getTables","true",task))

    # starting the scan
    print(sqlmap_start_scan(task,"https://157.27.244.25/chained/chained/index.php"))

    stopFlag = threading.Event()

    # Thread checking when sqlmap ends
    #thread = MyThread(stopFlag,task)
    #thread.start()
    #print("Hello world")
    # this will stop the timer
    #stopFlag.set()

    # blocking code that checks when sqlmap ends
    while not stopFlag.wait(5):
        print("my thread")
        r = sqlmap_get_status(task)
        if "terminated" in r:
            print("Analysis terminated")
            print(sqlmap_get_data(task))
            stopFlag.set()
            sqlmap_kill()
        else:
            print("Analysis in progress ... ")



