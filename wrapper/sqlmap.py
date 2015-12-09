#!/usr/local/bin/python3.5

"""
Wrapper around the sqlmap tool. This wrapper provides 
convenient methods for executing sqlmap and returning 
its output.
"""
#import global_var
from  my_print import cprint
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

sqlmap_process = None

def run_api_server():
    global sqlmap_process
    # NOTE: when executing sqlmapapi.py the working directory must be ./sqlmap/ otherwise when the analysis
    # is started, it raises an not fil execptio 'cause it cannot find sqlmap.py
    sqlmap_process = subprocess.Popen(SQLMAP_API.split(" "),stderr=subprocess.PIPE, stdout=subprocess.PIPE,cwd="./sqlmap/")
    cprint("""
     _____  _____ _                             
    /  ___||  _  | |                            
    \ `--. | | | | |      _ __ ___   __ _ _ __  
     `--. \| | | | |     | '_ ` _ \ / _` | '_ \ 
     /\__/ /\ \/' / |____ | | | | | | (_| | |_) |
     \____/  \_/\_\_____/ |_| |_| |_|\__,_| .__/ 
                                  | |      API    
                                  |_|""","INFO")
    while True:
        line = sqlmap_process.stdout.readline()
        if "REST-JSON API server connected to IPC database" in line.decode('utf-8'):
            # the webserver is up and running
            return
        if not line: break

def kill():
    sqlmap_process.kill()


# set a value for an option to a task_id
def set_option(option,value,task_id):
    url = SQLMAP_BASE_URL+"/option/"+task_id+"/set"
    params = { option : value }
    cprint("task " + task_id +" setting " + option + " to " + value ,"DEBUG")
    r = requests.post(url,json=params)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        cprint("JSON decoder error","ERROR")
        exit()
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
        cprint("JSON decoder error","ERROR")
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
        cprint("JSON decoder error","ERROR")
        exit()
    return json_result['success']

def start_scan(url_to_scan,task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/start"
    params = { "url" : url_to_scan }
    r = requests.post(url,json=params)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        cprint("Start scan JSON decoder error","ERROR")
        cprint(str(e),"DEBUG")
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
        cprint("JSON decoder error","ERROR")
        exit()
    return json_result['status']


def get_log(task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/log"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        cprint("JSON decoder error","ERROR")
        exit()
    return json_result['log']


def get_data(task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/data"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        cprint("JSON decoder error","ERROR")
        exit()
    return json_result


def kill_task(task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/kill"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        cprint("JSON decoder error","ERROR")
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
            r = get_status(self.task)
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

    # Thread checking when sqlmap ends
    #thread = MyThread(stopFlag,task)
    #thread.start()
    #print("Hello world")
    # this will stop the timer
    #stopFlag.set()

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



