#!/usr/local/bin/python3.5

"""
Wrapper around the sqlmap tool. This wrapper provides 
convenient methods for executing sqlmap and parsing its 
output.
"""
#import ../global_var
import subprocess
import pexpect
from sys import platform as _platform

import requests
import json
#from threading import Thread # This is the right package name
#from threading import Event # This is the right package name
import threading

#options = " --auth-type=basic --auth-cred=regis:password -u https://157.27.244.25/joomla3.4.4/index.php?option=com_contenthistory&view=history&list[select]=injection -p list[select] -T ppdqj_session --v 3"
options = " --auth-type=basic --auth-cred=regis:password -u https://157.27.244.25/chained/chained/index.php -T users --v 3"
SQLMAP_LOCATION = "xterm -e ./sqlmap/sqlmap.py" + options

SQLMAP_API = "./sqlmap/sqlmapapi.py -s"

SQLMAP_SERVER_IP = "127.0.0.1"
SQLMAP_SERVER_PORT = "8775"
SQLMAP_BASE_URL = "http://"+SQLMAP_SERVER_IP+":"+SQLMAP_SERVER_PORT

# notes: sqlmap executes and, at the ends, report a log in ~/.sqlmap/ folder
# probably the best option is to not capture the output from sqlmap, but to
# retrieve it from that folder after the execution.

# write a python wrapper for the sqlmapapi.py script

# run sqlmap with the specified arguments
def __exec_sqlmap_api():
    print("Executing sqlmap")
    # executing the sqlmapapi 
    p1 = subprocess.Popen(SQLMAP_API.split(" "),stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    #while True:
    #    line = p1.stdout.readline()
    #    print(line.decode('utf-8'))
    #    if not line: break
   # out,err = p1.communicate()
   # print(out)
    
    print("done")

# set a value for an option to a task_id
def sqlmap_option_set(option,value,task_id):
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

def sqlmap_new_task():
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

def sqlmap_del_task(task_id):
    url = SQLMAP_BASE_URL+"/task/"+task_id+"/delete"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        print("JSON decoder error")
        exit()
    return json_result['success']

# when sqlmap dumps something, it is saved in ~/.sqlmap/output/<target>/dump/
def retrieve_sqlmap_result():
        print("reading result")


def sqlmap_start_scan(task_id,url_to_scan):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/start"
    params = { "url" : url_to_scan }
    r = requests.post(url,json=params)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        print("JSON decoder error")
        #print(e)
        exit()
    if json_result['success'] == True:
        return json_result['engineid']
    else:
        return False

def sqlmap_get_status(task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/status"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        print("JSON decoder error")
        exit()
    return json_result['status']


def sqlmap_get_log(task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/log"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        print("JSON decoder error")
        exit()
    return json_result['log']


def sqlmap_get_data(task_id):
    url = SQLMAP_BASE_URL+"/scan/"+task_id+"/data"
    r = requests.get(url)
    try:
        json_result = json.loads(r.text)
    except json.decoder.JSONDecodeError as e:
        print("JSON decoder error")
        exit()
    return json_result

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
    task = sqlmap_new_task()

    # configuring the scanner for testing the chained attack case
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
        else:
            print("Analysis in progress ... ")



