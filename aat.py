#!/usr/local/bin/python3.5

# This module will provide functionality for parsing an
# ASLAn++ attack trace in the Alice and Bob motation

import re

def parse_aat(aat_file):
    # this regexp matches requests
    request_regexp = re.compile(r'(.*?)->\*(.*?):(.*?).request\((.*)\)')

    # this regexp matches responses
    response_regexp = re.compile(r'(.*?)->\*(.*?):(.*?).response\((.*?)\)(?:.tuple\((.*?)\))?')

    requests  = request_regexp.findall(aat_file)
    responses = response_regexp.findall(aat_file) 

    #print(requests)
    for req in requests:
        # read requests and check if the requests require an SQLi
        tuple_regexp = re.compile(r'tuple\(.*\)')
        sqli_regexp  = re.compile(r'sqli')
        has_tuple = tuple_regexp.findall(req[3])
        has_sqli  = sqli_regexp.findall(req[3])
        if not has_tuple and has_sqli:
            print("execute sqlmap")
        print(req[3])
        #print(req)

    #print(responses)


