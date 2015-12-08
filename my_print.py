#!/usr/local/bin/python3.5

"""
This module provides convinient output printing method
"""

import global_var

def cprint(msg,t="INFO"):
    t_msg = ""
    if t == "ERROR":
         print("\033[1;31m[ERROR]\t",end="")
         print(msg,end="")
         print("\033[0m")
    elif t == "INFO":
         print("[INFO]\t",end="")
         print(msg,end="") 
    elif t == "WARNING":
         print("\033[1;33m[WARNING]\t",end="")
         print(msg,end="")
         print("\033[0m")
    elif t == "DEBUG":
        t_msg = msg
    if (t == "DEBUG") & global_var.DEBUG:
        print("\033[1;35m[DEBUG]\t"+"\033[0m",end="")
        print(t_msg)
    elif t != "DEBUG":
        print(t_msg)

if __name__ == "__main__":
    cprint("ciao","ERROR")
