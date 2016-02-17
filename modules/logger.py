#!/usr/local/bin/python3.5

"""
This module provides convinient output printing method
"""

import config

def cprint(msg,t="I",color="d"):
    t_msg = ""

    if color == "d":
        #white
        print("",end="")
    if color == "r":
        #red
        print("\033[0;31m",end="")
    elif color == "g":
        #green
        print("\033[0;32m",end="")
    elif color == "y":
        #yellow
        print("\033[0;33m",end="")

    if t == "E":
         print("\033[0;31m[ERROR]\t",end="")
         print(msg,end="")
         print("\033[0m")
    elif t == "I":
         print("[INFO]\t",end="")
         print(msg,end="") 
         print("\033[0m")
    elif t == "W":
         print("\033[0;33m[WARNING]\t",end="")
         print(msg,end="")
         print("\033[0m")
    elif t == "D":
        t_msg = msg
    elif t == "V":
        t_msg = msg;
    if (t == "D") & config.DEBUG:
        print("\033[0;35m[DEBUG]\t"+"\033[0m",end="")
        print(t_msg)
    elif(t == "V") & config.verbosity:
        print("\033[0;32m[VERB]\t"+"\033[0m",end="")
        print(t_msg)

if __name__ == "__main__":
    cprint("ciao","E")
