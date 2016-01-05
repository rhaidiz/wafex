#!/usr/local/bin/python3.5

"""
This module provides convinient output printing method
"""

import global_var

def cprint(msg,t="I",color="d"):
    t_msg = ""

    if color == "d":
        #white
        print("",end="")
    if color == "r":
        #red
        print("\033[1;31m",end="")
    elif color == "g":
        #green
        print("\033[1;32m",end="")

    if t == "E":
         print("\033[1;31m[ERROR]\t",end="")
         print(msg,end="")
         print("\033[0m")
    elif t == "I":
         print("[INFO]\t",end="")
         print(msg,end="") 
         print("\033[0m")
    elif t == "W":
         print("\033[1;33m[WARNING]\t",end="")
         print(msg,end="")
         print("\033[0m")
    elif t == "D":
        t_msg = msg
    elif t == "V":
        t_msg = msg;
    if (t == "D") & global_var.DEBUG:
        print("\033[1;35m[DEBUG]\t"+"\033[0m",end="")
        print(t_msg)
    elif(t == "V") & global_var.verbosity:
        print("\033[1;32m[VERB]\t"+"\033[0m",end="")
        print(t_msg)

if __name__ == "__main__":
    cprint("ciao","E")
