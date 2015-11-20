#!/usr/local/bin/python3.5

"""
Wrapper around the sqlmap tool. This wrapper provides 
convenient methods for executing sqlmap and parsing its 
output.
"""


SQLMAP_LOCATION = "../sqlmap/sqlmap.py"

# notes: sqlmap executes and, at the ends, report a log in ~/.sqlmap/ folder
# probably the best option is to not capture the output from sqlmap, but to
# retrieve it from that folder after the execution.

# run sqlmap with the specified arguments
def exec_sqlmap(params):
    sqlmap_process = subprocess.Popen([SQLMAP_LOCATION],universal_newlines=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    out,err = sqlmap_process.communicate()




