#!/usr/local/bin/python3.5

"""
Variables that are shared among modules.
"""
verbosity = False
concretization = None
proxy = None
keep_cookie = False
cookies = None
DEBUG = False
CONNECTOR_1_4_1 = "modules/connector/aslanpp-connector-1.4.1.jar"
CONNECTOR_1_4_9 = "modules/connector/aslanpp-connector.jar"
CONNECTOR_1_3 = "modules/connector/aslanpp-connector-1.3.jar"

receiver_entities = {"webapplication","filesystem","database","<webapplication>","<filesystem>","<database>"}

TOOL_NAME = "Wfast"
EVIL_SCRIPT = "/Users/federicodemeo/Desktop/regis/PhDStudents/demeo/SQLi-formalization/wsfast/evil_file.txt"
remote_shell_write = "/Users/federicodemeo/Desktop/regis/PhDStudents/demeo/SQLi-formalization/wsfast/evil_file.txt"
