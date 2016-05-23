#!/usr/local/bin/python3.5

"""
Variables that are shared among modules.
"""
import os

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


BANNER = """\033[38;5;212m
 __      __   _____
/  \    /  \_/ ____\____    _______/  |__
\   \/\/   /\   __ \__  \  /  ___/\   __/
 \        /  |  |   / __ \_\___ \  |  |
  \__/\  /   |__|  (____  /____  > |__|
       \/               \/     \/        \033[38;5;195m[{}]\033[38;5;212m
\033[38;5;195m{}\033[38;5;212m
"""
VERSION = "1.0-alpha-dev"
SITE = "http://wfast.com"

HOME = os.path.expanduser("~")
WFAST_HOME = os.path.join(HOME,".wfast")
WFAST_EXTRACTED_FILES_DIR = os.path.join(WFAST_HOME,"files")


