#!/usr/local/bin/python3.5

"""
This module provides convinient output printing method
"""


import config
import logging

from modules.thirdparty.ansistrm.ansistrm import ColorizingStreamHandler

""" Setup the logger """
logging.getLogger("requests").setLevel(logging.WARNING) # configure loggin to log only from INFO up
LOGGER = logging.getLogger("wsfast")
LOGGER_HANDLER = ColorizingStreamHandler()
FORMATTER = logging.Formatter("\r[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")
LOGGER_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(LOGGER_HANDLER)
if config.DEBUG:
    LOGGER.setLevel(logging.DEBUG)
else:
    LOGGER.setLevel(logging.INFO)

logger = LOGGER

