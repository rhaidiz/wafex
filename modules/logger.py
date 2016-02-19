#!/usr/local/bin/python3.5

"""
This module provides convinient output printing method
"""
import logging
import config

from modules.thirdparty.ansistrm.ansistrm import ColorizingStreamHandler

""" Setup the logger """
logging.getLogger("requests").setLevel(logging.WARNING) # configure loggin to log only from WARNING up
LOGGER = logging.getLogger("wsfast")
LOGGER_HANDLER = ColorizingStreamHandler()
FORMATTER = logging.Formatter("\r[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")
LOGGER_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(LOGGER_HANDLER)
LOGGER.setLevel(logging.DEBUG)

logger = LOGGER

