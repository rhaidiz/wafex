#!/usr/bin/env python
# -*- coding: utf-8 -*-

import itertools
import config

from modules.logger import logger


def ciao():
    print("ciao")

def __split_(message):
    try:
        # raw_params = message.split(".",maxsplit=1)[1]
        # debugMsg = "get parameters from {} raw_params {}".format(message,raw_params)
        # logger.debug(debugMsg)
        #tmp = ["?" if idx%2 else k for idx,k in enumerate(raw_params.split(".s."))]
        tmp = message.split(".s.")
        if len(tmp) == 1:
            return {}
        return dict(itertools.zip_longest(*[iter(tmp)] * 2, fillvalue=""))
    except Exception as e:
        return {}

def __get_parameters(message):
    try:
        # raw_params = message.split(".",maxsplit=1)[1]
        # debugMsg = "get parameters from {} raw_params {}".format(message,raw_params)
        # logger.debug(debugMsg)
        #tmp = ["?" if idx%2 else k for idx,k in enumerate(raw_params.split(".s."))]
        tmp = raw_params.split(".s.")
        return dict(itertools.zip_longest(*[iter(tmp)] * 2, fillvalue=""))
    except Exception:
        return {}

def bootstrap(msc_table, concretization_json):

    for idx, row in enumerate(msc_table):
        tag = row[0]
        step = row[1]

        sender = step[0]
        receiver = step[1]
        msg = step[2]

        if sender not in config.receiver_entities:
            tmp = msg.split(",")
            str_param = tmp[1]
            str_cookie = tmp[2]

            page = tmp[0]
            parameters = __split_(str_param)
            cookies = __split_(str_cookie)

            entry = { "page" : page, "params" : parameters, "cookies" : cookies }
            ss = "tag {} entry {}".format(tag,entry)
            concretization_json[tag] = entry


