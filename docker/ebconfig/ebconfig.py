#!/usr/bin/env python3

"""

Controling Firewall powered by ebtables.

JSON Format.
[
  { "vlan" : vid, "blockaddrs" : [ X.X.X.X, Y.Y.Y.Y ]},
  { "vlan" : vid, "blockaddrs" : [ X.X.X.X, Y.Y.Y.Y ]},
]

1. ebconfig regularly tries to get json file from specified URL,
   and update filter rules.
2. if ebconfig kicked through the RESTGW (/update_from_url),
   ebconfig starts to get the json file.

"""


import os
import sys
import json
import time
import threading
import subprocess
import configparser

from optparse import OptionParser
from logging import getLogger, DEBUG, StreamHandler, Formatter
from logging.handlers import SysLogHandler

from flask import Flask
app = Flask(__name__)

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = getLogger(__name__)
logger.setLevel(DEBUG)
stream = StreamHandler()
syslog = SysLogHandler(address = "/dev/log")
syslog.setFormatter(Formatter("ebconfig: %(message)s"))
logger.addHandler(stream)
logger.addHandler(syslog)
logger.propagate = False

ebcmd = "/sbin/ebtables"

# OptionParser variable
options = None



def ebconfig_update(json_data) :
    
    logger.info("Start to config ebtable: %s" % json_data)

    cmds = [[ ebcmd, "-F" ]]
    
    for net in json_data :
        vid = net["vlan"]
        for blockaddr in net["blockaddrs"] :
            cmds.append([
                ebcmd, "-A", "FORWARD", "-i", "vxlan%d" % vid,
                "-p", "IPv4", "--ip-src", blockaddr, "-j", "DROP"
            ])

    for cmd in cmds :
        subprocess.check_output(cmd)


def get_ebconfig_json() :

    try :
        res = requests.get(options.url, timeout = options.timeout)
        if res.status_code != 200 :
            logger.error("GET JSON failed from %s, status %d" %
                         (options.url, res.status_code))
            return False
        json_data = res.json()

    except requests.exceptions.RequestException as e :
        logger.error("GET JSON failed from %s, %s", options.url, e)
        return False

    except Exception as e :
        logger.error("GET JSON failed from %s, %s", options.url, e)
        return False

    return json_data


def ebconfig_oneshot(nowait = False) :

    while True:
        try :
            json_data = get_ebconfig_json()
            if not json_data :
                if nowait: break
                time.sleep(options.error_interval)
            else :
                ebconfig_update(json_data)
                break

        except Exception as e :
            logger.error("ebconfig_loop failed, sleep %d sec : %s:%s" %
                          (options.error_interval, e.__class__, e))
            if nowait: break
            time.sleep(options.error_interval)


def ebconfig_loop() :

    while True:
        ebconfig_oneshot()
        logger.info("ebtable_onshot done. sleep %s sec" % options.interval)
        time.sleep(options.interval)


@app.route("/update_from_url", methods = [ "GET", "POST" ])
def ebconfig_rest_update_from_url() :
    logger.info("Update trigger kicked. start to obtain JSON from %s" %
                options.url)
    ebconfig_oneshot(nowait = True)
    return "Done", 200


def ebconfig_rest_start() :
    logger.info("Start REST Gateway on %s:%d" % (options.bind_addr,
                                                 options.bind_port))
    th = threading.Thread(name = "rest_gw", target = app.run,
                          kwargs = {
                              "threaded" : True,
                              "host" : options.bind_addr,
                              "port" : options.bind_port,
                          })
    th.start()



if __name__ == "__main__" :

    desc = "usage: %prog [options]"
    parser = OptionParser(desc)

    parser.add_option(
        "-u", "--url", type = "string", default = None, dest = "url",
        help = "JSON file URL"
    )
    parser.add_option(
        "-f", "--file", type = "string", default = None, dest = "jsonfile",
        help = "JFON file path (exclusive with -u URL)"
    )
    parser.add_option(
        "-t", "--timeout", type = "int", default = 10,
        dest = "timeout", help = "timeout for retrieving JSON file"
    )
    parser.add_option(
        "-e", "--error-interval", type = "int", default = 10,
        dest = "error_interval", help = "interval when error occur"
    )
    parser.add_option(
        "-i", "--interval", type = "int", default = 3600,
        dest = "interval", help = "regular JSON retrieve interval"
    )
    parser.add_option(
        "-b", "--bind-addr", type = "string", default = "127.0.0.1",
        dest = "bind_addr", help = "bind address of REST gateway"
    )
    parser.add_option(
        "-p", "--bind-port", type = "int", default = 80,
        dest = "bind_port", help = "bind port of REST gateway"
    )

    (options, args) = parser.parse_args()

    if options.jsonfile :
        with open(options.jsonfile, "r") as f :
            json_data = json.load(f)
            ebconfig_update(json_data)
        sys.exit(0)
        
    if not options.url :
        logger.error("-u (JSON file url) or -f (JSON file path) is required")
        sys.exit(1)

    # start REST gateway
    ebconfig_rest_start()

    # etnering loop
    ebconfig_loop()
