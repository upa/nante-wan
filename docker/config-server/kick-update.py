#!/usr/bin/env python3

import re
import sys
import time
import pyinotify
import configparser

from optparse import OptionParser

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from logging import getLogger, DEBUG, StreamHandler, Formatter
from logging.handlers import SysLogHandler
logger = getLogger(__name__)
logger.setLevel(DEBUG)
stream = StreamHandler()
syslog = SysLogHandler(address = "/dev/log")
syslog.setFormatter(Formatter("kick-update: %(message)s"))
logger.addHandler(stream)
logger.addHandler(syslog)
logger.propagate = False



class NotifyHandler(pyinotify.ProcessEvent):

    def __init__(self, configfile, dryrun) :
        
        self.dryrun = dryrun

        config = configparser.ConfigParser()
        config.read(configfile)

        pt_prefix = config.get("portconfig", "json_url_prefix")
        self.portconfig_path = "/".join(pt_prefix.split("/")[3:])
        self.portconfig_port = config.getint("portconfig", "bind_port")

        eb_prefix = config.get("ebconfig", "json_url_prefix")
        self.ebconfig_path = "/".join(eb_prefix.split("/")[3:])
        self.ebconfig_port = config.getint("ebconfig", "bind_port")

        logger.info("sub-directory for portconfig: %s" % self.portconfig_path)
        logger.info("sub-directory for ebconfig: %s" % self.ebconfig_path)
        logger.info("Port number of portconfig REST: %d" % self.portconfig_port)
        logger.info("Port number of ebconfig REST: %d" % self.ebconfig_port)
        

    def kick_update(self, name, port) :

        # name is X.X.X.X.json
        ipaddr = name[0:len(name) - 5]
        url = "http://%s:%d/update-kick" % (ipaddr, port)

        if self.dryrun :
            logger.info("dryrun: kick url is %s" % url)
            return

        for x in range (5) :
            try :
                res = requests.put(self. url, timeout = 5)
                if res.status_code == 200 :
                    logger.error("kick %s success" % url)
                    break
                else :
                    logger.error("Failed to kick %s, %d" % (url, res.status_code))

            except Exception as e :
                logger.error("Failed to kick %s :%s:%s" %
                             (url, e.__class__.__name__, e))



    def process_IN_CLOSE_WRITE(self, event) :

        name = event.name
        path = event.path

        if re.match(r'^(\d{1,3}\.){3,3}\d{1,3}\.json$', name) :

            if self.portconfig_path in path :
                port = self.portconfig_port
            elif self.ebconfig_path in path :
                port = self.ebconfig_port
            else :
                return

            self.kick_update(name, port)
                


if __name__ == "__main__" :

    desc = "usage : %prog [options]"
    parser = OptionParser(desc)

    parser.add_option(
        "-c", "--config", type = "string", default = None, dest = "configfile",
        help = "nante-wan config file"
    )
    parser.add_option(
        "-d", "--directory", type = "string", default = None, dest = "targetdir",
        help = "watch target directry (DocumentRoot of config serve)"
    )
    parser.add_option(
        "-n", "--no-execute", action = "store_true", default = False,
        dest = "dryrun", help = "no kick the RERST GWs (dryrun)"
    )

    (options, args) = parser.parse_args()

    if not options.configfile :
        logger.error("config file (-c option) is required")
        sys.exit(1)

    if not options.targetdir :
        logger.rror("target directory (-d option) is required")
        sys.exit(1)


    wm = pyinotify.WatchManager()
    nh = NotifyHandler(options.configfile, options.dryrun)
    notifier = pyinotify.Notifier(wm, nh)
    added = wm.add_watch(options.targetdir, pyinotify.IN_CLOSE_WRITE, rec = True)

    notifier.loop()


