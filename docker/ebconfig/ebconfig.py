#!/usr/bin/env python3

import os
import sys
import json
import asyncio
import threading
import subprocess
import configparser


from logging import getLogger, DEBUG, StreamHandler, Formatter
from logging.handlers import SysLogHandler

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



from flask import Flask
app = Flask(__name__)


# EbConfig instance

def run_cmds(cmds):
    for cmd in cmds :
        logger.debug(" ".join(list(map(str, cmd))))
        subprocess.check_output(list(map(str, cmd)))


class EbConfig() :

    def __init__ (self, configfile) :

        config = configparser.ConfigParser()
        config.read(configfile)

        self.dmvpn_addr = config.get("general", "dmvpn_addr")

        self.timeout = config.getint("config_fetch", "timeout")
        self.interval = config.getint("config_fetch", "interval")
        self.failed_interval = config.getint("config_fetch", "failed_interval")

        self.url = "%s/%s.json" % (config.get("ebconfig", "json_url_prefix"),
                                   config.get("general", "dmvpn_addr"))
        self.bind_port = config.getint("ebconfig", "bind_port")
        if config.has_option("ebconfig", "bind_addr") :
            self.bind_addr = config.get("ebconfig", "bind_addr")
        else :
            self.bind_addr = config.get("general", "dmvpn_addr")

        if config.has_option("ebconfig", "json_config") :
            self.json_config = config.get("ebconfig", "json_config")
        else :
            self.json_config = None


    def fetch(self) :
        # fetch the config json from confg server

        if self.json_config :
            with open(self.json_config, "r") as f :
                return json.load(f)

        try :
            res = requests.get(self.url, timeout = self.timeout)
            if res.status_code != 200 :
                logger.error("Failed to GET '%s', status_code %d" %
                             (self.url, res.status_code))
                return False
        except requests.exceptions.RequestException as e :
            logger.error("Failed to GET '%s': %s" % (self.url, e))
            return False

        except Exception as e :
            logger.error("Failed to GET '%s': %s" % (self.url, e))
            return False

        try :
            return res.json()
        except Exception as e :
            logger.error("Invalid JSON from '%s': %s" % (self.url, e))
            return False


            
    def execute(self) :

        jsonconfig = self.fetch()
        if not jsonconfig :
            return False

        self.flush_ebtables()
        for netconfig in jsonconfig :
            self.insert_ip_filter(netconfig)
            self.insert_mac_filter(netconfig)

        return True
        


    def flush_ebtables(self) :

        cmds = [
            [ ebcmd, "-X" ],
            [ ebcmd, "-F" ]
        ]

        run_cmds(cmds)


    def insert_ip_filter(self, netconfig) :

        if (not "vlan" in netconfig or
            not "ip-filter" in netconfig or
            not "rules" in netconfig["ip-filter"]) :
            return

        vlan = netconfig["vlan"]
        default = netconfig["ip-filter"]["default"]
        rules = netconfig["ip-filter"]["rules"]
        interface = "vxlan%d" % vlan

        if default == "permit" : default = "ACCEPT"
        elif default == "deny" : default = "DROP"
        else :
            raise RuntimeError("invalid default action '%s'" % default)

        cmds = []

        for rule in rules :

            proto = rule["proto"]
            src_ip = rule["src-ip"] if "src-ip" in rule else "0.0.0.0/0"
            dst_ip = rule["dst-ip"] if "dst-ip" in rule else "0.0.0.0/0"
            src_port = rule["src-port"] if "src-port" in rule else "any"
            dst_port = rule["dst-port"] if "dst-port" in rule else "any"

            action = rule["action"] if "action" in rule else "deny"
            if action == "permit" : action = "ACCEPT"
            elif action == "deny" : action = "DROP"
            else :
                raise RuntimeError("invalid action '%s'" % action)


            cmd = [ ebcmd, "-A", "FORWARD", "-o", interface,
                    "-p", "IPv4", "--ip-src", src_ip, "--ip-dst", dst_ip,
                    "--ip-proto", proto
            ]

            if src_port != "any" :
                cmd += [ "--ip-sport", src_port ]
            if dst_port != "any" :
                cmd += [ "--ip-dport", dst_port ]

            cmd += [ "-j", action ]

            cmds.append(cmd)
            
        cmds.append([
            ebcmd, "-A", "FORWARD", "-o", interface,
            "-p", "IPv4", "-j", default
        ])
        
        run_cmds(cmds)


    def insert_mac_filter(self, netconfig) :

        if (not "vlan" in netconfig or
            not "mac-filter" in netconfig or
            not "rules" in netconfig["mac-filter"]) :
            return

        vlan = netconfig["vlan"]
        default = netconfig["mac-filter"]["default"]
        rules = netconfig["mac-filter"]["rules"]
        interface = "vxlan%d" % vlan

        if default == "permit" : default = "ACCEPT"
        elif default == "deny" : default = "DROP"
        else :
            raise RuntimeError("invalid default action '%s'" % default)

        cmds = []

        for rule in rules :
            
            mac = rule["mac"]
            action = rule["action"] if "action" in rule else "deny"
            if action == "permit" : action = "ACCEPT"
            elif action == "deny" : action = "DROP"
            else :
                raise RuntimeError("invalid action '%s'" % action)
            
            cmd = [ ebcmd, "-A", "FORWARD", "-o", interface,
                    "--src", mac, "-j", action
            ]

            cmds.append(cmd)

        cmds.append([
            ebcmd, "-A", "FORWARD", "-o", interface, "-j", default
        ])

        run_cmds(cmds)


    
    def fetch_loop(self, loop, once) :

        try :
            ret = self.execute()
            if ret :
                if once :
                    loop.stop()
                    return True
                loop.call_later(self.interval, self.fetch_loop, loop, once)
            else :
                loop.call_later(self.failed_interval,
                                self.fetch_loop, loop, once)

        except KeyboardInterrupt:
            logger.info("Keyboard interrupt. stop ebconfig loop.")
            loop.stop()

        except Exception as e:
            logger.error("ebconfig error occurd:%s: %s" %
                         (e.__class__.__name__, e))
            loop.call_later(self.failed_interval, self.fetch_loop, loop, once)


    def start_loop(self) :
        loop = asyncio.get_event_loop()
        loop.call_soon(self.fetch_loop, loop, False)
        loop.run_forever()
        loop.close()


    def execute_once(self) :
        loop = asyncio.new_event_loop()
        loop.call_soon(self.fetch_loop, loop, True)
        loop.run_forever()
        loop.close()


@app.route("/update-kick", methods = [ "GET", "POST" ])
def ebconfig_rest_update_from_url() :
    logger.info("Update trigger. start to obtain JSON")

    global ebconfig
    ebconfig.execute_once()
    return "Start Update", 200


def ebconfig_rest_start(bind_addr, bind_port) :
    logger.info("Start REST Gateway on %s:%d" % (bind_addr,
                                                 bind_port))
    th = threading.Thread(name = "rest_gw", target = app.run,
                          kwargs = {
                              "threaded" : True,
                              "host" : bind_addr,
                              "port" : bind_port,
                          })
    th.start()



if __name__ == "__main__" :
    ebconfig = EbConfig(sys.argv[1])
    ebconfig_rest_start(ebconfig.bind_addr, ebconfig.bind_port)
    ebconfig.start_loop()
