#!/usr/bin/env python3


import os
import sys
import json
import time
import struct
import asyncio
import functools
import threading
import subprocess
import configparser

from optparse import OptionParser
from logging import getLogger, DEBUG, StreamHandler, Formatter
from logging.handlers import SysLogHandler

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = getLogger(__name__)
logger.setLevel(DEBUG)
stream = StreamHandler()
syslog = SysLogHandler(address = "/dev/log")
syslog.setFormatter(Formatter("portconfig: %(message)s"))
logger.addHandler(stream)
logger.addHandler(syslog)
logger.propagate = False

ipcmd = "/bin/ip"
brcmd = "/sbin/bridge"



# PortConfig Instance
global portconfig
portconfig = None


from flask import Flask
app = Flask(__name__)

class Port() :

    def __init__(self, name, master = None, vlan = 0) :
        self.name = name
        self.master = master
        self.vlan = vlan

    def __str__(self) :
        return "<Port %s: Master=%s VLAN=%d>" % \
            (self.name, self.master, self.vlan)

    def set_vlan(self, vlan) :
        self.vlan = vlan

    def diff_check(self, port) :
        # check parameters of 'self' and 'port' are same?
        if (self.name == port.name and
            self.master == port.master and
            self.vlan == port.vlan) :
            return False
        else:
            return True

    def destroy(self) :
        # destroy this port. physical ports cannot be removed,
        # so, this function actually remove only vxlan interface
        # and remove the interface from the associated bridge

        cmd = [ipcmd, "link", "set", "dev", self.name, "nomaster"]
        subprocess.check_output(cmd)


    def setup(self) :

        # ok, setup vlans
        cmds = [
            [ipcmd, "link", "set", "dev", self.name, "master", self.master],
            [brcmd, "vlan", "add", "vid", self.vlan, "dev", self.name,
             "untagged", "pvid"],
            [ipcmd, "link", "set", "up", "dev", self.name],
        ]

        for cmd in cmds :
            subprocess.check_output(list(map(str, cmd)))

class Bridge() :

    def __init__(self, name, dmvpn_addr) :
        self.name = name
        self.dmvpn_addr = dmvpn_addr
        self.ports = {} # key is name, value is class Port
        self.vlans = set() # vlan set

    def __str__(self) :
        ports = '  \n'.join(map(str, self.ports.values()))
        return "<Bridge %s: [\n%s\n]>" % (self.name, ports)

    def add_port(self, port):
        if port.name in self.ports :
            raise RuntimeError("port '%s' already exists on bridge '%s'"
                               % (port.name, self.name))
        self.ports[port.name] = port

    def list_ports(self) :
        return self.ports.values()

    def find_port(self, port_name) :
        if port_name in self.ports :
            return self.ports[port_name]
        else :
            return None

    def update_vlan_set(self) :
        self.vlans = set()
        for port in self.ports.values() :
            self.vlans.add(port.vlan)

    def vlan_set_validate(self) :
        # check this vlan has vxlan interface
        rem = []
        for vlan in self.vlans :
            if not os.path.exists("/sys/class/net/vxlan%d" % vlan) :
                rem.append(vlan)
        for v in rem :
            self.vlans.remove(v)

    def add_vxlan(self, vlan) :
        # add new vxlan interface
        vxlan_name = "vxlan%d" % vlan

        cmds = []

        # check does vxlan interface exist. if not, make it.
        if not os.path.exists("/sys/class/net/%s" % vxlan_name) :
            cmds.append(
                [ipcmd, "link", "add", vxlan_name,
                 "type", "vxlan", "nolearning", "dstport", 4789,
                 "id", vlan, "local", self.dmvpn_addr]
            )

        cs = [
            [ipcmd, "link", "set", "dev", vxlan_name, "master", self.name],
            [brcmd, "vlan", "add", "vid", vlan, "dev", self.name, "self"],
            [brcmd, "vlan", "add", "vid", vlan, "dev", vxlan_name,
             "untagged", "pvid"],
            [ipcmd, "link", "set", "up", "dev", vxlan_name]
        ]
        for c in cs :
            cmds.append(c)

        for cmd in cmds :
            subprocess.check_output(list(map(str, cmd)))

    def delete_vxlan(self, vlan) :
        # remove vxlan interface
        vxlan_name = "vxlan%d" % vlan

        if not os.path.exists("/sys/class/net/%s" % vxlan_name) :
            return

        cmds = [
            [ipcmd, "link", "set", "down", "dev", vxlan_name],
            [ipcmd, "link", "del", "dev", vxlan_name],
            [brcmd, "vlan", "del", "vid", vlan, "dev", self.name, "self"]
        ]
        for cmd in cmds :
            subprocess.check_output(list(map(str, cmd)))

    def load_from_json(self, jsondata) :
        """
        json format is
        { 
          'name' : 'bridge_name',
          'ports' : [
            { 'name' : 'port1_name', 'vlan' : VLANID },
            { 'name' : 'port1_name', 'vlan' : VLANID },
            { 'name' : 'port1_name', 'vlan' : VLANID },
          ]
        }
        
        """

        try :
            self.name = jsondata["name"]
            for jport in jsondata["ports"] :

                if not os.path.exists("/sys/class/net/%s" % jport["name"]) :
                    logger.error("Port '%s' does not exist" % jport["name"])
                    continue

                self.add_port(Port(jport["name"],
                                   master = self.name,
                                   vlan = jport["vlan"]))

            # update vlan set of this bridge
            self.update_vlan_set()

        except Exception as e:
            logger.error("Invalid JSON file : %s" % e)
            return False

        return True

    def load_from_os(self) :

        # check associated ports
        brout = subprocess.check_output([brcmd, "link", "show"])
        brout = brout.decode("utf-8")
        for line in brout.split('\n') :
            if "vxlan" in line : continue
            s = line.split(' ')
            for n in range(len(s)) :
                if s[n] == "master" and s[n + 1] == self.name :
                    port = Port(s[1], master = self.name)
                    self.add_port(port)


        # check vlan id of associated ports
        brout = subprocess.check_output([brcmd, "-json", "vlan", "show"])
        brout = brout.decode("utf-8")
        vlanshow = json.loads(brout)
        for port in self.list_ports() :
            if not port.name in vlanshow : continue

            vlans = vlanshow[port.name]
            for vlan in vlans :
                if ("PVID" in vlan["flags"] and
                    "Egress Untagged" in vlan["flags"]) :
                    port.set_vlan(vlan["vlan"])

        # update vlan set of this bridge
        self.update_vlan_set()
        self.vlan_set_validate()


class PortConfig() :

    def __init__(self, configfile) :

        config = configparser.ConfigParser()
        config.read(configfile)

        self.dmvpn_addr = config.get("general", "dmvpn_addr")

        self.timeout = config.getint("config_fetch", "timeout")
        self.interval = config.getint("config_fetch", "interval")
        self.failed_interval = config.getint("config_fetch", "failed_interval")

        self.br_name = config.get("portconfig", "br_interface")
        self.url = "%s/%s.json" % (config.get("portconfig", "json_url_prefix"),
                                   config.get("general", "dmvpn_addr"))
        self.bind_port = config.getint("portconfig", "bind_port")
        if config.has_option("portconfig", "bind_addr") :
            self.bind_addr = config.get("portconfig", "bind_addr")
        else :
            self.bind_addr = config.get("general", "dmvpn_addr")
            
        if config.has_option("portconfig", "json_config") :
            self.json_config = config.get("portconfig", "json_config")
        else :
            self.json_config = None


    def fetch(self) :
        # fetch the config json

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
            

        bridge_now = Bridge(self.br_name, self.dmvpn_addr)
        bridge_now.load_from_os()

        bridge_new = Bridge(self.br_name, self.dmvpn_addr)
        if not bridge_new.load_from_json(jsonconfig) :
            return False

        logger.info("Start to configure bridge '%s'" % bridge_now.name)

        # 1. remove unnecessary vlans
        for vlan in bridge_now.vlans - bridge_new.vlans :
            logger.debug("- remove vlan %d", vlan)
            bridge_new.delete_vxlan(vlan)

        # 2. create new vlans
        for vlan in bridge_new.vlans - bridge_now.vlans :
            logger.debug("- add vlan %d", vlan)
            bridge_new.add_vxlan(vlan)


        # 3. check removed or changed ports and remove them
        for now_port in bridge_now.list_ports() :
            if not bridge_new.find_port(now_port.name) :
                logger.debug("- destroy %s" % now_port)
                now_port.destroy()

            elif now_port.diff_check(bridge_new.find_port(now_port.name)) :
                now_port.destroy()

        # 4. check new or changed ports and setup them
        for new_port in bridge_new.list_ports() :
            if not bridge_now.find_port(new_port.name) :
                logger.debug("- setup %s" % new_port)
                new_port.setup()

            elif new_port.diff_check(bridge_now.find_port(new_port.name)) :
                logger.debug("- setup %s" % new_port)
                new_port.setup()        
        
        return True


    def fetch_loop(self, loop, once) :
        
        ret = self.execute()
        try:
            if ret :
                if once :
                    loop.stop()
                    return True
                loop.call_later(self.interval, self.fetch_loop, loop, once)
            else :
                loop.call_later(self.failed_interval,
                                self.fetch_loop, loop, once)
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt. stop portconfig loop.")
            loop.stop()
            
        except Exception as e:
            logger.erro("portconfig error occurd: %s" % e)
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
def portconfig_rest_update_from_url() :
    logger.info("Update trigger. start to obtain JSON")

    global portconfig
    portconfig.execute_once()
    return "Start Update", 200


def portconfig_rest_start(bind_addr, bind_port) :
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
    portconfig = PortConfig(sys.argv[1])
    portconfig_rest_start(portconfig.bind_addr, portconfig.bind_port)
    portconfig.start_loop()
