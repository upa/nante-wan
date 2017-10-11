#!/usr/bin/env python3


import os
import sys
import json
import time
import threading
import subprocess

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
syslog.setFormatter(Formatter("sdwconfig: %(message)s"))
logger.addHandler(stream)
logger.addHandler(syslog)
logger.propagate = False


ipcmd = "/bin/ip"
brcmd = "/sbin/bridge"

localaddr = None
bridge_name = "bridge"

# ConfigParser Option
options = None


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

    def __init__(self, name) :
        self.name = name
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

        # check does vxlan interface exist. if not, make it.
        if os.path.exists("/sys/class/net/%s" % vxlan_name) :
            return

        cmds = [
            [ipcmd, "link", "add", vxlan_name,
             "type", "vxlan", "nolearning", "dstport", 4789,
             "id", vlan, "local", localaddr],
            [ipcmd, "link", "set", "dev", vxlan_name, "master", self.name],
            [brcmd, "vlan", "add", "vid", vlan, "dev", self.name, "self"],
            [brcmd, "vlan", "add", "vid", vlan, "dev", vxlan_name,
             "untagged", "pvid"],
            [ipcmd, "link", "set", "up", "dev", vxlan_name]
        ]
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



def sdwconfig_config(bridge_now, bridge_new) :
    
    logger.info("Start to configure bridge '%s'" % bridge_now.name)
    #logger.debug("now: %s" % bridge_now)
    #logger.debug("new: %s" % bridge_new)

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



def sdwconfig_from_file(options) :

    jsondata = json.load(open(options.jsonfile, 'r'))

    bridge_now = Bridge(bridge_name)
    bridge_now.load_from_os()

    bridge_new = Bridge(bridge_name)
    ret = bridge_new.load_from_json(jsondata)
    if not ret :
        return False

    sdwconfig_config(bridge_now, bridge_new)



def sdwconfig_from_url(options) :

    # retrieve json from from configured url

    while True :
        try :
            res = requests.get(options.url, timeout = options.timeout)
            if res.status_code == 200 and res.json() :
                break
            else :
                logger.error("Failed to GET '%s', sleep %d seconds: %s",
                             options.url, options.failedinterval,
                             "status_code is %d" % res.status_code)
                time.sleep(options.failedinterval)

        except requests.exceptions.RequestException as e :
            logger.error("Failed to GET '%s', sleep %d seconds: %s",
                         options.url, options.failedinterval, e)
            time.sleep(options.failedinterval)
    
        except Exception as e :
            logger.error("Failed to GET '%s', sleep %d seconds: %s",
                         options.url, options.failedinterval, e)
            time.sleep(options.failedinterval)


    bridge_now = Bridge(bridge_name)
    bridge_now.load_from_os()

    bridge_new = Bridge(bridge_name)
    ret = bridge_new.load_from_json(res.json())
    if not ret :
        return False

    sdwconfig_config(bridge_now, bridge_new)
    return True


def sdwconfig_loop(options) :

    while True:
        try :
            sdwconfig_from_url(options)
            time.sleep(options.interval)
        except Exception as e :
            logger.error("sdwconfig_loop failed, sleep %d sec : %s:%s" % 
                         (options.failedinterval, e.__class__, e))
            time.sleep(options.failedinterval)


        
@app.route("/update_from_url", methods = [ "GET" ])
def sdwconfig_rest_update_from_url() :
    logger.info("Update trigger. start to obtain json from %s" % options.url)
    ret = sdwconfig_from_url(options)
    if ret :
        return "Ok!", 200
    else :
        return "Failed", 400

def sdwconfig_rest_start(options) :
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
        help = "json file url (exclusive to '-j')"
    )
    parser.add_option(
        "-j", "--json", type = "string", default = None, dest = "jsonfile",
        help = "json file path (exclusive to '-u')"
    )
    parser.add_option(
        "-i", "--interval", type = "int", default = 3600, dest = "interval",
        help = "json file retrieve interval (sec)"
    )
    parser.add_option(
        "-g", "--failedinterval", type = "int", default = 10,
        dest = "failedinterval",
        help = "retry interval if any failed (sec)"
    )
    parser.add_option(
        "-t", "--timeout", type = "int", default = 10, dest = "timeout",
        help = "timeout of retrieving the json url (sec)"
    )
    parser.add_option(
        "-l", "--local-addr", type = "string", default = None,
        dest = "local_addr", help = "vxlan local address"
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
    localaddr = options.local_addr

    # start rest gateway
    sdwconfig_rest_start(options)

    if options.jsonfile :
        sdwconfig_from_file(options)

    elif options.url :
        sdwconfig_loop(options)
