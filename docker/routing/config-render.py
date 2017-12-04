#!/usr/bin/env python3

import re
import os
import sys
import socket
import fcntl
import struct
import configparser
from optparse import OptionParser
from jinja2 import Environment, FileSystemLoader



def config_render_frr_conf(config, of) :

    d = { "dmvpn_addr" : config.get("general", "dmvpn_addr")}

    rr_addrs = []

    for param in config["routing"] :
        d[param] = config["routing"][param]
        if re.match(r"rr_addr\d*", param) :
            rr_addrs.append(config["routing"][param])

    d["rr_addrs"] = rr_addrs

    tmp = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader = FileSystemLoader(tmp, encoding = "utf-8"))
    tpl = env.get_template("frr.conf.template")

    frr_conf = tpl.render(d)
    print(frr_conf, file = of)

    
def config_render_ipsec_secrets(config, of) :

    d = {
            "ipsec_secret" : config.get("routing", "ipsec_secret")
    }

    tmp = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader = FileSystemLoader(tmp, encoding = "utf-8"))
    tpl = env.get_template("ipsec.secrets.template")

    ipsec_secrets = tpl.render(d)
    print(ipsec_secrets, file = of)



if __name__ == '__main__' :

    desc = "usage: %prog [options] configfile"
    parser = OptionParser(desc)
    parser.add_option('-s', '--stdout', action = "store_true",
                      default = None, dest = "stdout",
                      help = "output to stdout")
    options, args = parser.parse_args()
    try :
            ini_file = args.pop()
    except :
            print("config file is not specified")
            sys.exit()

    config = configparser.ConfigParser()
    config.read(ini_file)

    if options.stdout :
        of_frr = sys.stdout
        of_ipsec_secrets = sys.stdout
    else :
        of_frr = open("/etc/frr/frr.conf", "w")
        of_ipsec_secrets = open("/usr/local/etc/ipsec.secrets", "w")

        
    config_render_frr_conf(config, of_frr)
    config_render_ipsec_secrets(config, of_ipsec_secrets)
