#!/usr/bin/env python

import os
import sys
import socket
import fcntl
import struct
import ConfigParser
from optparse import OptionParser
from jinja2 import Environment, FileSystemLoader


def get_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
    )[20:24])


def config_render_frr_conf(config, of) :

    identifier = get_ip
        
    d = {
        "hostname" : config.get("general", "hostname"),
        "as_number" : config.get("general", "as_number"),
        "identifier" : get_ip(config.get("address", "identifier_interface")),
        "locator_interface" : config.get("address", "locator_interface"),
        "nhs_identifier" : config.get("address", "nhs_identifier"),
        "nhs_locator" : config.get("address", "nhs_locator"),
        "rr_identifier" : config.get("address", "rr_identifier")
    }

    tmp = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader = FileSystemLoader(tmp, encoding = "utf-8"))
    tpl = env.get_template("frr.conf.template")

    frr_conf = tpl.render(d)
    print >> of, frr_conf

    
def config_render_ipsec_secrets(config, of) :

    d = {
            "ipsec_secret" : config.get("ipsec", "ipsec_secret")
    }

    tmp = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader = FileSystemLoader(tmp, encoding = "utf-8"))
    tpl = env.get_template("ipsec.secrets.template")

    ipsec_secrets = tpl.render(d)
    print >> of, ipsec_secrets



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
            print "config file is not specified"
            sys.exit()

    config = ConfigParser.ConfigParser()
    config.read(ini_file)

    if options.stdout :
        of_frr = sys.stdout
        of_ipsec_secrets = sys.stdout
    else :
        of_frr = open("/etc/frr/frr.conf", "w")
        of_ipsec_secrets = open("/usr/local/etc/ipsec.secrets", "w")

        
    config_render_frr_conf(config, of_frr)
    config_render_ipsec_secrets(config, of_ipsec_secrets)
