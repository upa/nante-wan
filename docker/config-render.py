#!/usr/bin/env python

import os
import sys
import ConfigParser
from optparse import OptionParser
from jinja2 import Environment, FileSystemLoader


def config_render_frr_conf(config, of) :

    d = {
        "hostname" : config.get("general", "hostname"),
        "identifier" : config.get("address", "identifier"),
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

def config_render_ipsec_conf(config, of) :
    
    d = {
        "locator" : config.get("address", "locator")
        }

    tmp = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader = FileSystemLoader(tmp, encoding = "utf-8"))
    tpl = env.get_template("ipsec.conf.template")

    ipsec_conf = tpl.render(d)
    print >> of, ipsec_conf

    
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
        of_ipsec = sys.stdout
        of_ipsec_secrets = sys.stdout
    else :
        of_frr = open("/etc/frr.conf", "w")
        of_ipsec = open("/usr/local/etc/ipsec.conf", "w")
        of_ipsec_secrets = open("/usr/local/etc/ipsec.secrets", "w")

        
    config_render_frr_conf(config, of_frr)
    config_render_ipsec_conf(config, of_ipsec)
    config_render_ipsec_secrets(config, of_ipsec_secrets)
