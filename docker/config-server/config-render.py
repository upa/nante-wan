#!/usr/bin/env python3

import os
import sys
import socket
import fcntl
import struct
import configparser
from optparse import OptionParser
from jinja2 import Environment, FileSystemLoader



def config_render_nginx(config, of) :

    d = { "dmvpn_addr" : config.get("general", "dmvpn_addr")}

    tmp = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader = FileSystemLoader(tmp, encoding = "utf-8"))
    tpl = env.get_template("default")

    nginx_conf = tpl.render(d)
    print(nginx_conf, file = of)

    
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
        of_nginx = sys.stdout
    else :
        of_nginx = open("/etc/nginx/sites-enabled/default")

        
    config_render_nginx(config, of_nginx)
