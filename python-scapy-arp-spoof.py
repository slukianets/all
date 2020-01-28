#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP address")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP address")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify an Target IP address , use --help for more info.")
    elif options.gateway:
        parser.error("[-] Please specify an Gateway IP address, use --help for more info.")
    return options

def get_mac(ip):
    response, unresponse = scapy.arping(ip, verbose = False)
    mac = response[0][1].hwsrc
    return mac


options = get_arguments()
print(get_mac(options.target))
print(get_mac(options.gateway))

