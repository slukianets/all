#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    answered, unanswered = scapy.srp(broadcast_frame/arp_request, timeout = 1, verbose = False)
    for reply in answered:
        print(reply[1].psrc, reply[1].hwsrc)


scan("10.21.100.1")