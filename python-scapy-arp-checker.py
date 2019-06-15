#!/usr/bin/env python

from scapy.all import *


def show_arp_info(pkt):
    if pkt[0].op == 1:
        print("ARP package: HOST, source IP {0} and HW {1} ask about HW {2} for IP {3}".format(pkt[0].psrc, pkt[0].hwsrc, pkt[0].hwdst, pkt[0].pdst))
    elif pkt[0].op == 2:
        print("ARP package: HOST, IP {0} HW {1} answer to HOST IP {2} HW {3}".format(pkt[0].psrc, pkt[0].hwsrc, pkt[0].pdst, pkt[0].hwdst))
#   print(pkt[0].op)  
#   print(type(pkt[0].op))


sniff(filter = "arp", prn = show_arp_info)   
