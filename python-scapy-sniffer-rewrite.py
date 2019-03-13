#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

old_server = "10.21.10.150"
new_server = "10.21.10.105"
old_port = 8000
new_port = 8888
timeout = 5
filter = "tcp"

def rewrite(pkt):
    if pkt[IP].dst == old_server and pkt[TCP].dport == old_port:
        print("ORIG: {0}".format(pkt.summary()))
        pkt[IP].dst = new_server
        pkt[TCP].dport = new_port
        print("NEW {0}".format(pkt.summary))
        print()
        sendp(pkt)


sniff(filter=filter, prn = rewrite)

