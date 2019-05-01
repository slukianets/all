#! /usr/bin/python
from contextlib import contextmanager
import sys, os, netaddr 
from scapy.all import *

@contextmanager
def outnull():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout

network = netaddr.IPNetwork(str(sys.argv[1]))
list_ip_addr = []
for ip_addr in network:
    list_ip_addr.append(str(ip_addr))
del(list_ip_addr[0])
del(list_ip_addr[-1])
#print(list_ip_addr)
for dest_ip in list_ip_addr:
    print(dest_ip)
    package = IP(dst = dest_ip)/ICMP()
    with outnull():
        reply,unasw = sr(package, timeout = 0.1)
#print(reply[0])
    if reply:
        if((reply[0][1].ihl == 5) and (reply[0][1].src == dest_ip)):
            print("Host " + dest_ip + " is online")
    else:
       print("Host " + dest_ip + " is offline")



