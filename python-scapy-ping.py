#! /usr/bin/python
from contextlib import contextmanager
import sys, os 
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

dest_ip =str(sys.argv[1])
#print(dest_ip)
package = IP(dst = dest_ip)/ICMP()
with outnull():
    reply,unasw = sr(package, timeout = 0.2)
#print(reply[0])
if reply:
    if((reply[0][1].ihl == 5) and (reply[0][1].src == dest_ip)):
        print("Host " + dest_ip + " is online")
else:
     print("Host " + dest_ip + " is offline")



