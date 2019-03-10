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
    reply = sr1(package, timeout = 0.2)
#print(reply)
if reply:
    if((reply.ihl == 5) and (reply.src == dest_ip)):
        print("Host " + dest_ip + " is online")
else:
     print("Host " + dest_ip + " is offline")



