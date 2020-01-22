#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    answered, unanswered = scapy.srp(broadcast_frame/arp_request, timeout = 1, verbose = False)
    list_arp_response = []
    for reply in answered:
        list_arp_response.append({"ip" : reply[1].psrc, "mac" : reply[1].hwsrc})
    return list_arp_response

def output_results(list):
    print("IP\t\t\tMAC")
    print("-" * 42)
    for element in list:
        print(element["ip"],"\t\t", element["mac"])
        print("-" * 42)

scan_result = scan("10.0.2.1/24")
output_results(scan_result)
