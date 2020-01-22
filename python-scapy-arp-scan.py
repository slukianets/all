#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP address and IP range")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify an IP address or an IP range, use --help for more info.")
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, unanswered = scapy.srp(broadcast_frame / arp_request, timeout=1, verbose=False)
    list_arp_response = []
    for reply in answered:
        list_arp_response.append({"ip": reply[1].psrc, "mac": reply[1].hwsrc})
    return list_arp_response


def output_results(list):
    print("IP\t\t\tMAC")
    print("-" * 42)
    for element in list:
        print(element["ip"], "\t\t", element["mac"])
        print("-" * 42)


options = get_arguments()
scan_result = scan(options.target)
output_results(scan_result)
