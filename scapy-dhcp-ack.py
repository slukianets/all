from typing import Optional, Dict, Any, Union

from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
import re

# pcap_file = rdpcap('/Users/lukianets/dhcp-log.pcap')
# pcap_file = rdpcap('/Users/lukianets/core3-dhcp-pkg.pcap')
# pcap_file = rdpcap('/Users/lukianets/atlas-dhcp-ipv6.pcap')
#pcap_file = rdpcap('/Users/lukianets/dhcp-trafic.pcap')
#pcap_file = rdpcap('/Users/lukianets/dhcp-trafic-all.pcap')
filter = "udp"

def getIpV4Address(ipv4):
    pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    ip_address = pattern.match(ipv4)
    if ip_address:
        return ipv4
    else:
        return None


def getMacAddress(bytesMacAddress: object) -> object:
    bytesMacString = map('{:02x}'.format, bytesMacAddress)
    macAddress = ':'.join(bytesMacString).upper()
    return macAddress

def sniff_dhcp_ack(pkg):
    mac_ip_dic = {}
    if pkg[1].version == 4:
        if pkg[2].sport == 67 or pkg[2].sport == 68:
            if pkg[DHCP].options[0][1] == 5:
                leased_ip_address = getIpV4Address(pkg[BOOTP].yiaddr)
                device_mac_address = getMacAddress(pkg[BOOTP].chaddr[0:6])
                if device_mac_address not in mac_ip_dic:
                    mac_ip_dic.update({device_mac_address: leased_ip_address})
                print(device_mac_address, " ", mac_ip_dic[device_mac_address])
#    else:
#        if (pkg[2].sport == 546) or (pkg[2].sport == 547):
#            if pkg[2].msgtype == 13 and pkg[2][4].msgtype == 7:
#                if pkg['DHCP6 IA Address Option (IA_TA or IA_NA suboption)'].addr:
#                    leased_ip_address = pkg['DHCP6 IA Address Option (IA_TA or IA_NA suboption)'].addr
#                if pkg['DHCP6 Client Identifier Option'][1].lladdr:
#                    device_mac_address = pkg['DHCP6 Client Identifier Option'][1].lladdr.upper()
#                    # print(leased_ip_address, " ", device_mac_address)
#                    if device_mac_address not in mac_ip_dic:
#                        mac_ip_dic.update({device_mac_address: leased_ip_address})
#                        print(device_mac_address, " ", mac_ip_dic[device_mac_address])
#    print(mac_ip_dic)


sniff(filter=filter, prn=sniff_dhcp_ack)