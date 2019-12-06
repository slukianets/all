from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
import re

# pcap_file = rdpcap('/Users/lukianets/dhcp-log.pcap')
# pcap_file = rdpcap('/Users/lukianets/core3-dhcp-pkg.pcap')
# pcap_file = rdpcap('/Users/lukianets/atlas-dhcp-ipv6.pcap')
pcap_file = rdpcap('/Users/lukianets/dhcp-trafic.pcap')


def getIpV4Address(ipv4):
    pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    ip_address = pattern.match(ipv4)
    if ip_address:
        return ipv4
    else:
        return None


def getMacAddress(bytesMacAddress):
    bytesMacString = map('{:02x}'.format, bytesMacAddress)
    macAddress = ':'.join(bytesMacString).upper()
    return macAddress

mac_ip_dic = {}
for pkg in pcap_file:
    try:
        if pkg[1].version == 4:
            if pkg[2].sport == 67 or pkg[2].sport == 68:
                if pkg[DHCP].options[0][1] == 3 and pkg[DHCP].options[-5][0] == 'requested_addr':
                # 3 == ack
                # print(leased_ip_address, " ", device_mac_address)
                    leased_ip_address = getIpV4Address(pkg[DHCP].options[-5][1])
                    device_mac_address = getMacAddress(pkg[BOOTP].chaddr[0:6])
                    if device_mac_address not in mac_ip_dic:
                        mac_ip_dic.update({device_mac_address : leased_ip_address})
        else:
            if (pkg[2].sport == 546) or (pkg[2].sport == 547):
                if pkg[2].msgtype == 13 and pkg[2][4].msgtype == 7:
                    leased_ip_address = pkg['DHCP6 IA Address Option (IA_TA or IA_NA suboption)'].addr
                    device_mac_address = pkg['DHCP6 Client Identifier Option'][1].lladdr.upper()
                    #print(leased_ip_address, " ", device_mac_address)
                    if device_mac_address not in mac_ip_dic:
                        mac_ip_dic.update({device_mac_address : leased_ip_address})

    except AttributeError:
        continue
    except IndexError:
        continue

for mac, ip in mac_ip_dic.items():
    print(mac, " ", ip)

