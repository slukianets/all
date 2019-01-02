#!/usr/bin/python
import netifaces as ni
import socket

ifaces_list = ni.interfaces()
ifaces_info = {}
for i in ifaces_list:
	ip_address = ni.ifaddresses(i)[ni.AF_INET][0]['addr']
	ip_mask = ni.ifaddresses(i)[ni.AF_INET][0]['netmask']
	ifaces_info[i]=(ip_address,ip_mask)

#print(ifaces_info)
#for key in ifaces_info.keys():
#	ip_bin = socket.inet_aton(ifaces_info[key][0])
#	mask_bin = socket.inet_aton(ifaces_info[key][1])
#	print(ip_bin.decode("utf-8") ,mask_bin.decode("utf-8"))
for key in ifaces_info.keys():
	print(ifaces_info[key])
