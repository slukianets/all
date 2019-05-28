import subprocess
import optparse

parser = optparse.OptionParser()

parser.add_option("-i", "--interfase", dest = "interface", help="Interface to change its MAC address")
parser.add_option("-m", "--new_mac", dest = "new_mac", help="New MAC address")

(options, arguments) = parser.parse_args()

interface = options.interface
new_mac = options.new_mac

if interface:
    print("interface:" , interface)

if new_mac:
    print("MAC address: ", new_mac)