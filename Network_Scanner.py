#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description="A script to scan network")
    parser.add_argument("-t", "--target", dest="target", help="Enter IP / IP range.", required=True)
    args = parser.parse_args()
    return args

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered:
        print("List of devices in the network range")
        print("IP Address\t\tMAC Address\n---------------------------------------------------------")
        for sent, received in answered:
            print(f"{received.psrc}\t\t{received.hwsrc}")
    else:
        print("No devices found.")

if __name__ == "__main__":
    options = get_arguments()
    scan_results = (options.target)
    scan(scan_results)