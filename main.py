"""
Author: lia yosef
date:2/3/2024

description:
this program gets an ip from the client and prints the open ports
"""

from scapy.all import *
from scapy.layers.inet import TCP, IP

Timeout = 0.5
PORTS = range(20, 1025)


def main():
    ip_address = input("enter ip:")
    ports = PORTS
    for port in ports:
        syn_packet = IP(dst=ip_address) / TCP(sport=RandShort(), dport=port, flags="S")
        response = sr1(syn_packet, timeout=Timeout)
        if response and response.haslayer(TCP) and response[TCP].flags & 0x1F == 0x12:
            print(f"the {port} is open")


if __name__ == '__main__':
    main()
