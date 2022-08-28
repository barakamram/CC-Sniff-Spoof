#!/usr/bin/env python3
from scapy.all import *

# Showing packet info while sniffing
def print_pkt(pkt):
    pkt.show()
    
# Sniffing with the wanted filter
pkt = sniff(iface=['docker0', 'enp0s3','lo'], filter='icmp', prn=print_pkt)
    
