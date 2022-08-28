#!/usr/bin/env python3
from scapy.all import *

# Showing packet info while sniffing
def print_pkt(pkt):
    pkt.show()
    
# Sniffing with the wanted filter
pkt = sniff(iface=['br-8b86d076ab3c','docker0', 'enp0s3','lo'], filter='tcp and dst port 23 and src host 10.9.0.1', prn=print_pkt)
  
