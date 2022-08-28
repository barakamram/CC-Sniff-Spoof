#!/usr/bin/env python3
from scapy.all import *

#creating a spoofed packet 
a = IP()
a.dst = '172.17.0.1'
a.src = '2.2.2.2'
b = ICMP()
p = a/b
send(p)
