from scapy.all import sniff, IP, UDP, TCP, ICMP
import sys

FILTER_PROTOCOL = TCP  # Set to "TCP", "UDP", "ICMP", or None for all protocols.
FILTER_IP = None  # Set to an IP address string to filter by source or destination IP, or None for all IPs.


def packet_callback(packet):
    if packet.haslayer(IP):
        ip_origin = packet[IP].src
        ip_dest = packet[IP].dst
        
        if packet.haslayer("TCP"):
            protocol = "TCP"
            origin_port = packet["TCP"].sport
            dest_port = packet["TCP"].dport
            info = f"[TCP] Origin: {ip_origin}:{origin_port} --> Destination: {ip_dest}:{dest_port}";       
        elif packet.haslayer("UDP"):
            protocol = "UDP"
            origin_port = packet["UDP"].sport
            dest_port = packet["UDP"].dport
            info = f"[UDP] Origin: {ip_origin}:{origin_port} --> Destination: {ip_dest}:{dest_port}";       
        elif packet.haslayer("ICMP"):
            protocol = "ICMP"
            info = f"[ICMP] Origin: {ip_origin} --> Destination: {ip_dest}"
        else:
            protocol = "Other"
            info = f"[{protocol}] Origin: {ip_origin} --> Destination: {ip_dest}"
            
            if FILTER_PROTOCOL and protocol != FILTER_PROTOCOL:
                return
            if FILTER_IP and FILTER_IP not in (ip_origin, ip_dest):
                return
            
            print(info)


sniff(prn=packet_callback, store=False, count=0)