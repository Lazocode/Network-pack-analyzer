from scapy.all import sniff, IP, UDP, TCP, ICMP


def packet_callback(packet):
    if packet.haslayer(IP):
        ip_origin = packet[IP].src
        ip_dest = packet[IP].dst
        
        if packet.haslayer("TCP"):
            origin_port = packet["TCP"].sport
            dest_port = packet["TCP"].dport
            print(f"[TCP] Origin: {ip_origin}:{origin_port} --> Destination: {ip_dest}:{dest_port}");       
        elif packet.haslayer("UDP"):
            origin_port = packet["UDP"].sport
            dest_port = packet["UDP"].dport
            print(f"[UDP] Origin: {ip_origin}:{origin_port} --> Destination: {ip_dest}:{dest_port}");       
        elif packet.haslayer("ICMP"):
            print(f"[ICMP] Origin: {ip_origin} --> Destination: {ip_dest}");
        else:
            protocol = "Other"
            print(f"[{protocol}] Origin: {ip_origin} --> Destination: {ip_dest}");
      
      
sniff(prn=packet_callback, store=False, count=10)