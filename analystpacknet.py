from scapy.all import sniff, IP


def packet_callback(packet):
    if packet.haslayer(IP):
        ip_origin = packet[IP].src
        ip_dest = packet[IP].dst
        
        if packet.haslayer("TCP"):
            protocol = "TCP"        
        elif packet.haslayer("UDP"):
            protocol = "UDP"
        elif packet.haslayer("ICMP"):
            protocol = "ICMP"
        else:
            protocol = "Other"
             
        print(f"[{protocol}] Origin: {ip_origin} --> Destination: {ip_dest}");
        print("Capturando pacotes... Pressione Ctrl+C para parar.")
     
      
sniff(prn=packet_callback, store=False, count=10)