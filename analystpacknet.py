from scapy.all import sniff, IP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_origin = packet[IP].src
        ip_destination = packet[IP].dst
        print(f"Origin: {ip_origin} --> Destination: {ip_destination}");
        print("Capturando pacotes... Pressione Ctrl+C para parar.")
      
        
sniff(prn=packet_callback, store=False, count=10)        