from scapy.all import sniff, IP, UDP, TCP, ICMP, Raw
import datetime

FILTER_PROTOCOL = None  # Set to "TCP", "UDP", "ICMP", or None for all protocols.
FILTER_IP = None  # Set to an IP address string to filter by source or destination IP, or None for all IPs.
LOG_FILE = "capture_log.txt"


def save_to_log(message):
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")


def packet_callback(packet):
    if packet.haslayer(IP):
        ip_origin = packet[IP].src
        ip_dest = packet[IP].dst
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if packet.haslayer("TCP"):
            protocol = "TCP"
            origin_port = packet["TCP"].sport
            dest_port = packet["TCP"].dport
            info = f"[{timestamp}][TCP] Origin: {ip_origin}:{origin_port} --> Destination: {ip_dest}:{dest_port}";       
        elif packet.haslayer("UDP"):
            protocol = "UDP"
            origin_port = packet["UDP"].sport
            dest_port = packet["UDP"].dport
            info = f"[{timestamp}][UDP] Origin: {ip_origin}:{origin_port} --> Destination: {ip_dest}:{dest_port}";       
        elif packet.haslayer("ICMP"):
            protocol = "ICMP"
            info = f"[{timestamp}][ICMP] Origin: {ip_origin} --> Destination: {ip_dest}"
        else:
            protocol = "Other"
            info = f"[{timestamp}][{protocol}] Origin: {ip_origin} --> Destination: {ip_dest}"
            
            if FILTER_PROTOCOL and protocol != FILTER_PROTOCOL:
                return
            if FILTER_IP and FILTER_IP not in (ip_origin, ip_dest):
                return
            
            print(info)
            save_to_log(info)

            if packet.haslayer("Raw"):
                payload = packet["Raw"].load
                try:
                    payload_info = f"Payload: {payload.decode('utf-8', errors='ignore')[:100]}"
                except UnicodeDecodeError:
                    payload_info = f"Payload (hex): {payload.hex()[:100]}"
                print(payload_info)
                save_to_log(payload_info)


print(f"Save logs to: {LOG_FILE}")
sniff(prn=packet_callback, store=False, count=0)