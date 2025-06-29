from scapy.all import sniff, IP, TCP, UDP, conf


conf.use_pcap = True

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"\n[+] Packet captured:")
        print(f"    Source IP: {ip_src}")
        print(f"    Destination IP: {ip_dst}")
        print(f"    Protocol: {proto}")

        if TCP in packet:
            print(f"    TCP Port: {packet[TCP].sport} → {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    UDP Port: {packet[UDP].sport} → {packet[UDP].dport}")

print("Starting packet sniffer...")
sniff(prn=packet_callback, count=10, store=False)
