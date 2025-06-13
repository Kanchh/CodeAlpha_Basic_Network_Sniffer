# CodeAlpha_Basic_Network_Sniffer
from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    # Check if packet has IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, str(proto))
        
        print(f"[+] {ip_src} -> {ip_dst} | Protocol: {protocol_name}")
        
        # Display TCP/UDP ports if available
        if TCP in packet:
            print(f"    TCP Sport: {packet[TCP].sport}, Dport: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    UDP Sport: {packet[UDP].sport}, Dport: {packet[UDP].dport}")
        
        # Optional: Print payload (raw data)
        if packet.haslayer(Raw):
            print(f"    Payload: {packet[Raw].load}")

def main():
    print("Starting packet sniffer... Press CTRL+C to stop.")
    sniff(prn=process_packet, store=0)

if __name__ == "__main__":
    main()
