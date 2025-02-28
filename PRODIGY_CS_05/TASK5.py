from scapy.all import *


def packet_callback(packet):
    print("\n[Packet Captured]")
    print(f"Source IP: {packet[IP].src}")
    print(f"Destination IP: {packet[IP].dst}")
    print(f"Protocol: {packet.proto}")

    if packet.haslayer(TCP):
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
    elif packet.haslayer(UDP):
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")

    if packet.haslayer(Raw):
        print(f"Payload: {packet[Raw].load}")


def start_sniffer():
    print("Starting packet sniffer. Press Ctrl+C to stop...")
    sniff(prn=packet_callback, store=0)  # sniffs indefinitely


if __name__ == "__main__":
    start_sniffer()
