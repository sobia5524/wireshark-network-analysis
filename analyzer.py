from scapy.layers.inet import IP
from collections import Counter

from scapy.all import rdpcap
from scapy.layers.inet import TCP, UDP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP

# Read packets
packets = rdpcap("captures/sample_capture.pcapng")

print("=" * 50)
print("WIRESHARK NETWORK ANALYZER")
print("=" * 50)

print(f"Total Packets Captured : {len(packets)}")
print()

protocols = Counter()
source_ips = Counter()
destination_ips = Counter()

packet_sizes = []
for packet in packets:
    
    packet_sizes.append(len(packet))

    if packet.haslayer(TCP):
        protocols["TCP"] += 1

    if packet.haslayer(UDP):
        protocols["UDP"] += 1

    if packet.haslayer(DNS):
        protocols["DNS"] += 1

    if packet.haslayer(ARP):
        protocols["ARP"] += 1
    if packet.haslayer(IP):
        source_ips[packet[IP].src] += 1
        destination_ips[packet[IP].dst] += 1
    
print("Protocol Statistics")
print("-" * 25)

for protocol, count in protocols.items():
    print(f"{protocol:<8}: {count}")

print()
print("Top 5 Source IP Addresses")
print("-" * 30)

for ip, count in source_ips.most_common(5):
    print(f"{ip:<20} {count} packets")

print()
print("Top 5 Destination IP Addresses")
print("-" * 30)

for ip, count in destination_ips.most_common(5):
    print(f"{ip:<20} {count} packets")
    
print()
print("Packet Size Statistics")
print("-" * 30)

average_size = sum(packet_sizes) / len(packet_sizes)
largest_packet = max(packet_sizes)
smallest_packet = min(packet_sizes)

print(f"Average Packet Size : {average_size:.2f} bytes")
print(f"Largest Packet      : {largest_packet} bytes")
print(f"Smallest Packet     : {smallest_packet} bytes")

