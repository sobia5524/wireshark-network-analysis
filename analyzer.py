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

for packet in packets:

    if packet.haslayer(TCP):
        protocols["TCP"] += 1

    if packet.haslayer(UDP):
        protocols["UDP"] += 1

    if packet.haslayer(DNS):
        protocols["DNS"] += 1

    if packet.haslayer(ARP):
        protocols["ARP"] += 1

print("Protocol Statistics")
print("-" * 25)

for protocol, count in protocols.items():
    print(f"{protocol:<8}: {count}")