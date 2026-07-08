from collections import Counter
from scapy.layers.inet import IP


def analyze_ips(packets):
    source_ips = Counter()
    destination_ips = Counter()

    for packet in packets:
        if packet.haslayer(IP):
            source_ips[packet[IP].src] += 1
            destination_ips[packet[IP].dst] += 1

    return source_ips, destination_ips