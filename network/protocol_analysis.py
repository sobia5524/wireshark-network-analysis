from collections import Counter
from scapy.layers.inet import TCP, UDP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP


def analyze_protocols(packets):
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

    return protocols