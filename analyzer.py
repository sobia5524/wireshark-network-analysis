from network.report import generate_report
import sys
from collections import Counter
from scapy.all import rdpcap
from scapy.layers.inet import IP
from scapy.layers.dns import DNS
from network.protocol_analysis import analyze_protocols
from network.ip_analysis import analyze_ips

# Read packets
if len(sys.argv) != 2:
    print("Usage:")
    print("    python analyzer.py <pcap_file>")
    print()
    print("Example:")
    print("    python analyzer.py captures/sample_capture.pcapng")
    sys.exit(1)

pcap_file = sys.argv[1]

packets = rdpcap(pcap_file)

print("=" * 50)
print("WIRESHARK NETWORK ANALYZER")
print("=" * 50)

print(f"Total Packets Captured : {len(packets)}")
print()
protocols = analyze_protocols(packets)
source_ips, destination_ips = analyze_ips(packets)

packet_sizes = []

dns_queries = Counter()
conversations = Counter()
for packet in packets:
    
    packet_sizes.append(len(packet))

    if packet.haslayer(IP):
        conversation = (
            packet[IP].src,
            packet[IP].dst
        )

    conversations[conversation] += 1

    if packet.haslayer(DNS):
        dns = packet[DNS]

        if dns.qr == 0 and dns.qd:
            domain = dns.qd.qname.decode(errors="ignore").rstrip(".")
            if "in-addr.arpa" not in domain:
                dns_queries[domain] += 1
    
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
print("Top DNS Queries")
print("-" * 30)

for domain, count in dns_queries.most_common(10):
    print(f"{domain:<35} {count}")

print()
print("Packet Size Statistics")
print("-" * 30)

average_size = sum(packet_sizes) / len(packet_sizes)
largest_packet = max(packet_sizes)
smallest_packet = min(packet_sizes)

print(f"Average Packet Size : {average_size:.2f} bytes")
print(f"Largest Packet      : {largest_packet} bytes")
print(f"Smallest Packet     : {smallest_packet} bytes")

print()
print("Top Network Conversations")
print("-" * 40)

for (src, dst), count in conversations.most_common(10):
    print(f"{src}")
    print(f"   ↓")
    print(f"{dst}")
    print(f"Packets : {count}")
    print()

# Generate report
generate_report(
    "reports/network_report.txt",
    len(packets),
    protocols,
    source_ips,
    destination_ips,
    dns_queries,
    packet_sizes,
    conversations,
)

print()
print("✅ Report saved to reports/network_report.txt")

