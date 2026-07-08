def generate_report(
    filename,
    total_packets,
    protocols,
    source_ips,
    destination_ips,
    dns_queries,
    packet_sizes,
    conversations,
):

    average_size = sum(packet_sizes) / len(packet_sizes)
    largest_packet = max(packet_sizes)
    smallest_packet = min(packet_sizes)

    with open(filename, "w") as file:

        file.write("=" * 45 + "\n")
        file.write("WIRESHARK NETWORK ANALYZER REPORT\n")
        file.write("=" * 45 + "\n\n")

        file.write(f"Total Packets: {total_packets}\n\n")

        file.write("Protocol Statistics\n")
        file.write("-" * 25 + "\n")

        for protocol, count in protocols.items():
            file.write(f"{protocol}: {count}\n")

        file.write("\nTop Source IP Addresses\n")
        file.write("-" * 25 + "\n")

        for ip, count in source_ips.most_common(5):
            file.write(f"{ip}: {count}\n")

        file.write("\nTop Destination IP Addresses\n")
        file.write("-" * 25 + "\n")

        for ip, count in destination_ips.most_common(5):
            file.write(f"{ip}: {count}\n")

        file.write("\nTop DNS Queries\n")
        file.write("-" * 25 + "\n")

        for domain, count in dns_queries.most_common(10):
            file.write(f"{domain}: {count}\n")

        file.write("\nPacket Size Statistics\n")
        file.write("-" * 25 + "\n")

        file.write(f"Average Packet Size: {average_size:.2f} bytes\n")
        file.write(f"Largest Packet: {largest_packet} bytes\n")
        file.write(f"Smallest Packet: {smallest_packet} bytes\n")

        file.write("\nTop Network Conversations\n")
        file.write("-" * 30 + "\n")

        for (src, dst), count in conversations.most_common(10):
            file.write(f"{src} -> {dst} : {count} packets\n")