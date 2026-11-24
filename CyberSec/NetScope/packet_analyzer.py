from datetime import datetime

from scapy.all import (
    sniff,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ARP,
    DNS
)

packet_count = 0


def analyze_packet(packet):
    global packet_count
    packet_count += 1

    # Get packet timestamp
    timestamp = datetime.fromtimestamp(
        float(packet.time)
    ).strftime("%H:%M:%S")

    # Default values
    source_ip = "Unknown"
    destination_ip = "Unknown"
    transport = "Other"
    application = "-"
    source_port = "-"
    destination_port = "-"

    # Identify IPv4 addresses
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    # Identify IPv6 addresses
    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    # Identify ARP packets
    if ARP in packet:
        source_ip = packet[ARP].psrc
        destination_ip = packet[ARP].pdst
        transport = "ARP"

    # Identify TCP packets
    elif TCP in packet:
        transport = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    # Identify UDP packets
    elif UDP in packet:
        transport = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    # Identify ICMP packets
    elif ICMP in packet:
        transport = "ICMP"

    # Identify ICMPv6 packets
    elif (
        ICMPv6EchoRequest in packet
        or ICMPv6EchoReply in packet
    ):
        transport = "ICMPv6"

    elif IPv6 in packet and packet.haslayer("ICMPv6"):
        transport = "ICMPv6"

    elif IPv6 in packet:
        transport = "IPv6"

    elif IP in packet:
        transport = "IPv4"

    # Identify DNS application traffic
    if DNS in packet:
        application = "DNS"

    # Get packet size
    packet_size = len(packet)

    # Display packet information
    print(
        f"{packet_count:<6}"
        f"{timestamp:<12}"
        f"{source_ip:<40}"
        f"{destination_ip:<40}"
        f"{transport:<10}"
        f"{str(source_port):<12}"
        f"{str(destination_port):<12}"
        f"{application:<12}"
        f"{packet_size:<10}"
    )


def start_capture():
    print("\n" + "=" * 155)
    print("             NETSCOPE - NETWORK PACKET ANALYZER")
    print("=" * 155)

    print(
        f"{'No.':<6}"
        f"{'Time':<12}"
        f"{'Source IP':<40}"
        f"{'Destination IP':<40}"
        f"{'Transport':<10}"
        f"{'Src Port':<12}"
        f"{'Dst Port':<12}"
        f"{'Application':<12}"
        f"{'Size':<10}"
    )

    print("-" * 155)
    print("Capturing packets... Press Ctrl+C to stop.\n")

    try:
        sniff(
            prn=analyze_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\n\nPacket capture stopped.")

        print(f"Total packets captured: {packet_count}")


if __name__ == "__main__":
    start_capture()