from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import Counter
from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
PCAP_FILE = BASE_DIR / "sample_pcaps" / "normal_traffic.pcapng"
OUTPUT_DIR = BASE_DIR / "reports"
OUTPUT_DIR.mkdir(exist_ok=True)

packets = rdpcap(str(PCAP_FILE))

protocols = Counter()
source_ips = Counter()
destination_ips = Counter()

total_packets = len(packets)
ip_packets = 0

for packet in packets:
    if not packet.haslayer(IP):
        continue

    ip_packets += 1

    src = packet[IP].src
    dst = packet[IP].dst

    source_ips[src] += 1
    destination_ips[dst] += 1

    if packet.haslayer(TCP):
        protocols["TCP"] += 1
    elif packet.haslayer(UDP):
        protocols["UDP"] += 1
    elif packet.haslayer(ICMP):
        protocols["ICMP"] += 1
    else:
        protocols["Other IP"] += 1

print("=" * 60)
print("           NETWORK TRAFFIC ANALYSIS REPORT")
print("=" * 60)

print(f"\nPCAP File: {PCAP_FILE.name}")
print(f"Total Packets: {total_packets}")
print(f"IP Packets: {ip_packets}")

print("\nProtocol Distribution")
print("-" * 60)

for protocol, count in protocols.items():
    percent = (count / ip_packets * 100) if ip_packets else 0
    print(f"{protocol:<10} {count:>8} packets   ({percent:>6.2f}%)")

print("\nTop Source IPs")
print("-" * 60)
for i, (ip, count) in enumerate(source_ips.most_common(5), start=1):
    print(f"{i}. {ip:<20} {count:>6} packets")

print("\nTop Destination IPs")
print("-" * 60)
for i, (ip, count) in enumerate(destination_ips.most_common(5), start=1):
    print(f"{i}. {ip:<20} {count:>6} packets")

protocol_report = pd.DataFrame([
    {
        "Protocol": protocol,
        "Count": count,
        "Percentage": round((count / ip_packets * 100), 2) if ip_packets else 0
    }
    for protocol, count in protocols.items()
])

source_ip_report = pd.DataFrame(
    source_ips.most_common(10), columns=["Source IP", "Count"]
)

destination_ip_report = pd.DataFrame(
    destination_ips.most_common(10), columns=["Destination IP", "Count"]
)

protocol_report.to_csv(OUTPUT_DIR / "protocol_report.csv", index=False)
source_ip_report.to_csv(OUTPUT_DIR / "top_source_ips.csv", index=False)
destination_ip_report.to_csv(OUTPUT_DIR / "top_destination_ips.csv", index=False)

print("\n" + "=" * 60)
print("Reports saved successfully in:", OUTPUT_DIR)
print("=" * 60)