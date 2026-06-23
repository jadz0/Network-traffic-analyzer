# Architecture

## Workflow

Network Traffic

↓

Wireshark Packet Capture

↓

PCAP File (.pcapng)

↓

Python Analysis Engine

↓

Traffic Report

## Components

### Wireshark

Captures network packets and exports traffic to PCAP format.

### Python Analyzer

Processes PCAP files and extracts useful network statistics.

### Reports

Exports protocol and traffic statistics to CSV format.

## Data Flow

1. Network traffic is captured using Wireshark.
2. The capture is saved as a PCAP file.
3. Python reads the PCAP file using Scapy.
4. Traffic statistics are generated.
5. Results are exported to CSV.
