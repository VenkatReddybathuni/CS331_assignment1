# Network Analysis Tools

Tools for network packet analysis and capture.

## Requirements

```bash
pip install -r requirements.txt
```

## 1. Packet Analyzer

```bash
python3 packet_analyzer.py <path_to_pcap_file>
```

Output files:
- metrics.txt - Statistics including packet counts, sizes, and flow data
- packet_distribution.png - Histogram of packet sizes

## 2. Packet Sniffer

```bash
# Run with default 15-minute duration
sudo python socket_sniffer.py -i <interface_name>

# Run with custom duration (in seconds)
sudo python socket_sniffer.py -i <interface_name> -d <duration>
```

Features:
- Default 15-minute packet capture (customizable)
- Real-time packet capture statistics
- Live PPS and Mbps display
- Peak speed measurement
- Remaining time display

Output files:
- sniff.pcap - Captured network packets
- sniff.txt - Statistics including peak PPS and Mbps

## Network Interface Setup

```bash
# Create dummy interface
sudo ip link add veth0 type dummy
sudo ip link set veth0 up

# Remove when done (optional)
sudo ip link delete veth0
```
