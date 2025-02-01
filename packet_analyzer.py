from scapy.all import *
import matplotlib.pyplot as plt
from collections import defaultdict
import numpy as np
import os
from datetime import datetime

def analyze_packet_sizes(packets):
    """Analyze packet sizes and return statistics"""
    sizes = [len(packet) for packet in packets]
    return {
        'total_bytes': sum(sizes),
        'total_packets': len(sizes),
        'min_size': min(sizes),
        'max_size': max(sizes),
        'avg_size': sum(sizes) / len(sizes),
        'sizes': sizes
    }

def plot_packet_size_distribution(sizes):
    """Create histogram of packet sizes"""
    plt.figure(figsize=(10, 6))
    plt.hist(sizes, bins=50, edgecolor='black')
    plt.title('Packet Size Distribution')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.savefig('packet_distribution.png')
    plt.close()

def analyze_flows(packets):
    """Analyze source-destination pairs and flow statistics"""
    flows = defaultdict(int)
    src_flows = defaultdict(int)
    dst_flows = defaultdict(int)
    flow_data = defaultdict(int)
    
    for packet in packets:
        if IP in packet and (TCP in packet or UDP in packet):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            else:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            flow_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            flows[flow_key] += 1
            src_flows[src_ip] += 1
            dst_flows[dst_ip] += 1
            flow_data[flow_key] += len(packet)
    
    return flows, src_flows, dst_flows, flow_data

def main(pcap_file):
    # Write results to simple filenames
    output_file = 'metrics.txt'

    with open(output_file, 'w') as f:
        # Read pcap file
        f.write(f"Reading pcap file: {pcap_file}\n")
        packets = rdpcap(pcap_file)
        
        # Analyze packet sizes
        size_stats = analyze_packet_sizes(packets)
        f.write("\nPacket Statistics:\n")
        f.write(f"Total data transferred: {size_stats['total_bytes']} bytes\n")
        f.write(f"Total packets: {size_stats['total_packets']}\n")
        f.write(f"Minimum packet size: {size_stats['min_size']} bytes\n")
        f.write(f"Maximum packet size: {size_stats['max_size']} bytes\n")
        f.write(f"Average packet size: {size_stats['avg_size']:.2f} bytes\n")
        
        # Plot packet size distribution
        plot_packet_size_distribution(size_stats['sizes'])
        
        # Analyze flows
        flows, src_flows, dst_flows, flow_data = analyze_flows(packets)
        
        f.write("\nUnique Source-Destination Pairs:\n")
        for flow in flows:
            f.write(f"{flow}: {flows[flow]} packets\n")
        
        f.write("\nSource IP Flow Counts:\n")
        f.write(f"{dict(src_flows)}\n")
        
        f.write("\nDestination IP Flow Counts:\n")
        f.write(f"{dict(dst_flows)}\n")
        
        # Find the flow with most data transferred
        max_flow = max(flow_data.items(), key=lambda x: x[1])
        f.write(f"\nFlow with most data transferred:\n")
        f.write(f"{max_flow[0]}: {max_flow[1]} bytes\n")

    print(f"Analysis complete. Results saved in {output_file} and packet_distribution.png")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python packet_analyzer.py <pcap_file>")
        sys.exit(1)
    
    main(sys.argv[1])
