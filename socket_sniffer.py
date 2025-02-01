import socket
import time
import struct
from collections import defaultdict
import argparse
import dpkt
import signal

class PacketSniffer:
    def __init__(self):
        self.packet_count = 0
        self.start_time = None
        self.total_bytes = 0
        self.stats = defaultdict(int)
        self.peak_pps = 0
        self.peak_mbps = 0
        self.running = True

    def parse_packet(self, packet):
        # This function simply calculates the packet length, and could be extended to parse more details
        packet_length = len(packet)
        return packet_length

    def packet_callback(self, packet, pcap_writer):
        if self.start_time is None:
            self.start_time = time.time()
        
        packet_length = self.parse_packet(packet)
        self.packet_count += 1
        self.total_bytes += packet_length
        
        # Write the packet to pcap file
        timestamp = time.time()
        pcap_writer.writepkt(packet, ts=timestamp)

        # Calculate current metrics
        duration = time.time() - self.start_time
        pps = self.packet_count / duration
        mbps = (self.total_bytes * 8 / (1024 * 1024)) / duration
        
        # Track peak values
        self.peak_pps = max(self.peak_pps, pps)
        self.peak_mbps = max(self.peak_mbps, mbps)
        
        # Update stats in the same line
        if int(duration) > len(self.stats):
            self.stats[int(duration)] = (pps, mbps)
            print(f"\rPackets: {self.packet_count} | PPS: {pps:.2f} | Mbps: {mbps:.2f}", end='', flush=True)

    def print_stats(self):
        if self.start_time:
            total_duration = time.time() - self.start_time
            print(f"\n\nCapture Statistics:")
            print(f"Total Packets: {self.packet_count}")
            print(f"Peak PPS: {self.peak_pps:.2f}")
            print(f"Peak Mbps: {self.peak_mbps:.2f}")
            print(f"Duration: {total_duration:.2f} seconds")

    def signal_handler(self, signum, frame):
        print("\nCapture interrupted by user")
        self.running = False

    def start_sniffing(self, interface="eth0", duration=60, pcap_path=None):
        signal.signal(signal.SIGINT, self.signal_handler)
        print(f"Starting packet capture on {interface} for {duration/60} mins...")

        # Create a raw socket and bind it to the interface
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        try:
            sock.bind((interface, 0))
            print(f"Successfully bound to {interface}")
        except Exception as e:
            print(f"Failed to bind to {interface}: {e}")
            return
        
        sock.settimeout(1)

        # Open pcap file for writing
        if pcap_path:
            pcap_file = open(pcap_path, 'wb')
            pcap_writer = dpkt.pcap.Writer(pcap_file)
        else:
            pcap_writer = None

        start_time = time.time()
        try:
            while self.running:
                try:
                    packet = sock.recv(65535)
                    self.packet_callback(packet, pcap_writer)
                except socket.timeout:
                    # Check if duration exceeded
                    if time.time() - start_time >= duration:
                        break
                    continue
        except KeyboardInterrupt:
            self.running = False
        finally:
            self.print_stats()
            if pcap_writer:
                pcap_file.close()
            sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Network Packet Sniffer')
    parser.add_argument('--interface', '-i', default='eth0', help='Interface to sniff on')
    parser.add_argument('--duration', '-d', type=int, default=15*60, help='Duration to sniff (seconds)')
    parser.add_argument('--pcap', '-p', default="sniff.pcap", help='Path to save the pcap file')
    args = parser.parse_args()

    sniffer = PacketSniffer()
    sniffer.start_sniffing(args.interface, args.duration, args.pcap)
