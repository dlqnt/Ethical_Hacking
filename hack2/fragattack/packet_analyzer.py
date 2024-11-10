#!/usr/bin/env python3
from scapy.all import rdpcap, IP, TCP
from collections import defaultdict
import argparse
import logging
from typing import Dict, List, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class FragmentAnalyzer:
    def __init__(self, pcap_file: str):
        """
        Initialize the fragment analyzer
        
        Args:
            pcap_file (str): Path to the PCAP file to analyze
        """
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)
        self.fragments: Dict[Tuple[str, str, int], List[IP]] = defaultdict(list)
        
    def analyze_fragments(self) -> None:
        """
        Analyze IP fragments in the captured traffic
        """
        fragment_count = 0
        reassembled_count = 0
        
        # Group fragments by IP ID
        for packet in self.packets:
            if IP in packet:
                ip = packet[IP]
                # Key: (source IP, destination IP, IP ID)
                key = (ip.src, ip.dst, ip.id)
                
                if ip.flags == 1 or ip.frag > 0:  # MF flag set or fragment offset > 0
                    fragment_count += 1
                    self.fragments[key].append(ip)
                    
        logging.info(f"Total fragments found: {fragment_count}")
        
        # Analyze each group of fragments
        for key, frags in self.fragments.items():
            src_ip, dst_ip, ip_id = key
            
            # Sort fragments by offset
            frags.sort(key=lambda x: x.frag)
            
            # Check if we have a complete set of fragments
            is_complete = any(pkt.flags == 0 for pkt in frags)  # Last fragment has MF=0
            total_size = sum(len(pkt.payload) for pkt in frags)
            
            if is_complete:
                reassembled_count += 1
                
                logging.info(f"\nReassembled Packet:")
                logging.info(f"  Source IP: {src_ip}")
                logging.info(f"  Destination IP: {dst_ip}")
                logging.info(f"  IP ID: {ip_id}")
                logging.info(f"  Number of fragments: {len(frags)}")
                logging.info(f"  Total payload size: {total_size} bytes")
                
                # Analyze TCP data if present
                if TCP in frags[0]:
                    tcp = frags[0][TCP]
                    logging.info(f"  TCP Flags: {tcp.flags}")
                    logging.info(f"  Source Port: {tcp.sport}")
                    logging.info(f"  Destination Port: {tcp.dport}")
        
        logging.info(f"\nSummary:")
        logging.info(f"Total fragment groups: {len(self.fragments)}")
        logging.info(f"Successfully reassembled packets: {reassembled_count}")
        
    def get_fragment_statistics(self) -> None:
        """
        Print statistics about fragment sizes and distribution
        """
        sizes = []
        for frags in self.fragments.values():
            for frag in frags:
                sizes.append(len(frag.payload))
        
        if sizes:
            avg_size = sum(sizes) / len(sizes)
            max_size = max(sizes)
            min_size = min(sizes)
            
            logging.info(f"\nFragment Statistics:")
            logging.info(f"  Average fragment size: {avg_size:.2f} bytes")
            logging.info(f"  Maximum fragment size: {max_size} bytes")
            logging.info(f"  Minimum fragment size: {min_size} bytes")

def main():
    parser = argparse.ArgumentParser(
        description='Analyze fragmented packets from PCAP file'
    )
    parser.add_argument(
        'pcap_file',
        help='Path to the PCAP file to analyze'
    )
    
    args = parser.parse_args()
    
    analyzer = FragmentAnalyzer(args.pcap_file)
    analyzer.analyze_fragments()
    analyzer.get_fragment_statistics()

if __name__ == "__main__":
    main()