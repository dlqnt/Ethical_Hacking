#!/usr/bin/env python3
from scapy.all import rdpcap, IP, TCP
import numpy as np
from datetime import datetime
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def analyze_scan_timing(pcap_file):
    """Analyze timing patterns in the scan traffic"""
    packets = rdpcap(pcap_file)
    scan_times = []
    ports = []
    source_ports = []

    # Extract SYN packets
    for pkt in packets:
        if IP in pkt and TCP in pkt and pkt[TCP].flags == 'S':
            scan_times.append(float(pkt.time))
            ports.append(pkt[TCP].dport)
            source_ports.append(pkt[TCP].sport)

    # Calculate delays
    delays = np.diff(scan_times)
    
    logging.info("\nDetailed Timing Analysis:")
    logging.info("-----------------------")
    for i in range(len(ports)-1):
        logging.info(f"Scan {i+1}:")
        logging.info(f"  Port: {ports[i]} -> {ports[i+1]}")
        logging.info(f"  Delay: {delays[i]:.2f} seconds")
        logging.info(f"  Source Ports: {source_ports[i]} -> {source_ports[i+1]}")
    
    logging.info("\nTiming Statistics:")
    logging.info(f"Average Delay: {np.mean(delays):.2f} seconds")
    logging.info(f"Std Deviation: {np.std(delays):.2f} seconds")
    logging.info(f"Total Scan Duration: {scan_times[-1] - scan_times[0]:.2f} seconds")
    logging.info(f"Number of source ports used: {len(set(source_ports))}")

if __name__ == "__main__":
    analyze_scan_timing("timing_scan.pcap")