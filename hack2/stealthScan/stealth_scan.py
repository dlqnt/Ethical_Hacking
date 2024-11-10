#!/usr/bin/env python3
from scapy.all import IP, TCP, sr1, RandShort, send
import random
import time
import argparse
import logging
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class StealthScanner:
    def __init__(self, target_ip: str, min_delay: float = 2.0, max_delay: float = 5.0):
        """
        Initialize the stealth port scanner
        
        Args:
            target_ip (str): Target IP address
            min_delay (float): Minimum delay between scans in seconds
            max_delay (float): Maximum delay between scans in seconds
        """
        self.target_ip = target_ip
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.results: Dict[int, str] = {}
        
    def get_random_delay(self) -> float:
        """
        Get a random delay between min_delay and max_delay
        
        Returns:
            float: Random delay in seconds
        """
        return random.uniform(self.min_delay, self.max_delay)
    
    def scan_port(self, port: int) -> Optional[str]:
        """
        Scan a single port with stealth techniques
        
        Args:
            port (int): Port number to scan
            
        Returns:
            Optional[str]: Port status or None if error
        """
        try:
            # Craft a stealth SYN packet
            ip = IP(dst=self.target_ip)
            tcp = TCP(
                sport=RandShort(),
                dport=port,
                flags='S',
                seq=RandShort(),
                window=RandShort()
            )
            
            # Send packet and wait for response
            response = sr1(ip/tcp, timeout=2, verbose=False)
            
            if response is None:
                return "Filtered"
            elif response.haslayer(TCP):
                tcp_flags = response[TCP].flags
                if tcp_flags & 0x12:  # SYN-ACK
                    # Send RST to close connection
                    rst = IP(dst=self.target_ip)/TCP(
                        dport=port,
                        sport=response[TCP].dport,
                        flags='R',
                        seq=response[TCP].ack
                    )
                    send(rst, verbose=False)
                    return "Open"
                elif tcp_flags & 0x14:  # RST-ACK
                    return "Closed"
            
            return "Unknown"
            
        except Exception as e:
            logging.error(f"Error scanning port {port}: {e}")
            return None
            
    def scan_ports(self, ports: List[int], max_workers: int = 1) -> None:
        """
        Scan multiple ports with random delays
        
        Args:
            ports (List[int]): List of ports to scan
            max_workers (int): Maximum number of concurrent scans
        """
        try:
            for port in ports:
                # Random delay between scans
                time.sleep(self.get_random_delay())
                
                result = self.scan_port(port)
                if result:
                    self.results[port] = result
                    if result == "Open":
                        logging.info(f"Port {port}: {result}")
                    else:
                        logging.debug(f"Port {port}: {result}")
                
                # Additional random delay after each scan
                time.sleep(self.get_random_delay() / 2)
                
        except KeyboardInterrupt:
            logging.info("Scan interrupted by user")
            sys.exit(1)
            
    def print_results(self) -> None:
        """
        Print scan results
        """
        logging.info("\nScan Results:")
        open_ports = [port for port, status in self.results.items() if status == "Open"]
        
        if open_ports:
            logging.info("Open ports:")
            for port in sorted(open_ports):
                logging.info(f"  {port}/tcp")
        else:
            logging.info("No open ports found")

def main():
    parser = argparse.ArgumentParser(
        description='Stealthy port scanner with timing-based evasion'
    )
    parser.add_argument(
        'target_ip',
        help='Target IP address'
    )
    parser.add_argument(
        '-p', '--ports',
        help='Port range (e.g., 20-25) or comma-separated ports (e.g., 22,80,443)',
        default='1-1024'
    )
    parser.add_argument(
        '--min-delay',
        type=float,
        default=2.0,
        help='Minimum delay between scans in seconds'
    )
    parser.add_argument(
        '--max-delay',
        type=float,
        default=5.0,
        help='Maximum delay between scans in seconds'
    )
    
    args = parser.parse_args()
    
    # Parse port range
    try:
        if ',' in args.ports:
            ports = [int(p) for p in args.ports.split(',')]
        elif '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(args.ports)]
    except ValueError:
        logging.error("Invalid port range")
        sys.exit(1)
    
    scanner = StealthScanner(
        args.target_ip,
        args.min_delay,
        args.max_delay
    )
    
    logging.info(f"Starting stealthy scan of {args.target_ip}")
    logging.info(f"Using delays between {args.min_delay} and {args.max_delay} seconds")
    
    scanner.scan_ports(ports)
    scanner.print_results()

if __name__ == "__main__":
    main()