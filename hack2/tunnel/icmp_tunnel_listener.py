#!/usr/bin/env python3
from scapy.all import sniff, IP, ICMP, Raw
import base64
import logging
import sys
import argparse
from collections import defaultdict
from typing import Dict, List, Optional
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class ICMPTunnelListener:
    def __init__(self, interface: str = "enp0s1"):
        """
        Initialize ICMP tunnel listener
        
        Args:
            interface (str): Network interface to listen on
        """
        self.interface = interface
        self.chunks: Dict[int, List[Optional[str]]] = defaultdict(list)
        self.last_cleanup = time.time()
        
    def decode_payload(self, data: str) -> Optional[str]:
        """
        Decode and validate payload
        
        Args:
            data (str): Data to decode
            
        Returns:
            Optional[str]: Decoded data if valid
        """
        try:
            decoded = base64.b64decode(data).decode()
            if decoded.startswith("ICMP_TUNNEL:"):
                return decoded[11:]  # Remove marker
        except:
            pass
        return None
        
    def process_chunk(self, chunk_data: str) -> None:
        """
        Process a received chunk
        
        Args:
            chunk_data (str): Chunk data to process
        """
        try:
            # Parse chunk metadata
            meta, data = chunk_data.split(":", 1)
            chunk_num, total_chunks = map(int, meta.split("/"))
            
            # Store chunk
            if len(self.chunks[total_chunks]) <= chunk_num:
                self.chunks[total_chunks].extend([None] * (chunk_num - len(self.chunks[total_chunks]) + 1))
            self.chunks[total_chunks][chunk_num] = data
            
            # Check if we have all chunks
            if None not in self.chunks[total_chunks] and len(self.chunks[total_chunks]) == total_chunks:
                # Reconstruct and decode payload
                complete_data = ''.join(self.chunks[total_chunks])
                decoded = self.decode_payload(complete_data)
                
                if decoded:
                    logging.info(f"\nReceived command: {decoded}")
                    # Clean up completed chunks
                    del self.chunks[total_chunks]
                    
        except Exception as e:
            logging.debug(f"Error processing chunk: {e}")
            
    def cleanup_old_chunks(self) -> None:
        """
        Clean up incomplete chunk sets
        """
        current_time = time.time()
        if current_time - self.last_cleanup > 30:  # Cleanup every 30 seconds
            self.chunks.clear()
            self.last_cleanup = current_time
            
    def process_packet(self, packet) -> None:
        """
        Process received ICMP packet
        
        Args:
            packet: Scapy packet to process
        """
        try:
            if ICMP in packet and Raw in packet:
                # Check if it's our tunnel packet
                if packet[ICMP].type == 8 and packet[ICMP].id == 0x1337:
                    raw_data = packet[Raw].load
                    if isinstance(raw_data, bytes):
                        chunk_data = raw_data.decode(errors='ignore')
                        self.process_chunk(chunk_data)
                    
            self.cleanup_old_chunks()
            
        except Exception as e:
            logging.debug(f"Error processing packet: {e}")
            
    def start_listening(self) -> None:
        """
        Start listening for ICMP tunnel packets
        """
        logging.info(f"Starting ICMP tunnel listener on {self.interface}")
        logging.info("Waiting for commands...")
        
        try:
            sniff(
                iface=self.interface,
                filter="icmp",
                prn=self.process_packet
            )
        except KeyboardInterrupt:
            logging.info("\nStopping listener")
            sys.exit(0)
        except Exception as e:
            logging.error(f"Sniffing error: {e}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='ICMP Tunnel Listener'
    )
    parser.add_argument(
        '-i', '--interface',
        default='enp0s1',
        help='Network interface to listen on'
    )
    
    args = parser.parse_args()
    listener = ICMPTunnelListener(args.interface)
    listener.start_listening()

if __name__ == "__main__":
    main()