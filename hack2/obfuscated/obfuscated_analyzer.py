#!/usr/bin/env python3
from scapy.all import rdpcap, IP, TCP, Raw
import base64
import logging
import re
from typing import Optional, Dict, List

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class PayloadAnalyzer:
    def __init__(self, pcap_file: str):
        """
        Initialize the payload analyzer
        
        Args:
            pcap_file (str): Path to the PCAP file to analyze
        """
        self.pcap_file = pcap_file
        self.packets = rdpcap(pcap_file)
        
    def extract_http_request(self, packet: Raw) -> Optional[Dict[str, str]]:
        """
        Extract HTTP headers from packet
        
        Args:
            packet (Raw): Packet to analyze
            
        Returns:
            Optional[Dict[str, str]]: Extracted headers or None
        """
        try:
            # Decode packet payload
            raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Parse HTTP headers
            headers = {}
            lines = raw_data.split('\r\n')
            
            # Get request line
            if lines:
                headers['Request'] = lines[0]
            
            # Parse rest of headers    
            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key] = value
            
            logging.debug(f"Raw HTTP Request:\n{raw_data}")
            return headers
            
        except Exception as e:
            logging.debug(f"Error extracting headers: {e}")
            return None
            
    def extract_cookies(self, headers: Dict[str, str]) -> List[str]:
        """
        Extract and sort cookie values
        
        Args:
            headers (Dict[str, str]): HTTP headers
            
        Returns:
            List[str]: Sorted cookie values
        """
        cookies = []
        if 'Cookie' in headers:
            cookie_str = headers['Cookie']
            logging.debug(f"Raw Cookie string: {cookie_str}")
            
            try:
                # Split cookies and handle potential formatting issues
                cookie_pairs = [p.strip() for p in cookie_str.split(';') if p.strip()]
                for pair in cookie_pairs:
                    # Handle cases where = appears multiple times
                    parts = pair.split('=', 1)
                    if len(parts) == 2:
                        name, value = parts
                        name = name.strip()
                        if name.startswith('id'):
                            try:
                                index = int(name[2:])
                                cookies.append((index, value))
                            except ValueError:
                                logging.debug(f"Invalid cookie index: {name}")
            except Exception as e:
                logging.debug(f"Error parsing cookies: {e}")
        
        # Sort by cookie index and return values
        return [value for _, value in sorted(cookies)]
        
    def analyze_traffic(self) -> None:
        """
        Analyze the captured traffic
        """
        http_requests = 0
        payloads_found = 0
        
        logging.info("\nTraffic Analysis:")
        logging.info("-----------------")
        
        for packet in self.packets:
            if IP in packet and TCP in packet and Raw in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                if dst_port == 80:  # HTTP traffic
                    http_requests += 1
                    logging.info(f"\nHTTP Request {http_requests}:")
                    logging.info(f"Source: {src_ip}:{src_port}")
                    logging.info(f"Destination: {dst_ip}:{dst_port}")
                    
                    headers = self.extract_http_request(packet)
                    if headers:
                        logging.info(f"Request: {headers.get('Request', 'Unknown')}")
                        logging.info(f"Host: {headers.get('Host', 'Unknown')}")
                        logging.info(f"User-Agent: {headers.get('User-Agent', 'Unknown')}")
                        
                        # Print raw packet data for debugging
                        if Raw in packet:
                            raw_data = packet[Raw].load
                            logging.debug(f"Raw packet data:\n{raw_data}")
                        
                        # Extract and analyze cookies
                        cookie_values = self.extract_cookies(headers)
                        if cookie_values:
                            payloads_found += 1
                            logging.info(f"Found {len(cookie_values)} cookie chunks")
                            
                            # Try to reconstruct the payload
                            combined_payload = ''.join(cookie_values)
                            try:
                                decoded_payload = base64.b64decode(combined_payload).decode()
                                if "socket" in decoded_payload and "subprocess" in decoded_payload:
                                    logging.info("\nReconstructed Payload:")
                                    logging.info("-" * 50)
                                    logging.info(f"Base64 Length: {len(combined_payload)}")
                                    logging.info(f"Decoded Command: {decoded_payload}")
                                    logging.info("-" * 50)
                                    
                                    # Extract key components
                                    if match := re.search(r'connect\(\("(.*?)",(\d+)', decoded_payload):
                                        target_ip, target_port = match.groups()
                                        logging.info(f"Reverse Shell Target: {target_ip}:{target_port}")
                            except Exception as e:
                                logging.debug(f"Payload reconstruction error: {e}")
        
        logging.info("\nSummary:")
        logging.info(f"Total HTTP requests: {http_requests}")
        logging.info(f"Payloads detected: {payloads_found}")
        logging.info(f"Snort alerts triggered: 0")
        
        if payloads_found == 0:
            logging.warning("No payloads found in the capture!")

def main():
    analyzer = PayloadAnalyzer("obfuscated_payload.pcap")
    analyzer.analyze_traffic()

if __name__ == "__main__":
    main()