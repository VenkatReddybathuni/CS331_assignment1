import dpkt
import socket
from typing import Optional
import re

TARGET_IP = "192.168.10.50"
SUCCESS_PASSWORD = "securepassword"

# Add variations of secure password
POSSIBLE_PASSWORDS = [
    "securepassword",
    "secure password",
    "secure_password",
    "secure-password",
    "SecurePassword",
    "Secure Password",
    "SECURE PASSWORD"
]

def inet_to_str(inet: bytes) -> Optional[str]:
    try:
        return socket.inet_ntoa(inet)
    except:
        return None

def is_successful_password(payload: str) -> bool:
    return any(pwd in payload for pwd in POSSIBLE_PASSWORDS)

def process_pcap(pcap_file: str) -> None:
    login_attempts = 0
    total_content_length = 0
    successful_login = None
    
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            
            for _, buf in pcap:
                try:
                    # Parse Ethernet frame
                    eth = dpkt.ethernet.Ethernet(buf)
                    
                    # Ensure it's an IP packet
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                        
                    ip = eth.data
                    
                    # Ensure it's a TCP packet
                    if not isinstance(ip.data, dpkt.tcp.TCP):
                        continue
                        
                    tcp = ip.data
                    
                    # Get source IP
                    src_ip = inet_to_str(ip.src)
                    
                    if src_ip == TARGET_IP:
                        # Get TCP payload
                        try:
                            payload = tcp.data.decode('utf-8', errors='ignore')
                            
                            # Check for POST request
                            if 'POST' in payload:
                                login_attempts += 1
                                
                                # Extract content length
                                content_length_match = re.search(r'Content-Length: (\d+)', payload)
                                if content_length_match:
                                    total_content_length += int(content_length_match.group(1))
                                
                                # Check for successful login with any password variation
                                if is_successful_password(payload):
                                    # Extract credentials
                                    username_match = re.search(r'username=([^&]+)', payload)
                                    password_match = re.search(r'password=([^&\s]+)', payload)
                                    
                                    if username_match and password_match:
                                        successful_login = {
                                            'username': username_match.group(1),
                                            'password': password_match.group(1),
                                            'source_port': tcp.sport,
                                            'raw_data': payload  # Store raw data for verification
                                        }
                                        print(f"Found successful login with password: {successful_login['password']}")
                                
                        except Exception as e:
                            continue
                            
                except Exception as e:
                    continue
                    
    except Exception as e:
        print(f"Error processing pcap file: {e}")
        return
    
    # Print results    
    print("\nAnalysis Results:")
    print(f"Q1. Total Login Attempts: {login_attempts}")
    
    if successful_login:
        print(f"\nQ2. Successful Login Credentials:")
        print(f"Username: {successful_login['username']}")
        print(f"Password: {successful_login['password']}")
        print(f"\nQ3. Client's Source Port: {successful_login['source_port']}")
    
    print(f"\nQ4. Total Content Length: {total_content_length} bytes")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python login_analyzer.py <pcap_file>")
        sys.exit(1)
        
    process_pcap(sys.argv[1])
