import os
import sys
import time
import socket
import hashlib
import argparse
from datetime import datetime

# ==========================================
# CONFIGURATION & CONSTANTS
# ==========================================
DEFAULT_PORT = 1812
TIMEOUT = 3 # seconds

# RADIUS Codes
ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ACCESS_CHALLENGE = 11

RADIUS_CODES = {
    1: "Access-Request",
    2: "Access-Accept",
    3: "Access-Reject",
    11: "Access-Challenge"
}

# Terminal Colors (ANSI)
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# ==========================================
# RFC 2865 PASSWORD OBFUSCATION ENGINE
# ==========================================
def encrypt_radius_password(password, shared_secret, authenticator):
    """
    Implements the standard RFC 2865 RADIUS password encryption:
    p = padded password (null-padded to multiples of 16 bytes, max 128)
    c(0) = p(0) XOR MD5(Secret + Authenticator)
    c(i) = p(i) XOR MD5(Secret + c(i-1))
    """
    secret_bytes = shared_secret.encode('utf-8')
    pass_bytes = password.encode('utf-8')
    
    # Pad password to a multiple of 16 bytes
    pad_len = 16 - (len(pass_bytes) % 16)
    if pad_len == 0:
        pad_len = 16
    padded_pass = pass_bytes + (b'\x00' * pad_len)
    
    encrypted = b''
    last_block = authenticator
    
    # Process password in 16-byte blocks
    for i in range(0, len(padded_pass), 16):
        block = padded_pass[i:i+16]
        md = hashlib.md5(secret_bytes + last_block).digest()
        
        # XOR 16 bytes
        xor_block = bytes(b1 ^ b2 for b1, b2 in zip(block, md))
        encrypted += xor_block
        last_block = xor_block
        
    return encrypted

# ==========================================
# RADIUS PACKET BUILDER
# ==========================================
def craft_access_request(username, password, shared_secret, identifier=1):
    """
    Assembles a raw RADIUS Access-Request packet.
    """
    # 1. Generate a cryptographically secure 16-byte random Authenticator
    authenticator = os.urandom(16)
    
    # 2. Encrypt the password using RFC 2865 algorithm
    encrypted_password = encrypt_radius_password(password, shared_secret, authenticator)
    
    # 3. Construct attributes payload (Type-Length-Value format)
    attributes = b''
    
    # Attribute: User-Name (Type 1)
    username_bytes = username.encode('utf-8')
    attributes += bytes([1, 2 + len(username_bytes)]) + username_bytes
    
    # Attribute: User-Password (Type 2)
    attributes += bytes([2, 2 + len(encrypted_password)]) + encrypted_password
    
    # 4. Build Header: Code (1B) | ID (1B) | Length (2B) | Authenticator (16B)
    packet_length = 20 + len(attributes)
    header = bytes([
        ACCESS_REQUEST,
        identifier,
        (packet_length >> 8) & 0xFF,
        packet_length & 0xFF
    ]) + authenticator
    
    return header + attributes, authenticator

# ==========================================
# RESPONSE VALIDATOR
# ==========================================
def verify_response_authenticator(response_packet, request_authenticator, shared_secret):
    """
    Verifies that the response packet authenticator is authentic.
    Response Authenticator = MD5(Code + ID + Length + RequestAuthenticator + Attributes + SharedSecret)
    """
    if len(response_packet) < 20:
        return False
        
    res_code = response_packet[0]
    res_id = response_packet[1]
    res_len = int.from_bytes(response_packet[2:4], byteorder='big')
    res_auth = response_packet[4:20]
    res_attrs = response_packet[20:]
    
    # Construct signature check payload
    signature_payload = (
        bytes([res_code, res_id]) +
        (res_len).to_bytes(2, byteorder='big') +
        request_authenticator +
        res_attrs +
        shared_secret.encode('utf-8')
    )
    
    expected_auth = hashlib.md5(signature_payload).digest()
    return res_auth == expected_auth

# ==========================================
# AUDITING TASK CONTROLLER
# ==========================================
def test_authentication(target, port, username, password, shared_secret, identifier=1):
    """
    Sends an Access-Request and awaits a response to determine auth status.
    """
    print(f"[*] Targeting RADIUS Server: {Colors.CYAN}{target}:{port}{Colors.RESET}")
    print(f"[*] Sending Access-Request for user: '{Colors.BOLD}{username}{Colors.RESET}'")
    
    packet, req_auth = craft_access_request(username, password, shared_secret, identifier)
    
    # Initialize UDP Client Socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(TIMEOUT)
    
    try:
        start_time = time.time()
        client_socket.sendto(packet, (target, port))
        
        # Receive response from socket
        response, server = client_socket.recvfrom(1024)
        rtt = (time.time() - start_time) * 1000
        
        if len(response) < 20:
            print(f"{Colors.RED}[!] Malformed or empty response payload received.{Colors.RESET}")
            return False

        res_code = response[0]
        res_name = RADIUS_CODES.get(res_code, f"Unknown Code ({res_code})")
        
        # Verify packet integrity and shared secret alignment
        is_authentic = verify_response_authenticator(response, req_auth, shared_secret)
        
        print(f"\n{Colors.BLUE}=================== SECURITY ASSESSMENT REPORT ==================={Colors.RESET}")
        print(f"Response Received In : {Colors.CYAN}{rtt:.2f} ms{Colors.RESET}")
        
        # Format output based on packet code types
        if res_code == ACCESS_ACCEPT:
            print(f"Transaction Result   : {Colors.GREEN}{Colors.BOLD}ACCESS ACCEPTED (Login Successful){Colors.RESET}")
        elif res_code == ACCESS_REJECT:
            print(f"Transaction Result   : {Colors.RED}{Colors.BOLD}ACCESS REJECTED (Invalid Credentials){Colors.RESET}")
        elif res_code == ACCESS_CHALLENGE:
            print(f"Transaction Result   : {Colors.YELLOW}{Colors.BOLD}ACCESS CHALLENGE (MFA Required){Colors.RESET}")
        else:
            print(f"Transaction Result   : {Colors.YELLOW}{res_name}{Colors.RESET}")
            
        if is_authentic:
            print(f"Shared Secret Verification: {Colors.GREEN}VALID (Secret aligns perfectly with server signature){Colors.RESET}")
        else:
            print(f"Shared Secret Verification: {Colors.RED}{Colors.BOLD}INVALID / WARNING! (Authenticator check failed. Either the shared secret is wrong, or the response was spoofed.){Colors.RESET}")
        print(f"{Colors.BLUE}=================================================================={Colors.RESET}")
        
    except socket.timeout:
        print(f"\n{Colors.RED}[!] Error: Request Timed Out after {TIMEOUT} seconds. (Is the target server up, or did a firewall drop the packet?){Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Socket Exception Occurred: {e}{Colors.RESET}")
    finally:
        client_socket.close()

# ==========================================
# MAIN COMMAND LINE PARSER
# ==========================================
if __name__ == "__main__":
    # Display professional security research banner
    print(f"{Colors.BLUE}{Colors.BOLD}==========================================================================================")
    print(f"       ⚔️  RADIUS PENETRATION TESTING & COMPLIANCE UTILITY [RESEARCHER: tarnished0ne]")
    print(f"=========================================================================================={Colors.RESET}\n")

    parser = argparse.ArgumentParser(description="RADIUS Active Authentication Audit Tool")
    parser.add_argument("-t", "--target", default="127.0.0.1", help="Target IP address of the RADIUS server")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help="Target UDP port (default: 1812)")
    parser.add_argument("-u", "--username", required=True, help="Username to test")
    parser.add_argument("-w", "--password", required=True, help="Cleartext password to test")
    parser.add_argument("-s", "--secret", required=True, help="The shared secret configured on the server")
    parser.add_argument("-i", "--id", type=int, default=1, help="Session Transaction Identifier (0-255)")

    # If no arguments are passed, show help
    if len(sys.argv) == 1:
        parser.print_help()
        print(f"\n{Colors.YELLOW}Example Usage:{Colors.RESET}")
        print("  python radius_auditor.py -t 192.168.1.50 -u administrator -w SecurePassword123! -s testing123")
        sys.exit(0)

    args = parser.parse_args()
    
    # Run active security test
    test_authentication(
        target=args.target,
        port=args.port,
        username=args.username,
        password=args.password,
        shared_secret=args.secret,
        identifier=args.id
    )