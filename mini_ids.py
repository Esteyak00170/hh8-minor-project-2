import logging
from scapy.all import *
from urllib.parse import unquote_to_bytes # NEW: Needed for decoding

# --- Configuration ---
logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

ip_mac_map = {}

# EXPANDED list of attack signatures
SQLI_KEYWORDS = [
    b"UNION SELECT", 
    b"' OR '1'='1", 
    b"--", 
    b"information_schema", 
    b"DROP TABLE",
    b"SLEEP(",        # Detects sleep() and pg_sleep()
    b"BENCHMARK(",    # Common in MySQL attacks
    b"<SCRIPT>"       # Basic XSS detection
]

def detect_arp_spoofing(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2: 
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        if src_ip in ip_mac_map:
            if ip_mac_map[src_ip] != src_mac:
                old_mac = ip_mac_map[src_ip]
                logging.warning(f"[!] ARP SPOOFING DETECTED: IP {src_ip} moved from {old_mac} to {src_mac}")
                return 
        else:
            ip_mac_map[src_ip] = src_mac

def detect_nmap_scan(packet):
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        # Check for Xmas Scan (Nmap -sX)
        if tcp_layer.flags == 0x29: 
            logging.warning(f"[!] NMAP XMAS SCAN DETECTED from {packet[IP].src}")

def detect_sqli(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        # Ignore Encrypted Traffic (Port 443)
        if packet[TCP].sport == 443 or packet[TCP].dport == 443:
            return

        # Get raw payload
        raw_load = packet[Raw].load
        
        # NEW: Decode URL-encoded characters (e.g., %20 -> Space, %2D -> -)
        try:
            decoded_load = unquote_to_bytes(raw_load)
        except:
            decoded_load = raw_load

        # Check for keywords in the DECODED text
        for keyword in SQLI_KEYWORDS:
            if keyword.lower() in decoded_load.lower():
                src_ip = packet[IP].src
                logging.critical(f"[!!!] SQL INJECTION DETECTED from {src_ip} | Keyword found: {keyword}")
                break

def packet_callback(packet):
    try:
        detect_arp_spoofing(packet)
        if packet.haslayer(IP):
            detect_nmap_scan(packet)
            detect_sqli(packet)
    except Exception:
        pass

def start_sniffer():
    print(f"[*] Starting Mini IDS...")
    print(f"[*] Sniffing for ARP Spoofing, Nmap, and SQLi (Decoded)...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    # Force Npcap usage if needed
    conf.use_pcap = True
    start_sniffer()