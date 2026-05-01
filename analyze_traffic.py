import sys
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR
import matplotlib.pyplot as plt

def analyze_pcap(file_path):
    print(f"Loading {file_path} for analysis... This might take a few seconds.")
    try:
        packets = rdpcap(file_path)
    except FileNotFoundError:
        print(f"Error: {file_path} not found. Please run generate_pcap.py first or provide your own pcap.")
        sys.exit(1)

    print(f"Successfully loaded {len(packets)} packets.")

    # 1. Protocol Distribution
    protocols = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'HTTP': 0, 'DNS': 0, 'Other': 0}
    
    # 2. Anomaly Tracking Variables
    syn_counts = Counter()  # (target_ip, target_port) -> count
    dns_queries = Counter() # (src_ip, domain) -> count

    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            
            # Check for ICMP
            if ICMP in pkt:
                protocols['ICMP'] += 1
                
            # Check for TCP
            elif TCP in pkt:
                tcp_layer = pkt[TCP]
                # Check for HTTP (port 80 or 443) - Simple heuristic
                if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                    protocols['HTTP'] += 1
                else:
                    protocols['TCP'] += 1
                    
                # Anomaly Detection: SYN Flood
                if tcp_layer.flags == 'S':  # SYN flag only
                    syn_counts[(ip_layer.dst, tcp_layer.dport)] += 1
                    
            # Check for UDP
            elif UDP in pkt:
                udp_layer = pkt[UDP]
                if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].qd: # Standard query
                    protocols['DNS'] += 1
                    domain = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                    dns_queries[(ip_layer.src, domain)] += 1
                else:
                    protocols['UDP'] += 1
        else:
            protocols['Other'] += 1

    # Print Protocol Distribution
    print("\n--- Protocol Distribution ---")
    for proto, count in protocols.items():
        if count > 0:
            print(f"{proto}: {count} packets")

    # Generate Chart
    labels = [p for p in protocols.keys() if protocols[p] > 0]
    sizes = [protocols[p] for p in protocols.keys() if protocols[p] > 0]
    
    plt.figure(figsize=(8, 6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=['#ff9999','#66b3ff','#99ff99','#ffcc99','#c2c2f0','#ffb3e6'])
    plt.title('Network Protocol Distribution')
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.savefig('protocol_distribution.png')
    print("\n[+] Saved Protocol Distribution Chart to 'protocol_distribution.png'")

    # Print Suspicious Packet Report
    print("\n--- Suspicious Packet Report ---")
    anomalies_found = False
    
    # Check SYN Floods (Threshold > 100 SYN packets to same destination)
    for (dst_ip, dst_port), count in syn_counts.items():
        if count > 100:
            print(f"[!] POTENTIAL SYN FLOOD DETECTED: {count} SYN packets sent to {dst_ip}:{dst_port}")
            anomalies_found = True

    # Check Repeated DNS Queries (Threshold > 50 identical queries from same IP)
    for (src_ip, domain), count in dns_queries.items():
        if count > 50:
            print(f"[!] REPEATED DNS QUERIES DETECTED: {src_ip} requested '{domain}' {count} times")
            anomalies_found = True

    if not anomalies_found:
        print("No suspicious activity detected based on current thresholds.")
    
    print("\nAnalysis Complete.")

if __name__ == "__main__":
    pcap_file = "sample_traffic.pcap"
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    
    analyze_pcap(pcap_file)
