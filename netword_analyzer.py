import sys
import logging
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import *
from tabulate import tabulate
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

def read_pcap(pcap_file):
    """Read packets from a PCAP file."""
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        logger.error(f"PCAP file not found: {pcap_file}")
        sys.exit(1)
    except Scapy_Exception as e:
        logger.error(f"Error reading PCAP file: {e}")
        sys.exit(1)
    return packets

def extract_packet_data(packets):
    """Extract key packet information into a DataFrame."""
    packet_data = []
    for packet in tqdm(packets, desc="Processing packets", unit="packet"):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            size = len(packet)
            dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)
            timestamp = packet.time
            packet_data.append({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "size": size, "dst_port": dst_port, "timestamp": timestamp})
    return pd.DataFrame(packet_data)

def protocol_name(number):
    """Convert protocol numbers to human-readable names."""
    protocol_dict = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    return protocol_dict.get(number, f"Unknown({number})")

def analyze_packet_data(df):
    """Analyze total bandwidth and protocol usage."""
    if "size" not in df.columns:
        logger.error("Missing 'size' column in DataFrame. Please check PCAP parsing.")
        sys.exit(1)
    total_bandwidth = df["size"].sum()
    df["protocol_name"] = df["protocol"].map(protocol_name)
    protocol_counts = df["protocol_name"].value_counts(normalize=True) * 100
    ip_communication_table = df.groupby(["src_ip", "dst_ip"]).size().reset_index(name='count')
    return total_bandwidth, protocol_counts, ip_communication_table

def plot_visualizations(df, protocol_counts):
    """Generate visualizations for network traffic analysis."""
    plt.figure(figsize=(12, 6))
    sns.barplot(x=protocol_counts.index, y=protocol_counts.values, hue=protocol_counts.index, legend=False, palette="viridis")
    plt.xlabel("Protocol")
    plt.ylabel("Percentage")
    plt.title("Protocol Distribution")
    plt.xticks(rotation=45)
    plt.show()
    
    plt.figure(figsize=(12, 6))
    top_ips = df['src_ip'].value_counts().nlargest(10)
    sns.barplot(x=top_ips.index, y=top_ips.values, hue=top_ips.index, legend=False, palette="coolwarm")
    plt.xlabel("Source IP")
    plt.ylabel("Packet Count")
    plt.title("Top 10 Source IPs by Packet Count")
    plt.xticks(rotation=45)
    plt.show()
    
    plt.figure(figsize=(12, 6))
    sns.histplot(df['size'], bins=30, kde=True, color='purple')
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.title("Packet Size Distribution")
    plt.show()
        
    plt.figure(figsize=(12, 6))
    top_ports = df['dst_port'].value_counts().nlargest(10)
    sns.barplot(x=top_ports.index, y=top_ports.values, hue=top_ports.index, legend=False, palette="magma")
    plt.xlabel("Destination Port")
    plt.ylabel("Packet Count")
    plt.title("Top 10 Destination Ports")
    plt.xticks(rotation=45)
    plt.show()

def main(pcap_file):
    """Main function to analyze network traffic and generate visualizations."""
    packets = read_pcap(pcap_file)
    df = extract_packet_data(packets)
    total_bandwidth, protocol_counts, ip_communication_table = analyze_packet_data(df)
    logger.info(f"Total bandwidth used: {total_bandwidth / 10**6:.2f} Mbps")
    plot_visualizations(df, protocol_counts)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        logger.error("Please provide the path to the PCAP file.")
        sys.exit(1)
    pcap_file = sys.argv[1]
    main(pcap_file)
