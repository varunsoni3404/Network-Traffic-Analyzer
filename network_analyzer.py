import sys
import logging
import argparse
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import networkx as nx
from scapy.all import rdpcap, Scapy_Exception, IP, TCP, UDP
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# List of commonly abused ports by malware
MALICIOUS_PORTS = {4444, 5555, 6667, 8080, 9001, 4443}

def read_pcap(pcap_file):
    """
    Reads a PCAP file and returns a list of packets.
    
    :param pcap_file: Path to the PCAP file.
    :return: List of packets.
    """
    try:
        packets = rdpcap(pcap_file)
        logger.info(f"Loaded {len(packets)} packets from {pcap_file}")
    except FileNotFoundError:
        logger.error(f"PCAP file not found: {pcap_file}")
        sys.exit(1)
    except Scapy_Exception as e:
        logger.error(f"Error reading PCAP file: {e}")
        sys.exit(1)
    return packets

def extract_packet_data(packets):
    """
    Extracts relevant data from each packet.
    
    :param packets: List of packets.
    :return: DataFrame containing extracted packet data.
    """
    packet_data = []
    for packet in tqdm(packets, desc="Processing packets", unit="packet"):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            size = len(packet)
            dst_port = None
            if TCP in packet:
                dst_port = packet[TCP].dport
            elif UDP in packet:
                dst_port = packet[UDP].dport
            timestamp = packet.time
            # Check for failed TCP connection (using RST flag)
            failed_conn = TCP in packet and packet[TCP].flags == 0x04
            packet_data.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "size": size,
                "dst_port": dst_port,
                "timestamp": timestamp,
                "failed_conn": failed_conn
            })
    df = pd.DataFrame(packet_data)
    logger.info("Packet data extraction complete.")
    return df

def analyze_packet_data(df):
    """
    Performs basic analysis on the packet data.
    
    :param df: DataFrame of packet data.
    :return: Total bandwidth and protocol counts.
    """
    total_bandwidth = df["size"].sum()
    protocol_counts = df["protocol"].value_counts()
    avg_packet_size = df["size"].mean()
    logger.info(f"Total Bandwidth: {total_bandwidth} bytes")
    logger.info(f"Average Packet Size: {avg_packet_size:.2f} bytes")
    logger.info("Protocol distribution:")
    logger.info(protocol_counts.to_string())
    return total_bandwidth, protocol_counts

def analyze_network_graph(df):
    """
    Constructs and analyzes a network graph from IP communications.
    
    :param df: DataFrame of packet data.
    :return: Graph and degree centrality of nodes.
    """
    G = nx.Graph()
    for _, row in df.iterrows():
        G.add_edge(row["src_ip"], row["dst_ip"])
    centrality = nx.degree_centrality(G)
    logger.info("Computed degree centrality for network graph.")
    return G, centrality

def save_or_show(fig, filename, output_dir):
    """
    Save figure to file if output directory is provided; otherwise, display the plot.
    
    :param fig: Matplotlib figure object.
    :param filename: Filename to use when saving the figure.
    :param output_dir: Directory to save the figure; if None, the figure is displayed.
    """
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
        fig.savefig(filepath, bbox_inches='tight')
        logger.info(f"Saved figure: {filepath}")
        plt.close(fig)
    else:
        plt.show()

def visualize_suspicious_activity(df, protocol_counts, total_bandwidth, output_dir=None):
    """
    Generates several visualizations to detect suspicious network activity.
    
    :param df: DataFrame of packet data.
    :param protocol_counts: Series of protocol counts.
    :param total_bandwidth: Total bandwidth used.
    :param output_dir: Optional directory to save figures.
    """
    sns.set_style("darkgrid")
    
    # Traffic Spikes Detection (Line Plot)
    df_sorted = df.sort_values("timestamp")
    fig1, ax1 = plt.subplots(figsize=(12, 6))
    sns.lineplot(x=df_sorted["timestamp"], y=df_sorted["size"], color='blue', ax=ax1)
    threshold = df_sorted['size'].quantile(0.95)
    ax1.axhline(y=threshold, color='red', linestyle='--', label="95th Percentile Threshold")
    ax1.set_xlabel("Time")
    ax1.set_ylabel("Packet Size (bytes)")
    ax1.set_title("Traffic Over Time (Detecting Spikes)")
    ax1.legend()
    save_or_show(fig1, "traffic_spikes.png", output_dir)
    
    # Malicious Port Activity (Bar Plot)
    fig2, ax2 = plt.subplots(figsize=(10, 5))
    df_ports = df["dst_port"].value_counts().nlargest(10)
    colors = ["red" if port in MALICIOUS_PORTS else "blue" for port in df_ports.index]
    sns.barplot(x=df_ports.index, y=df_ports.values, palette=colors, ax=ax2)
    ax2.set_xlabel("Destination Port")
    ax2.set_ylabel("Packet Count")
    ax2.set_title("Top 10 Destination Ports (Flagging Malicious Ports)")
    ax2.tick_params(axis='x', rotation=45)
    save_or_show(fig2, "malicious_ports.png", output_dir)
    
    # Suspicious IP Activity (Bar Plot)
    fig3, ax3 = plt.subplots(figsize=(10, 6))
    suspicious_ips = df["src_ip"].value_counts().nlargest(10)
    sns.barplot(x=suspicious_ips.index, y=suspicious_ips.values, palette="coolwarm", ax=ax3)
    ax3.set_xlabel("Source IP")
    ax3.set_ylabel("Packet Count")
    ax3.set_title("Top 10 Source IPs (Potential Attackers)")
    ax3.tick_params(axis='x', rotation=45)
    save_or_show(fig3, "suspicious_ips.png", output_dir)
    
    # Failed Connection Attempts (Bar Plot)
    fig4, ax4 = plt.subplots(figsize=(10, 5))
    failed_attempts = df[df["failed_conn"] == True]
    failed_counts = failed_attempts["src_ip"].value_counts().nlargest(10)
    sns.barplot(x=failed_counts.index, y=failed_counts.values, palette="Reds", ax=ax4)
    ax4.set_xlabel("Source IP")
    ax4.set_ylabel("Failed Connection Count")
    ax4.set_title("Top 10 Source IPs with Failed Connections (Potential Brute Force)")
    ax4.tick_params(axis='x', rotation=45)
    save_or_show(fig4, "failed_connections.png", output_dir)
    
    # Packet Size Distribution (Histogram)
    fig5, ax5 = plt.subplots(figsize=(10, 6))
    sns.histplot(df["size"], bins=30, kde=True, ax=ax5)
    ax5.set_xlabel("Packet Size (bytes)")
    ax5.set_title("Packet Size Distribution")
    save_or_show(fig5, "packet_size_distribution.png", output_dir)
    
    # Scatter Plot: Packet Size over Time
    fig6, ax6 = plt.subplots(figsize=(12, 6))
    sns.scatterplot(x=df_sorted["timestamp"], y=df_sorted["size"], ax=ax6, s=10, color="green")
    ax6.set_xlabel("Time")
    ax6.set_ylabel("Packet Size (bytes)")
    ax6.set_title("Packet Size Scatter Plot Over Time")
    save_or_show(fig6, "packet_size_scatter.png", output_dir)
    
    # Network Graph of Unusual Connections and Centrality
    G, centrality = analyze_network_graph(df)
    fig7, ax7 = plt.subplots(figsize=(12, 8))
    pos = nx.spring_layout(G, k=0.15)
    node_color = [centrality[node] for node in G.nodes()]
    nx.draw(G, pos, with_labels=True, node_color=node_color, cmap=plt.cm.viridis,
            edge_color="gray", font_size=8, node_size=500, ax=ax7)
    ax7.set_title("IP Communication Graph with Degree Centrality")
    save_or_show(fig7, "network_graph.png", output_dir)
    
    # G, centrality = analyze_network_graph(df)
    # plt.figure(figsize=(12, 8))

# Use a fixed seed for reproducibility in layout
#     pos = nx.spring_layout(G, k=0.15, seed=42)

# # Scale node sizes based on degree centrality (adjust scaling factor as needed)
#     node_sizes = [1000 * centrality[node] for node in G.nodes()]

# # Draw nodes with improved aesthetics
#     nodes = nx.draw_networkx_nodes(
#         G, pos,
#         node_color=list(centrality.values()),
#         cmap=plt.cm.plasma,
#         node_size=node_sizes,
#         alpha=0.9
#     )

# # Draw edges with transparency
#     nx.draw_networkx_edges(G, pos, edge_color='gray', alpha=0.5)

# # Draw labels with a consistent font size
#     nx.draw_networkx_labels(G, pos, font_size=8, font_color='black')

#     plt.title("Unusual IP Communication Graph with Degree Centrality", fontsize=16)

# # Add a colorbar to reflect the degree centrality
#     plt.colorbar(nodes, label='Degree Centrality')

# # Remove axes for a cleaner look
#     plt.axis('off')
#     plt.tight_layout()

#     save_or_show(plt.gcf(), "network_graph.png", output_dir)


def main():
    parser = argparse.ArgumentParser(description="Network Packet Analyzer")
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    parser.add_argument("--output", "-o", help="Directory to save the output visualizations", default=None)
    args = parser.parse_args()
    
    packets = read_pcap(args.pcap_file)
    df = extract_packet_data(packets)
    total_bandwidth, protocol_counts = analyze_packet_data(df)
    visualize_suspicious_activity(df, protocol_counts, total_bandwidth, output_dir=args.output)

if __name__ == "__main__":
    main()
