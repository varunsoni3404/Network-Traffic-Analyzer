# Network Traffic Analyzer Using Wireshark and Python

## Overview
This project is a **Network Traffic Analyzer** that utilizes **Wireshark** to capture network packets and **Python** for analysis and visualization. The tool processes PCAP files to extract key network statistics, helping in network monitoring and security analysis.

## Features
- Reads and processes PCAP files using **Scapy**.
- Extracts key packet details (IP addresses, protocol, size, ports, timestamp).
- Analyzes network traffic to compute:
  - Bandwidth usage
  - Protocol distribution (TCP, UDP, ICMP)
  - Top source IPs
  - Top destination ports
  - Packet size distribution
- Generates **visualizations** using **Matplotlib** and **Seaborn**.

## Installation
### Prerequisites
Ensure you have the following installed:
- Python 3.x
- Wireshark (for capturing packets)
- Required Python libraries:
  ```bash
  pip install scapy pandas matplotlib seaborn tqdm tabulate
  ```

## Usage
1. Capture network traffic using **Wireshark** and save it as a `.pcap` file.
2. Run the script with the PCAP file as input:
   ```bash
   python network_analyzer.py <path_to_pcap_file> <port_number>
   ```
3. The script will:
   - Process and analyze the packets
   - Display bandwidth usage and protocol distribution
   - Generate and show visualizations

## Output
- **Total bandwidth used** (in Mbps)
- **Protocol distribution** (% usage of TCP, UDP, ICMP)
- **Top source IPs** by packet count
- **Top destination ports**
- **Packet size distribution graph**

## Screenshots
![packet_size_distribution](https://github.com/user-attachments/assets/59a8c63f-a475-497a-9671-3e5a34b800e2)
![protocol_distribution](https://github.com/user-attachments/assets/0213f0a8-5aba-403c-bd87-b2bc6c2a3115)
![top_destination_ports](https://github.com/user-attachments/assets/c8912192-3511-4d0d-9221-fdf3019e7e8f)
![top_source_ips](https://github.com/user-attachments/assets/69ea70a3-5504-47b5-83f2-76ee88582f2c)

## Limitations
- Requires Wireshark to capture live traffic.
- Does not support real-time packet analysis.
- No built-in anomaly detection or intrusion prevention.

## Applications
- **Network security monitoring**
- **Bandwidth utilization analysis**
- **Detecting unauthorized network activity**
- **Identifying potential security threats**



