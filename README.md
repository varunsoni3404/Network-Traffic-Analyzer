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
   python network_analyzer.py <path_to_pcap_file>
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
(Include relevant screenshots of the output and visualizations.)

## Limitations
- Requires Wireshark to capture live traffic.
- Does not support real-time packet analysis.
- No built-in anomaly detection or intrusion prevention.

## Applications
- **Network security monitoring**
- **Bandwidth utilization analysis**
- **Detecting unauthorized network activity**
- **Identifying potential security threats**

## Contributing
Contributions are welcome! Feel free to open issues or submit pull requests.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact
For any questions or support, reach out to [your contact info].

