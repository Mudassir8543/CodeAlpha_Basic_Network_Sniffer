# CodeAlpha_Basic_Network_Sniffer
This repository contains the "Basic Network Sniffer" project completed as part of the Cyber Security Internship at CodeAlpha.

**Intern Name:** Md Mudassir Ansari  
**Company:** CodeAlpha  
**Task:** Task 1 - Basic Network Sniffer  

##  Project Description
This project is a Python-based network sniffer built using the `scapy` library. It captures live network traffic, analyzes packets, and extracts essential information such as Source IP, Destination IP, Protocols (TCP, UDP, ICMP), Ports, and payload data.

##  Features
- Captures network packets in real-time.
- Identifies and filters IPv4 packets.
- Extracts protocols (TCP, UDP, ICMP).
- Displays Source and Destination IP addresses and Ports.
- Shows the first 50 bytes of the payload for deep packet inspection.

##  Prerequisites & Installation
1. Install Python 3.x
2. Install the required library:
   ```bash
   pip install scapy
