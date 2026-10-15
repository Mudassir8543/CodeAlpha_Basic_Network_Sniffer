# Import necessary modules from the scapy library
from scapy.all import sniff, IP, TCP, UDP, ICMP

# This function will be called for each packet that is sniffed
def packet_processor(packet):
    """
    This function processes each captured packet and prints its details.
    """
    # Check if the packet has an IP layer. We are interested in IP packets.
    if packet.haslayer(IP):
        # Extract the source and destination IP addresses
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        
        # Print the basic IP header information
        print(f"\n[+] IP Packet: {source_ip} -> {destination_ip}")
        
        # Check for TCP layer
        if packet.haslayer(TCP):
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            print(f"    - Protocol: {protocol}")
            print(f"    - Ports: {source_port} -> {destination_port}")
            
            # Check for payload (the actual data)
            if packet[TCP].payload:
                # We print a small part of the payload to keep the output clean
                payload_data = bytes(packet[TCP].payload)
                print(f"    - Payload (first 50 bytes): {payload_data[:50]!r}")

        # Check for UDP layer
        elif packet.haslayer(UDP):
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            print(f"    - Protocol: {protocol}")
            print(f"    - Ports: {source_port} -> {destination_port}")

            # Check for payload
            if packet[UDP].payload:
                payload_data = bytes(packet[UDP].payload)
                print(f"    - Payload (first 50 bytes): {payload_data[:50]!r}")
        
        # Check for ICMP layer (used for ping, etc.)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            print(f"    - Protocol: {protocol}")
        
        # If it's another protocol within IP
        else:
            protocol = packet.getlayer(IP).proto
            print(f"    - Protocol Number: {protocol} (Other)")


def main():
    """
    Main function to start the packet sniffer.
    """
    print("Starting network sniffer... Press Ctrl+C to stop.")
    
    # Start sniffing. The `prn` argument specifies the function to call for each packet.
    # The `store=0` argument tells scapy not to store the packets in memory.
    try:
        sniff(prn=packet_processor, store=0)
    except Exception as e:
        print(f"An error occurred: {e}")
        print("Please ensure you are running the script with root/administrator privileges.")

# This ensures the main function is called when the script is executed
if __name__ == "__main__":
    main()

