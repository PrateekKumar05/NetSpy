# Import necessary modules
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
from colorama import Fore, Style
import colorama
import pyfiglet
import matplotlib.pyplot as plt
import pandas as pd

# Set up colorama
colorama.init()

# Initialize data for reporting
packet_data = {
    'Type': [],
    'Source IP': [],
    'Destination IP': [],
    'Source Port': [],
    'Destination Port': [],
    'Packet Length': [],
    'Timestamp': []
}

# Initialize counters
packet_count = 0
ip_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
arp_count = 0

def print_netspy():
    custom_fig = pyfiglet.Figlet(font='slant', width=160)
    print(custom_fig.renderText('NetSpy'))

def update_data(packet):
    global packet_count, ip_count, tcp_count, udp_count, icmp_count, arp_count

    packet_count += 1

    if IP in packet:
        ip_count += 1

    if TCP in packet:
        tcp_count += 1

    if UDP in packet:
        udp_count += 1

    if ICMP in packet:
        icmp_count += 1

    if ARP in packet:
        arp_count += 1

    packet_data['Type'].append(packet.name)
    packet_data['Source IP'].append(packet[IP].src if IP in packet else None)
    packet_data['Destination IP'].append(packet[IP].dst if IP in packet else None)
    packet_data['Source Port'].append(packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None)
    packet_data['Destination Port'].append(packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None)
    packet_data['Packet Length'].append(len(packet))
    packet_data['Timestamp'].append(datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f'))

def generate_report():
    df = pd.DataFrame(packet_data)
    df.to_csv('netspy_report.csv', index=False)

def visualize_data():
    # Generate a pie chart for packet types
    labels = ['IP', 'TCP', 'UDP', 'ICMP', 'ARP']
    sizes = [ip_count, tcp_count, udp_count, icmp_count, arp_count]

    plt.figure(figsize=(10, 6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title('Packet Types Distribution')
    plt.savefig('packet_types_distribution.png')
    plt.show()

def print_packet(packet):
    """Prints a packet with styling."""
    update_data(packet)

    print(colorama.Fore.LIGHTWHITE_EX + "=" * 60)
    print(colorama.Fore.LIGHTCYAN_EX + f"Packet Type: {packet.name}")

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(colorama.Fore.LIGHTGREEN_EX + f"Source IP: {ip_src}")
        print(colorama.Fore.LIGHTGREEN_EX + f"Destination IP: {ip_dst}")

    if TCP in packet:
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        print(colorama.Fore.LIGHTBLUE_EX + f"Source Port: {sport}")
        print(colorama.Fore.LIGHTBLUE_EX + f"Destination Port: {dport}")

    if UDP in packet:
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        print(colorama.Fore.LIGHTMAGENTA_EX + f"Source Port: {sport}")
        print(colorama.Fore.LIGHTMAGENTA_EX + f"Destination Port: {dport}")

    if ICMP in packet:
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        print(colorama.Fore.LIGHTYELLOW_EX + f"ICMP Type: {icmp_type}")
        print(colorama.Fore.LIGHTYELLOW_EX + f"ICMP Code: {icmp_code}")

    if ARP in packet:
        arp_op = packet[ARP].op
        arp_src_ip = packet[ARP].psrc
        arp_dst_ip = packet[ARP].pdst
        print(colorama.Fore.LIGHTRED_EX + f"ARP Operation: {arp_op}")
        print(colorama.Fore.LIGHTRED_EX + f"Source IP: {arp_src_ip}")
        print(colorama.Fore.LIGHTRED_EX + f"Destination IP: {arp_dst_ip}")

    # Display packet length
    print(colorama.Fore.LIGHTWHITE_EX + f"Packet Length: {len(packet)} bytes")

    # Display timestamp
    timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')
    print(colorama.Fore.LIGHTWHITE_EX + f"Timestamp: {timestamp}")

    # Display TTL (if applicable)
    if IP in packet:
        ttl = packet[IP].ttl
        print(colorama.Fore.LIGHTWHITE_EX + f"TTL: {ttl}")

    # Display TCP flags (if applicable)
    if TCP in packet:
        flags = packet[TCP].flags
        print(colorama.Fore.LIGHTWHITE_EX + f"TCP Flags: {flags}")

    # Display UDP payload length and content (if applicable)
    if UDP in packet:
        payload_len = len(packet[UDP])
        payload = packet[UDP].payload
        print(colorama.Fore.LIGHTWHITE_EX + f"UDP Payload Length: {payload_len} bytes")
        print(colorama.Fore.LIGHTWHITE_EX + f"UDP Payload Content: {payload}")

    # Display ICMP type and code (if applicable)
    if ICMP in packet:
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        print(colorama.Fore.LIGHTWHITE_EX + f"ICMP Type: {icmp_type}")
        print(colorama.Fore.LIGHTWHITE_EX + f"ICMP Code: {icmp_code}")

    
def main():
    """Sniffs all packets on the network and prints them out with detailed information."""

    try:
        # Start sniffing the network
        print_netspy()
        sniff(prn=print_packet, filter="ip or tcp or udp or icmp or arp", store=0)
        visualize_data()
        generate_report()
    except KeyboardInterrupt:
        print("Sniffing stopped.")
        visualize_data()
        generate_report()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
