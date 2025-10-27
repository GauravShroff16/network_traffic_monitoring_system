from scapy.all import sniff, IP
from collections import defaultdict
from threading import Thread, Lock

packet_data = defaultdict(lambda: {'sent': 0, 'received': 0})
data_lock = Lock() #A thread lock to ensure only one thread modifies packet_data at a time.

def process_packet(packet):
    if IP in packet: #Checks if the packet has an IP layer (i.e., it’s an IPv4 packet).
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_len = len(packet)

        # Thread-safe update to packet data
        with data_lock:
            packet_data[src_ip]['sent'] += packet_len #incremeant sent and received count for packets
            packet_data[dst_ip]['received'] += packet_len

def start_packet_monitoring():
    try:
        sniff(prn=process_packet, store=False, filter="ip") #calls process_packet for each packet and dosent store values to save space , captures ipv4
    except Exception as e:
        print(f"Error occurred while sniffing packets: {e}")

def start_sniffer_thread():
    sniffer_thread = Thread(target=start_packet_monitoring, daemon=True)
    sniffer_thread.start()
    return sniffer_thread

if __name__ == "__main__": #Ensures the script only runs when executed directly, not when imported.
    print("Starting packet monitoring...")
    start_sniffer_thread() # Add logic to periodically print or handle packet_data as needed
    while True:
        with data_lock:
            print(packet_data) 