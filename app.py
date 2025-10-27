from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import psutil
import threading
import socket
from werkzeug.exceptions import BadRequestKeyError
import time

# Data structure to store packet timestamps for DDoS detection
packet_timestamps = defaultdict(list)

app = Flask(__name__) #Initializes the Flask application
app.secret_key = 'your_secret_key'  # Replace with a secure, random secret key


users = {'admin': {'password': 'admin123'}} #Dictionary storing user credentials for login


packet_data = defaultdict(lambda: {'sent': 0, 'received': 0, 'protocols': set()}) ## Data structures to store traffic information
network_traffic = {}  # To store general network stats
thresholds = {'sent': 100000, 'received': 100000}  # Default thresholds

lock = threading.Lock()  # To prevent race conditions
# Port-based classification
PORT_CATEGORIES = {
    
    'Downloading': {21, 80, 443, 8080},
    
}

def classify_traffic(port):
    for category, ports in PORT_CATEGORIES.items():
        if port in ports:
            return category
    return 'Other'

# Function to get the hostname from an IP address
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Local Host"

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)  # Get packet length
        ttl = packet[IP].ttl  # Extract TTL
        protocol = packet[IP].proto  # Protocol number
        
        # Extract port from TCP/UDP packets
        if TCP in packet:
            port = packet[TCP].sport  # Source port
        elif UDP in packet:
            port = packet[UDP].sport  # Source port
        else:
            port = None
        
        category = classify_traffic(port) if port else 'Unknown'
        
        # Map protocol number to name
        protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP", 2: "IGMP"}
        protocol_name = protocol_map.get(protocol, f"Protocol {protocol}") #if protocol not in dictionary it returns the f string

        # Thread-safe update of packet data
        with lock:
            if src_ip not in packet_data: #check whether the src_ip (source IP) and dst_ip (destination IP) are already present 
                packet_data[src_ip] = {
                    'sent': 0, #initialize sent 
                    'received': 0, 
                    'protocols': set(), #A set to store the unique protocols used by that IP
                    'hostname': get_hostname(src_ip), 
                    'ttl': ttl,  # Store TTL
                    'length': 0  # Initialize length
                }
            if dst_ip not in packet_data:
                packet_data[dst_ip] = {
                    'sent': 0, 
                    'received': 0, 
                    'protocols': set(), 
                    'hostname': get_hostname(dst_ip), 
                    'ttl': ttl,  # Store TTL
                    'length': 0  # Initialize length
                }

            # Update sent, received, and length of packet_data dictionary
            packet_data[src_ip]['sent'] += packet_size
            packet_data[src_ip]['protocols'].add(protocol_name)
            packet_data[src_ip]['length'] = packet_size
            packet_data[src_ip]['category'] = category

            packet_data[dst_ip]['received'] += packet_size
            packet_data[dst_ip]['protocols'].add(protocol_name)
            packet_data[dst_ip]['length'] = packet_size
            packet_data[dst_ip]['category'] = category

            # Track timestamps for DDoS detection
            timestamp = time.time()
            packet_timestamps[src_ip].append(timestamp)
            
            # Clean up old timestamps 
            packet_timestamps[src_ip] = [t for t in packet_timestamps[src_ip] if timestamp - t <= 10]
            
            # If more than 100 packets flag as DDoS
            if len(packet_timestamps[src_ip]) > 100:
                packet_data[src_ip]['ddos'] = True  # Flag as DDoS
            else:
                packet_data[src_ip]['ddos'] = False  # Not a DDoS


# Start the packet sniffer in a separate thread
threading.Thread(target=lambda: sniff(prn=process_packet, store=False), daemon=True).start()
#The thread starts and runs the sniff function.(lamda=anonymus)
#The sniff function captures packets from the network interface.
#For each packet, the process_packet function is called to analyze or log the packet.
#The use of a daemon thread ensures that if the main program exits, the thread stops automatically.

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Authenticate user
        if username in users and users[username]['password'] == password:
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return "Invalid credentials. Please try again.", 401

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)  # Clear session
    return redirect(url_for('login'))

@app.route('/set_threshold', methods=['POST'])
def set_threshold():
    if 'username' not in session:
        return redirect(url_for('login'))  # Redirect to login if not authenticated

    try:
        # Fetch thresholds from the form
        sent_threshold = int(request.form['sent_threshold'])
        received_threshold = int(request.form['received_threshold'])

        # Update thresholds in dictionary
        with lock:
            thresholds['sent'] = sent_threshold
            thresholds['received'] = received_threshold

        return redirect(url_for('home'))  # Redirect to home to display updated values
    except (ValueError, BadRequestKeyError):
        return "Invalid input. Please provide valid integers for thresholds.", 400

@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))  # Redirect to login if not authenticated
    
    # Fetch system-wide network stats
    network_info = psutil.net_io_counters(pernic=True) #psutil fetches all network wide daya and pernic true basically means wifi-ethernet
    global network_traffic

    with lock:
        network_traffic = {
            interface: {'sent': stats.bytes_sent, 'received': stats.bytes_recv}
            for interface, stats in network_info.items()
        }   #update network traffic dictionary

        # Filter device-level traffic that exceeds thresholds , scans every ip in the dictionary
        flagged_devices = {
            ip: data for ip, data in packet_data.items()
            if data.get('ddos', False)  # Only include devices flagged as DDoS
        }

    return render_template(
        'index.html',
        network_traffic=network_traffic,
        device_traffic=packet_data,
        flagged_devices=flagged_devices  # Pass the flagged devices to the frontend
    )

@app.route('/get_ddos_insights')
def get_ddos_insights():
    if 'username' not in session:
        return redirect(url_for('login'))  # Redirect to login if not authenticated

    with lock:
        ddos_alerts = {
            ip: data for ip, data in packet_data.items() if data.get('ddos', False) #Looks for the key 'ddos' in each device's data.
        }                                                                            #If the key exists and its value is True, the device is flagged for potential DDoS activity.
         #If the key doesn't exist or its value is False, the device is excluded from the result.
        #ip:  means for that ip the data is being checked to be flagged
        
        
    return jsonify({'ddos_alerts': list(ddos_alerts)})  # This should be aligned with the 'with lock' block
#converts python file to json format -> distionary to list
@app.route('/get_filtered_traffic_data')
def get_filtered_traffic_data():
    protocol_filter = request.args.get('protocol', 'all')  # Get protocol filter (TCP, UDP, etc.)
    above_threshold_filter = request.args.get('above_threshold', 'false') == 'true'  # Get threshold filter

    with lock:
        filtered_data = {
            'devices': {
                ip: {
                    'sent': data['sent'],
                    'received': data['received'],
                    'protocols': list(data['protocols']),
                    'hostname': data.get('hostname', 'Unknown Host'),
                    'ttl': data.get('ttl', 'N/A'),
                    'length': data.get('length', 'N/A'),
                    'category': data.get('category', 'Unknown'),
                    'ddos': data.get('ddos', False)
                } for ip, data in packet_data.items()
                if (protocol_filter == 'all' or protocol_filter in data['protocols'])  # Filter by protocol
                and (not above_threshold_filter or data['sent'] > thresholds['sent'] or data['received'] > thresholds['received'])  # Filter by threshold
            },
            'thresholds': thresholds,
            'flagged_devices': [
                {'ip': ip, 'sent': data['sent'], 'received': data['received']}
                for ip, data in packet_data.items()
                if data['sent'] > thresholds['sent'] or data['received'] > thresholds['received']
            ]
        }

    return jsonify(filtered_data)

@app.route('/get_traffic_data')
def get_traffic_data():
    if 'username' not in session:
        return redirect(url_for('login'))  # Redirect to login if not authenticated

    with lock:
        return jsonify({
            'devices': {
                ip: {
                    'sent': data['sent'],
                    'received': data['received'],
                    'protocols': list(data['protocols']),
                    'hostname': data.get('hostname', 'Unknown Host'),
                    'ttl': data.get('ttl', 'N/A'),
                    'length': data.get('length', 'N/A'),
                    'category': data.get('category', 'Unknown'),
                    'ddos': data.get('ddos', False)
                } for ip, data in packet_data.items()
            },
            'thresholds': thresholds,
            'flagged_devices': [
                {'ip': ip, 'sent': data['sent'], 'received': data['received']}
                for ip, data in packet_data.items()
                if data['sent'] > thresholds['sent'] or data['received'] > thresholds['received']
            ]
        })


@app.route('/data_analysis')
def data_analysis():
    return render_template('data_analysis.html')

if __name__ == '__main__':
    app.run(debug=True)
