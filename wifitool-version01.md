# **📜 Installation & Usage Guide for WiFi Attack Tool** 🚀  

![WiFi Attack Tool](https://img.shields.io/badge/WiFi%20Attack-Tool%20🔥-red)  
![Python](https://img.shields.io/badge/Python-3.x-blue.svg)  
![Linux](https://img.shields.io/badge/Linux-Supported-green.svg)  
![Security](https://img.shields.io/badge/Security-Penetration%20Testing-orange)  
![License](https://img.shields.io/badge/License-Educational%20Use-red)  

> ⚠️ **This tool is for educational and penetration testing purposes only.** Unauthorized use is **illegal**.

---

## 📌 **Installation Guide**  

### **🔹 Step 1: Update & Install Dependencies**  
Run the following commands in **Kali Linux** or any **Debian-based Linux** distribution:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip aircrack-ng hcxtools macchanger iw net-tools
pip3 install scapy argparse
```

---

### **🔹 Step 2: Clone the Repository**  
```bash
git clone https://github.com/your-repo-link/WiFi-Attack-Tool.git
cd WiFi-Attack-Tool
```
🔹 If you don’t have Git installed, use:  
```bash
sudo apt install git -y
```

---

### **🔹 Step 3: Grant Execution Permission**  
```bash
chmod +x wifi_tool.py
```

---

### **🔹 Step 4: Run the Tool**  
```bash
sudo python3 wifi_tool.py --help
```
📌 This will display the **help menu** with available commands.

---

### **🔹 Step 5: Exiting & Restoring Wi-Fi Interface**
After using **Monitor Mode**, switch back to **Managed Mode**:
```bash
sudo python3 wifi_tool.py --disable-monitor
```
Or manually:
```bash
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode managed
sudo ifconfig wlan0 up
```

---

# **📜 Usage Commands & Examples**  

## 📌 **Basic Commands**  

### **🔍 1️⃣ Scan for WiFi Networks**  
```bash
sudo python3 wifi_tool.py --mode scan
```
✅ Detects **WiFi networks**, including **hidden SSIDs**.

---

### **📡 2️⃣ Sniff Packets (Capture Network Traffic)**  
```bash
sudo python3 wifi_tool.py --mode sniff --output captured_traffic.pcap
```
✅ Captures **WiFi packets** and saves them for later analysis in **Wireshark**.

---

### **💥 3️⃣ Deauthentication Attack (Disconnect Clients)**  
```bash
sudo python3 wifi_tool.py --mode deauth --target <MAC> --bssid <BSSID>
```
✅ Kicks a client **off a WiFi network**.

📌 **Example:**
```bash
sudo python3 wifi_tool.py --mode deauth --target AA:BB:CC:DD:EE:FF --bssid 11:22:33:44:55:66
```

---

### **🔑 4️⃣ Capture WPA2/WPA3 Handshake (For Security Testing)**  
```bash
sudo python3 wifi_tool.py --mode pmkid --output pmkid_capture.pcap
```
✅ Captures **PMKID WPA2/WPA3 handshakes** without client interaction.

---

### **🎭 5️⃣ Create a Fake AP (Evil Twin Attack)**  
```bash
sudo python3 wifi_tool.py --mode fake_ap --ssid "Free WiFi"
```
✅ Creates a **rogue WiFi access point** to trick users into connecting.

---

## 📌 **Advanced Commands**  

### **🦠 6️⃣ ARP Spoofing (Redirect Network Traffic)**
```bash
sudo python3 wifi_tool.py --mode arp_spoof --target <TARGET_IP> --gateway <GATEWAY_IP>
```
✅ Redirects network traffic to intercept and analyze.

---

### **📶 7️⃣ Signal Strength Mapping (WiFi Coverage Audit)**
```bash
sudo python3 wifi_tool.py --mode signal_map --output signal_report.txt
```
✅ Measures **WiFi signal strength** for coverage testing.

---

### **📋 8️⃣ Log & Report Generation**
```bash
sudo python3 wifi_tool.py --mode log --output attack_log.txt
```
✅ Saves **attack details** for auditing and documentation.

---

## **🚀 Example Usage Scenarios**  

| **Scenario** | **Command** |
|-------------|-------------|
| Scan WiFi networks | `sudo python3 wifi_tool.py --mode scan` |
| Capture WiFi packets | `sudo python3 wifi_tool.py --mode sniff --output packets.pcap` |
| Deauth attack on a device | `sudo python3 wifi_tool.py --mode deauth --target AA:BB:CC:DD:EE:FF --bssid 11:22:33:44:55:66` |
| Capture WPA2 PMKID (Handshake) | `sudo python3 wifi_tool.py --mode pmkid --output pmkid.pcap` |
| Create a Fake AP | `sudo python3 wifi_tool.py --mode fake_ap` |
| Perform ARP Spoofing | `sudo python3 wifi_tool.py --mode arp_spoof --target 192.168.1.10 --gateway 192.168.1.1` |
| Generate logs & reports | `sudo python3 wifi_tool.py --mode log --output attack_log.txt` |

---

## ⚠️ **Disclaimer**  

🔹 This tool is created for **educational and security auditing purposes only**.  
🔹 **Unauthorized use is illegal** and may lead to serious consequences.  
🔹 Always **obtain proper authorization** before testing networks.  

📢 **Be an ethical hacker – Use responsibly!**  

---

💡 **Developed by: [Your Name]**  
🌐 Visit: [Your Website](https://yourwebsite.com)  
🔗 **Follow for Updates:** [Twitter](https://twitter.com/your-handle) | [GitHub](https://github.com/your-repo-link) 🚀
