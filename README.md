# Hidden Camera Detector

This project is a **Python-based tool** that scans your Wi-Fi network for devices and attempts to identify hidden cameras. It does so by performing ARP scans to find connected devices and uses Nmap to fingerprint their details. It’s a helpful utility for detecting unauthorized surveillance devices in your environment.

---

## Features

- **Network Scan**: Identifies all devices connected to your Wi-Fi network.
- **Device Fingerprinting**: Uses Nmap to determine device types and vendors.
- **Camera Detection**: Flags devices that could potentially be cameras based on their operating system or vendor information.

---

## Prerequisites

1. **Python 3.8 or higher**
2. Install required Python libraries:
   ```bash
   pip install scapy python-nmap
   ```
3. **Nmap** must be installed on your system:
   - For Linux:
     ```bash
     sudo apt install nmap
     ```
   - For macOS:
     ```bash
     brew install nmap
     ```
   - For Windows: Download and install from [Nmap's official website](https://nmap.org/download.html).

---

## Installation

1. Clone or download this repository.
2. Save the script as `main.py`.

---

## Usage

1. Open a terminal and navigate to the script's directory.
2. Run the script:
   ```bash
   python main.py
   ```
3. Enter your network's IP range when prompted (default is `192.168.1.0/24`).
4. The tool will scan your network, display connected devices, and identify potential cameras.

---

## Example Output

```
Enter the IP range of your network (default 192.168.1.0/24): 
[*] Scanning the network...
[*] Found 4 devices on the network.
 - IP: 192.168.1.2, MAC: 00:1A:2B:3C:4D:5E
 - IP: 192.168.1.3, MAC: 00:1A:2B:3C:4D:5F
 - IP: 192.168.1.4, MAC: 00:1A:2B:3C:4D:60
 - IP: 192.168.1.5, MAC: 00:1A:2B:3C:4D:61

[*] Identifying potential cameras...
[*] Scanning 192.168.1.4...
[!] Potential camera detected: 192.168.1.4 (MAC: 00:1A:2B:3C:4D:60)

[!] Potential hidden cameras detected:
 - IP: 192.168.1.4, MAC: 00:1A:2B:3C:4D:60
```

---

## Limitations

- **Not foolproof**: This tool relies on fingerprinting and may miss some cameras, especially if they mask their identifiers.
- **Network Restrictions**: Ensure you have administrative access to your Wi-Fi network.
- **Hidden Networks**: Cameras connected to hidden networks or using proprietary protocols won’t be detected.

---

## Contributing

Feel free to contribute by submitting pull requests or raising issues! Suggestions for improving detection accuracy or adding new features are always welcome.

---

## Disclaimer

This tool is for **educational and lawful use only**. Unauthorized scanning or surveillance of networks that you do not own or have permission to access is illegal in many jurisdictions. Use responsibly.
