import os
import nmap
from scapy.all import ARP, Ether, srp

def scan_network(ip_range="192.168.1.0/24"):
    """
    Scans the network for connected devices using ARP requests.
    :param ip_range: The IP range to scan (default is 192.168.1.0/24).
    :return: List of detected devices with IP and MAC addresses.
    """
    print("[*] Scanning the network...")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices


def identify_cameras(devices):
    """
    Uses Nmap to fingerprint devices and identify potential cameras.
    :param devices: List of devices with IP and MAC addresses.
    :return: List of potential hidden cameras.
    """
    scanner = nmap.PortScanner()
    potential_cameras = []

    for device in devices:
        try:
            print(f"[*] Scanning {device['ip']}...")
            scan = scanner.scan(hosts=device['ip'], arguments='-O')
            os_type = scan['scan'][device['ip']].get('osmatch', [{}])[0].get('name', '')
            vendor = scan['scan'][device['ip']].get('vendor', {}).get(device['mac'], '')

            if "camera" in os_type.lower() or "camera" in vendor.lower():
                print(f"[!] Potential camera detected: {device['ip']} ({device['mac']})")
                potential_cameras.append(device)
        except Exception as e:
            print(f"[!] Error scanning {device['ip']}: {e}")
    
    return potential_cameras


def main():
    ip_range = input("Enter the IP range of your network (default 192.168.1.0/24): ") or "192.168.1.0/24"
    devices = scan_network(ip_range)

    if not devices:
        print("[!] No devices found on the network.")
        return

    print(f"[*] Found {len(devices)} devices on the network.")
    for device in devices:
        print(f" - IP: {device['ip']}, MAC: {device['mac']}")

    print("[*] Identifying potential cameras...")
    cameras = identify_cameras(devices)

    if cameras:
        print("[!] Potential hidden cameras detected:")
        for cam in cameras:
            print(f" - IP: {cam['ip']}, MAC: {cam['mac']}")
    else:
        print("[*] No cameras detected.")

if __name__ == "__main__":
    main()
