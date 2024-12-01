import os
import nmap
import threading
from scapy.all import ARP, Ether, srp

# Known camera-related service ports and vendors
CAMERA_PORTS = [554, 80, 8080, 443, 8888]
CAMERA_KEYWORDS = ["camera", "webcam", "IP Camera", "surveillance", "dahua", "hikvision"]

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
    result = srp(packet, timeout=3, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices


def scan_device(device, scanner, potential_cameras):
    """
    Scans a specific device for open ports and fingerprints its services.
    :param device: A dictionary containing device IP and MAC addresses.
    :param scanner: An Nmap scanner instance.
    :param potential_cameras: Shared list to store detected cameras.
    """
    try:
        print(f"[*] Scanning {device['ip']}...")
        scan = scanner.scan(hosts=device['ip'], arguments="-sV -O")
        ip = device['ip']
        mac = device['mac']
        details = scan['scan'].get(ip, {})

        # Check for camera indicators
        os_type = details.get('osmatch', [{}])[0].get('name', '')
        vendor = details.get('vendor', {}).get(mac, '')
        open_ports = [port for port in details.get('tcp', {}).keys() if port in CAMERA_PORTS]

        is_camera = False
        if any(keyword.lower() in os_type.lower() for keyword in CAMERA_KEYWORDS):
            is_camera = True
        if any(keyword.lower() in vendor.lower() for keyword in CAMERA_KEYWORDS):
            is_camera = True
        if open_ports:
            is_camera = True

        # Add to potential cameras if identified
        if is_camera:
            camera_info = {
                'ip': ip,
                'mac': mac,
                'os': os_type,
                'vendor': vendor,
                'open_ports': open_ports
            }
            potential_cameras.append(camera_info)
            print(f"[!] Potential camera detected: {camera_info}")
    except Exception as e:
        print(f"[!] Error scanning {device['ip']}: {e}")


def identify_cameras(devices):
    """
    Multithreaded scan for identifying potential cameras.
    :param devices: List of devices with IP and MAC addresses.
    :return: List of potential hidden cameras.
    """
    scanner = nmap.PortScanner()
    potential_cameras = []
    threads = []

    for device in devices:
        thread = threading.Thread(target=scan_device, args=(device, scanner, potential_cameras))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

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
        print("\n[!] Potential hidden cameras detected:")
        for cam in cameras:
            print(f" - IP: {cam['ip']}, MAC: {cam['mac']}, OS: {cam['os']}, Vendor: {cam['vendor']}, Open Ports: {cam['open_ports']}")
    else:
        print("[*] No cameras detected.")

if __name__ == "__main__":
    main()
