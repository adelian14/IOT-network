"""
Network scanner for the offensive node.
Discovers active hosts and open MQTT ports on the target subnet.
Uses raw socket connection attempts (no nmap dependency required).
"""

import socket
import time


def scan_host(ip, port, timeout=1.0):
    """Check if a specific port is open on a host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except (socket.error, OSError):
        return False


def scan_subnet(subnet_base="10.0.0", start=1, end=100, port=1883, timeout=0.5):
    """
    Scan a range of IPs for open MQTT ports.
    Returns list of (ip, port, is_open) tuples.
    """
    results = []
    print(f"[SCANNER] Scanning {subnet_base}.{start}-{end} on port {port}")
    start_time = time.time()

    for i in range(start, end + 1):
        ip = f"{subnet_base}.{i}"
        is_open = scan_host(ip, port, timeout)
        if is_open:
            results.append(ip)
            print(f"  [+] {ip}:{port} OPEN")

    elapsed = time.time() - start_time
    print(f"[SCANNER] Scan complete in {elapsed:.1f}s. Found {len(results)} hosts with port {port} open.")
    return results


def fingerprint_mqtt(ip, port=1883, timeout=2.0):
    """Attempt a basic MQTT CONNECT to identify broker."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        connect_packet = bytearray([
            0x10, 0x0F,
            0x00, 0x04, 0x4D, 0x51, 0x54, 0x54,
            0x04,
            0x02,
            0x00, 0x3C,
            0x00, 0x03, 0x73, 0x63, 0x6E,
        ])
        sock.send(connect_packet)
        response = sock.recv(4)
        sock.close()

        if len(response) >= 4 and response[0] == 0x20:
            return_code = response[3]
            if return_code == 0:
                return f"MQTT broker at {ip}:{port} - Connection accepted (no auth required)"
            else:
                return f"MQTT broker at {ip}:{port} - Connection refused (code {return_code})"
        return f"MQTT broker at {ip}:{port} - Unexpected response"
    except Exception as e:
        return f"MQTT fingerprint failed for {ip}:{port} - {e}"


def run_full_scan(subnet_base="10.0.0", start=1, end=100):
    """Complete reconnaissance: subnet scan + MQTT fingerprinting."""
    print("=" * 50)
    print("  Network Reconnaissance")
    print("=" * 50)

    hosts = scan_subnet(subnet_base, start, end)

    print(f"\n[SCANNER] Fingerprinting {len(hosts)} discovered MQTT hosts...")
    for ip in hosts:
        result = fingerprint_mqtt(ip)
        print(f"  {result}")

    common_ports = [22, 80, 443, 8080, 8883]
    print(f"\n[SCANNER] Checking common ports on discovered hosts...")
    for ip in hosts:
        for port in common_ports:
            if scan_host(ip, port, timeout=0.3):
                print(f"  [+] {ip}:{port} OPEN")

    return hosts


if __name__ == "__main__":
    run_full_scan()
