import socket
import sys
import threading
import ipaddress
from prettytable import PrettyTable
import nmap

ALL_PORTS = 65535
TOP_THOUSAND_PORTS = 1024
DEFAULT_TIMEOUT = 1

# Lock for thread-safe printing
print_lock = threading.Lock()

def print_help():
    """Prints Features."""
    help_text = """
Usage: python scanner.py <IP Address> [options]

Options:
  -p <ports>         Specify ports to scan (single, comma-separated, or range).
                     Examples:
                     - Single port: -p 80
                     - Range: -p 20-80
                     - Comma-separated: -p 22,80,443
                     - All ports: -p-

  -A                 Perform an advanced scan using Nmap for service and version detection.

  --help             Display this help page.

Features:
  - Multi-threaded scanning for faster results.
  - Custom port selection (single, range, or all ports).
  - Banner grabbing for open ports.
  - PrettyTable output for clean and organized results.
  - Nmap integration for advanced service detection with `-A`.
    """
    print(help_text)

def validate_ip(ip):
    """Validate IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def port_selection(arg: str):
    """Parse port input (single, range, or comma-separated)."""
    ports = []
    if ',' in arg:
        ports = [int(p) for p in arg.split(',')]
    elif '-' in arg:
        start, end = map(int, arg.split('-'))
        ports = list(range(start, end + 1))
    else:
        ports = [int(arg)]
    return ports

def scan_port(ip, port, results):
    """Scan a single port and perform banner grabbing."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(DEFAULT_TIMEOUT)
            if sock.connect_ex((ip, port)) == 0:  # Port is open
                banner = ""
                try:
                    sock.send(b"version")
                    banner = sock.recv(1024).decode().strip()
                except:
                    banner = "No banner"
                with print_lock:
                    print(f"[+] Port {port} is open: {banner}")
                    results.append((port, banner))
    except Exception as e:
        pass

def multi_thread_scan(ip, ports):
    """Perform multi-threaded port scanning."""
    results = []
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(ip, port, results))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()
    return results

def nmap_scan(ip, ports):
    """Use Nmap for advanced service detection."""
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, ports=','.join(map(str, ports)), arguments='-sV')
        results = []
        for host in nm.all_hosts():
            print(f"\nNmap Scan Results for {host}:")
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    service = nm[host][proto][port].get('product', 'Unknown')
                    version = nm[host][proto][port].get('version', 'Unknown')
                    print(f"Port {port}: {service} {version}")
                    results.append((port, f"{service} {version}"))
        return results
    except Exception as e:
        print(f"Error with Nmap scan: {e}")
        return []

def main():
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print_help()
        sys.exit(0)

    ip = sys.argv[1]
    if not validate_ip(ip):
        print("Invalid IP address format.")
        sys.exit(1)

    ports = list(range(0, TOP_THOUSAND_PORTS + 1))
    advanced_scan = False

    try:
        if "-A" in sys.argv:
            advanced_scan = True
        if "-p" in sys.argv:
            port_arg_index = sys.argv.index("-p") + 1
            if port_arg_index < len(sys.argv):
                port_arg = sys.argv[port_arg_index]
                if port_arg == "-":
                    ports = list(range(0, ALL_PORTS + 1))
                else:
                    ports = port_selection(port_arg)
    except Exception as e:
        print(f"Error processing arguments: {e}")
        print_help()
        sys.exit(1)

    print(f"Scanning {ip} on ports: {ports[:10]}{'...' if len(ports) > 10 else ''}")

    if advanced_scan:
        print("\nPerforming advanced Nmap scan...")
        results = nmap_scan(ip, ports)
    else:
        results = multi_thread_scan(ip, ports)

    # Display results in a PrettyTable
    table = PrettyTable(["Port", "Details"])
    for port, details in results:
        table.add_row([port, details])
    print("\nScan Results:")
    print(table)

if __name__ == "__main__":
    main()