# Port Scanner

## Project Overview

This project is a multi-threaded port scanner written in Python. It scans a target host for open ports, performs banner grabbing, and optionally integrates with Nmap for advanced service and version detection.

## Features

- **Multi-threaded scanning** for faster results.
- **Custom port selection** (single port, range, or all ports).
- **Banner grabbing** to identify running services.
- **PrettyTable output** for organized results.
- **Nmap integration** (`-A` flag) for detailed service and version detection.
- **Command-line options** for flexibility in scanning.

<img src="sample-image/sample.png" alt="Sample" height="350">

## Installation

### Prerequisites
Ensure you have **Python 3** installed on your system. Additionally, install the required dependencies using:

```bash
pip install -r requirements.txt
```

Or manually install required packages:
```bash
pip install prettytable python-nmap
```

> **Note:** `socket`, `sys`, `threading`, and `ipaddress` are built-in Python modules and do not require installation.

## Usage

### Basic Scan
To scan the top 1024 ports on a target IP address:
```bash
python scanner.py <target_ip>
```
Example:
```bash
python scanner.py 192.168.1.100
```

### Custom Port Scan
Scan specific ports:
```bash
python scanner.py <target_ip> -p <ports>
```
Examples:
```bash
python scanner.py 192.168.1.100 -p 22       # Scan port 22
python scanner.py 192.168.1.100 -p 20-80    # Scan ports from 20 to 80
python scanner.py 192.168.1.100 -p 22,80,443 # Scan multiple ports
python scanner.py 192.168.1.100 -p-         # Scan all 65535 ports
```

### Advanced Scan with Nmap
For detailed service and version detection:
```bash
python scanner.py <target_ip> -A
```
Example:
```bash
python scanner.py 192.168.1.100 -A
```

### Help Menu
To see available options:
```bash
python scanner.py --help
```

## Output Example
After scanning, results are displayed in a structured table format:
```
+------+------------------+
| Port | Details         |
+------+------------------+
| 22   | Open (SSH)      |
| 80   | Open (HTTP)     |
| 443  | Open (HTTPS)    |
+------+------------------+
```

## Notes
- Running a scan may require **administrator/root privileges** depending on the network setup.
- Scanning public IPs without permission **may be illegal**. Always ensure you have authorization.
- The **Nmap feature** requires `nmap` to be installed on your system. If not installed, run:
  ```bash
  sudo apt install nmap  # Linux
  brew install nmap      # macOS
  choco install nmap     # Windows (Chocolatey)
  ```

## License
This project is for **educational purposes only**. Use responsibly.

---

Developed by Haardik Bhagtani