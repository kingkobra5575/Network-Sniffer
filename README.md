Network Sniffer using Scapy

A Python-based command-line network sniffer built with Scapy. This tool captures and displays detailed information about IP, TCP, and UDP packets on a selected network interface.

## ✨ Features

- Capture packets on a specific or all interfaces
- Supports BPF (Berkeley Packet Filter) strings
- Optional filtering by TCP/UDP port
- Displays:
  - Timestamp
  - Source → Destination IP
  - Protocol (TCP, UDP, or others)
  - Packet length
  - Ports (if applicable)
  - First 50 bytes of payload (if available)
- Stops capture based on packet count or timeout
- Reports if no matching packets were captured

## 🚀 How to Run

```bash
python sniffer.py [OPTIONS]
````

### Options:

| Option              | Description                                  |
| ------------------- | -------------------------------------------- |
| `-i`, `--interface` | Interface to sniff on (e.g., `eth0`, `lo`)   |
| `-f`, `--filter`    | BPF filter string (default: `ip`)            |
| `-p`, `--port`      | Optional port number to filter (e.g., `53`)  |
| `-c`, `--count`     | Number of packets to capture (0 = unlimited) |
| `-t`, `--timeout`   | Stop after N seconds (0 = unlimited)         |

### Example:

```bash
python sniffer.py -i lo -f udp -p 53 -c 20 -t 30
```

## 🛠 Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/enhanced-sniffer.git
cd enhanced-sniffer
```

### 2. Create a virtual environment (optional)

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## ⚠️ Notes

* Run as root or with administrator privileges for packet capture.
* Ensure the specified interface exists and is active.
* Works best on Unix-based systems. On Windows, admin privileges and certain filter features may vary.
