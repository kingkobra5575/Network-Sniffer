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
python3 sniffer.py [OPTIONS]
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
python3 sniffer.py -i lo -f udp -p 53 -c 20 -t 30
```

## 🛠 Installation

### 1. Clone the repository

```bash
git clone https://github.com/kingkobra5575/Network-Sniffer.git
cd Network-Sniffer
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
sudo apt install python3-scapy
```

## ⚠️ Notes

* Run the script with **administrator/root privileges** to capture packets:

  ```bash
  sudo python3 sniffer.py ...
  ```
* Make sure the specified interface exists and is active.
* Scapy is required to run the code.
* Best used on **Linux/macOS**. On Windows, Scapy may require extra configuration and admin access.
