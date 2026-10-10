# Basic Network Packet Sniffer & Analyzer.

A modular Python program designed to capture live network traffic packets, parse binary headers layer-by-layer, analyze protocol structures, and display payload content.

Built for Windows, Linux, and macOS. Supports zero-dependency pure Python **Raw Sockets** and optional **Scapy** capturing.

---

## 📚 Network Traffic & Protocol Fundamentals

When data travels across a network (e.g., loading a webpage, streaming video), it is divided into small chunked units called **packets**. Each packet travels through the **OSI (Open Systems Interconnection) 7-Layer Model**:

```
+-----------------------------------------------------------------------+
|  Layer 7: Application Layer (HTTP, DNS, HTTPS, FTP)                   |
+-----------------------------------------------------------------------+
|  Layer 4: Transport Layer   (TCP [connection-oriented], UDP [fast])   |
+-----------------------------------------------------------------------+
|  Layer 3: Network Layer     (IPv4 / IPv6 addresses, ICMP ping)        |
+-----------------------------------------------------------------------+
|  Layer 2: Data Link Layer   (Ethernet MAC addresses: 00:1A:2B:...)    |
+-----------------------------------------------------------------------+
|  Layer 1: Physical Layer    (Network Card, Cables, Wi-Fi Radio)       |
+-----------------------------------------------------------------------+
```

### Packet Encapsulation & Structure
When sending data, each layer prepends a **Header** containing control information:

```
[ Ethernet Header ] [ IP Header ] [ TCP/UDP Header ] [ Payload Data (HTTP/DNS/raw) ]
  (SRC/DST MAC)       (SRC/DST IP)    (SRC/DST Port)     "GET /index.html HTTP/1.1"
```

1. **Ethernet Header (14 Bytes):** MAC address of sender and next network hop device.
2. **IPv4 Header (20 Bytes minimum):** Source & Destination IP addresses, Time To Live (TTL), Protocol Identifier (TCP=6, UDP=17, ICMP=1).
3. **TCP Header (20 Bytes minimum):** Source & Destination Ports, Sequence Number, Acknowledgment Number, Control Flags (SYN, ACK, FIN, PSH, RST).
4. **UDP Header (8 Bytes):** Lightweight header containing Source & Destination Ports and Length.
5. **Payload:** The actual application content transmitted over the network connection.

---

## 🚀 Key Features of this Sniffer

- 🔍 **Pure Python Binary Parsing:** Uses Python's standard `struct` module to unpack binary network frames byte-by-byte.
- ⚡ **Dual Capture Engines:**
  - **Raw Socket Engine:** Uses standard library `socket.SOCK_RAW` (Zero third-party capture library required).
  - **Scapy Engine:** High-level layer-2 packet capturing when `scapy` is installed.
- 🎨 **Payload Hex & ASCII Viewer:** Displays canonical hex dumps matching Wireshark inspection.
- 📊 **Live Statistical Summaries:** Tracks total packets, volume, protocol counts, top source/dest IPs, and active ports.
- 📁 **Export Options:** Export capture sessions to `JSON`, `CSV`, or `PCAP` files.

---

## 💻 Installation & Setup

### Prerequisites
Python 3.8+ installed on your system.

### Install Dependencies
```bash
pip install -r requirements.txt
```

---

## ⚠️ Important Note for Windows Users

Capturing raw IP packets on Windows using Python sockets (`socket.AF_INET`, `socket.SOCK_RAW`, `socket.IPPROTO_IP`) requires **Administrator Privileges**.

### How to Run on Windows:
1. Open your terminal (**Command Prompt** or **PowerShell**) as Administrator:
   - Press `Win + S`, type `PowerShell` or `cmd`, right-click and select **"Run as administrator"**.
2. Navigate to project directory:
   ```cmd
   cd "C:\Users\sahil\OneDrive\Desktop\Basic Network Sniffer"
   ```python
3. Run the sniffer.

---

## 🎮 Usage Examples

### 1. Basic Packet Sniffing (Capture 10 Packets)
```bash
python main.py -c 10
```

### 2. Inspecting Payloads (Hex Dump View)
```bash
python main.py -c 5 --hex
```

### 3. Filter by Protocol (TCP Only)
```bash
python main.py --protocol TCP -c 20
```

### 4. Filter by Target Port (HTTP - Port 80)
```bash
python main.py --port 80 --hex
```

### 5. Exporting Capture Session to JSON or CSV
```bash
python main.py -c 30 --export capture_output.json
python main.py -c 30 --export capture_output.csv
```

### 6. Using Scapy Engine (Layer-2 Ethernet Capturing)
```bash
python main.py -e scapy -c 10 --export session.pcap
```

---

## 🧪 Running Automated Tests

Run unit tests to verify the binary struct unpackers:

```bash
python -m pytest tests/
```

---

## 📁 File Structure Overview

- `packet_parser.py` - Low-level binary decoding for IPv4, TCP, UDP, ICMP, DNS, HTTP, and Hex dumps.
- `capture_engine.py` - Windows/Linux raw sockets and Scapy integration engines.
- `stats.py` - Real-time statistics collector & protocol counter.
- `exporter.py` - File exporter for JSON, CSV, and PCAP formats.
- `main.py` - Command-line interface with interactive filters and terminal output.
- `tests/test_parser.py` - Unit test suite for protocol parsing functions.
