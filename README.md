
![Logo](https://png.pngtree.com/png-vector/20230728/ourmid/pngtree-anubis-clipart-an-egyptian-black-dog-with-gold-armor-on-his-vector-png-image_6797853.png)


# Faro 

Faro - CLI based Packet Analyzer in C++

## Features




Live packet capture from network interfaces

PCAP file support for reading and writing captures

BPF filtering with standard tcpdump filter syntax

Protocol decoding for Ethernet, IP, TCP, UDP, and ICMP

Color highlighting for better visibility (can be disabled)

Hex dump with ASCII representation (similar to tcpdump -x)

Service name resolution for common ports

Multiple output formats with customizable verbosity



## Installation

Installation
Prerequisites
libpcap development package

C++17 compatible compiler (g++ 7+ or clang 5+)

# Linux (Debian/Ubuntu)
```Linux (Debian/Ubuntu)

sudo apt update
sudo apt install libpcap-dev g++
git clone https://github.com/yourusername/cppdump.git
cd Faro
make
sudo make install
```
    

---

# 📘 Usage Guide: Faro

Faro is a fast, flexible C++ packet analyzer. Below is a complete usage reference including command-line options, example commands, and advanced filtering.

---

## 🔧 Basic Examples

### Capture from default interface
```bash
sudo Faro
```

### Capture from specific interface
```bash
sudo Faro -i eth0
```

### List available interfaces
```bash
Faro -l
```

### Capture a limited number of packets
```bash
sudo Faro -c 100
```

### Set snapshot length
```bash
sudo Faro -s 96
```

### Disable promiscuous mode
```bash
sudo Faro -p
```

### Disable timestamps
```bash
sudo Faro -t
```

---

## 💾 File Operations

### Save captured traffic to file
```bash
sudo Faro -w capture.pcap
```

### Read from a capture file
```bash
Faro -r capture.pcap
```

---

## 🧪 Filtering Examples

### Use a basic BPF filter
```bash
sudo Faro -f "tcp port 80"
```

### Capture DNS queries
```bash
sudo Faro -f "udp port 53"
```

### Traffic between two hosts
```bash
sudo Faro -f "host 192.168.1.100 and host 8.8.8.8"
```

### Subnet-based filtering
```bash
sudo Faro -f "net 192.168.1.0/24"
```

### Capture ICMP packets
```bash
sudo Faro -f "icmp"
```

### TCP SYN packets only
```bash
sudo Faro -f "tcp[tcpflags] & tcp-syn != 0"
```

---

## 🧾 Output Formatting

### Show packets in hex + ASCII
```bash
sudo Faro -x
```

### Enable verbose mode
```bash
sudo Faro -v
```

### Show Ethernet headers
```bash
sudo Faro -e
```

### Disable DNS and port resolution
```bash
sudo Faro -n
```

### Disable color output
```bash
sudo Faro -C
```

---

## 🚀 Advanced Options

### Increase capture buffer size
```bash
sudo Faro --buffer-size 256
```

### Enable immediate mode (disable buffering)
```bash
sudo Faro --immediate-mode
```

---

## 📦 Full Usage Scenarios

### 1. Capture HTTP traffic to a file
```bash
sudo Faro -i eth0 -f "tcp port 80" -w http.pcap
```

### 2. Read a capture file with hex output
```bash
Faro -r http.pcap -x
```

### 3. Capture ICMP (ping) without color
```bash
sudo Faro -f "icmp" -C
```

### 4. Capture first 50 packets on Wi-Fi
```bash
sudo Faro -i wlan0 -c 50
```

---

## 📚 BPF Filter Snippets

```bash
# HTTP traffic (port 80)
-f "tcp port 80"

# Traffic between two hosts
-f "host 10.0.0.5 and host 10.0.0.10"

# Non-HTTP traffic
-f "not port 80"

# Fragmented packets
-f "ip[6] & 0x20 != 0"

# TCP SYN packets
-f "tcp[tcpflags] & tcp-syn != 0"
```

---

## ℹ️ Notes

- Requires `sudo` for live packet capture.
- Filters use standard **BPF syntax** (like tcpdump/Wireshark).
- Combine any options to build your ideal capture scenario.
- Color output is enabled by default (use `-C` to disable).

---

## Screenshots

![App Screenshot](https://via.placeholder.com/468x300?text=App+Screenshot+Here)

