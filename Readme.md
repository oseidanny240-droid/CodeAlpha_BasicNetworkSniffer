# CodeAlpha_BasicNetworkSniffer

A Python network sniffer built with [Scapy](https://scapy.net/) for the CodeAlpha Cyber Security Internship (Task 1).

It captures live packets and shows, for each one: timestamp, protocol (TCP, UDP, ICMP, DNS, ARP), source and destination IP and port, TCP flags, packet length, and a short payload preview. A summary of protocol counts prints when you stop.

## Setup

```bash
pip install scapy
```

- **Linux/macOS:** run with `sudo`.
- **Windows:** install [Npcap](https://npcap.com/) and run the terminal as Administrator.

## Usage

```bash
sudo python3 sniffer.py                       # capture until Ctrl+C
sudo python3 sniffer.py -c 50                 # stop after 50 packets
sudo python3 sniffer.py -f "tcp port 80"      # only HTTP traffic
sudo python3 sniffer.py -f icmp               # only ping traffic
sudo python3 sniffer.py -i eth0 -o log.txt    # choose interface, save to file
```

| Option | Meaning |
|---|---|
| `-i` | Network interface (default: automatic) |
| `-c` | Number of packets to capture (0 = unlimited) |
| `-f` | BPF filter expression |
| `-o` | Also write output to a file |

## Example output

```
[14:02:11] TCP   192.168.1.5:51234 -> 93.184.216.34:80  len=74  flags=S
[14:02:11] DNS   192.168.1.5:55120 -> 8.8.8.8:53  len=72  query=example.com.
[14:02:12] ICMP  192.168.1.5 -> 8.8.8.8  len=84  type=8
```

## How it works

1. Scapy's `sniff()` listens on the interface and passes each packet to `handle_packet()`.
2. The handler checks which layers are present (Ethernet, IP, TCP/UDP/ICMP, DNS, Raw) and reads the fields.
3. The `Raw` layer holds the application payload. Printable data is shown as text, anything else as hex.

## What you learn from it

- Packets are stacked layers: Ethernet, then IP, then TCP/UDP, then application data.
- A TCP connection starts with a handshake (SYN, SYN-ACK, ACK), visible in the flags.
- Unencrypted protocols (HTTP, FTP, Telnet) expose their payloads. HTTPS payloads appear as unreadable bytes. This is why encryption matters.

## Legal and ethical use

Only capture traffic on networks you own or have written permission to monitor. Sniffing other people's traffic without consent is illegal in most places.

## Ideas to extend it

- Save captures to a `.pcap` file with `wrpcap()`
- Flag suspicious activity, such as many SYN packets from one IP (port scan)
- Add a live chart of packets per protocol