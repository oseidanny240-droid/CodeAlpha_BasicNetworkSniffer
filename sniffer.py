#Sniffer codes
"""
CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer

Captures live packets with Scapy and prints, for each one:
  - timestamp, protocol, source -> destination (IP and port)
  - TCP flags / ICMP type
  - a short payload preview (printable text or hex)

Run only on networks you own or have permission to monitor.
Needs admin/root privileges (and Npcap on Windows).

Examples:
  sudo python3 sniffer.py                      # capture until Ctrl+C
  sudo python3 sniffer.py -c 50                # stop after 50 packets
  sudo python3 sniffer.py -f "tcp port 80"     # BPF filter (HTTP only)
  sudo python3 sniffer.py -i eth0 -o log.txt   # pick interface, save to file
"""

import argparse
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw, ARP
except ImportError:
    sys.exit("Scapy is not installed. Run: pip install scapy")

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
stats = Counter()
out_file = None


def payload_preview(packet, limit=60):
    """Return a short, safe preview of the packet payload."""
    if not packet.haslayer(Raw):
        return "(no payload)"
    data = bytes(packet[Raw].load)[:limit]
    text = data.decode("utf-8", errors="replace")
    # Show as text if mostly printable, otherwise as hex
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
    if data and printable / len(data) > 0.8:
        return repr(text)
    return data.hex(" ")


def emit(line):
    print(line)
    if out_file:
        out_file.write(line + "\n")


def handle_packet(packet):
    """Called by Scapy for every captured packet."""
    time = datetime.now().strftime("%H:%M:%S")

    # ARP has no IP layer, so handle it separately
    if packet.haslayer(ARP):
        arp = packet[ARP]
        stats["ARP"] += 1
        emit(f"[{time}] ARP  {arp.psrc} -> {arp.pdst}  (op={arp.op})")
        return

    if packet.haslayer(IP):
        ip = packet[IP]
        src, dst = ip.src, ip.dst
        proto = PROTO_NAMES.get(ip.proto, f"IP-proto-{ip.proto}")
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]
        src, dst = ip.src, ip.dst
        proto = PROTO_NAMES.get(ip.nh, f"IPv6-nh-{ip.nh}")
    else:
        stats["Other"] += 1
        return

    extra = ""
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        src, dst = f"{src}:{tcp.sport}", f"{dst}:{tcp.dport}"
        extra = f"flags={tcp.sprintf('%flags%')}"
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        src, dst = f"{src}:{udp.sport}", f"{dst}:{udp.dport}"
        if packet.haslayer(DNSQR):
            proto = "DNS"
            extra = f"query={packet[DNSQR].qname.decode(errors='replace')}"
    elif packet.haslayer(ICMP):
        extra = f"type={packet[ICMP].type}"

    stats[proto] += 1
    emit(f"[{time}] {proto:<5} {src} -> {dst}  len={len(packet)}  {extra}")
    if proto not in ("DNS",) and packet.haslayer(Raw):
        emit(f"          payload: {payload_preview(packet)}")


def main():
    global out_file
    parser = argparse.ArgumentParser(description="Basic network sniffer (Scapy)")
    parser.add_argument("-i", "--iface", help="network interface (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="",
                        help='BPF filter, e.g. "tcp port 80" or "icmp"')
    parser.add_argument("-o", "--output", help="also save output to this file")
    args = parser.parse_args()

    if args.output:
        out_file = open(args.output, "w", encoding="utf-8")

    print("Sniffing... press Ctrl+C to stop.\n")
    try:
        sniff(iface=args.iface, filter=args.filter or None,
              prn=handle_packet, count=args.count, store=False)
    except PermissionError:
        sys.exit("Permission denied. Run as root/Administrator.")
    except KeyboardInterrupt:
        pass
    finally:
        print("\n--- Capture summary ---")
        for name, n in stats.most_common():
            print(f"{name:<8}{n}")
        print(f"Total   {sum(stats.values())}")
        if out_file:
            out_file.close()


if __name__ == "__main__":
    main()