import argparse
from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

# Map IP protocol numbers to names
PROTO_MAP = {6: "TCP", 17: "UDP"}

# Callback to process each packet
packet_count = 0

def packet_callback(pkt):
    global packet_count
    if IP not in pkt:
        return
    packet_count += 1

    ip = pkt[IP]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src, dst = ip.src, ip.dst
    proto = PROTO_MAP.get(ip.proto, str(ip.proto))
    length = ip.len

    # Show TCP/UDP ports if present
    if TCP in pkt:
        print(f"    TCP Ports: {pkt[TCP].sport} -> {pkt[TCP].dport}")
    if UDP in pkt:
        print(f"    UDP Ports: {pkt[UDP].sport} -> {pkt[UDP].dport}")

    print(f"[{timestamp}] {src} -> {dst} | Proto: {proto} | Len: {length}")
    
    # Show raw payload (first 50 bytes)
    if Raw in pkt:
        raw_data = pkt[Raw].load[:50]
        try:
            printable = raw_data.decode(errors='replace')
        except Exception:
            printable = repr(raw_data)
        print(f"    Payload: {printable}")

    print('-' * 60)


def validate_filter(expr: str) -> str:
    """Normalize common shorthand in BPF expressions."""
    expr = expr.strip()
    expr = expr.replace('udp ports', 'udp')
    expr = expr.replace('tcp ports', 'tcp')
    return expr or ''


def build_bpf(filter_expr: str, port: int) -> str:
    base = validate_filter(filter_expr)
    if port:
        # If user wants specific port, filter both TCP and UDP if base is 'ip' or generic
        if base in ('', 'ip'):
            return f"(tcp port {port} or udp port {port})"
        # If explicitly filtering UDP or TCP
        if base == 'udp':
            return f"udp port {port}"
        if base == 'tcp':
            return f"tcp port {port}"
        # Compound or other cases
        return f"{base} and (tcp port {port} or udp port {port})"
    # No port specified: use base filter
    return base


def main():
    parser = argparse.ArgumentParser(description="Enhanced Network Sniffer using Scapy")
    parser.add_argument('-i', '--interface', type=str, default=None,
                        help='Network interface to sniff on (default: all)')
    parser.add_argument('-f', '--filter', type=str, default='ip',
                        help='BPF filter string (e.g. "tcp", "udp", "ip")')
    parser.add_argument('-p', '--port', type=int,
                        help='(Optional) TCP/UDP port to filter on')
    parser.add_argument('-c', '--count', type=int, default=0,
                        help='Stop after this many packets (0 = infinite)')
    parser.add_argument('-t', '--timeout', type=int, default=0,
                        help='Stop after this many seconds (0 = infinite)')
    args = parser.parse_args()

    # Build final BPF filter
    bpf = build_bpf(args.filter, args.port)

    print('-' * 60)
    print("\tStarting Network Sniffer")
    print(f"Interface    : {args.interface or 'ALL'}")
    print(f"Filter       : '{bpf or 'none'}'")
    print(f"Packet limit : {args.count if args.count>0 else 'infinite'}")
    print(f"Timeout      : {args.timeout if args.timeout>0 else 'infinite'}s")
    print('-' * 60)

    global packet_count
    packet_count = 0

    sniff_kwargs = {'prn': packet_callback, 'store': False}
    if args.interface:
        sniff_kwargs['iface'] = args.interface
    if bpf:
        sniff_kwargs['filter'] = bpf
    if args.count > 0:
        sniff_kwargs['count'] = args.count
    if args.timeout > 0:
        sniff_kwargs['timeout'] = args.timeout

    try:
        sniff(**sniff_kwargs)
    except Exception as e:
        print(f"ERROR: Failed to start sniffing: {e}")
        return

    # Report summary
    if packet_count == 0:
        print("\nNo packets were captured that matched the filter.")
    else:
        print(f"\n*** Sniffer stopped after capturing {packet_count} packet(s) ***")


if __name__ == "__main__":
    main()

