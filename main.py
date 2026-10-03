import sys
import os
import argparse
import time
from typing import List, Dict, Any

from capture_engine import RawSocketEngine, ScapyEngine, get_default_host_ip, is_admin
from packet_parser import format_hex_dump
from stats import TrafficStats
from exporter import export_to_json, export_to_csv, export_to_pcap

# Try importing rich for enhanced UI rendering
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None


def print_banner():
    """Print ASCII logo banner."""
    banner = r"""
========================================================================
   __  _ ___ _____  _  _ ___  ___  _  __  ___ _  _ ___ ___ ___ ___ ___ 
  |  \| | __|_   _|| || | __||_ _|| |/ / / __| || |_ _| __| __| __| _ \
  | | ' | _|  | |  | \/ | _|  | | | ' <  \__ \ __ || || _|| _|| _|   /
  |_|\__|___| |_|   \__/|___||___||_|\_\ |___/_||_|___|_|  |_| |___|_|_\

               Network Packet Sniffer & Protocol Analyzer
========================================================================
"""
    if HAS_RICH:
        console.print(Panel(Text(banner, style="bold cyan"), title="[bold green]PACKET SNIFFER[/bold green]", border_style="blue"))
    else:
        print(banner)


def match_filters(pkt_dict: Dict[str, Any], proto_filter: str, port_filter: int) -> bool:
    """Check if packet matches user filters."""
    if proto_filter != "ALL":
        transport_proto = pkt_dict.get("transport_proto", "OTHER")
        if transport_proto.upper() != proto_filter.upper():
            return False

    if port_filter > 0:
        transport_info = pkt_dict.get("transport") or {}
        src_port = transport_info.get("src_port", 0)
        dest_port = transport_info.get("dest_port", 0)
        if src_port != port_filter and dest_port != port_filter:
            return False

    return True


def display_packet(pkt_dict: Dict[str, Any], pkt_number: int, show_hex: bool = False):
    """Render packet details to stdout."""
    summary = pkt_dict.get("summary", "")
    proto = pkt_dict.get("transport_proto", "OTHER")
    length = pkt_dict.get("raw_length", 0)
    ts = time.strftime("%H:%M:%S", time.localtime(pkt_dict.get("timestamp", time.time())))

    if HAS_RICH:
        color = "green" if proto == "TCP" else ("yellow" if proto == "UDP" else ("magenta" if proto == "ICMP" else "white"))
        header_text = f"[{color}]#{pkt_number:04d} [{ts}] {summary} ({length} bytes)[/{color}]"
        console.print(header_text)
    else:
        print(f"#{pkt_number:04d} [{ts}] {summary} ({length} bytes)")

    if show_hex and pkt_dict.get("payload"):
        payload = pkt_dict["payload"]
        if payload:
            hex_dump = format_hex_dump(payload)
            if HAS_RICH:
                console.print(f"[dim]{hex_dump}[/dim]\n")
            else:
                print(f"{hex_dump}\n")


def main():
    parser = argparse.ArgumentParser(description="Python Network Packet Sniffer & Analyzer")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-p", "--protocol", type=str, default="ALL", choices=["ALL", "TCP", "UDP", "ICMP"], help="Protocol filter")
    parser.add_argument("--port", type=int, default=0, help="Port filter (e.g. 80, 443, 53)")
    parser.add_argument("--hex", action="store_true", help="Display payload hex & ASCII dump")
    parser.add_argument("-e", "--engine", type=str, default="socket", choices=["socket", "scapy"], help="Capture engine selection")
    parser.add_argument("-i", "--interface", type=str, default="", help="Network interface IP or name")
    parser.add_argument("-o", "--export", type=str, default="", help="Export file path (.json, .csv, .pcap)")
    args = parser.parse_args()

    print_banner()

    host_ip = args.interface or get_default_host_ip()
    print(f"[*] Target Interface IP: {host_ip}")
    print(f"[*] Engine             : {args.engine.upper()}")
    print(f"[*] Protocol Filter    : {args.protocol}")
    if args.port > 0:
        print(f"[*] Port Filter        : {args.port}")
    if args.count > 0:
        print(f"[*] Packet Limit       : {args.count}")
    print("-" * 60)

    if os.name == 'nt' and args.engine == "socket" and not is_admin():
        print("\n[!] WARNING: Windows raw sockets require Administrator privileges.")
        print("[!] Right-click your terminal application and select 'Run as Administrator'.\n")

    stats = TrafficStats()
    captured_packets: List[Dict[str, Any]] = []

    # Select Capture Engine
    if args.engine == "scapy":
        try:
            engine = ScapyEngine(interface=args.interface if args.interface else None)
            packet_generator = engine.capture(packet_count=0 if args.count == 0 else 0)
        except Exception as err:
            print(f"[-] Scapy Engine Initialization Error: {err}")
            sys.exit(1)
    else:
        try:
            engine = RawSocketEngine(host_ip=host_ip)
            engine.start()
            packet_generator = engine.capture(packet_count=0)
        except Exception as err:
            print(f"[-] Raw Socket Engine Initialization Error: {err}")
            sys.exit(1)

    print("[+] Packet capture started. Press Ctrl+C to stop...\n")
    pkt_count = 0

    try:
        for pkt in packet_generator:
            if not match_filters(pkt, args.protocol, args.port):
                continue

            pkt_count += 1
            stats.process_packet(pkt)
            captured_packets.append(pkt)

            display_packet(pkt, pkt_count, show_hex=args.hex)

            if args.count > 0 and pkt_count >= args.count:
                break
    except KeyboardInterrupt:
        print("\n[*] Capture interrupted by user.")
    finally:
        if args.engine == "socket" and 'engine' in locals():
            engine.stop()

    # Display Final Statistics
    stats.print_summary()

    # Export session if requested
    if args.export:
        filepath = args.export
        if filepath.endswith(".json"):
            export_to_json(captured_packets, filepath)
        elif filepath.endswith(".csv"):
            export_to_csv(captured_packets, filepath)
        elif filepath.endswith(".pcap"):
            export_to_pcap(captured_packets, filepath)
        else:
            export_to_json(captured_packets, filepath + ".json")


if __name__ == "__main__":
    main()
