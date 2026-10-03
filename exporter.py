import json
import csv
import binascii
from typing import List, Dict, Any


def export_to_json(packets: List[Dict[str, Any]], filepath: str):
    """
    Export list of packet dictionaries to JSON file.
    Raw bytes are hex-encoded for JSON serialization compatibility.
    """
    exportable = []
    for pkt in packets:
        p_copy = dict(pkt)
        if "raw_bytes" in p_copy:
            p_copy["raw_hex"] = binascii.hexlify(p_copy["raw_bytes"]).decode("ascii")
            del p_copy["raw_bytes"]
        if "payload" in p_copy and isinstance(p_copy["payload"], bytes):
            p_copy["payload_hex"] = binascii.hexlify(p_copy["payload"]).decode("ascii")
            del p_copy["payload"]
        exportable.append(p_copy)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(exportable, f, indent=2)
    print(f"[+] Exported {len(packets)} packets to JSON: {filepath}")


def export_to_csv(packets: List[Dict[str, Any]], filepath: str):
    """
    Export packet metadata to CSV spreadsheet.
    """
    fields = [
        "timestamp", "transport_proto", "src_ip", "src_port",
        "dest_ip", "dest_port", "raw_length", "summary"
    ]

    rows = []
    for pkt in packets:
        ip = pkt.get("ip") or {}
        transport = pkt.get("transport") or {}
        rows.append({
            "timestamp": pkt.get("timestamp", 0),
            "transport_proto": pkt.get("transport_proto", "UNKNOWN"),
            "src_ip": ip.get("src_ip", "N/A"),
            "src_port": transport.get("src_port", "N/A"),
            "dest_ip": ip.get("dest_ip", "N/A"),
            "dest_port": transport.get("dest_port", "N/A"),
            "raw_length": pkt.get("raw_length", 0),
            "summary": pkt.get("summary", "")
        })

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] Exported {len(packets)} packets to CSV: {filepath}")


def export_to_pcap(packets: List[Dict[str, Any]], filepath: str):
    """
    Export packets to standard PCAP format (usable in Wireshark) via Scapy.
    """
    try:
        from scapy.all import wrpcap, Ether, IP, TCP, UDP, ICMP, Raw
    except ImportError:
        print("[-] PCAP export requires Scapy library (`pip install scapy`). Skipping PCAP export.")
        return

    scapy_pkts = []
    for pkt in packets:
        raw_bytes = pkt.get("raw_bytes")
        if raw_bytes:
            # If raw bytes include ethernet header or pure IP
            if pkt.get("ethernet"):
                scapy_pkts.append(Ether(raw_bytes))
            else:
                scapy_pkts.append(IP(raw_bytes))

    if scapy_pkts:
        wrpcap(filepath, scapy_pkts)
        print(f"[+] Exported {len(packets)} packets to PCAP file: {filepath}")
    else:
        print("[-] No raw packet byte data available to export to PCAP.")
