import socket
import struct
from typing import Dict, Any, Tuple, Optional


def mac_address(bytestring: bytes) -> str:
    """Format raw MAC address bytes into readable string (e.g. 00:1A:2B:3C:4D:5E)."""
    return ":".join(f"{b:02X}" for b in bytestring)


def parse_ethernet_frame(data: bytes) -> Tuple[Dict[str, Any], bytes]:
    """
    Parse 14-byte Ethernet header.
    Returns dictionary with MAC addresses and EtherType, along with remaining payload.
    """
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    ether_type = socket.htons(proto)
    return {
        "dest_mac": mac_address(dest_mac),
        "src_mac": mac_address(src_mac),
        "eth_proto": ether_type,
        "proto_name": "IPv4" if ether_type == 8 else ("ARP" if ether_type == 1544 else f"0x{ether_type:04x}")
    }, data[14:]


def parse_ipv4_header(data: bytes) -> Tuple[Dict[str, Any], bytes]:
    """
    Parse IPv4 header (minimum 20 bytes).
    Extracts version, header length, TTL, protocol, source and destination IP.
    """
    if len(data) < 20:
        raise ValueError("Data too short for IPv4 header")

    version_header_length = data[0]
    version = version_header_length >> 4
    ihl = (version_header_length & 15) * 4  # Header length in bytes

    if len(data) < ihl:
        raise ValueError("Data length shorter than IPv4 header length indicated by IHL")

    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])

    protocol_map = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        2: "IGMP"
    }

    info = {
        "version": version,
        "ihl": ihl,
        "ttl": ttl,
        "protocol_num": proto,
        "protocol": protocol_map.get(proto, f"Protocol-{proto}"),
        "src_ip": socket.inet_ntoa(src),
        "dest_ip": socket.inet_ntoa(target),
        "header_length": ihl
    }

    return info, data[ihl:]


def parse_tcp_header(data: bytes) -> Tuple[Dict[str, Any], bytes]:
    """
    Parse TCP header (minimum 20 bytes).
    Extracts ports, sequence number, ack number, data offset, and TCP flags.
    """
    if len(data) < 20:
        raise ValueError("Data too short for TCP header")

    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack(
        "! H H L L H", data[:14]
    )

    offset = (offset_reserved_flags >> 12) * 4
    flags_raw = offset_reserved_flags & 0x01FF

    flags = {
        "NS": bool(flags_raw & 256),
        "CWR": bool(flags_raw & 128),
        "ECE": bool(flags_raw & 64),
        "URG": bool(flags_raw & 32),
        "ACK": bool(flags_raw & 16),
        "PSH": bool(flags_raw & 8),
        "RST": bool(flags_raw & 4),
        "SYN": bool(flags_raw & 2),
        "FIN": bool(flags_raw & 1)
    }

    flag_names = [name for name, is_set in flags.items() if is_set]

    info = {
        "src_port": src_port,
        "dest_port": dest_port,
        "sequence": sequence,
        "ack": acknowledgment,
        "offset": offset,
        "flags": flags,
        "flag_summary": ",".join(flag_names) if flag_names else "NONE"
    }

    return info, data[offset:]


def parse_udp_header(data: bytes) -> Tuple[Dict[str, Any], bytes]:
    """
    Parse 8-byte UDP header.
    Extracts source port, destination port, and length.
    """
    if len(data) < 8:
        raise ValueError("Data too short for UDP header")

    src_port, dest_port, length, checksum = struct.unpack("! H H H H", data[:8])

    info = {
        "src_port": src_port,
        "dest_port": dest_port,
        "length": length,
        "checksum": checksum
    }

    return info, data[8:]


def parse_icmp_header(data: bytes) -> Tuple[Dict[str, Any], bytes]:
    """
    Parse ICMP header (8 bytes).
    Extracts ICMP type, code, and checksum.
    """
    if len(data) < 4:
        raise ValueError("Data too short for ICMP header")

    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])

    type_map = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        8: "Echo Request",
        11: "Time Exceeded"
    }

    info = {
        "type": icmp_type,
        "code": code,
        "type_description": type_map.get(icmp_type, f"Type {icmp_type}"),
        "checksum": checksum
    }

    return info, data[4:]


def parse_application_payload(payload: bytes, src_port: int, dest_port: int) -> Dict[str, Any]:
    """
    Basic application layer inspection (HTTP, DNS, TLS info detection).
    """
    info: Dict[str, Any] = {"summary": None, "app_protocol": "RAW"}

    if not payload:
        return info

    # Check for HTTP
    if src_port == 80 or dest_port == 80 or src_port == 8080 or dest_port == 8080:
        try:
            decoded = payload[:500].decode("utf-8", errors="ignore")
            lines = decoded.split("\r\n")
            first_line = lines[0]
            if any(first_line.startswith(m) for m in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "HTTP/"]):
                info["app_protocol"] = "HTTP"
                info["summary"] = first_line
                return info
        except Exception:
            pass

    # Check for DNS (Port 53)
    if src_port == 53 or dest_port == 53:
        info["app_protocol"] = "DNS"
        if len(payload) >= 12:
            try:
                transaction_id, flags, qdcount, ancount = struct.unpack("! H H H H", payload[:8])
                qr = (flags >> 15) & 1
                type_str = "Response" if qr == 1 else "Query"
                info["summary"] = f"DNS {type_str} (TxID: 0x{transaction_id:04x}, Questions: {qdcount}, Answers: {ancount})"
                return info
            except Exception:
                pass

    # Check for TLS Handshake
    if src_port == 443 or dest_port == 443:
        info["app_protocol"] = "HTTPS/TLS"
        if payload[0] == 0x16:  # Handshake record
            info["summary"] = "TLS Handshake"
        elif payload[0] == 0x17:  # Application Data
            info["summary"] = "TLS Encrypted Application Data"
        return info

    return info


def format_hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """
    Generates a traditional formatted Hex & ASCII dump for packet payload display.
    Example:
    0000   45 00 00 3c 1c 46 40 00  40 06 b1 e6 ac 10 00 01   E..<..@.@.......
    """
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex representation to align ASCII column
        hex_formatted = f"{hex_bytes:<{bytes_per_line * 3}}"
        ascii_bytes = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_formatted}   {ascii_bytes}")
    return "\n".join(lines)


def parse_packet(raw_data: bytes, includes_eth: bool = False) -> Dict[str, Any]:
    """
    Main packet entry point. Parses full packet stream (with or without Ethernet header).
    Returns structured dictionary with metadata, headers, payload, and protocol summary.
    """
    packet_info: Dict[str, Any] = {
        "raw_length": len(raw_data),
        "ethernet": None,
        "ip": None,
        "transport": None,
        "transport_proto": "UNKNOWN",
        "app": None,
        "payload": b"",
        "summary": ""
    }

    remaining = raw_data

    # Parse Ethernet layer if present
    if includes_eth and len(remaining) >= 14:
        eth_info, remaining = parse_ethernet_frame(remaining)
        packet_info["ethernet"] = eth_info
        if eth_info["eth_proto"] != 8:  # Not IPv4
            packet_info["summary"] = f"Ethernet {eth_info['proto_name']} ({eth_info['src_mac']} -> {eth_info['dest_mac']})"
            packet_info["payload"] = remaining
            return packet_info

    # Parse IPv4 layer
    try:
        ip_info, remaining = parse_ipv4_header(remaining)
        packet_info["ip"] = ip_info
        proto_name = ip_info["protocol"]
        src_ip = ip_info["src_ip"]
        dest_ip = ip_info["dest_ip"]

        # Parse Transport layer
        if proto_name == "TCP":
            tcp_info, remaining = parse_tcp_header(remaining)
            packet_info["transport"] = tcp_info
            packet_info["transport_proto"] = "TCP"
            packet_info["payload"] = remaining
            app_info = parse_application_payload(remaining, tcp_info["src_port"], tcp_info["dest_port"])
            packet_info["app"] = app_info

            flags_str = f" [{tcp_info['flag_summary']}]" if tcp_info["flag_summary"] != "NONE" else ""
            app_str = f" | {app_info['summary']}" if app_info["summary"] else ""
            packet_info["summary"] = (
                f"TCP {src_ip}:{tcp_info['src_port']} -> {dest_ip}:{tcp_info['dest_port']}"
                f"{flags_str}{app_str}"
            )

        elif proto_name == "UDP":
            udp_info, remaining = parse_udp_header(remaining)
            packet_info["transport"] = udp_info
            packet_info["transport_proto"] = "UDP"
            packet_info["payload"] = remaining
            app_info = parse_application_payload(remaining, udp_info["src_port"], udp_info["dest_port"])
            packet_info["app"] = app_info

            app_str = f" | {app_info['summary']}" if app_info["summary"] else ""
            packet_info["summary"] = (
                f"UDP {src_ip}:{udp_info['src_port']} -> {dest_ip}:{udp_info['dest_port']}"
                f"{app_str}"
            )

        elif proto_name == "ICMP":
            icmp_info, remaining = parse_icmp_header(remaining)
            packet_info["transport"] = icmp_info
            packet_info["transport_proto"] = "ICMP"
            packet_info["payload"] = remaining
            packet_info["summary"] = (
                f"ICMP {src_ip} -> {dest_ip} ({icmp_info['type_description']})"
            )
        else:
            packet_info["payload"] = remaining
            packet_info["summary"] = f"{proto_name} {src_ip} -> {dest_ip} ({len(remaining)} bytes payload)"

    except Exception as e:
        packet_info["summary"] = f"Malformed/Partial Packet ({len(raw_data)} bytes): {e}"
        packet_info["payload"] = raw_data

    return packet_info
