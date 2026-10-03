import pytest
import socket
import struct
from packet_parser import (
    parse_ethernet_frame,
    parse_ipv4_header,
    parse_tcp_header,
    parse_udp_header,
    parse_icmp_header,
    parse_packet,
    format_hex_dump
)


def create_mock_ipv4_header(src_ip: str, dest_ip: str, protocol: int = 6) -> bytes:
    """Helper to craft synthetic 20-byte IPv4 binary header."""
    version_ihl = (4 << 4) | 5  # Version 4, IHL 5 (20 bytes)
    tos = 0
    total_length = 40
    identification = 54321
    flags_fragment = 0
    ttl = 64
    checksum = 0
    src_bytes = socket.inet_aton(src_ip)
    dest_bytes = socket.inet_aton(dest_ip)

    return struct.pack(
        "! B B H H H B B H 4s 4s",
        version_ihl, tos, total_length, identification,
        flags_fragment, ttl, protocol, checksum, src_bytes, dest_bytes
    )


def create_mock_tcp_header(src_port: int, dest_port: int, flags: int = 2) -> bytes:
    """Helper to craft synthetic 20-byte TCP header."""
    seq = 1000
    ack = 0
    data_offset_reserved_flags = (5 << 12) | flags  # Offset 5 (20 bytes), SYN flag (2)
    window = 65535
    checksum = 0
    urgent_pointer = 0

    return struct.pack(
        "! H H L L H H H H",
        src_port, dest_port, seq, ack,
        data_offset_reserved_flags, window, checksum, urgent_pointer
    )


def create_mock_udp_header(src_port: int, dest_port: int, length: int = 12) -> bytes:
    """Helper to craft synthetic 8-byte UDP header."""
    return struct.pack("! H H H H", src_port, dest_port, length, 0)


def test_parse_ipv4_header():
    raw_ip = create_mock_ipv4_header("192.168.1.50", "10.0.0.1", protocol=6)
    info, remaining = parse_ipv4_header(raw_ip)

    assert info["version"] == 4
    assert info["ihl"] == 20
    assert info["ttl"] == 64
    assert info["protocol"] == "TCP"
    assert info["src_ip"] == "192.168.1.50"
    assert info["dest_ip"] == "10.0.0.1"
    assert remaining == b""


def test_parse_tcp_header():
    raw_tcp = create_mock_tcp_header(src_port=443, dest_port=54321, flags=0x012)  # SYN+ACK
    info, remaining = parse_tcp_header(raw_tcp)

    assert info["src_port"] == 443
    assert info["dest_port"] == 54321
    assert info["flags"]["SYN"] is True
    assert info["flags"]["ACK"] is True
    assert info["flags"]["FIN"] is False
    assert remaining == b""


def test_parse_udp_header():
    raw_udp = create_mock_udp_header(src_port=53, dest_port=12345, length=10)
    info, remaining = parse_udp_header(raw_udp)

    assert info["src_port"] == 53
    assert info["dest_port"] == 12345
    assert info["length"] == 10
    assert remaining == b""


def test_parse_icmp_header():
    # ICMP Echo Request (Type 8, Code 0)
    raw_icmp = struct.pack("! B B H I", 8, 0, 0x1234, 0)
    info, remaining = parse_icmp_header(raw_icmp)

    assert info["type"] == 8
    assert info["code"] == 0
    assert info["type_description"] == "Echo Request"


def test_parse_full_tcp_packet():
    ip_header = create_mock_ipv4_header("192.168.1.10", "1.1.1.1", protocol=6)
    tcp_header = create_mock_tcp_header(80, 50000, flags=2)
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

    full_packet = ip_header + tcp_header + payload
    result = parse_packet(full_packet, includes_eth=False)

    assert result["ip"]["src_ip"] == "192.168.1.10"
    assert result["ip"]["dest_ip"] == "1.1.1.1"
    assert result["transport_proto"] == "TCP"
    assert result["transport"]["src_port"] == 80
    assert result["transport"]["dest_port"] == 50000
    assert result["app"]["app_protocol"] == "HTTP"
    assert "GET / HTTP/1.1" in result["summary"]


def test_format_hex_dump():
    data = b"Hello Network Packet World!"
    dump = format_hex_dump(data)

    assert "0000" in dump
    assert "48 65 6c 6c 6f" in dump  # Hex representation of "Hello"
    assert "Hello Network Pa" in dump
