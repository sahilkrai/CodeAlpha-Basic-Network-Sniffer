import sys
import os
import socket
import time
from typing import Callable, Optional, Generator, Tuple, Dict, Any

from packet_parser import parse_packet


def get_default_host_ip() -> str:
    """Find local machine's primary IPv4 address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually connect, used to find interface IP route
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def is_admin() -> bool:
    """Check if script is running with administrative/root privileges."""
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


class RawSocketEngine:
    """
    Native Python socket capture engine.
    Supports Windows (SIO_RCVALL promiscuous mode) and Unix/Linux raw sockets.
    """
    def __init__(self, host_ip: Optional[str] = None):
        self.host_ip = host_ip or get_default_host_ip()
        self.sock: Optional[socket.socket] = None
        self.is_windows = os.name == 'nt'

    def start(self):
        """Initialize and bind raw socket."""
        if self.is_windows:
            if not is_admin():
                raise PermissionError(
                    "Raw Sockets on Windows require Administrator privileges.\n"
                    "Please re-run your terminal or script as Administrator."
                )
            try:
                # Create raw socket on Windows for IP layer
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((self.host_ip, 0))
                # Enable promiscuous mode to receive all incoming & outgoing IP packets
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            except Exception as e:
                raise RuntimeError(f"Failed to bind raw socket on Windows ({self.host_ip}): {e}")
        else:
            # Unix / Linux layer 2 raw socket
            try:
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            except AttributeError:
                # macOS / BSD fallback to IP layer
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((self.host_ip, 0))

        self.sock.settimeout(1.0)

    def capture(self, packet_count: int = 0, callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> Generator[Dict[str, Any], None, None]:
        """
        Yield packets as parsed dictionaries.
        """
        if not self.sock:
            self.start()

        count = 0
        includes_eth = not self.is_windows  # Windows raw IP socket starts at IPv4 layer

        while True:
            if packet_count > 0 and count >= packet_count:
                break
            try:
                raw_data, addr = self.sock.recvfrom(65535)
                packet_dict = parse_packet(raw_data, includes_eth=includes_eth)
                packet_dict["timestamp"] = time.time()
                packet_dict["raw_bytes"] = raw_data
                
                count += 1
                if callback:
                    callback(packet_dict)
                yield packet_dict
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break

    def stop(self):
        """Clean up raw socket and disable promiscuous mode on Windows."""
        if self.sock:
            if self.is_windows:
                try:
                    self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


class ScapyEngine:
    """
    Packet capture engine powered by Scapy.
    Captures full Layer 2 Ethernet frames.
    """
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        try:
            import scapy.all as scapy
            self.scapy = scapy
        except ImportError:
            raise RuntimeError("Scapy library is not installed. Install via: pip install scapy")

    def capture(self, packet_count: int = 0, filter_bpf: Optional[str] = None, callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> Generator[Dict[str, Any], None, None]:
        """
        Yield packets captured via Scapy.
        """
        scapy = self.scapy

        def process_scapy_packet(scapy_pkt):
            raw_bytes = bytes(scapy_pkt)
            packet_dict = parse_packet(raw_bytes, includes_eth=True)
            packet_dict["timestamp"] = time.time()
            packet_dict["raw_bytes"] = raw_bytes
            return packet_dict

        if packet_count > 0:
            scapy_packets = scapy.sniff(
                iface=self.interface,
                count=packet_count,
                filter=filter_bpf,
                store=False,
                prn=lambda p: None
            )
            for pkt in scapy_packets:
                p_dict = process_scapy_packet(pkt)
                if callback:
                    callback(p_dict)
                yield p_dict
        else:
            # Streaming sniff loop
            def pkt_handler(scapy_pkt):
                p_dict = process_scapy_packet(scapy_pkt)
                if callback:
                    callback(p_dict)

            scapy.sniff(iface=self.interface, filter=filter_bpf, prn=pkt_handler, store=False)
