from collections import Counter
from typing import Dict, Any, List


class TrafficStats:
    """
    Collects live traffic metrics, protocol distribution, and top talkers.
    """
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = Counter()
        self.src_ip_counts = Counter()
        self.dest_ip_counts = Counter()
        self.src_port_counts = Counter()
        self.dest_port_counts = Counter()
        self.app_protocol_counts = Counter()

    def process_packet(self, packet_info: Dict[str, Any]):
        """Update statistics with a newly captured packet."""
        self.total_packets += 1
        self.total_bytes += packet_info.get("raw_length", 0)

        proto = packet_info.get("transport_proto", "OTHER")
        self.protocol_counts[proto] += 1

        ip_info = packet_info.get("ip")
        if ip_info:
            src_ip = ip_info.get("src_ip")
            dest_ip = ip_info.get("dest_ip")
            if src_ip:
                self.src_ip_counts[src_ip] += 1
            if dest_ip:
                self.dest_ip_counts[dest_ip] += 1

        transport_info = packet_info.get("transport")
        if transport_info and isinstance(transport_info, dict):
            src_p = transport_info.get("src_port")
            dest_p = transport_info.get("dest_port")
            if src_p:
                self.src_port_counts[src_p] += 1
            if dest_p:
                self.dest_port_counts[dest_p] += 1

        app_info = packet_info.get("app")
        if app_info and app_info.get("app_protocol"):
            app_proto = app_info["app_protocol"]
            if app_proto != "RAW":
                self.app_protocol_counts[app_proto] += 1


    def get_summary_dict(self) -> Dict[str, Any]:
        """Return structured summary report."""
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "protocols": dict(self.protocol_counts),
            "top_src_ips": self.src_ip_counts.most_common(5),
            "top_dest_ips": self.dest_ip_counts.most_common(5),
            "top_src_ports": self.src_port_counts.most_common(5),
            "top_dest_ports": self.dest_port_counts.most_common(5),
            "applications": dict(self.app_protocol_counts)
        }

    def print_summary(self):
        """Print clean ASCII summary report to console."""
        print("\n" + "=" * 50)
        print("         TRAFFIC ANALYSIS SUMMARY")
        print("=" * 50)
        print(f" Total Packets Captured : {self.total_packets}")
        print(f" Total Volume           : {self.total_bytes / 1024:.2f} KB ({self.total_bytes} bytes)")
        print("-" * 50)
        print(" Protocol Breakdown:")
        for proto, count in self.protocol_counts.items():
            pct = (count / self.total_packets * 100) if self.total_packets > 0 else 0
            print(f"   - {proto:<10}: {count:>5} packets ({pct:.1f}%)")

        if self.app_protocol_counts:
            print("-" * 50)
            print(" Application Protocols:")
            for app, count in self.app_protocol_counts.items():
                print(f"   - {app:<10}: {count:>5} packets")

        print("-" * 50)
        print(" Top Source IP Addresses:")
        for ip, count in self.src_ip_counts.most_common(5):
            print(f"   - {ip:<16}: {count} packets")

        print("-" * 50)
        print(" Top Destination IP Addresses:")
        for ip, count in self.dest_ip_counts.most_common(5):
            print(f"   - {ip:<16}: {count} packets")
        print("=" * 50 + "\n")
