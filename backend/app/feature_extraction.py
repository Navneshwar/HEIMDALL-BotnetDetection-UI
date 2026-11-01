"""PCAP to bidirectional flow feature extraction.

Only packet metadata is inspected. Packet payload bytes are never decoded.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

from .settings import FLOW_IDLE_TIMEOUT_SECONDS, MAX_FLOWS, MAX_PACKETS


@dataclass
class FlowAccumulator:
    protocol: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    first_seen: float
    last_seen: float
    packet_count: int = 0
    total_bytes: int = 0

    def add(self, timestamp: float, packet_bytes: int) -> None:
        self.first_seen = min(self.first_seen, timestamp)
        self.last_seen = max(self.last_seen, timestamp)
        self.packet_count += 1
        self.total_bytes += max(int(packet_bytes), 0)

    def to_record(self, flow_number: int) -> dict[str, Any]:
        duration = max(self.last_seen - self.first_seen, 0.0)
        mean_iat = duration / (self.packet_count - 1) if self.packet_count > 1 else 0.0
        mean_size = self.total_bytes / self.packet_count if self.packet_count else 0.0
        byte_rate = self.total_bytes / duration if duration > 0 else 0.0
        return {
            "flow_id": flow_number,
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "flow_duration": duration,
            "packet_count": float(self.packet_count),
            "total_bytes": float(self.total_bytes),
            "mean_packet_size": mean_size,
            "mean_inter_arrival_time": mean_iat,
            "bytes_per_second": byte_rate,
        }


def _packet_endpoints(packet: Any) -> tuple[str, str, int, int, str, int] | None:
    if packet.haslayer(IP):
        network = packet[IP]
    elif packet.haslayer(IPv6):
        network = packet[IPv6]
    else:
        return None

    if packet.haslayer(TCP):
        transport = packet[TCP]
        protocol = "TCP"
    elif packet.haslayer(UDP):
        transport = packet[UDP]
        protocol = "UDP"
    else:
        return None

    return (
        str(network.src),
        str(network.dst),
        int(transport.sport),
        int(transport.dport),
        protocol,
        max(len(network), 0),
    )


def _flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> tuple:
    endpoint_a = (src_ip, src_port)
    endpoint_b = (dst_ip, dst_port)
    first, second = sorted((endpoint_a, endpoint_b))
    return protocol, first, second


def extract_flows(
    pcap_path: str | Path,
    *,
    idle_timeout_seconds: float = FLOW_IDLE_TIMEOUT_SECONDS,
    max_packets: int = MAX_PACKETS,
    max_flows: int = MAX_FLOWS,
) -> dict[str, Any]:
    """Read a PCAP/PCAPNG and produce six-feature bidirectional flow records.

    A flow is split when the same bidirectional 5-tuple is idle longer than
    ``idle_timeout_seconds``. IPv4/IPv6 TCP and UDP are supported.
    """
    active: dict[tuple, FlowAccumulator] = {}
    records: list[dict[str, Any]] = []
    packets_seen = 0
    packets_used = 0

    reader = PcapReader(str(pcap_path))
    try:
        for packet in reader:
            packets_seen += 1
            if packets_seen > max_packets:
                raise ValueError(
                    f"Capture exceeds the configured packet limit ({max_packets:,})."
                )

            parsed = _packet_endpoints(packet)
            if parsed is None:
                continue

            src_ip, dst_ip, src_port, dst_port, protocol, packet_bytes = parsed
            try:
                timestamp = float(packet.time)
            except (TypeError, ValueError, OverflowError):
                continue

            if packet_bytes <= 0:
                continue

            key = _flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
            current = active.get(key)

            if current is not None and timestamp - current.last_seen > idle_timeout_seconds:
                records.append(current.to_record(len(records) + 1))
                del active[key]
                current = None

            if current is None:
                current = FlowAccumulator(
                    protocol=protocol,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
                active[key] = current

            current.add(timestamp, packet_bytes)
            packets_used += 1

            if len(active) + len(records) > max_flows:
                raise ValueError(
                    f"Capture exceeds the configured flow limit ({max_flows:,})."
                )
    finally:
        reader.close()

    for flow in active.values():
        records.append(flow.to_record(len(records) + 1))

    return {
        "flows": records,
        "packets_seen": packets_seen,
        "packets_used": packets_used,
        "packets_ignored": packets_seen - packets_used,
    }
