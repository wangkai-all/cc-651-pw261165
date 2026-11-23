"""Data models shared by the analyzer, parser and API layer."""

from __future__ import annotations

from dataclasses import dataclass, field

from .reassembly import DirectionStream


@dataclass
class PacketRecord:
    """One TCP-bearing packet, kept lightweight for provenance lookups."""

    index: int                 # 0-based position in the capture
    frame_number: int          # 1-based display number
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    flags: str                 # e.g. "PA", "S", "FA"
    seq: int
    ack: int
    raw_len: int               # TCP payload length on the wire
    ip_total_len: int          # raw IP total length (wire-length stats)
    direction: str             # "c2s" | "s2c" | "none"
    payload: bytes


@dataclass
class Session:
    """One TCP connection instance.

    A fresh SYN on the same 5-tuple opens a new instance, so reconnects never
    merge into the previous conversation.
    """

    session_id: str
    instance: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    c2s: DirectionStream = field(default_factory=lambda: DirectionStream("c2s"))
    s2c: DirectionStream = field(default_factory=lambda: DirectionStream("s2c"))
    packets: list[PacketRecord] = field(default_factory=list)
    start_time: float | None = None
    end_time: float | None = None
    # Set by the analysis stage:
    is_tls: bool = False
    tls_reason: str = ""
    non_http: bool = False
    parse_errors: list[str] = field(default_factory=list)

    @property
    def five_tuple(self) -> tuple[str, int, str, int, int]:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, 6)

    @property
    def endpoint_label(self) -> str:
        return f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port}"

    def stream(self, direction: str) -> DirectionStream:
        return self.c2s if direction == "c2s" else self.s2c
