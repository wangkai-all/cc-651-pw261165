"""Helpers for synthesizing deterministic HTTP/1.x-over-TCP PCAPs.

The samples are built from raw IP/TCP segments with Scapy so we can freely
control sequence numbers, retransmissions, overlap conflicts, missing
segments and FIN placement -- conditions that are difficult to capture on a
real socket on demand.  Checksums do not matter for offline analysis and are
left at Scapy's defaults.
"""

from __future__ import annotations

import os
from scapy.all import IP, TCP, PacketList, wrpcap

CLIENT = "10.0.0.10"
SERVER = "10.0.0.20"
C_PORT = 44000
S_PORT = 80


class CaptureBuilder:
    def __init__(self, client_isn: int = 1000, server_isn: int = 5000):
        self.packets = PacketList()
        self.c_isn = client_isn
        self.s_isn = server_isn
        # Next sequence number for data (SYN consumes one).
        self.c_seq = client_isn + 1
        self.s_seq = server_isn + 1
        self.c_ack = server_isn + 1
        self.s_ack = client_isn + 1
        self.frame = 0

    def _emit(self, src, dst, sport, dport, seq, ack, flags, payload=b""):
        self.frame += 1
        pkt = (
            IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
            / payload
        )
        pkt.time = 1_700_000_000 + self.frame * 0.01
        self.packets.append(pkt)
        return pkt

    # -- handshake ----------------------------------------------------- #
    def handshake(self):
        self._emit(CLIENT, SERVER, C_PORT, S_PORT, self.c_isn, 0, "S")
        self._emit(SERVER, CLIENT, S_PORT, C_PORT, self.s_isn, self.c_isn + 1, "SA")
        self._emit(CLIENT, SERVER, C_PORT, S_PORT, self.c_isn + 1, self.s_isn + 1, "A")

    def teardown(self):
        self._emit(CLIENT, SERVER, C_PORT, S_PORT, self.c_seq, self.s_seq, "FA")
        self._emit(SERVER, CLIENT, S_PORT, C_PORT, self.s_seq, self.c_seq + 1, "FA")
        self._emit(CLIENT, SERVER, C_PORT, S_PORT, self.c_seq + 1, self.s_seq + 1, "A")

    # -- data ---------------------------------------------------------- #
    def client(self, data: bytes, flags: str = "PA", seq: int | None = None):
        use_seq = self.c_seq if seq is None else seq
        self._emit(CLIENT, SERVER, C_PORT, S_PORT, use_seq, self.s_seq, flags, data)
        if seq is None:
            self.c_seq += len(data)
            self.s_ack = self.c_seq
        return use_seq

    def server(self, data: bytes, flags: str = "PA", seq: int | None = None):
        use_seq = self.s_seq if seq is None else seq
        self._emit(SERVER, CLIENT, S_PORT, C_PORT, use_seq, self.c_seq, flags, data)
        if seq is None:
            self.s_seq += len(data)
            self.c_ack = self.s_seq
        return use_seq

    def client_raw(self, seq: int, data: bytes, flags: str = "PA"):
        """Emit with an explicit sequence and do NOT advance the cursor."""
        return self._emit(
            CLIENT, SERVER, C_PORT, S_PORT, seq, self.s_seq, flags, data
        )

    def server_raw(self, seq: int, data: bytes, flags: str = "PA"):
        return self._emit(
            SERVER, CLIENT, S_PORT, C_PORT, seq, self.c_seq, flags, data
        )

    def write(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        wrpcap(path, self.packets)


def http_request(
    method: str = "GET",
    target: str = "/",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    version: str = "HTTP/1.1",
) -> bytes:
    lines = [f"{method} {target} {version}"]
    hdrs = {"Host": "example.test", "User-Agent": "pcap-station/1.0"}
    if headers:
        hdrs.update(headers)
    if body and "Content-Length" not in hdrs:
        hdrs["Content-Length"] = str(len(body))
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode("latin-1") + body


def http_response(
    status: str = "200",
    reason: str = "OK",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    version: str = "HTTP/1.1",
    include_cl: bool = True,
) -> bytes:
    lines = [f"{version} {status} {reason}"]
    hdrs = {"Server": "pcap-station/1.0", "Connection": "keep-alive"}
    if headers:
        hdrs.update(headers)
    if include_cl and body and "Content-Length" not in hdrs and \
            "Transfer-Encoding" not in hdrs:
        hdrs["Content-Length"] = str(len(body))
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode("latin-1") + body


def chunked_response(chunks: list[bytes], trailers: dict[str, str] | None = None,
                     extra_headers: dict[str, str] | None = None) -> bytes:
    hdrs = {
        "Server": "pcap-station/1.0",
        "Content-Type": "text/plain",
        "Transfer-Encoding": "chunked",
        "Connection": "keep-alive",
    }
    if extra_headers:
        hdrs.update(extra_headers)
    lines = ["HTTP/1.1 200 OK"] + [f"{k}: {v}" for k, v in hdrs.items()]
    out = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    for chunk in chunks:
        out += f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n"
    out += b"0\r\n"
    if trailers:
        for k, v in trailers.items():
            out += f"{k}: {v}\r\n".encode("latin-1")
    out += b"\r\n"
    return out
