"""End-to-end PCAP analysis orchestration.

Pipeline:

1. Read every packet with Scapy and extract IP/TCP metadata + payloads.
2. Demultiplex into :class:`Session` instances keyed by the canonical
   5-tuple; a new SYN on an existing 5-tuple opens a new instance so repeated
   connections stay separate.
3. Feed payloads into the per-direction reassembly engines (wrap-around,
   reordering, duplicates, overlap conflicts all handled there).
4. Detect TLS by content type (never attempted to be decrypted) and parse
   everything else as HTTP/1.x over the gap-aware stream views.
5. Pair requests with responses in order and compute length statistics.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from scapy.all import IP, IPv6, PcapReader, TCP

from .http_parser import HttpMessage, parse_direction
from .models import PacketRecord, Session
from .reassembly import data_offset_of
from .stream_view import StreamView

logger = logging.getLogger("pcap_station")

# First byte of a TLS record content type (handshake=22) and the second byte
# of the TLS record version (0x03) -- plaintext HTTP never starts this way.
_TLS_HINTS = {20, 21, 22, 23}


@dataclass
class AnalysisResult:
    capture_id: str
    file_name: str
    packet_count: int
    tcp_packet_count: int
    sessions: list[Session] = field(default_factory=list)
    messages: dict[str, list[HttpMessage]] = field(default_factory=dict)
    # session_id -> list of (request_index, response_index_or_None)
    pairs: dict[str, list[tuple[int | None, int | None]]] = field(default_factory=dict)
    parse_errors: dict[str, list[str]] = field(default_factory=dict)
    stats: dict = field(default_factory=dict)
    packets: dict[str, list[PacketRecord]] = field(default_factory=dict)


def analyze_pcap(path: str, capture_id: str, file_name: str) -> AnalysisResult:
    result = AnalysisResult(
        capture_id=capture_id,
        file_name=file_name,
        packet_count=0,
        tcp_packet_count=0,
    )

    # 5-tuple (canonical, endpoint-agnostic) -> list of Session instances.
    sessions_by_tuple: dict[tuple, list[Session]] = {}
    # Active session lookup keyed by direction-aware tuple.
    active: dict[tuple, Session] = {}
    instance_counter: dict[tuple, int] = {}

    with PcapReader(path) as reader:
        for pkt_index, pkt in enumerate(reader):
            result.packet_count += 1
            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            tcp = pkt.getlayer(TCP)
            if ip_layer is None or tcp is None:
                continue
            result.tcp_packet_count += 1

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            sport, dport = int(tcp.sport), int(tcp.dport)
            flags = str(tcp.flags)
            payload = bytes(tcp.payload) if tcp.payload else b""
            ip_total = getattr(ip_layer, "len", 0) or 0

            canon = tuple(sorted(((src_ip, sport), (dst_ip, dport))))
            key_fwd = (src_ip, sport, dst_ip, dport)
            key_rev = (dst_ip, dport, src_ip, sport)

            is_syn = "S" in flags and "A" not in flags
            tuple_known = key_fwd in active or key_rev in active
            # A fresh SYN on a 5-tuple that already has a live instance means
            # the connection was reopened: the old instance is retired first
            # so the two conversations never share reassembly state.
            if is_syn and tuple_known:
                old = active.pop(key_fwd, None) or active.pop(key_rev, None)
                active.pop(key_rev, None)
                if old is not None:
                    logger.debug("retiring session %s on reconnect SYN", old.session_id)
                tuple_known = False

            if not tuple_known:
                # First packet for this 5-tuple: a fresh SYN opens the
                # connection; a mid-capture pickup (no SYN seen) also starts a
                # new instance rather than being merged with anything.
                instance = instance_counter.get(canon, 0)
                instance_counter[canon] = instance + 1
                session = Session(
                    session_id=f"{capture_id}-s{len(result.sessions)}",
                    instance=instance,
                    src_ip=src_ip,
                    src_port=sport,
                    dst_ip=dst_ip,
                    dst_port=dport,
                )
                result.sessions.append(session)
                sessions_by_tuple.setdefault(canon, []).append(session)
                active[key_fwd] = session
                active[key_rev] = session
                if session.start_time is None:
                    session.start_time = float(pkt.time)

            # Direction is decided by the endpoint that initiated the
            # session: its -> dst packets are client-to-server, regardless of
            # TCP flags (so pure ACKs and FINs route correctly).
            if key_fwd in active and active[key_fwd] is active.get(key_rev):
                session = active[key_fwd]
                direction = (
                    "c2s"
                    if (src_ip, sport) == (session.src_ip, session.src_port)
                    else "s2c"
                )
            else:
                session = active[key_fwd]
                direction = "c2s"
            stream = session.stream(direction)

            if "S" in flags:
                stream.add_syn(int(tcp.seq))
            if payload:
                stream.add_segment(
                    raw_seq=int(tcp.seq),
                    payload=payload,
                    packet_index=pkt_index,
                    frame_number=result.packet_count,
                )
            if "F" in flags:
                stream.add_fin(int(tcp.seq), len(payload))

            record = PacketRecord(
                index=pkt_index,
                frame_number=result.packet_count,
                timestamp=float(pkt.time),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sport,
                dst_port=dport,
                flags=flags,
                seq=int(tcp.seq),
                ack=int(tcp.ack),
                raw_len=len(payload),
                ip_total_len=ip_total,
                direction=direction,
                payload=payload,
            )
            session.packets.append(record)
            session.end_time = float(pkt.time)

    _post_process(result)
    return result


# ---------------------------------------------------------------------- #
def _post_process(result: AnalysisResult) -> None:
    total_wire = 0
    total_reassembled = 0
    total_decoded = 0

    for session in result.sessions:
        session.c2s.finalize()
        session.s2c.finalize()
        result.packets[session.session_id] = session.packets

        _detect_tls(session)
        if session.is_tls or not session.packets:
            result.messages[session.session_id] = []
            result.pairs[session.session_id] = []
            result.parse_errors[session.session_id] = []
            continue

        c2s_view = StreamView(session.c2s)
        requests, req_errors = parse_direction(c2s_view, "c2s")
        methods = [m.method for m in requests]
        s2c_view = StreamView(session.s2c)
        responses, resp_errors = parse_direction(
            s2c_view, "s2c", request_methods=methods
        )

        _check_http_like(session, requests, responses)
        messages = requests + responses
        messages.sort(key=lambda m: (m.start_mono, 0 if m.direction == "c2s" else 1))
        result.messages[session.session_id] = messages

        _compute_wire_lengths(session, requests + responses)
        _pair_messages(result, session, requests, responses)

        errors = list(req_errors) + list(resp_errors)
        session.parse_errors = errors
        result.parse_errors[session.session_id] = errors

        for msg in requests + responses:
            total_wire += msg.raw_wire_len
            total_reassembled += msg.reassembled_len
            total_decoded += msg.decoded_len

    result.stats = {
        "session_count": len(result.sessions),
        "tls_session_count": sum(1 for s in result.sessions if s.is_tls),
        "non_http_session_count": sum(1 for s in result.sessions if s.non_http),
        "message_count": sum(len(v) for v in result.messages.values()),
        "total_wire_payload_bytes": total_wire,
        "total_reassembled_bytes": total_reassembled,
        "total_decoded_bytes": total_decoded,
        "conflict_count": sum(
            len(s.c2s.conflicts) + len(s.s2c.conflicts) for s in result.sessions
        ),
        "gap_session_count": sum(
            1
            for s in result.sessions
            if s.c2s.gaps() or s.s2c.gaps()
        ),
    }


def _detect_tls(session: Session) -> None:
    """Classify a session as TLS purely from the plaintext record header."""
    stream = session.c2s
    if not stream.blocks or stream.contig_end <= stream.data_origin:
        return
    try:
        first = bytes(stream.slice(stream.data_origin, stream.data_origin + 3))
    except KeyError:
        return
    if len(first) >= 2 and first[0] in _TLS_HINTS and first[1] == 0x03:
        session.is_tls = True
        session.tls_reason = (
            f"first client byte 0x{first[0]:02x} 0x{first[1]:02x} looks like a "
            "TLS record header; encrypted traffic is not decrypted"
        )


def _check_http_like(
    session: Session, requests: list[HttpMessage], responses: list[HttpMessage]
) -> None:
    if not requests and not responses:
        session.non_http = True
        return
    if not requests and responses:
        session.non_http = True
        session.parse_errors.append(
            "server-to-client data parses as HTTP but no client request was found"
        )
    if requests and not responses and not session.s2c.blocks:
        session.parse_errors.append("request(s) present but no response data captured")


def _compute_wire_lengths(session: Session, messages: list[HttpMessage]) -> None:
    by_index = {p.index: p for p in session.packets}
    for msg in messages:
        total = 0
        end = msg.end_mono if msg.end_mono is not None else msg.start_mono
        for idx in msg.source_packet_indices:
            pkt = by_index.get(idx)
            if pkt is None or pkt.raw_len == 0:
                continue
            # Only count the portion of the packet that actually falls inside
            # this message's stream range.  On a keep-alive connection one
            # segment can carry bytes belonging to several messages, and
            # retransmitted/duplicate bytes are counted via provenance rather
            # than by double-summing the same coordinates.
            stream = session.stream(msg.direction)
            mono_start = data_offset_of(
                pkt.seq, stream._anchor_seq, stream._anchor_mono, stream.syn_seen
            )
            mono_end = mono_start + pkt.raw_len
            lo = max(mono_start, msg.start_mono)
            hi = min(mono_end, end)
            if hi > lo:
                total += hi - lo
        msg.raw_wire_len = total


def _pair_messages(
    result: AnalysisResult,
    session: Session,
    requests: list[HttpMessage],
    responses: list[HttpMessage],
) -> None:
    """Pair requests with responses in arrival order.

    Pipelined requests queue up; 1xx interim responses attach to the request
    still in flight.  A response with no request (or vice versa) is paired
    with ``None`` rather than dropped.
    """
    pairs: list[tuple[int | None, int | None]] = []
    req_queue = list(range(len(requests)))
    current_req: int | None = None
    for j, resp in enumerate(responses):
        is_interim = resp.status.startswith("1")
        if current_req is None and req_queue:
            current_req = req_queue.pop(0)
        if is_interim:
            pairs.append((current_req, j))
            continue
        pairs.append((current_req, j))
        current_req = req_queue.pop(0) if req_queue else None
    # Any requests never answered remain visible with a None response.
    leftover = ([current_req] if current_req is not None else []) + req_queue
    for i in leftover:
        pairs.append((i, None))
    result.pairs[session.session_id] = pairs
