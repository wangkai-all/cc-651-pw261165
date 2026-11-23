"""Convert analysis dataclasses into JSON-serializable API payloads."""

from __future__ import annotations

import base64

from .analyzer import AnalysisResult
from .http_parser import HttpMessage
from .models import PacketRecord, Session


def _b64(data: bytes | None) -> str | None:
    if data is None:
        return None
    return base64.b64encode(data).decode("ascii")


def packet_brief(pkt: PacketRecord) -> dict:
    return {
        "index": pkt.index,
        "frame_number": pkt.frame_number,
        "timestamp": pkt.timestamp,
        "src": f"{pkt.src_ip}:{pkt.src_port}",
        "dst": f"{pkt.dst_ip}:{pkt.dst_port}",
        "flags": pkt.flags,
        "seq": pkt.seq,
        "ack": pkt.ack,
        "raw_len": pkt.raw_len,
        "ip_total_len": pkt.ip_total_len,
        "direction": pkt.direction,
    }


def packet_detail(pkt: PacketRecord) -> dict:
    brief = packet_brief(pkt)
    brief["payload_hex"] = pkt.payload.hex()
    brief["payload_b64"] = _b64(pkt.payload)
    return brief


def gap_dict(gaps: list[tuple[int, int]], origin: int) -> list[dict]:
    return [
        {"start": s - origin, "end": e - origin, "length": e - s}
        for s, e in gaps
    ]


def session_summary(session: Session, result: AnalysisResult) -> dict:
    messages = result.messages.get(session.session_id, [])
    c2s_gaps = gap_dict(session.c2s.gaps(), session.c2s.data_origin)
    s2c_gaps = gap_dict(session.s2c.gaps(), session.s2c.data_origin)
    complete = all(m.complete for m in messages) if messages else True
    has_gap = bool(c2s_gaps or s2c_gaps)
    return {
        "session_id": session.session_id,
        "instance": session.instance,
        "endpoint": session.endpoint_label,
        "src": f"{session.src_ip}:{session.src_port}",
        "dst": f"{session.dst_ip}:{session.dst_port}",
        "packet_count": len(session.packets),
        "message_count": len(messages),
        "request_count": sum(1 for m in messages if m.direction == "c2s"),
        "response_count": sum(1 for m in messages if m.direction == "s2c"),
        "is_tls": session.is_tls,
        "tls_reason": session.tls_reason,
        "non_http": session.non_http,
        "has_gap": has_gap,
        "complete": complete and not has_gap,
        "conflict_count": len(session.c2s.conflicts) + len(session.s2c.conflicts),
        "gaps": {"c2s": c2s_gaps, "s2c": s2c_gaps},
        "start_time": session.start_time,
        "end_time": session.end_time,
        "parse_errors": session.parse_errors,
    }


def message_dict(
    msg: HttpMessage,
    session: Session,
    include_body: bool = True,
    body_encoding: str = "utf-8",
) -> dict:
    origin = session.stream(msg.direction).data_origin
    payload: dict
    if include_body:
        payload = _body_payload(msg, body_encoding)
    else:
        payload = {"omitted": True}

    return {
        "id": f"{session.session_id}:{msg.direction}:{msg.index}",
        "direction": msg.direction,
        "kind": "request" if msg.direction == "c2s" else "response",
        "index": msg.index,
        "display_title": msg.display_title,
        "start_line": msg.start_line,
        "method": msg.method,
        "target": msg.target,
        "status": msg.status,
        "headers": [{"name": k, "value": v} for k, v in msg.headers],
        "framing": msg.framing,
        "complete": msg.complete,
        "has_body": msg.has_body,
        "gap": msg.gap,
        "gap_info": msg.gap_info,
        "parse_note": msg.parse_note,
        "content_encoding": msg.encoding,
        "transfer_encoding": msg.transfer_encoding,
        "decode_error": msg.decode_error,
        "stream_range": {
            "start": msg.start_mono - origin,
            "end": (msg.end_mono - origin) if msg.end_mono is not None else None,
        },
        "lengths": {
            "raw_wire": msg.raw_wire_len,
            "reassembled": msg.reassembled_len,
            "header": len(msg.header_bytes),
            "body_encoded": len(msg.body_bytes),
            "body_decoded": msg.decoded_len,
        },
        "conflict_impact": msg.conflict_impact,
        "conflicts": msg.conflicts,
        "chunks": [
            {
                "index": c.index,
                "size": c.size,
                "data_start": c.data_start - origin,
                "data_end": c.data_end - origin,
                "sources": c.sources,
            }
            for c in msg.chunks
        ],
        "source_packets": msg.sources,
        "body": payload,
    }


def _body_payload(msg: HttpMessage, encoding: str) -> dict:
    encoded = msg.body_bytes
    decoded = msg.decoded_bytes
    text = None
    decoded_text = None
    try:
        text = encoded.decode(encoding, errors="replace")
    except (LookupError, TypeError):
        text = encoded.decode("latin-1", errors="replace")
    if decoded is not None:
        try:
            decoded_text = decoded.decode(encoding, errors="replace")
        except (LookupError, TypeError):
            decoded_text = decoded.decode("latin-1", errors="replace")
    return {
        "encoded_b64": _b64(encoded),
        "encoded_len": len(encoded),
        "encoded_text": text,
        "decoded_b64": _b64(decoded),
        "decoded_len": len(decoded) if decoded is not None else 0,
        "decoded_text": decoded_text,
        "is_binary": _looks_binary(decoded if decoded is not None else encoded),
    }


def _looks_binary(data: bytes) -> bool:
    if not data:
        return False
    # NUL bytes or a high ratio of non-printable bytes => binary file content.
    if b"\x00" in data[:4096]:
        return True
    sample = data[:4096]
    non_printable = sum(
        1 for b in sample if b < 9 or (13 < b < 32)
    )
    return non_printable / max(len(sample), 1) > 0.30


def stream_layout(session: Session) -> dict:
    return {
        "c2s": {
            "origin": session.c2s.data_origin,
            "contig_end": session.c2s.contig_end - session.c2s.data_origin,
            "expected_end": (
                session.c2s.expected_end - session.c2s.data_origin
                if session.c2s.expected_end is not None
                else None
            ),
            "gaps": gap_dict(session.c2s.gaps(), session.c2s.data_origin),
            "blocks": [
                {
                    **b,
                    "start": b["start"] - session.c2s.data_origin,
                    "end": b["end"] - session.c2s.data_origin,
                }
                for b in session.c2s.block_view()
            ],
            "conflicts": [_conflict_dict(c, session.c2s.data_origin) for c in session.c2s.conflicts],
            "fin_seen": session.c2s.fin_seen,
        },
        "s2c": {
            "origin": session.s2c.data_origin,
            "contig_end": session.s2c.contig_end - session.s2c.data_origin,
            "expected_end": (
                session.s2c.expected_end - session.s2c.data_origin
                if session.s2c.expected_end is not None
                else None
            ),
            "gaps": gap_dict(session.s2c.gaps(), session.s2c.data_origin),
            "blocks": [
                {
                    **b,
                    "start": b["start"] - session.s2c.data_origin,
                    "end": b["end"] - session.s2c.data_origin,
                }
                for b in session.s2c.block_view()
            ],
            "conflicts": [_conflict_dict(c, session.s2c.data_origin) for c in session.s2c.conflicts],
            "fin_seen": session.s2c.fin_seen,
        },
    }


def _conflict_dict(conflict, origin: int) -> dict:
    return {
        "start": conflict.start - origin,
        "end": conflict.end - origin,
        "length": conflict.end - conflict.start,
        "existing_text": _safe(conflict.existing_bytes),
        "alternative_text": _safe(conflict.alternative_bytes),
        "existing_hex": conflict.existing_bytes.hex(),
        "alternative_hex": conflict.alternative_bytes.hex(),
        "existing_sources": [
            {"frame_number": s.frame_number, "seq": s.seq}
            for s in conflict.existing_sources
        ],
        "alternative_sources": [
            {"frame_number": s.frame_number, "seq": s.seq}
            for s in conflict.alternative_sources
        ],
    }


def _safe(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def full_capture_payload(result: AnalysisResult) -> dict:
    sessions = []
    for session in result.sessions:
        sessions.append(
            {
                **session_summary(session, result),
                "pairs": result.pairs.get(session.session_id, []),
                "messages": [
                    message_dict(m, session)
                    for m in result.messages.get(session.session_id, [])
                ],
                "layout": stream_layout(session),
            }
        )
    return {
        "capture_id": result.capture_id,
        "file_name": result.file_name,
        "packet_count": result.packet_count,
        "tcp_packet_count": result.tcp_packet_count,
        "stats": result.stats,
        "sessions": sessions,
    }
