"""HTTP/1.x message parser over gap-aware reassembled TCP streams.

Message boundaries are determined strictly from the protocol:

* ``Content-Length`` -- exactly that many body bytes;
* ``Transfer-Encoding: chunked`` -- the chunk framing determines the end,
  and a gap inside a chunk aborts the message instead of being skipped;
* neither present -- the body runs until connection close (requests without
  a defined body length have no body);
* responses to HEAD, and 1xx/204/304 responses, have no body by definition.

When a gap is hit the current message is returned with ``complete=False`` and
parsing of that direction stops: bytes past the hole are *not* reinterpreted
as a fresh message.  Overlap conflicts lying inside a message are reported on
the message with an impact assessment.
"""

from __future__ import annotations

import gzip
import zlib
from dataclasses import dataclass, field

from .stream_view import MissingDataError, ProtocolError, StreamView

NO_BODY_RESPONSE_STATUSES = {204, 304}
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}


@dataclass
class ChunkInfo:
    index: int
    start: int               # monotonic coordinate of chunk-size line
    data_start: int
    data_end: int
    size: int
    sources: list[dict] = field(default_factory=list)


@dataclass
class HttpMessage:
    direction: str                       # "c2s" (request) | "s2c" (response)
    index: int                           # 0-based within direction
    start_mono: int
    end_mono: int | None                 # None when truncated at a gap
    start_line: str
    headers: list[tuple[str, str]]
    header_bytes: bytes
    body_bytes: bytes                    # reassembled (still-encoded) body
    body_start_mono: int | None
    framing: str                         # "content-length" | "chunked" | "close" | "none"
    complete: bool
    has_body: bool
    gap: bool
    gap_info: dict | None
    status: str = ""                     # response status code, e.g. "200"
    method: str = ""
    target: str = ""
    encoding: str = "identity"           # content-encoding applied to the body
    transfer_encoding: str = ""
    decoded_bytes: bytes | None = None   # after gzip/deflate, when applicable
    decode_error: str = ""
    chunks: list[ChunkInfo] = field(default_factory=list)
    conflicts: list[dict] = field(default_factory=list)
    conflict_impact: str = "none"        # none | header | body | framing
    sources: list[dict] = field(default_factory=list)
    source_packet_indices: list[int] = field(default_factory=list)
    raw_wire_len: int = 0                # sum of TCP payload bytes of source pkts
    reassembled_len: int = 0             # header + body bytes in the stream
    decoded_len: int = 0
    parse_note: str = ""

    # Header helpers --------------------------------------------------- #
    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def all_headers(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def is_response(self) -> bool:
        return self.direction == "s2c"

    @property
    def display_title(self) -> str:
        if self.is_response:
            return f"HTTP {self.status}"
        return f"{self.method} {self.target}"


# ---------------------------------------------------------------------- #
# Parsing
# ---------------------------------------------------------------------- #
def parse_direction(
    view: StreamView,
    direction: str,
    request_methods: list[str] | None = None,
) -> tuple[list[HttpMessage], list[str]]:
    """Parse every HTTP message readable in one direction.

    Stops at the first permanent gap or protocol error and reports it.
    ``request_methods`` (used for the response direction) is the ordered list
    of request methods in this session, so HEAD responses can skip the body
    that their headers appear to advertise.
    """
    request_methods = request_methods or []
    messages: list[HttpMessage] = []
    errors: list[str] = []
    idx = 0
    while True:
        # Nothing (new) waiting at all?
        if view.remaining_contiguous() == 0:
            break
        head_response = (
            direction == "s2c"
            and idx < len(request_methods)
            and request_methods[idx] == "HEAD"
        )
        try:
            msg = _parse_one(view, direction, idx, head_response)
        except MissingDataError as exc:
            # The gap hit before a complete message could be built.  Emit a
            # partial placeholder carrying whatever contiguous prefix exists,
            # so the UI can show the truncated headers instead of nothing.
            partial = _partial_message(view, direction, idx, exc)
            if partial is not None:
                messages.append(partial)
            errors.append(
                f"message #{idx} incomplete: {exc}; bytes after the gap were "
                "not parsed into further messages"
            )
            break
        except ProtocolError as exc:
            errors.append(f"message #{idx} parse error: {exc}")
            break
        messages.append(msg)
        if not msg.complete:
            errors.append(
                f"message #{idx} truncated by a gap; remaining bytes were not "
                "interpreted as a new message"
            )
            break
        idx += 1
    return messages, errors


def _partial_message(
    view: StreamView, direction: str, index: int, exc: MissingDataError
) -> HttpMessage | None:
    start_mono = view.pos
    available = view.remaining_contiguous()
    if available == 0:
        return None
    prefix = bytes(view.stream.slice(start_mono, start_mono + available))
    view.pos = start_mono + available
    first_line = prefix.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    msg = HttpMessage(
        direction=direction,
        index=index,
        start_mono=start_mono,
        end_mono=view.pos,
        start_line=first_line,
        headers=[],
        header_bytes=prefix,
        body_bytes=b"",
        body_start_mono=None,
        framing="unknown",
        complete=False,
        has_body=False,
        gap=True,
        gap_info={
            "stage": "before message boundary could be established",
            "available": exc.available,
            "gap_at_mono": exc.gap_at,
        },
    )
    return msg


def _parse_one(
    view: StreamView,
    direction: str,
    index: int,
    head_response: bool = False,
) -> HttpMessage:
    start_mono = view.pos
    start_line_raw = view.read_line()
    start_line = _decode_text(start_line_raw)
    if not start_line:
        # Tolerate a single leading CRLF between messages; anything else is
        # an error.
        if view.remaining_contiguous() == 0:
            raise MissingDataError(1, 0, view.next_gap_start())
        raise ProtocolError("empty start line")

    method = status = target = ""
    is_response = direction == "s2c"
    if is_response:
        parts = start_line.split(" ", 2)
        if len(parts) < 2 or not parts[0].startswith("HTTP/"):
            raise ProtocolError(f"invalid status line: {start_line!r}")
        status = parts[1]
    else:
        parts = start_line.split(" ", 2)
        if len(parts) < 3:
            raise ProtocolError(f"invalid request line: {start_line!r}")
        method, target = parts[0], parts[1]

    # Headers ---------------------------------------------------------- #
    headers: list[tuple[str, str]] = []
    while True:
        line = view.read_line()
        if line == b"":
            break
        # Obsolete line folding (obs-fold): fold onto previous header.
        if line[:1] in (b" ", b"\t") and headers:
            k, v = headers[-1]
            headers[-1] = (k, v + " " + _decode_text(line).strip())
            continue
        text = _decode_text(line)
        if ":" not in text:
            raise ProtocolError(f"malformed header line: {text!r}")
        k, v = text.split(":", 1)
        headers.append((k.strip(), v.strip()))

    header_end = view.pos
    header_bytes = bytes(view.stream.slice(start_mono, header_end))

    msg = HttpMessage(
        direction=direction,
        index=index,
        start_mono=start_mono,
        end_mono=None,
        start_line=start_line,
        headers=headers,
        header_bytes=header_bytes,
        body_bytes=b"",
        body_start_mono=None,
        framing="none",
        complete=False,
        has_body=False,
        gap=False,
        gap_info=None,
        status=status,
        method=method,
        target=target,
    )

    _apply_body(view, msg, head_response)
    _annotate_conflicts(view, msg)
    _annotate_provenance(view, msg)
    _decode_body(msg)
    return msg


# ---------------------------------------------------------------------- #
# Body framing
# ---------------------------------------------------------------------- #
def _apply_body(view: StreamView, msg: HttpMessage, head_response: bool) -> None:
    te = _first_header(msg, "transfer-encoding")
    ce = _first_header(msg, "content-encoding")
    msg.transfer_encoding = te
    msg.encoding = ce or "identity"

    # Response statuses without a body.
    if msg.is_response and msg.status and (
        msg.status.startswith("1") or int(msg.status) in NO_BODY_RESPONSE_STATUSES
    ):
        msg.framing = "none"
        msg.has_body = False
        msg.complete = True
        msg.end_mono = view.pos
        return

    # HEAD responses advertise a length but carry no body on the wire.
    if head_response:
        msg.framing = "none"
        msg.complete = True
        msg.end_mono = view.pos
        return

    if te and "chunked" in te.lower():
        msg.framing = "chunked"
        _read_chunked(view, msg)
        return

    cl_values = msg.all_headers("content-length")
    if cl_values:
        # Duplicate conflicting Content-Length values are a protocol error;
        # identical duplicates are tolerated (common with some proxies).
        distinct = {v.strip() for v in cl_values}
        if len(distinct) > 1:
            raise ProtocolError(f"conflicting Content-Length values: {cl_values}")
        try:
            length = int(next(iter(distinct)))
        except ValueError as exc:
            raise ProtocolError(f"invalid Content-Length: {cl_values}") from exc
        msg.framing = "content-length"
        msg.body_start_mono = view.pos
        msg.has_body = True
        try:
            msg.body_bytes = view.read(length)
        except MissingDataError as exc:
            msg.gap = True
            msg.gap_info = {
                "declared_length": length,
                "available": exc.available,
                "gap_at_mono": exc.gap_at,
            }
            # Keep the partial prefix as evidence, cursor stays at contig end.
            msg.body_bytes = bytes(
                view.stream.slice(view.pos, view.pos + exc.available)
            )
            view.pos += exc.available
            msg.end_mono = view.pos
            msg.complete = False
            return
        # read() already advanced the cursor.
        msg.complete = True
        msg.end_mono = view.pos
        return

    # No explicit length.
    if msg.is_response:
        keepalive = _is_keepalive(msg)
        # Body until connection close.  The stream may end at FIN (complete),
        # at a gap (incomplete -- the bytes behind the hole stay unparsed), or
        # simply because the capture stopped without a FIN.
        if not keepalive:
            msg.framing = "close"
            msg.has_body = True
            msg.body_start_mono = view.pos
            available = view.remaining_contiguous()
            msg.body_bytes = view.read(available)
            msg.end_mono = view.pos
            finished = (
                view.stream.fin_seen
                and view.stream.expected_end is not None
                and view.pos >= view.stream.expected_end
            )
            msg.complete = bool(finished)
            if not finished:
                msg.gap = True
                msg.gap_info = {
                    "reason": "close-delimited body but FIN not observed",
                    "gap_at_mono": view.next_gap_start(),
                    "fin_seen": view.stream.fin_seen,
                }
            return
        # Keep-alive response without length: cannot locate the boundary.
        msg.framing = "none"
        msg.parse_note = "response without Content-Length on keep-alive connection"
        msg.complete = True
        msg.end_mono = view.pos
        return

    # Requests without Content-Length/Transfer-Encoding have no defined body
    # (e.g. GET).  A POST with no length is treated as no body but noted.
    msg.framing = "none"
    if msg.method in {"POST", "PUT", "PATCH"}:
        msg.parse_note = "request with body semantics but no Content-Length"
    msg.complete = True
    msg.end_mono = view.pos


def _read_chunked(view: StreamView, msg: HttpMessage) -> None:
    msg.has_body = True
    msg.body_start_mono = view.pos
    body = bytearray()
    chunk_index = 0
    while True:
        chunk_line_start = view.pos
        size_line = view.read_line()
        # Chunk extensions after ';' are ignored for sizing.
        size_token = size_line.split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_token, 16)
        except ValueError as exc:
            raise ProtocolError(f"invalid chunk size: {size_line!r}") from exc

        if chunk_size == 0:
            # Trailer section until blank line.
            while True:
                trailer = view.read_line()
                if trailer == b"":
                    break
            msg.complete = True
            msg.body_bytes = bytes(body)
            msg.end_mono = view.pos
            return

        data_start = view.pos
        try:
            chunk_data = view.read(chunk_size)
        except MissingDataError as exc:
            # Gap inside a chunk: the message is truncated.  We must not scan
            # ahead for another chunk marker -- the missing bytes could have
            # contained anything.
            msg.gap = True
            msg.gap_info = {
                "chunk_index": chunk_index,
                "declared_chunk_size": chunk_size,
                "available": exc.available,
                "gap_at_mono": exc.gap_at,
            }
            partial = bytes(view.stream.slice(view.pos, view.pos + exc.available))
            body += partial
            view.pos += exc.available
            msg.body_bytes = bytes(body)
            msg.end_mono = view.pos
            msg.complete = False
            return
        data_end = view.pos
        body += chunk_data
        # Every chunk is followed by CRLF.
        crlf = view.read(2)
        if crlf != b"\r\n":
            raise ProtocolError("missing CRLF after chunk data")
        msg.chunks.append(
            ChunkInfo(
                index=chunk_index,
                start=chunk_line_start,
                data_start=data_start,
                data_end=data_end,
                size=chunk_size,
                sources=[
                    _source_dict(s)
                    for s in view.sources_for(data_start, data_end)
                ],
            )
        )
        chunk_index += 1


# ---------------------------------------------------------------------- #
# Decoding, conflicts, provenance
# ---------------------------------------------------------------------- #
def _decode_body(msg: HttpMessage) -> None:
    if not msg.has_body or not msg.body_bytes:
        msg.decoded_bytes = msg.body_bytes if msg.has_body else b""
        msg.decoded_len = len(msg.decoded_bytes or b"")
        return
    ce = (msg.encoding or "").lower()
    try:
        if "gzip" in ce:
            msg.decoded_bytes = gzip.decompress(msg.body_bytes)
        elif "deflate" in ce:
            try:
                msg.decoded_bytes = zlib.decompress(msg.body_bytes)
            except zlib.error:
                # Raw deflate (no zlib wrapper), which some servers emit.
                msg.decoded_bytes = zlib.decompress(msg.body_bytes, -15)
        else:
            msg.decoded_bytes = msg.body_bytes
    except (OSError, zlib.error, EOFError) as exc:
        msg.decode_error = f"{type(exc).__name__}: {exc}"
        msg.decoded_bytes = None
    msg.decoded_len = len(msg.decoded_bytes) if msg.decoded_bytes is not None else 0


def _annotate_conflicts(view: StreamView, msg: HttpMessage) -> None:
    end = msg.end_mono if msg.end_mono is not None else view.pos
    conflicts = view.conflicts_in(msg.start_mono, end)
    if not conflicts:
        msg.conflict_impact = "none"
        return
    worst = "body"
    for c in conflicts:
        in_header = c.start < (msg.body_start_mono or end)
        in_framing = msg.framing == "chunked" and _in_chunk_control(msg, c.start)
        if in_header:
            worst = "header"
        elif in_framing and worst != "header":
            worst = "framing"
        msg.conflicts.append(
            {
                "start": c.start,
                "end": c.end,
                "existing_hex": c.existing_bytes.hex(),
                "existing_text": _safe_text(c.existing_bytes),
                "alternative_hex": c.alternative_bytes.hex(),
                "alternative_text": _safe_text(c.alternative_bytes),
                "existing_sources": [_source_dict(s) for s in c.existing_sources],
                "alternative_sources": [_source_dict(s) for s in c.alternative_sources],
            }
        )
    msg.conflict_impact = worst


def _in_chunk_control(msg: HttpMessage, mono: int) -> bool:
    for ch in msg.chunks:
        if ch.start <= mono < ch.data_start:
            return True
    return False


def _annotate_provenance(view: StreamView, msg: HttpMessage) -> None:
    end = msg.end_mono if msg.end_mono is not None else view.pos
    sources = view.sources_for(msg.start_mono, end)
    msg.sources = [_source_dict(s) for s in sources]
    # The analyzer resolves these indices against the packet table to sum the
    # real on-wire payload lengths (counting retransmissions).
    msg.source_packet_indices = sorted({s.packet_index for s in sources})
    msg.reassembled_len = end - msg.start_mono


def _source_dict(source) -> dict:
    return {
        "packet_index": source.packet_index,
        "frame_number": source.frame_number,
        "seq": source.seq,
        "mono_start": source.mono_start,
    }


def _first_header(msg: HttpMessage, name: str) -> str:
    value = msg.header(name)
    return value or ""


def _is_keepalive(msg: HttpMessage) -> bool:
    """Whether the message's connection is meant to stay open.

    An explicit ``Connection`` header always wins; otherwise HTTP/1.1
    defaults to keep-alive and HTTP/1.0 (or anything older) defaults to close.
    """
    connection = (msg.header("connection") or "").lower()
    tokens = {t.strip() for t in connection.split(",") if t.strip()}
    if "close" in tokens:
        return False
    if "keep-alive" in tokens:
        return True
    version = msg.start_line.split(" ", 1)[0].upper()
    return version == "HTTP/1.1"


def _decode_text(data: bytes) -> str:
    # Header fields are defined as octets; latin-1 never fails and preserves
    # every byte for later charset interpretation.
    return data.decode("latin-1")


def _safe_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")
