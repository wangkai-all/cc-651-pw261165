"""Unit tests for the HTTP/1.x parser's boundary and gap semantics."""

import gzip

from app.core.http_parser import parse_direction
from app.core.reassembly import DirectionStream
from app.core.stream_view import StreamView


def _feed(direction, chunks, syn=True, isn=1000):
    """Build a stream from (seq, payload) chunks and parse it."""
    st = DirectionStream(direction)
    if syn:
        st.add_syn(isn)
    for i, (seq, payload) in enumerate(chunks):
        st.add_segment(seq, payload, i, i + 1)
    st.finalize()
    view = StreamView(st)
    return st, parse_direction(view, direction)


# ---------------------------------------------------------------------- #
# Message boundaries
# ---------------------------------------------------------------------- #
def test_content_length_determines_body_boundary():
    req = (
        b"POST /up HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"
        b"GET /next HTTP/1.1\r\n\r\n"
    )
    st, (msgs, errors) = _feed("c2s", [(1001, req)])
    assert errors == []
    assert len(msgs) == 2
    assert msgs[0].body_bytes == b"hello"
    assert msgs[0].framing == "content-length"
    assert msgs[1].method == "GET" and msgs[1].has_body is False


def test_keepalive_multiple_responses_are_split():
    body1 = b"one"
    body2 = b"two"
    raw = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n" + body1
        + b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n" + body2
    )
    _, (msgs, errors) = _feed("s2c", [(1001, raw)])
    assert errors == []
    assert [m.body_bytes for m in msgs] == [b"one", b"two"]


def test_no_body_status_codes_have_no_body():
    raw = (
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
        b"HTTP/1.1 304 Not Modified\r\n\r\n"
    )
    _, (msgs, _) = _feed("s2c", [(1001, raw)])
    assert len(msgs) == 2
    assert all(not m.has_body for m in msgs)
    assert msgs[0].framing == "none"


def test_head_response_skips_advertised_body():
    # Headers claim a length but, because the request was HEAD, no body bytes
    # follow and the next message must still parse.
    raw = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    )
    st = DirectionStream("s2c")
    st.add_syn(1000)
    st.add_segment(1001, raw, 0, 1)
    view = StreamView(st)
    msgs, errors = parse_direction(view, "s2c", request_methods=["HEAD", "GET"])
    assert errors == []
    assert msgs[0].has_body is False
    assert msgs[1].body_bytes == b"hi"


def test_close_delimited_body_runs_to_fin():
    raw = b"HTTP/1.0 200 OK\r\n\r\nstream-until-close"
    st = DirectionStream("s2c")
    st.add_syn(1000)
    st.add_segment(1001, raw, 0, 1)
    st.add_fin(1001 + len(raw), 0)
    view = StreamView(st)
    msgs, errors = parse_direction(view, "s2c")
    assert errors == []
    assert msgs[0].framing == "close"
    assert msgs[0].complete is True
    assert msgs[0].body_bytes == b"stream-until-close"


def test_close_delimited_without_fin_is_incomplete():
    raw = b"HTTP/1.0 200 OK\r\n\r\npartial"
    st = DirectionStream("s2c")
    st.add_syn(1000)
    st.add_segment(1001, raw, 0, 1)  # no FIN
    view = StreamView(st)
    msgs, _ = parse_direction(view, "s2c")
    assert msgs[0].complete is False
    assert msgs[0].gap is True


# ---------------------------------------------------------------------- #
# Chunked transfer encoding
# ---------------------------------------------------------------------- #
def test_chunked_body_is_decoded_and_framed():
    raw = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n"
        b"6\r\n world\r\n"
        b"0\r\nX-Trailer: yes\r\n\r\n"
    )
    _, (msgs, errors) = _feed("s2c", [(1001, raw)])
    assert errors == []
    msg = msgs[0]
    assert msg.framing == "chunked"
    assert msg.body_bytes == b"hello world"
    assert len(msg.chunks) == 2


def test_gap_inside_chunk_aborts_message():
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    st = DirectionStream("s2c")
    st.add_syn(1000)
    # Chunk header promises 16 bytes but only 4 are present.
    prefix = head + b"10\r\n" + b"A" * 4
    st.add_segment(1001, prefix, 0, 1)
    # FIN declares more data than the captured bytes, making the hole real.
    st.add_fin(1001 + len(prefix) + 12, 0)
    view = StreamView(st)
    msgs, errors = parse_direction(view, "s2c")
    assert len(msgs) == 1
    assert msgs[0].complete is False
    assert msgs[0].gap is True
    assert msgs[0].gap_info.get("declared_chunk_size") == 16
    # No second message is invented from trailing bytes.
    assert any("gap" in e for e in errors)


def test_gap_after_content_length_does_not_create_new_message():
    head = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n"
    st = DirectionStream("s2c")
    st.add_syn(1000)
    st.add_segment(1001, head + b"abcde", 0, 1)   # only 5 of 20 body bytes
    # A later, disconnected fragment that superficially looks like a request.
    st.add_segment(1001 + len(head) + 20, b"GET /evil HTTP/1.1\r\n\r\n", 1, 2)
    view = StreamView(st)
    msgs, errors = parse_direction(view, "s2c")
    assert len(msgs) == 1
    assert msgs[0].complete is False
    assert msgs[0].body_bytes == b"abcde"
    assert errors  # the gap is surfaced


# ---------------------------------------------------------------------- #
# Content encoding
# ---------------------------------------------------------------------- #
def test_gzip_body_is_decompressed():
    payload = b'{"ok": true, "n": 42}'
    encoded = gzip.compress(payload)
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Encoding: gzip\r\n"
        + f"Content-Length: {len(encoded)}\r\n\r\n".encode()
        + encoded
    )
    _, (msgs, _) = _feed("s2c", [(1001, raw)])
    assert msgs[0].decoded_bytes == payload
    assert msgs[0].decode_error == ""


def test_corrupt_gzip_is_flagged_not_crashed():
    raw = (
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
        b"Content-Length: 4\r\n\r\nNOTG"
    )
    _, (msgs, _) = _feed("s2c", [(1001, raw)])
    assert msgs[0].decoded_bytes is None
    assert msgs[0].decode_error != ""


# ---------------------------------------------------------------------- #
# Conflicts surfaced on messages
# ---------------------------------------------------------------------- #
def test_conflict_in_header_region_is_classified():
    st = DirectionStream("s2c")
    st.add_syn(1000)
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    st.add_segment(1001, raw, 0, 1)
    # Overlap the status line byte with a conflicting value.
    st.add_segment(1001, b"X", 1, 2)
    st.finalize()
    view = StreamView(st)
    msgs, _ = parse_direction(view, "s2c")
    assert msgs[0].conflict_impact == "header"
    assert msgs[0].conflicts
