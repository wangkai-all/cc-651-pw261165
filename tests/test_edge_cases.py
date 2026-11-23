"""Additional edge-case tests: protocol variants and capture conditions."""

from app.core.http_parser import parse_direction
from app.core.reassembly import DirectionStream
from app.core.stream_view import StreamView


def _parse(raw: bytes, direction: str = "s2c", methods=None, fin: bool = True):
    st = DirectionStream(direction)
    st.add_syn(1000)
    st.add_segment(1001, raw, 0, 1)
    if fin:
        st.add_fin(1001 + len(raw), 0)
    view = StreamView(st)
    return parse_direction(view, direction, request_methods=methods)


def test_http10_default_close_delimited_body():
    # HTTP/1.0 defaults to connection close; no Content-Length needed.
    raw = b"HTTP/1.0 200 OK\r\nServer: old\r\n\r\nlegacy body content"
    msgs, errors = _parse(raw)
    assert errors == []
    assert msgs[0].framing == "close"
    assert msgs[0].body_bytes == b"legacy body content"
    assert msgs[0].complete is True


def test_http10_keepalive_without_length_does_not_invent_body():
    # Explicit keep-alive but no length and no FIN: the body boundary cannot
    # be located, so the parser marks the framing as indeterminate rather than
    # treating the remaining bytes as a (possibly wrong) response body.
    raw = b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\nsome bytes"
    msgs, _ = _parse(raw, fin=False)
    assert msgs[0].framing == "none"
    assert "keep-alive" in msgs[0].parse_note


def test_bare_lf_line_endings_are_tolerated():
    raw = b"HTTP/1.1 200 OK\nContent-Length: 4\n\nbody"
    msgs, errors = _parse(raw)
    assert errors == []
    assert msgs[0].body_bytes == b"body"
    assert msgs[0].header("Content-Length") == "4"


def test_obsolete_header_folding_is_joined():
    raw = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
        b"X-Multi: part1\r\n\tpart2\r\n\r\nhi"
    )
    msgs, _ = _parse(raw)
    assert msgs[0].header("X-Multi") == "part1 part2"


def test_conflicting_duplicate_content_length_is_error():
    raw = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"
        b"Content-Length: 5\r\n\r\nabcd"
    )
    msgs, errors = _parse(raw)
    assert errors
    assert "Content-Length" in errors[0]


def test_request_without_length_has_no_body():
    raw = b"GET / HTTP/1.1\r\nHost: x.test\r\n\r\n"
    msgs, errors = _parse(raw, direction="c2s")
    assert errors == []
    assert msgs[0].has_body is False
    assert msgs[0].method == "GET"


def test_post_with_content_length_reads_exact_body():
    raw = b"POST /up HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"
    msgs, errors = _parse(raw, direction="c2s")
    assert errors == []
    assert msgs[0].body_bytes == b"hello"


def test_interim_1xx_then_final_response():
    raw = (
        b"HTTP/1.1 100 Continue\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    )
    msgs, errors = _parse(raw, methods=["POST"])
    assert errors == []
    assert msgs[0].status == "100" and msgs[0].has_body is False
    assert msgs[1].status == "200" and msgs[1].body_bytes == b"hi"


def test_deflate_wrapper_and_raw_deflate():
    import zlib
    payload = b"deflate payload data"
    wrapped = zlib.compress(payload)
    raw_w = (
        b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\n"
        + f"Content-Length: {len(wrapped)}\r\n\r\n".encode() + wrapped
    )
    msgs, _ = _parse(raw_w)
    assert msgs[0].decoded_bytes == payload

    compressor = zlib.compressobj(wbits=-15)
    raw_deflate = compressor.compress(payload) + compressor.flush()
    raw_r = (
        b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\n"
        + f"Content-Length: {len(raw_deflate)}\r\n\r\n".encode() + raw_deflate
    )
    msgs2, _ = _parse(raw_r)
    assert msgs2[0].decoded_bytes == payload


def test_mid_capture_pickup_without_syn():
    st = DirectionStream("c2s")
    # No add_syn: the capture began after the handshake.
    st.add_segment(7777, b"GET /mid HTTP/1.1\r\nHost: x\r\n\r\n", 0, 1)
    st.add_fin(7777 + len(b"GET /mid HTTP/1.1\r\nHost: x\r\n\r\n"), 0)
    view = StreamView(st)
    msgs, errors = parse_direction(view, "c2s")
    assert errors == []
    assert msgs[0].target == "/mid"
    assert st.gaps() == []
