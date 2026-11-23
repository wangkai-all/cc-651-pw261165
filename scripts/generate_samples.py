#!/usr/bin/env python3
"""Generate the visualization sample PCAPs under ``samples/``.

Run with the project virtualenv::

    .venv/bin/python scripts/generate_samples.py
"""

from __future__ import annotations

import gzip
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from _pcap_tools import (  # noqa: E402
    CaptureBuilder,
    chunked_response,
    http_request,
    http_response,
)

OUT = os.path.join(os.path.dirname(__file__), "..", "samples")


def sample_basic():
    """01: single request/response, no body on the request, clean HTTP."""
    b = CaptureBuilder()
    b.handshake()
    b.client(http_request("GET", "/index.html"))
    body = b"<html><body><h1>Hello from offline capture</h1></body></html>"
    b.server(http_response(
        "200", "OK",
        {"Content-Type": "text/html"},
        body,
    ))
    b.teardown()
    b.write(os.path.join(OUT, "01_basic_http.pcap"))


def sample_persistent_pipeline():
    """02: keep-alive connection carrying three pipelined requests."""
    b = CaptureBuilder()
    b.handshake()
    b.client(http_request("GET", "/first"))
    b.client(http_request("GET", "/second"))
    b.client(http_request("GET", "/third"))
    b.server(http_response("200", "OK", {"Content-Type": "text/plain"}, b"one"))
    b.server(http_response("200", "OK", {"Content-Type": "text/plain"}, b"two"))
    b.server(http_response("200", "OK", {"Content-Type": "text/plain"}, b"three"))
    b.teardown()
    b.write(os.path.join(OUT, "02_persistent_pipeline.pcap"))


def sample_reconnect():
    """03: the same 5-tuple reopened twice -- must become two sessions."""
    from scapy.all import wrpcap

    path = os.path.join(OUT, "03_reconnect_same_tuple.pcap")
    all_packets = []
    for which in range(2):
        b = CaptureBuilder(client_isn=1000 + which * 77, server_isn=9000 + which)
        b.handshake()
        b.client(http_request("GET", f"/reconnect-{which}"))
        b.server(http_response(
            "200", "OK", {"Content-Type": "text/plain"},
            f"connection instance {which}".encode(),
        ))
        b.teardown()
        all_packets.extend(list(b.packets))
    os.makedirs(OUT, exist_ok=True)
    wrpcap(path, all_packets)


def sample_reorder_duplicate():
    """04: out-of-order segments plus an exact duplicate retransmission."""
    b = CaptureBuilder()
    b.handshake()
    req = http_request("POST", "/upload", {"Content-Type": "text/plain"}, b"")
    # Split the request into three pieces and emit the middle one last.
    third = len(req) // 3
    p1, p2, p3 = req[:third], req[third:2 * third], req[2 * third:]
    base = b.c_seq
    b.client_raw(base, p1)
    b.client_raw(base + 2 * third, p3)          # out of order
    b.client_raw(base + third, p2)              # fills the hole
    b.client_raw(base, p1)                      # exact duplicate of piece 1
    b.c_seq = base + len(req)
    body = b"received in order after reassembly"
    b.server(http_response("201", "Created", {"Content-Type": "text/plain"}, body))
    b.teardown()
    b.write(os.path.join(OUT, "04_reorder_duplicate.pcap"))


def sample_seq_wraparound():
    """05: server sequence numbers cross the 32-bit boundary mid-response."""
    b = CaptureBuilder(client_isn=1000, server_isn=(2 ** 32) - 200)
    b.handshake()
    b.client(http_request("GET", "/wrapped"))
    # 600 bytes of body: the first ~200 sit before 2**32, the rest wrap to 0.
    payload_blob = bytes((i % 26) + 97 for i in range(600))  # a..z repeated
    resp_head = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(payload_blob)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("latin-1")
    full = resp_head + payload_blob
    assert len(full) <= 800, "response must straddle the 2**32 sequence boundary"
    # Emit head+body in 100-byte chunks, deliberately shuffled.  Chunks
    # straddling 2**32 carry wrapped raw sequence numbers, exercising the
    # engine's modulo handling.
    chunks = [
        (b.s_seq + i * 100, full[i * 100:min((i + 1) * 100, len(full))])
        for i in range((len(full) + 99) // 100)
    ]
    order = list(range(len(chunks)))
    order.sort(key=lambda i: (i % 3, i))  # deterministic shuffle: 0,3,6,1,4,7,2,5
    for i in order:
        seq, data = chunks[i]
        b.server_raw(seq % (2 ** 32), data)
    b.s_seq = (b.s_seq + len(full)) % (2 ** 32)
    b.teardown()
    b.write(os.path.join(OUT, "05_seq_wraparound.pcap"))


def sample_overlap_conflict():
    """06: retransmissions disagree inside the response body.

    The first-arrived bytes stay in the primary reassembly; every
    alternative version is retained with its source packets and the affected
    message is flagged.  A separate identical retransmission must be reusable
    without producing a conflict.
    """
    b = CaptureBuilder()
    b.handshake()
    b.client(http_request("GET", "/conflict"))
    head = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 40\r\n"
        "Connection: close\r\n\r\n"
    ).encode("latin-1")
    body = b"VERSION-A: this is the original body!!!!"
    assert len(body) == 40, len(body)
    full = head + body
    base = b.s_seq

    # Original segment carries the whole response.
    b.server_raw(base, full)

    # Conflict 1: the version token in the body (body offsets 8..9, the "A").
    body_start = len(head)
    c1_start = base + body_start + 8
    b.server_raw(c1_start, b"B")  # primary has "A", retransmit says "B"

    # Conflict 2: a wider range with multiple differing bytes.
    c2_body_lo, c2_body_hi = 20, 28  # "original"
    c2_primary = body[c2_body_lo:c2_body_hi]
    c2_alt = b"REWRITTN"
    assert len(c2_alt) == len(c2_primary)
    b.server_raw(base + body_start + c2_body_lo, c2_alt)

    # Identical retransmission of the first 10 body bytes: reusable, and must
    # NOT register a conflict -- provenance gains a second source only.
    b.server_raw(base + body_start, body[:10])

    b.s_seq = base + len(full)
    b.teardown()
    b.write(os.path.join(OUT, "06_overlap_conflict.pcap"))


def sample_gap():
    """07: middle segments missing -- later bytes must not form a new message."""
    b = CaptureBuilder()
    b.handshake()
    b.client(http_request("GET", "/missing"))
    head = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 300\r\n"
        "Connection: close\r\n\r\n"
    ).encode("latin-1")
    body = bytes((i % 26) + 65 for i in range(300))
    full = head + body
    base = b.s_seq
    chunk = 100
    # Emit chunk 0, skip chunk 1, emit chunk 2.
    b.server_raw(base, full[0:chunk])
    b.server_raw(base + 2 * chunk, full[2 * chunk:3 * chunk])
    # FIN at the full length, proving bytes are known-missing, not just EOF.
    b.s_seq = base + len(full)
    b.teardown()
    b.write(os.path.join(OUT, "07_middle_gap.pcap"))


def sample_gzip_chunked():
    """08: chunked transfer encoding carrying a gzip-compressed file."""
    b = CaptureBuilder()
    b.handshake()
    b.client(http_request("GET", "/data.json", {"Accept-Encoding": "gzip"}))
    original = (
        b'{"items":[' + b",".join(b'{"id":%d}' % i for i in range(50)) + b"]}"
    )
    compressed = gzip.compress(original, compresslevel=9)
    # Split the compressed payload into four chunks on the wire.
    step = max(1, len(compressed) // 4)
    wire_chunks = [
        compressed[i:i + step] for i in range(0, len(compressed), step)
    ]
    resp = chunked_response(
        wire_chunks,
        extra_headers={
            "Content-Encoding": "gzip",
            "Content-Type": "application/json",
            "Trailer": "X-Checksum",
        },
        trailers={"X-Checksum": "deadbeef"},
    )
    # Emit the response split across several disordered TCP segments.
    base = b.s_seq
    half = len(resp) // 2
    b.server_raw(base + half, resp[half:])       # second half first
    b.server_raw(base, resp[:half])              # then the first half
    b.s_seq = base + len(resp)
    # Also a second, empty-body 204 response on the same keep-alive conn.
    b.client(http_request("GET", "/ping"))
    b.server(http_response("204", "No Content", include_cl=False))
    b.teardown()
    b.write(os.path.join(OUT, "08_gzip_chunked.pcap"))


def main():
    os.makedirs(OUT, exist_ok=True)
    sample_basic()
    sample_persistent_pipeline()
    sample_reconnect()
    sample_reorder_duplicate()
    sample_seq_wraparound()
    sample_overlap_conflict()
    sample_gap()
    sample_gzip_chunked()
    for name in sorted(os.listdir(OUT)):
        if name.endswith(".pcap"):
            print("wrote", name)


if __name__ == "__main__":
    main()
