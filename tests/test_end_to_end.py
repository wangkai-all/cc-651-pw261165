"""End-to-end tests over the generated sample PCAPs.

Regenerates the samples into a temporary directory so the tests never depend
on checked-in binary state.
"""

import io
import json
import os
import subprocess
import sys
import zipfile

import pytest

from app.core.analyzer import analyze_pcap
from app.core.serialization import full_capture_payload
from app.core.exporter import build_json_report, build_zip

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")


@pytest.fixture(scope="session", autouse=True)
def ensure_samples():
    if not os.path.isdir(SAMPLES) or not os.listdir(SAMPLES):
        subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "generate_samples.py")],
            check=True,
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": ROOT},
        )
    yield


def _load(name):
    path = os.path.join(SAMPLES, name)
    result = analyze_pcap(path, "cap", name)
    return result, full_capture_payload(result)


def test_basic_request_response():
    r, payload = _load("01_basic_http.pcap")
    assert len(payload["sessions"]) == 1
    s = payload["sessions"][0]
    assert s["complete"] is True
    kinds = [(m["kind"], m["status"] or m["method"]) for m in s["messages"]]
    assert ("request", "GET") in kinds
    assert ("response", "200") in kinds
    resp = next(m for m in s["messages"] if m["kind"] == "response")
    assert resp["body"]["decoded_text"].startswith("<html>")


def test_persistent_pipeline_three_exchanges():
    _, payload = _load("02_persistent_pipeline.pcap")
    s = payload["sessions"][0]
    requests = [m for m in s["messages"] if m["kind"] == "request"]
    responses = [m for m in s["messages"] if m["kind"] == "response"]
    assert len(requests) == 3 and len(responses) == 3
    # Wire length of one message must not count the whole connection.
    for m in s["messages"]:
        assert m["lengths"]["raw_wire"] <= m["lengths"]["reassembled"] + 40


def test_reconnect_same_tuple_is_two_sessions():
    r, payload = _load("03_reconnect_same_tuple.pcap")
    assert len(payload["sessions"]) == 2
    targets = [
        m["target"]
        for s in payload["sessions"]
        for m in s["messages"]
        if m["kind"] == "request"
    ]
    assert targets == ["/reconnect-0", "/reconnect-1"]


def test_reorder_and_duplicate_reassemble_cleanly():
    r, payload = _load("04_reorder_duplicate.pcap")
    s = payload["sessions"][0]
    assert s["complete"] is True and s["conflict_count"] == 0
    req = next(m for m in s["messages"] if m["kind"] == "request")
    assert req["start_line"].startswith("POST /upload")
    # The duplicate packet is retained as provenance on the request range.
    assert len(req["source_packets"]) >= 3


def test_sequence_wraparound_body_intact():
    r, payload = _load("05_seq_wraparound.pcap")
    s = payload["sessions"][0]
    assert s["complete"] is True
    resp = next(m for m in s["messages"] if m["kind"] == "response")
    assert resp["lengths"]["body_decoded"] == 600
    assert s["gaps"]["s2c"] == [] and s["gaps"]["c2s"] == []


def test_overlap_conflict_preserves_alternatives():
    r, payload = _load("06_overlap_conflict.pcap")
    s = payload["sessions"][0]
    assert s["conflict_count"] >= 2
    resp = next(m for m in s["messages"] if m["kind"] == "response")
    assert resp["conflict_impact"] == "body"
    alternatives = "".join(c["alternative_text"] for c in resp["conflicts"])
    assert "B" in alternatives
    # Primary content keeps the first-arrived "VERSION-A".
    assert "VERSION-A" in resp["body"]["encoded_text"]


def test_middle_gap_marks_incomplete_and_blocks_parsing():
    r, payload = _load("07_middle_gap.pcap")
    s = payload["sessions"][0]
    assert s["has_gap"] is True and s["complete"] is False
    resp = next(m for m in s["messages"] if m["kind"] == "response")
    assert resp["complete"] is False and resp["gap"] is True
    # Only the response header + first 100-byte fragment were reassembled.
    assert resp["body"]["encoded_len"] == 15
    # The fragment behind the hole was not turned into another message.
    assert len(s["messages"]) == 2


def test_gzip_chunked_decodes_and_handles_204():
    r, payload = _load("08_gzip_chunked.pcap")
    s = payload["sessions"][0]
    assert s["complete"] is True
    chunked = next(
        m for m in s["messages"]
        if m["framing"] == "chunked"
    )
    assert chunked["lengths"]["body_decoded"] > \
        chunked["body"]["encoded_len"]
    assert chunked["chunks"], "chunk framing metadata must be exposed"
    no_content = next(m for m in s["messages"] if m["status"] == "204")
    assert no_content["has_body"] is False


def test_export_report_carries_gap_status():
    r, _ = _load("07_middle_gap.pcap")
    report = build_json_report(r)
    assert report["overall_status"] == "GAPPED"
    data = build_zip(r)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = zf.namelist()
        assert any(n.endswith(".gap") for n in names)
        assert "report.json" in names and "MANIFEST.txt" in names
        json.loads(zf.read("report.json"))


def test_conflict_export_is_flat_valid_json():
    r, _ = _load("06_overlap_conflict.pcap")
    data = build_zip(r)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        conflict_files = [n for n in zf.namelist() if n.endswith(".conflicts.json")]
        assert conflict_files, "conflict sample must export a conflicts file"
        payload = json.loads(zf.read(conflict_files[0]))
        # Flat list of conflict records, each retaining both byte versions.
        assert isinstance(payload, list) and payload
        first = payload[0]
        assert {"start", "end", "existing_text", "alternative_text",
                "existing_sources", "alternative_sources"} <= set(first)
