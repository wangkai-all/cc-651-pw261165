"""Unit tests for the TCP reassembly engine.

These exercise the hard invariants directly with hand-built segments,
including wrap-around, reordering, duplicates and overlap conflicts.
"""

import pytest

from app.core.reassembly import DirectionStream, data_offset_of, signed_delta


# ---------------------------------------------------------------------- #
# Sequence arithmetic
# ---------------------------------------------------------------------- #
def test_signed_delta_wraps_forward():
    assert signed_delta(5, (2 ** 32) - 10) == 15


def test_signed_delta_wraps_backward():
    assert signed_delta((2 ** 32) - 10, 5) == -15


def test_data_offset_normalizes_syn_unit():
    # SYN at 5000 anchored at monotonic 0; first data byte (5001) -> offset 0.
    off = data_offset_of(5001, anchor_seq=5000, anchor_mono=0, syn_seen=True)
    assert off == 0


def test_data_offset_no_syn_is_zero_based():
    off = data_offset_of(700, anchor_seq=700, anchor_mono=0, syn_seen=False)
    assert off == 0


# ---------------------------------------------------------------------- #
# Basic reassembly
# ---------------------------------------------------------------------- #
def test_in_order_segments_merge_into_one_block():
    st = DirectionStream("s2c")
    st.add_syn(1000)
    st.add_segment(1001, b"hello ", 0, 1)
    st.add_segment(1007, b"world", 1, 2)
    assert st.contig_end == 11
    assert bytes(st.slice(0, 11)) == b"hello world"
    assert st.gaps() == []


def test_out_of_order_segments_fill_hole():
    st = DirectionStream("c2s")
    st.add_syn(100)
    st.add_segment(101, b"aa", 0, 1)          # offsets 0-2
    st.add_segment(105, b"ee", 2, 3)          # offsets 4-6, arrives second
    st.add_segment(103, b"cc", 1, 2)          # offsets 2-4
    assert st.gaps() == []
    assert bytes(st.slice(0, 6)) == b"aaccee"


def test_fully_duplicate_segment_is_reused_not_appended():
    st = DirectionStream("s2c")
    st.add_syn(1000)
    st.add_segment(1001, b"abcdef", 0, 1)
    st.add_segment(1001, b"abcdef", 1, 2)    # exact retransmission
    assert len(st.blocks) == 1
    assert bytes(st.slice(0, 6)) == b"abcdef"
    # Both packets remain as provenance.
    sources = st.sources_for_range(0, 6)
    assert {s.frame_number for s in sources} == {1, 2}


def test_partial_overlap_identical_bytes_reused():
    st = DirectionStream("s2c")
    st.add_syn(1000)
    st.add_segment(1001, b"abcdef", 0, 1)
    st.add_segment(1004, b"defXYZ", 1, 2)    # overlaps "def", extends new
    assert st.gaps() == []
    assert bytes(st.slice(0, 9)) == b"abcdefXYZ"
    assert st.conflicts == []


def test_conflicting_overlap_keeps_both_versions():
    st = DirectionStream("s2c")
    st.add_syn(1000)
    st.add_segment(1001, b"VERSION-A", 0, 1)
    st.add_segment(1009, b"B", 1, 2)         # primary has "A" at offset 8
    assert len(st.conflicts) == 1
    c = st.conflicts[0]
    assert c.existing_bytes == b"A"
    assert c.alternative_bytes == b"B"
    # Primary stream keeps first-arrived content.
    assert bytes(st.slice(0, 9)) == b"VERSION-A"
    # Alternative source packet is recorded.
    assert c.alternative_sources[0].frame_number == 2


def test_conflict_with_identical_neighbors_splits_runs():
    st = DirectionStream("s2c")
    st.add_syn(1000)
    st.add_segment(1001, b"abcdefgh", 0, 1)
    st.add_segment(1001, b"abXdefgh", 1, 2)  # only offset 2 differs
    assert len(st.conflicts) == 1
    assert st.conflicts[0].start == 2 and st.conflicts[0].end == 3
    assert st.conflicts[0].alternative_bytes == b"X"


# ---------------------------------------------------------------------- #
# Gaps and wrap-around
# ---------------------------------------------------------------------- #
def test_middle_gap_is_reported_and_not_bridged():
    st = DirectionStream("s2c")
    st.add_syn(1000)
    st.add_segment(1001, b"first", 0, 1)            # 0-5
    st.add_segment(1011, b"third", 2, 3)            # 10-15
    assert st.gaps() == [(5, 10)]
    assert st.contig_end == 5
    with pytest.raises(KeyError):
        st.slice(0, 12)


def test_fin_declares_length_beyond_captured_bytes():
    st = DirectionStream("s2c")
    st.add_syn(1000)
    st.add_segment(1001, b"abc", 0, 1)
    st.add_fin(1004, 0)   # FIN right after 3 bytes: complete, no gap
    assert st.fin_mono_end == 3
    assert st.gaps() == []


def test_sequence_wraparound_reassembles_contiguously():
    st = DirectionStream("s2c")
    isn = (2 ** 32) - 4
    st.add_syn(isn)
    # First segment occupies raw M-3..0 (4 bytes); the next non-overlapping
    # segment therefore starts at raw seq 1, not 0.
    st.add_segment(isn + 1, b"abcd", 0, 1)
    st.add_segment(1, b"efgh", 1, 2)
    assert st.gaps() == []
    assert st.contig_end == 8
    assert bytes(st.slice(0, 8)) == b"abcdefgh"


def test_wraparound_with_reordering():
    st = DirectionStream("s2c")
    isn = (2 ** 32) - 6
    st.add_syn(isn)
    # First segment (raw M-5, 6 bytes) straddles the boundary and ends at
    # raw seq 1; the higher-offset segment is delivered first.
    st.add_segment(1, b"gh", 2, 3)
    st.add_segment(isn + 1, b"abcdef", 0, 1)
    assert bytes(st.slice(0, 8)) == b"abcdefgh"
    assert st.gaps() == []


def test_mid_capture_without_syn_uses_data_origin_zero():
    st = DirectionStream("c2s")
    # No add_syn: capture started mid-connection.
    st.add_segment(9000, b"GET / HTTP/1.1", 0, 1)
    assert st.blocks[0].start == 0
    assert st.contig_end == len(b"GET / HTTP/1.1")


def test_sources_for_range_only_returns_covering_packets():
    st = DirectionStream("s2c")
    st.add_syn(1000)
    st.add_segment(1001, b"0123456789", 0, 1)
    st.add_segment(1011, b"abcdefghij", 1, 2)
    sources = st.sources_for_range(2, 12)
    frames = {s.frame_number for s in sources}
    assert frames == {1, 2}
    only_first = st.sources_for_range(0, 5)
    assert {s.frame_number for s in only_first} == {1}
