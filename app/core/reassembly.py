"""TCP stream reassembly engine.

Handles, per *direction* of a TCP connection:

* 32-bit sequence number wrap-around (monotonic 64-bit coordinate space built
  from signed ``uint32`` deltas between observed segments);
* out-of-order delivery (blocks are kept sorted, later segments fill earlier
  holes instead of being discarded);
* fully duplicate segments and partially overlapping segments;
* overlapping segments carrying identical bytes (the existing bytes are
  reused, both sources are recorded as provenance);
* overlapping segments carrying *conflicting* bytes -- neither copy is
  silently chosen.  The first-arrived copy stays in the primary stream and
  every conflict region is retained with both byte versions plus the packets
  that carried each, so the HTTP layer and the UI can show the impact.

The engine never invents bytes: gaps stay gaps until real data covers them,
and every reassembled byte range can be traced back to the exact packets.
"""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass, field

UINT32_MOD = 1 << 32
UINT32_HALF = 1 << 31


def data_offset_of(
    raw_seq: int,
    anchor_seq: int | None,
    anchor_mono: int,
    syn_seen: bool,
) -> int:
    """Stateless raw-sequence -> data-offset conversion.

    Mirrors :meth:`DirectionStream._data_coord` without touching the stream's
    mutable anchor, so post-processing code (length accounting, UI lookups)
    can map arbitrary packet sequences safely.
    """
    if anchor_seq is None:
        mono = 0
    else:
        mono = anchor_mono + signed_delta(raw_seq, anchor_seq)
    return mono - 1 if syn_seen else mono


def signed_delta(seq_new: int, seq_ref: int) -> int:
    """Signed distance from ``seq_ref`` to ``seq_new`` in uint32 space.

    Result is in ``[-2**31, 2**31)``.  A segment whose sequence is more than
    2 GiB ahead of the last reference cannot occur on a real connection
    (segments are small and anchors update on every packet), so the modulo
    arithmetic used here covers every legitimate wrap-around case.
    """
    d = (seq_new - seq_ref) % UINT32_MOD
    if d >= UINT32_HALF:
        d -= UINT32_MOD
    return d


@dataclass(frozen=True)
class Source:
    """A packet contributing bytes to a block."""

    packet_index: int
    frame_number: int  # 1-based, for display
    seq: int           # raw uint32 TCP sequence of that packet
    mono_start: int    # monotonic coordinate where this segment starts
    mono_end: int      # monotonic coordinate one past this segment's data


@dataclass
class Block:
    """A contiguous run of reassembled bytes in monotonic coordinates.

    ``[start, end)`` never overlaps another block.  ``sources`` lists every
    packet that contributed the block's bytes (duplicate/identical overlaps
    append themselves here, which is how "reuse identical bytes" is visible).
    """

    start: int
    end: int
    data: bytearray
    sources: list[Source] = field(default_factory=list)

    def covers(self, mono_seq: int) -> bool:
        return self.start <= mono_seq < self.end


@dataclass
class Conflict:
    """A byte range where two segments disagreed.

    The primary stream keeps the first-arrived version (``existing_bytes``);
    the alternative version is retained verbatim instead of being dropped.
    """

    start: int
    end: int
    existing_bytes: bytes
    alternative_bytes: bytes
    existing_sources: list[Source]
    alternative_sources: list[Source]


@dataclass
class DirectionStream:
    """Reassembly state for one direction of one TCP session."""

    name: str  # "c2s" or "s2c"
    blocks: list[Block] = field(default_factory=list)
    conflicts: list[Conflict] = field(default_factory=list)
    fin_seen: bool = False
    fin_mono_end: int | None = None  # monotonic coordinate one past the FIN
    syn_seen: bool = False

    # Anchor state: raw seq of the anchor and its monotonic coordinate.
    # Monotonic coordinates are *relative data offsets*: the first data byte
    # is always at offset 0, regardless of whether the SYN was captured.
    _anchor_seq: int | None = None
    _anchor_mono: int = 0

    @property
    def data_origin(self) -> int:
        """Monotonic coordinate of the first data byte (always 0).

        Kept as an explicit, named constant so callers read clearly; it also
        documents that SYN/FIN sequence-space effects are normalized away
        inside the engine rather than leaked into the data coordinates.
        """
        return 0

    # ------------------------------------------------------------------ #
    # Coordinate handling
    # ------------------------------------------------------------------ #
    def _map_seq(self, raw_seq: int, advance_anchor: bool = True) -> int:
        """Map a raw uint32 sequence to a monotonic coordinate.

        Two anchor conventions, chosen by what the first observed packet is:

        * SYN seen first -- the SYN is anchored at monotonic 0.  Its sequence
          space counts the SYN itself, so data byte k (raw ISN+1+k) maps to
          monotonic k+1; :meth:`_data_coord` shifts that down by one so data
          offsets start at 0.
        * No SYN (mid-capture pickup) -- the first data packet is anchored at
          monotonic 0 and no shift is needed.

        Later packets join via signed modular deltas, which is what makes
        32-bit wrap-around transparent.  ``advance_anchor=False`` computes a
        coordinate without moving the anchor (used when the caller needs to
        rebase the anchor onto a segment *end* it computes itself).
        """
        if self._anchor_seq is None:
            self._anchor_seq = raw_seq
            self._anchor_mono = 0
            return 0
        delta = signed_delta(raw_seq, self._anchor_seq)
        mono = self._anchor_mono + delta
        if advance_anchor:
            self._anchor_seq = raw_seq
            self._anchor_mono = mono
        return mono

    def _data_coord(self, raw_seq: int, advance_anchor: bool = True) -> int:
        """Sequence of a data-carrying packet, expressed as a data offset."""
        mono = self._map_seq(raw_seq, advance_anchor=advance_anchor)
        # With a SYN anchor, monotonic 0 belongs to the SYN; data starts at 1
        # in that space, so shift down to make data offsets zero-based.
        return mono - 1 if self.syn_seen else mono

    # ------------------------------------------------------------------ #
    # Packet intake
    # ------------------------------------------------------------------ #
    def add_syn(self, raw_seq: int) -> None:
        """Record a SYN (or SYN-ACK).  SYN consumes one sequence number.

        Anchors the SYN at monotonic 0; data therefore begins at monotonic 1
        before :meth:`_data_coord` normalizes it to data offset 0.  If data
        was already anchored (capture began mid-connection) the anchor is
        left alone, since its zero-based data convention is already correct.
        """
        self.syn_seen = True
        if self._anchor_seq is None:
            self._anchor_seq = raw_seq
            self._anchor_mono = 0

    def add_fin(self, raw_seq: int, payload_len: int) -> None:
        data_start = self._data_coord(raw_seq)
        self.fin_seen = True
        # In data coordinates the FIN occupies no byte: the expected end is
        # the offset one past the payload carried by the FIN packet.
        self.fin_mono_end = data_start + payload_len

    def add_segment(
        self,
        raw_seq: int,
        payload: bytes,
        packet_index: int,
        frame_number: int,
    ) -> list[Conflict]:
        """Insert one TCP payload into the reassembly.

        Returns the list of *new* conflicts produced by this segment.
        """
        if not payload:
            # Pure ACKs carry no data and must not move the coordinate
            # anchor (the handshake ACK belongs to the other direction's
            # sequence space); FIN/SYN bookkeeping is handled separately.
            return []

        # Map the start without advancing the anchor: the anchor must move
        # forward by the real payload length, not by a modular delta that a
        # 32-bit wrap would otherwise shrink.
        mono_start = self._data_coord(raw_seq, advance_anchor=False)
        mono_end = mono_start + len(payload)
        # Rebase the anchor onto the segment end (in SYN-space when a SYN was
        # seen) so the next segment's delta measures from the true boundary.
        end_mono = mono_end + (1 if self.syn_seen else 0)
        self._anchor_seq = (raw_seq + len(payload)) % UINT32_MOD
        self._anchor_mono = end_mono
        source = Source(
            packet_index=packet_index,
            frame_number=frame_number,
            seq=raw_seq,
            mono_start=mono_start,
            mono_end=mono_end,
        )
        new_intervals: list[tuple[int, int, bytes]] = []
        new_conflicts: list[Conflict] = []

        # Walk the incoming bytes interval by interval against existing
        # blocks, classifying each run as identical / conflicting / new.
        # ``idx`` is a cursor over existing blocks that only moves forward;
        # recomputing it with bisect at every step would re-select the block
        # we are currently inside and misread covered bytes as a hole.
        pos = mono_start
        idx = bisect_left(self.blocks, mono_start, key=lambda b: b.start)
        if idx > 0 and self.blocks[idx - 1].end > mono_start:
            idx -= 1

        while pos < mono_end:
            if idx >= len(self.blocks) or self.blocks[idx].start > pos:
                # No block at ``pos``: either past the last block or sitting
                # in a hole before the next one.
                hole_end = (
                    mono_end
                    if idx >= len(self.blocks)
                    else min(self.blocks[idx].start, mono_end)
                )
                new_intervals.append(
                    (pos, hole_end, payload[pos - mono_start: hole_end - mono_start])
                )
                pos = hole_end
                continue

            block = self.blocks[idx]
            # block.start <= pos is guaranteed here; the overlap ends at the
            # earlier of the block boundary or the segment boundary.
            ov_end = min(block.end, mono_end)
            incoming = payload[pos - mono_start: ov_end - mono_start]
            existing = bytes(block.data[pos - block.start: ov_end - block.start])
            # Both slices are local to this overlap, so they share indices.
            run_start = 0
            run_same = incoming[0] == existing[0]
            for off in range(1, len(incoming)):
                is_same = incoming[off] == existing[off]
                if is_same != run_same:
                    self._record_overlap_run(
                        run_same,
                        pos + run_start,
                        pos + off,
                        incoming,
                        existing,
                        run_start,
                        block,
                        source,
                        new_conflicts,
                    )
                    run_start = off
                    run_same = is_same
            self._record_overlap_run(
                run_same,
                pos + run_start,
                ov_end,
                incoming,
                existing,
                run_start,
                block,
                source,
                new_conflicts,
            )
            # Identical or conflicting, this packet is still provenance for
            # the whole overlap with the existing block.
            if source not in block.sources:
                block.sources.append(source)
            pos = ov_end
            idx += 1

        for s, e, chunk in new_intervals:
            self._insert_new_block(s, e, bytearray(chunk), source)
        return new_conflicts

    def _record_overlap_run(
        self,
        run_same: bool,
        abs_start: int,
        abs_end: int,
        incoming: bytes,
        existing: bytes,
        run_start: int,
        block: Block,
        source: Source,
        new_conflicts: list[Conflict],
    ) -> None:
        if run_same:
            # Identical overlap: existing bytes are reused as-is.  Provenance
            # (this packet) is attached to the block by the caller.
            return
        length = abs_end - abs_start
        conflict = Conflict(
            start=abs_start,
            end=abs_end,
            existing_bytes=existing[run_start: run_start + length],
            alternative_bytes=incoming[run_start: run_start + length],
            existing_sources=list(block.sources),
            alternative_sources=[source],
        )
        self.conflicts.append(conflict)
        new_conflicts.append(conflict)

    def _insert_new_block(
        self, start: int, end: int, data: bytearray, source: Source
    ) -> None:
        """Insert a block known not to overlap any existing block."""
        idx = bisect_left(self.blocks, start, key=lambda b: b.start)
        # Merge with predecessor if adjacent.
        if idx > 0 and self.blocks[idx - 1].end == start:
            target = self.blocks[idx - 1]
            target.data.extend(data)
            target.end = end
            if source not in target.sources:
                target.sources.append(source)
        else:
            target = Block(start=start, end=end, data=bytearray(data), sources=[source])
            self.blocks.insert(idx, target)
        # Merge with successor if adjacent.
        after = bisect_left(self.blocks, end, key=lambda b: b.start)
        if after < len(self.blocks) and self.blocks[after] is not target and \
                self.blocks[after].start == end:
            nxt = self.blocks.pop(after)
            target.data.extend(nxt.data)
            target.end = nxt.end
            target.sources.extend(s for s in nxt.sources if s not in target.sources)

    # ----------------------------------------------------------------= #
    # Views over the reassembly (call after all packets ingested)
    # ----------------------------------------------------------------= #
    def finalize(self) -> None:
        """Sort recorded conflict ranges for deterministic display."""
        self.conflicts.sort(key=lambda c: (c.start, c.end))

    @property
    def contig_end(self) -> int:
        """Monotonic coordinate one past the longest gap-free prefix."""
        if not self.blocks:
            return 0
        first = self.blocks[0]
        if first.start != 0:
            return 0
        end = first.end
        for block in self.blocks[1:]:
            if block.start != end:
                break
            end = block.end
        return end

    @property
    def expected_end(self) -> int | None:
        """Total stream length if FIN was seen, else ``None`` (still open)."""
        if self.fin_mono_end is not None:
            return self.fin_mono_end
        return None

    def gaps(self) -> list[tuple[int, int]]:
        """Missing byte ranges in monotonic coordinates."""
        out: list[tuple[int, int]] = []
        cursor = 0
        for block in self.blocks:
            if block.start > cursor:
                out.append((cursor, block.start))
            cursor = max(cursor, block.end)
        if self.fin_mono_end is not None and cursor < self.fin_mono_end:
            out.append((cursor, self.fin_mono_end))
        return out

    def coverage_end(self) -> int:
        """One past the highest coordinate holding any (possibly gapped) data."""
        if not self.blocks:
            return 0
        return max(b.end for b in self.blocks)

    def slice(self, start: int, end: int) -> bytearray:
        """Contiguous slice of reassembled primary bytes.

        Raises ``KeyError`` if the range touches a gap -- callers must check
        :meth:`gaps` / :meth:`contig_end` first rather than getting fake bytes.
        """
        out = bytearray()
        pos = start
        idx = bisect_left(self.blocks, start, key=lambda b: b.start)
        if idx > 0 and self.blocks[idx - 1].covers(start):
            idx -= 1
        while pos < end:
            if idx >= len(self.blocks) or self.blocks[idx].start > pos:
                raise KeyError(f"gap at monotonic offset {pos}")
            block = self.blocks[idx]
            take = min(block.end, end)
            out += block.data[pos - block.start: take - block.start]
            pos = take
            idx += 1
        return out

    def sources_for_range(self, start: int, end: int) -> list[Source]:
        """All packets carrying bytes anywhere in ``[start, end)``.

        A merged block lists every packet that touched any part of it, so the
        packet's own span is tested against the query range rather than the
        enclosing block's span.
        """
        seen: dict[int, Source] = {}
        idx = bisect_left(self.blocks, start, key=lambda b: b.start)
        if idx > 0 and self.blocks[idx - 1].end > start:
            idx -= 1
        while idx < len(self.blocks) and self.blocks[idx].start < end:
            block = self.blocks[idx]
            if block.end > start:
                for src in block.sources:
                    if src.mono_end > start and src.mono_start < end:
                        seen[src.packet_index] = src
            idx += 1
        return sorted(seen.values(), key=lambda s: s.packet_index)

    def conflicts_in_range(self, start: int, end: int) -> list[Conflict]:
        return [
            c for c in self.conflicts if c.start < end and c.end > start
        ]

    def block_view(self) -> list[dict]:
        """Serializable description of the reassembly layout for the UI."""
        return [
            {
                "start": b.start,
                "end": b.end,
                "length": b.end - b.start,
                "sources": [
                    {
                        "packet_index": s.packet_index,
                        "frame_number": s.frame_number,
                        "seq": s.seq,
                    }
                    for s in b.sources
                ],
            }
            for b in self.blocks
        ]
