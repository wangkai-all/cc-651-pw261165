"""Gap-aware reading window over a reassembled :class:`DirectionStream`.

The HTTP parser must never silently bridge a hole.  This view exposes reads
that stop at the first gap and an explicit :meth:`gap_at` check, so the
parser can declare the current message incomplete and refuse to interpret
later bytes as a new message.
"""

from __future__ import annotations

from .reassembly import DirectionStream


class StreamView:
    def __init__(self, stream: DirectionStream):
        self.stream = stream
        # Cursor in monotonic coordinates.
        self.pos = stream.data_origin
        self.origin = stream.data_origin

    # -- positioning --------------------------------------------------- #
    def remaining_contiguous(self) -> int:
        """Bytes readable from ``pos`` without crossing a gap."""
        end = self.stream.contig_end
        return max(0, end - self.pos)

    def gap_at(self, length: int) -> bool:
        """True if fewer than ``length`` contiguous bytes remain."""
        return self.remaining_contiguous() < length

    def next_gap_start(self) -> int | None:
        """Monotonic coordinate of the first gap at/after the cursor."""
        for s, e in self.stream.gaps():
            if e > self.pos:
                return max(s, self.pos)
        return None

    # -- reads --------------------------------------------------------- #
    def read(self, length: int) -> bytes:
        """Read exactly ``length`` bytes or raise :class:`MissingDataError`.

        A short read means a gap (or stream truncation): callers must treat
        the message as incomplete rather than retry with later bytes.
        """
        if self.gap_at(length):
            raise MissingDataError(
                needed=length,
                available=self.remaining_contiguous(),
                gap_at=self.next_gap_start(),
            )
        data = bytes(self.stream.slice(self.pos, self.pos + length))
        self.pos += length
        return data

    def peek(self, length: int) -> bytes:
        if self.gap_at(length):
            raise MissingDataError(
                needed=length,
                available=self.remaining_contiguous(),
                gap_at=self.next_gap_start(),
            )
        return bytes(self.stream.slice(self.pos, self.pos + length))

    def read_line(self, max_length: int = 65536) -> bytes:
        """Read one CRLF (or tolerant bare-LF) terminated line, without EOL."""
        contig_end = self.stream.contig_end
        # Scan available contiguous bytes for the next LF.
        window = bytes(self.stream.slice(self.pos, contig_end))
        lf = window.find(b"\n")
        if lf == -1:
            if len(window) >= max_length:
                raise ProtocolError(f"line longer than {max_length} bytes")
            raise MissingDataError(
                needed=1,
                available=len(window),
                gap_at=self.next_gap_start(),
            )
        line = window[:lf]
        if line.endswith(b"\r"):
            line = line[:-1]
        self.pos += lf + 1
        return line

    # -- provenance helpers -------------------------------------------- #
    def sources_for(self, start: int, end: int):
        return self.stream.sources_for_range(start, end)

    def conflicts_in(self, start: int, end: int):
        return self.stream.conflicts_in_range(start, end)


class MissingDataError(Exception):
    """Raised when a read reaches a gap or the truncated end of a stream."""

    def __init__(self, needed: int, available: int, gap_at: int | None):
        super().__init__(
            f"missing data: needed {needed}, contiguous available {available}, "
            f"gap at {gap_at}"
        )
        self.needed = needed
        self.available = available
        self.gap_at = gap_at


class ProtocolError(Exception):
    """Raised on bytes that cannot be a valid HTTP/1.x message."""
