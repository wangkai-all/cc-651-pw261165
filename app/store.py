"""In-memory capture store.

Uploaded PCAPs and analysis results live for the lifetime of the server
process -- nothing is retained on disk beyond the upload temp file itself.
A lock guards writes so concurrent uploads cannot interleave.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass

from .core.analyzer import AnalysisResult, analyze_pcap


@dataclass
class StoredCapture:
    capture_id: str
    file_name: str
    source: str          # "upload" | "sample"
    result: AnalysisResult


class CaptureStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._captures: dict[str, StoredCapture] = {}

    def add_from_path(self, path: str, file_name: str, source: str) -> StoredCapture:
        capture_id = uuid.uuid4().hex[:12]
        result = analyze_pcap(path, capture_id, file_name)
        stored = StoredCapture(
            capture_id=capture_id,
            file_name=file_name,
            source=source,
            result=result,
        )
        with self._lock:
            self._captures[capture_id] = stored
        return stored

    def get(self, capture_id: str) -> StoredCapture:
        try:
            return self._captures[capture_id]
        except KeyError as exc:
            raise KeyError(f"capture {capture_id!r} not found") from exc

    def list_captures(self) -> list[StoredCapture]:
        return list(self._captures.values())

    def delete(self, capture_id: str) -> bool:
        with self._lock:
            return self._captures.pop(capture_id, None) is not None


store = CaptureStore()
