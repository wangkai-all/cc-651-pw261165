"""Export analysis results.

Two flavors:

* JSON report -- the full machine-readable status including every gap and
  overlap conflict, suitable for automated checks;
* ZIP bundle -- reconstructed files (decoded where the encoding is known),
  raw HTTP message streams, a human-readable manifest, and ``.gap`` marker
  files next to anything incomplete.  No incomplete content is presented as
  if it were whole.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from datetime import datetime, timezone

from .analyzer import AnalysisResult
from .serialization import full_capture_payload
from .models import Session
from .http_parser import HttpMessage

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def build_json_report(result: AnalysisResult) -> dict:
    payload = full_capture_payload(result)
    payload["exported_at"] = datetime.now(timezone.utc).isoformat()
    payload["overall_status"] = _overall_status(result)
    return payload


def _overall_status(result: AnalysisResult) -> str:
    for session in result.sessions:
        if session.c2s.gaps() or session.s2c.gaps():
            return "GAPPED"
        if session.c2s.conflicts or session.s2c.conflicts:
            return "CONFLICTS_PRESERVED"
    if any(
        not m.complete
        for msgs in result.messages.values()
        for m in msgs
    ):
        return "GAPPED"
    return "COMPLETE"


def build_zip(result: AnalysisResult) -> bytes:
    buffer = io.BytesIO()
    report = build_json_report(result)
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.json", json.dumps(report, indent=2, ensure_ascii=False))
        manifest_lines = [
            f"# Export manifest -- {result.file_name}",
            f"Overall status: {report['overall_status']}",
            f"Sessions: {len(result.sessions)}",
            "",
        ]
        for session in result.sessions:
            _write_session(zf, session, result, manifest_lines)
        zf.writestr("MANIFEST.txt", "\n".join(manifest_lines))
    return buffer.getvalue()


def _write_session(
    zf: zipfile.ZipFile,
    session: Session,
    result: AnalysisResult,
    manifest: list[str],
) -> None:
    sdir = f"session_{_SAFE.sub('_', session.session_id)}"
    manifest.append(f"## {session.session_id} -- {session.endpoint_label}")
    if session.is_tls:
        manifest.append("  TLS session: skipped (no decryption performed)")
        zf.writestr(f"{sdir}/TLS_NOT_DECRYPTED.txt", session.tls_reason)
        return

    for gap_dir, gaps in (
        ("c2s", session.c2s.gaps()),
        ("s2c", session.s2c.gaps()),
    ):
        for s, e in gaps:
            origin = session.stream(gap_dir).data_origin
            zf.writestr(
                f"{sdir}/{gap_dir}_gap_{s-origin}_{e-origin}.gap",
                f"missing {e - s} bytes at data offset {s - origin}..{e - origin}\n",
            )

    for msg in result.messages.get(session.session_id, []):
        _write_message(zf, sdir, session, msg, manifest)


def _write_message(
    zf: zipfile.ZipFile,
    sdir: str,
    session: Session,
    msg: HttpMessage,
    manifest: list[str],
) -> None:
    kind = "req" if msg.direction == "c2s" else "resp"
    base = f"{sdir}/{kind}_{msg.index:03d}"
    status = "complete" if msg.complete else "GAPPED"
    manifest.append(
        f"  {kind} #{msg.index} {msg.start_line} [{status}] "
        f"framing={msg.framing} conflicts={msg.conflict_impact}"
    )

    # Raw reconstructed HTTP bytes (headers + still-encoded body).
    raw = msg.header_bytes + msg.body_bytes
    zf.writestr(f"{base}.http", raw)
    if not msg.complete:
        zf.writestr(
            f"{base}.gap",
            "This message is truncated. Trailing bytes in the capture were "
            "not reassembled into it.\n"
            + json.dumps(msg.gap_info or {}, indent=2),
        )

    # Extract the file/payload content when there is a body.
    if msg.has_body and msg.body_bytes:
        suffix = _extension_for(msg)
        content = msg.decoded_bytes
        if content is None:
            # Decompression failed: keep the encoded bytes and flag it.
            zf.writestr(f"{base}.encoded{suffix}", msg.body_bytes)
            zf.writestr(
                f"{base}.decode-error.txt",
                msg.decode_error or "content decoding failed",
            )
            return
        zf.writestr(f"{base}_file{suffix}", content)

    if msg.conflicts:
        # The parser already converts conflicts to JSON-ready dicts carrying
        # both byte versions and the packets behind each; write them verbatim.
        zf.writestr(
            f"{base}.conflicts.json",
            json.dumps(msg.conflicts, indent=2, ensure_ascii=False),
        )


def _extension_for(msg: HttpMessage) -> str:
    ctype = (msg.header("content-type") or "").split(";", 1)[0].strip().lower()
    mapping = {
        "text/html": ".html",
        "text/plain": ".txt",
        "text/css": ".css",
        "application/javascript": ".js",
        "application/json": ".json",
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "image/svg+xml": ".svg",
        "application/pdf": ".pdf",
        "application/octet-stream": ".bin",
    }
    return mapping.get(ctype, ".bin")
