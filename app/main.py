"""FastAPI application: upload, inspect sessions/messages/packets, export."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles

from .core.exporter import build_json_report, build_zip
from .core.serialization import (
    full_capture_payload,
    message_dict,
    packet_detail,
    session_summary,
    stream_layout,
)
from .store import store

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR.parent / "web"
SAMPLES_DIR = BASE_DIR.parent / "samples"

app = FastAPI(
    title="Offline PCAP Receiving Station",
    description=(
        "Upload a plaintext-HTTP PCAP and inspect reassembled connections, "
        "HTTP/1.x messages, file contents, and the exact packets behind each "
        "byte. TLS is detected but never decrypted."
    ),
    version="1.0.0",
)

MAX_UPLOAD = 200 * 1024 * 1024  # 200 MiB


# ---------------------------------------------------------------------- #
# Helpers
# ---------------------------------------------------------------------- #
def _require(capture_id: str):
    try:
        return store.get(capture_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _require_session(stored, session_id: str):
    for session in stored.result.sessions:
        if session.session_id == session_id:
            return session
    raise HTTPException(status_code=404, detail=f"session {session_id!r} not found")


# ---------------------------------------------------------------------- #
# Capture endpoints
# ---------------------------------------------------------------------- #
@app.post("/api/captures/upload")
async def upload_capture(file: UploadFile = File(...)):
    name = file.filename or "upload.pcap"
    if not name.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(
            status_code=400,
            detail="only .pcap/.pcapng/.cap capture files are accepted",
        )
    # Stream to a temp file outside any untrusted directory; analysis reads
    # the path rather than executing anything from the archive.
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = tmp.name
        written = 0
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_UPLOAD:
                os.unlink(tmp_path)
                raise HTTPException(status_code=413, detail="capture exceeds 200 MiB")
            tmp.write(chunk)
    try:
        stored = store.add_from_path(tmp_path, name, source="upload")
    except Exception as exc:  # pcap parse failures -> clean 400
        raise HTTPException(status_code=400, detail=f"could not parse capture: {exc}") from exc
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return _capture_overview(stored.capture_id)


@app.get("/api/captures")
def list_captures():
    return {"captures": [_capture_overview(c.capture_id) for c in store.list_captures()]}


@app.get("/api/captures/{capture_id}")
def get_capture(capture_id: str):
    stored = _require(capture_id)
    return full_capture_payload(stored.result)


@app.delete("/api/captures/{capture_id}")
def delete_capture(capture_id: str):
    if not store.delete(capture_id):
        raise HTTPException(status_code=404, detail="capture not found")
    return {"deleted": capture_id}


def _capture_overview(capture_id: str) -> dict:
    stored = store.get(capture_id)
    result = stored.result
    return {
        "capture_id": capture_id,
        "file_name": result.file_name,
        "source": stored.source,
        "packet_count": result.packet_count,
        "tcp_packet_count": result.tcp_packet_count,
        "stats": result.stats,
        "sessions": [
            session_summary(s, result) for s in result.sessions
        ],
    }


# ---------------------------------------------------------------------- #
# Session / message / packet endpoints
# ---------------------------------------------------------------------- #
@app.get("/api/captures/{capture_id}/sessions/{session_id}")
def get_session(capture_id: str, session_id: str):
    stored = _require(capture_id)
    session = _require_session(stored, session_id)
    result = stored.result
    return {
        "session": session_summary(session, result),
        "pairs": result.pairs.get(session_id, []),
        "layout": stream_layout(session),
        "messages": [
            message_dict(m, session)
            for m in result.messages.get(session_id, [])
        ],
        "packets": [
            packet_detail(p) for p in session.packets
        ],
        "parse_errors": result.parse_errors.get(session_id, []),
    }


@app.get("/api/captures/{capture_id}/sessions/{session_id}/layout")
def get_layout(capture_id: str, session_id: str):
    stored = _require(capture_id)
    session = _require_session(stored, session_id)
    return stream_layout(session)


@app.get("/api/captures/{capture_id}/sessions/{session_id}/messages/{direction}/{index}")
def get_message(
    capture_id: str,
    session_id: str,
    direction: str,
    index: int,
    encoding: str = "utf-8",
):
    if direction not in ("c2s", "s2c"):
        raise HTTPException(status_code=400, detail="direction must be c2s or s2c")
    stored = _require(capture_id)
    session = _require_session(stored, session_id)
    for msg in stored.result.messages.get(session_id, []):
        if msg.direction == direction and msg.index == index:
            return message_dict(msg, session, body_encoding=encoding)
    raise HTTPException(status_code=404, detail="message not found")


@app.get("/api/captures/{capture_id}/sessions/{session_id}/packets/{packet_index}")
def get_packet(capture_id: str, session_id: str, packet_index: int):
    stored = _require(capture_id)
    session = _require_session(stored, session_id)
    for pkt in session.packets:
        if pkt.index == packet_index:
            return packet_detail(pkt)
    raise HTTPException(status_code=404, detail="packet not found")


# ---------------------------------------------------------------------- #
# Export
# ---------------------------------------------------------------------- #
@app.get("/api/captures/{capture_id}/export/report")
def export_report(capture_id: str):
    stored = _require(capture_id)
    report = build_json_report(stored.result)
    return JSONResponse(
        report,
        headers={
            "Content-Disposition": (
                f'attachment; filename="{stored.result.file_name}.report.json"'
            )
        },
    )


@app.get("/api/captures/{capture_id}/export/zip")
def export_zip(capture_id: str):
    stored = _require(capture_id)
    data = build_zip(stored.result)
    return Response(
        content=data,
        media_type="application/zip",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{stored.result.file_name}.export.zip"'
            )
        },
    )


# ---------------------------------------------------------------------- #
# Bundled visualization samples
# ---------------------------------------------------------------------- #
@app.get("/api/samples")
def list_samples():
    if not SAMPLES_DIR.exists():
        return {"samples": []}
    samples = []
    for path in sorted(SAMPLES_DIR.glob("*.pcap")):
        samples.append({"file": path.name, "path": str(path)})
    return {"samples": samples}


@app.post("/api/samples/load/{name}")
def load_sample(name: str):
    # Prevent path traversal: only bare file names inside SAMPLES_DIR.
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(status_code=400, detail="invalid sample name")
    path = SAMPLES_DIR / name
    if not path.is_file() or not name.endswith(".pcap"):
        raise HTTPException(status_code=404, detail="sample not found")
    stored = store.add_from_path(str(path), name, source="sample")
    return _capture_overview(stored.capture_id)


# Static frontend (mounted last so /api routes win).
@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")
