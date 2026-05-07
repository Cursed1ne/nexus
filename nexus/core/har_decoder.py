"""
HAR decoder for streaming AI chat targets.

Handles the realities of modern chat APIs:
  - Request bodies that are gzip/deflate/brotli compressed
  - Response bodies that are SSE event-streams or chunked NDJSON
  - WebSocket frames (Chrome/Firefox HAR _webSocketMessages extension)
  - Bodies that HAR encodes as base64 when not text-safe

Usage:
    from nexus.core.har_decoder import HARFile

    har = HARFile.load("/tmp/penny.har")
    har.print_summary()                            # list every request

    # Decode a specific entry by URL substring
    chat_entry = har.find("chat/pennyPortal")
    print(chat_entry.request_body_decoded())       # decompresses gzip etc.
    print(chat_entry.response_body_decoded())

    # Reconstruct an SSE/WebSocket conversation
    sse_entry = har.find("sse/subscribe")
    for ev in sse_entry.sse_events():
        print(ev.event, ev.data[:200])

    ws_entry = har.find("/ws/chat")
    for frame in ws_entry.websocket_frames():
        print(frame.direction, frame.opcode, frame.data[:200])
"""
from __future__ import annotations

import base64
import gzip
import json
import re
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Decompression helpers
# ─────────────────────────────────────────────────────────────────────────────

def decompress(body: bytes, encoding: str) -> bytes:
    """Decompress bytes according to Content-Encoding header value."""
    if not body:
        return body
    enc = (encoding or "").lower().strip()
    if enc in ("", "identity"):
        return body
    if enc == "gzip":
        return gzip.decompress(body)
    if enc == "deflate":
        try:
            return zlib.decompress(body)
        except zlib.error:
            return zlib.decompress(body, -zlib.MAX_WBITS)  # raw deflate
    if enc == "br":
        try:
            import brotli
        except ImportError as e:
            raise RuntimeError("Install brotli: pip install brotli") from e
        return brotli.decompress(body)
    if enc == "zstd":
        try:
            import zstandard as zstd
        except ImportError as e:
            raise RuntimeError("Install zstandard: pip install zstandard") from e
        return zstd.ZstdDecompressor().decompress(body)
    return body


def body_bytes_from_har_field(text: str, encoding_field: str) -> bytes:
    """HAR stores body as either plain text or base64. encoding_field=='base64' means decode."""
    if text is None:
        return b""
    if encoding_field == "base64":
        return base64.b64decode(text)
    return text.encode("utf-8", errors="replace")


# ─────────────────────────────────────────────────────────────────────────────
# Domain objects
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SSEEvent:
    event: str
    data: str
    id: str = ""


@dataclass
class WSFrame:
    direction: str  # "send" / "receive"
    opcode: int
    data: bytes
    time: float = 0.0


@dataclass
class HAREntry:
    raw: Dict[str, Any]

    @property
    def url(self) -> str:
        return self.raw["request"]["url"]

    @property
    def method(self) -> str:
        return self.raw["request"]["method"]

    @property
    def status(self) -> int:
        return self.raw["response"].get("status", 0)

    def header(self, name: str, where: str = "request") -> str:
        for h in self.raw[where].get("headers", []):
            if h["name"].lower() == name.lower():
                return h["value"]
        return ""

    def request_body_decoded(self) -> str:
        post = (self.raw["request"].get("postData") or {})
        text = post.get("text", "")
        if not text:
            return ""
        # HAR doesn't always set encoding=base64; some captures store gzip raw text
        ce = self.header("content-encoding", "request")
        # Try base64 first if it looks base64
        try:
            raw = base64.b64decode(text, validate=True)
        except Exception:
            raw = text.encode("latin-1", errors="replace")
        try:
            return decompress(raw, ce).decode("utf-8", errors="replace")
        except Exception:
            return raw.decode("utf-8", errors="replace")

    def response_body_decoded(self) -> str:
        content = self.raw["response"].get("content", {})
        text = content.get("text", "")
        enc_field = content.get("encoding", "")
        if not text:
            return ""
        raw = body_bytes_from_har_field(text, enc_field)
        ce = self.header("content-encoding", "response")
        try:
            return decompress(raw, ce).decode("utf-8", errors="replace")
        except Exception:
            return raw.decode("utf-8", errors="replace")

    def sse_events(self) -> List[SSEEvent]:
        """Parse a Server-Sent-Events response into events."""
        body = self.response_body_decoded()
        out: List[SSEEvent] = []
        cur = {"event": "message", "data": [], "id": ""}
        for line in body.splitlines():
            if line == "":
                if cur["data"]:
                    out.append(SSEEvent(
                        event=cur["event"],
                        data="\n".join(cur["data"]),
                        id=cur["id"],
                    ))
                cur = {"event": "message", "data": [], "id": ""}
                continue
            if ":" not in line:
                continue
            field, _, value = line.partition(":")
            value = value.lstrip(" ")
            if field == "event":
                cur["event"] = value
            elif field == "data":
                cur["data"].append(value)
            elif field == "id":
                cur["id"] = value
        if cur["data"]:
            out.append(SSEEvent(event=cur["event"], data="\n".join(cur["data"]), id=cur["id"]))
        return out

    def websocket_frames(self) -> List[WSFrame]:
        """
        Returns websocket frames from a HAR entry.

        Chrome/Firefox put them under entry["_webSocketMessages"]:
            [{ "type": "send"|"receive", "opcode": 1, "data": "...", "time": 1.234 }, ...]

        mitmproxy uses "_resourceType": "websocket" with frames in different shapes —
        we handle the most common ones.
        """
        msgs = self.raw.get("_webSocketMessages") or self.raw.get("_websocketMessages") or []
        out: List[WSFrame] = []
        for m in msgs:
            direction = m.get("type") or m.get("direction") or ""
            opcode = m.get("opcode", 1)
            data = m.get("data", "")
            if isinstance(data, str):
                # Sometimes binary frames are base64-encoded
                if opcode == 2 or m.get("encoding") == "base64":
                    try:
                        data = base64.b64decode(data)
                    except Exception:
                        data = data.encode("latin-1", errors="replace")
                else:
                    data = data.encode("utf-8", errors="replace")
            out.append(WSFrame(direction=direction, opcode=opcode, data=data,
                               time=float(m.get("time", 0))))
        return out


@dataclass
class HARFile:
    entries: List[HAREntry]

    @classmethod
    def load(cls, path: str) -> "HARFile":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"HAR file not found: {path}")
        size = p.stat().st_size
        if size == 0:
            raise ValueError(f"HAR file is empty: {path}")

        raw = p.read_bytes()

        # Identify the actual format from magic bytes
        if raw[:2] == b"\x1f\x8b":
            print(f"[har_decoder] Input is gzip-compressed; decompressing...")
            raw = gzip.decompress(raw)
        elif raw[:2] == b"PK":
            raise ValueError(
                f"Input looks like a ZIP archive (.saz/.zip), not a HAR file. "
                f"If this is a Burp 'Save Archive', extract it first or re-export "
                f"the request as HAR via Firefox/Chrome DevTools."
            )
        elif raw.startswith((b"<", b"\xef\xbb\xbf<")):
            raise ValueError(
                f"Input starts with an XML/HTML tag, not JSON. "
                f"Looks like Burp's project archive (XML) or an HTML 'Save Page As' "
                f"export. You need a HAR (JSON) file — capture it via "
                f"Firefox DevTools → Network → right-click → 'Save All As HAR'."
            )

        # Strip UTF-8/16 BOMs
        if raw[:3] == b"\xef\xbb\xbf":
            raw = raw[3:]
        elif raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            try:
                raw = raw.decode("utf-16").encode("utf-8")
            except Exception:
                pass

        try:
            text = raw.decode("utf-8", errors="replace").lstrip("﻿").lstrip()
        except Exception as e:
            raise ValueError(f"Could not decode {path} as UTF-8: {e}") from e

        if not text.startswith("{"):
            preview = text[:120].replace("\n", " ")
            raise ValueError(
                f"File doesn't start with a JSON object (starts with: {preview!r}). "
                f"This is not a valid HAR file. "
                f"To capture HAR properly: Firefox DevTools → Network tab → "
                f"right-click any request → 'Save All As HAR'."
            )

        try:
            har = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"File parsed as JSON failed at line {e.lineno}, col {e.colno}: {e.msg}. "
                f"Preview of that area: {text[max(0,e.pos-60):e.pos+60]!r}"
            ) from e

        if "log" not in har:
            raise ValueError(
                f"JSON loaded but doesn't contain 'log' key — "
                f"top-level keys: {list(har.keys())[:10]}. Not a HAR file."
            )

        entries = [HAREntry(e) for e in har.get("log", {}).get("entries", [])]
        if not entries:
            print(f"[har_decoder] Warning: HAR file has no entries.")
        return cls(entries=entries)

    def find(self, url_substring: str) -> Optional[HAREntry]:
        for e in self.entries:
            if url_substring in e.url:
                return e
        return None

    def find_all(self, url_substring: str) -> List[HAREntry]:
        return [e for e in self.entries if url_substring in e.url]

    def print_summary(self) -> None:
        print(f"HAR contains {len(self.entries)} entries:")
        for i, e in enumerate(self.entries):
            ce = e.header("content-encoding", "response")
            ct = e.header("content-type", "response")
            ws = "  [WS]" if (e.raw.get("_webSocketMessages") or e.raw.get("_websocketMessages")) else ""
            print(f"  {i:3d}  {e.method:5s} {e.status} {e.url[:90]}  ct={ct[:30]} ce={ce}{ws}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI helper
# ─────────────────────────────────────────────────────────────────────────────

def _main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="Decode a HAR file produced by Burp/DevTools.")
    ap.add_argument("har", help="Path to HAR file")
    ap.add_argument("--filter", help="URL substring to focus on (default: list all)")
    ap.add_argument("--show", choices=["request", "response", "sse", "ws", "both"],
                    default="both", help="What to print for each matched entry")
    args = ap.parse_args()

    har = HARFile.load(args.har)

    if not args.filter:
        har.print_summary()
        return

    matches = har.find_all(args.filter)
    if not matches:
        print(f"No entries matching {args.filter!r}.")
        har.print_summary()
        return

    for i, e in enumerate(matches):
        print(f"\n{'═'*70}")
        print(f"  [{i}] {e.method} {e.url}")
        print(f"  status={e.status}  req-ce={e.header('content-encoding','request')}  "
              f"resp-ce={e.header('content-encoding','response')}")
        print('═'*70)

        if args.show in ("request", "both"):
            body = e.request_body_decoded()
            print(f"\n--- REQUEST BODY (decoded, {len(body)} chars) ---")
            print(body[:4000])

        if args.show in ("response", "both"):
            body = e.response_body_decoded()
            print(f"\n--- RESPONSE BODY (decoded, {len(body)} chars) ---")
            print(body[:4000])

        if args.show in ("sse", "both"):
            evs = e.sse_events()
            if evs:
                print(f"\n--- SSE EVENTS ({len(evs)}) ---")
                for ev in evs:
                    print(f"  event={ev.event!r}  data={ev.data[:200]!r}")

        if args.show in ("ws", "both"):
            frames = e.websocket_frames()
            if frames:
                print(f"\n--- WEBSOCKET FRAMES ({len(frames)}) ---")
                for f in frames[:50]:
                    arrow = "→" if f.direction == "send" else "←"
                    preview = (f.data.decode('utf-8', errors='replace')
                               if isinstance(f.data, bytes) else str(f.data))[:200]
                    print(f"  {arrow} op={f.opcode} t={f.time:.3f} {preview!r}")


if __name__ == "__main__":
    _main()
