"""
Target adapters — decouple "what payload" from "how to deliver it".

Three adapters:
  - JSONFieldAdapter   : current --chat-field flow (manual config)
  - HARReplayAdapter   : replay a captured Burp/HAR request, swapping in payloads
  - OllamaAdapter      : direct Ollama API (handles NDJSON streaming responses)

Every adapter exposes the same interface:
    adapter.send(prompt: str) -> str
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx


class TargetAdapter:
    """Base adapter. Concrete subclasses translate string prompt → string response."""

    name: str = "adapter"

    def send(self, prompt: str) -> str:
        raise NotImplementedError


# ─────────────────────────────────────────────────────────────────────────────
# 1. Ollama adapter — handles the NDJSON streaming bug we hit earlier
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class OllamaAdapter(TargetAdapter):
    host: str
    model: str
    proxy: Optional[str] = None
    timeout: int = 120
    name: str = "ollama"

    def __post_init__(self) -> None:
        kwargs: Dict[str, Any] = {"timeout": self.timeout, "base_url": self.host}
        if self.proxy:
            kwargs["proxy"] = self.proxy
            kwargs["verify"] = False
        self._client = httpx.Client(**kwargs)

    def send(self, prompt: str) -> str:
        try:
            resp = self._client.post(
                "/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 1.0, "num_predict": 2048},
                },
            )
        except httpx.HTTPError as exc:
            return f"__ERROR__ {exc}"

        if resp.status_code >= 400:
            return f"__ERROR__ HTTP {resp.status_code}"

        body = resp.text.strip()
        # NDJSON streaming case (proxy ignored stream:false)
        if "\n" in body:
            chunks: List[str] = []
            for line in body.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if obj.get("response"):
                        chunks.append(obj["response"])
                    if obj.get("done"):
                        break
                except json.JSONDecodeError:
                    continue
            return "".join(chunks)
        try:
            return json.loads(body).get("response", "")
        except json.JSONDecodeError:
            return body


# ─────────────────────────────────────────────────────────────────────────────
# 2. JSONField adapter — for arbitrary HTTPS endpoints with known schema
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class JSONFieldAdapter(TargetAdapter):
    url: str
    prompt_field: str = "message"
    response_jsonpath: str = ""           # e.g. "data.choices.0.message.content"
    extra_body: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: str = ""
    proxy: Optional[str] = None
    timeout: int = 60
    method: str = "POST"
    name: str = "json_field"

    def __post_init__(self) -> None:
        h = {"Content-Type": "application/json", "Accept": "application/json", **self.headers}
        if self.cookies:
            h["Cookie"] = self.cookies
        kwargs: Dict[str, Any] = {"timeout": self.timeout, "headers": h}
        if self.proxy:
            kwargs["proxy"] = self.proxy
            kwargs["verify"] = False
        self._client = httpx.Client(**kwargs)

    def send(self, prompt: str) -> str:
        body = {**self.extra_body, self.prompt_field: prompt}
        try:
            resp = self._client.request(self.method, self.url, json=body)
        except httpx.HTTPError as exc:
            return f"__ERROR__ {exc}"
        if resp.status_code >= 400:
            return f"__ERROR__ HTTP {resp.status_code} {resp.text[:200]}"
        try:
            data = resp.json()
            return _extract_jsonpath(data, self.response_jsonpath) if self.response_jsonpath else json.dumps(data)
        except json.JSONDecodeError:
            return resp.text


# ─────────────────────────────────────────────────────────────────────────────
# 3. HAR replay adapter — the killer. Capture once in Burp, replay forever.
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HARReplayAdapter(TargetAdapter):
    """
    Replay a captured HTTP request, substituting the prompt at a known location.

    Workflow:
      1. User makes one real AI request in their browser through Burp/DevTools
      2. They export the request as HAR or paste raw HTTP
      3. They tell us what unique string they typed as the prompt (sentinel_prompt)
      4. We find that string in the request body, mark it as the prompt slot
      5. We optionally find the response text location too (so we know what to extract)

    From then on, every call to send(prompt) produces a real-looking request.
    """
    request_url: str
    request_method: str
    request_headers: Dict[str, str]
    body_template: str                     # has {NEXUS_PROMPT_SLOT} where the prompt goes
    response_jsonpath: str = ""
    proxy: Optional[str] = None
    timeout: int = 60
    name: str = "har_replay"

    def __post_init__(self) -> None:
        kwargs: Dict[str, Any] = {"timeout": self.timeout}
        if self.proxy:
            kwargs["proxy"] = self.proxy
            kwargs["verify"] = False
        self._client = httpx.Client(**kwargs)

    def send(self, prompt: str) -> str:
        # JSON-escape the prompt without surrounding quotes so it slots into a string field
        encoded = json.dumps(prompt)[1:-1]
        body = self.body_template.replace("{NEXUS_PROMPT_SLOT}", encoded)
        try:
            resp = self._client.request(
                self.request_method, self.request_url,
                headers=self.request_headers, content=body,
            )
        except httpx.HTTPError as exc:
            return f"__ERROR__ {exc}"
        if resp.status_code >= 400:
            return f"__ERROR__ HTTP {resp.status_code} {resp.text[:200]}"

        # Extract response
        ctype = resp.headers.get("content-type", "")
        if "application/json" in ctype:
            try:
                data = resp.json()
                return _extract_jsonpath(data, self.response_jsonpath) if self.response_jsonpath else json.dumps(data)
            except json.JSONDecodeError:
                pass
        # NDJSON
        if "x-ndjson" in ctype or "\n{" in resp.text[:200]:
            return _join_ndjson_response_field(resp.text)
        return resp.text

    @classmethod
    def from_har(cls, har_path: str, sentinel_prompt: str,
                 sentinel_response: str = "", proxy: Optional[str] = None) -> "HARReplayAdapter":
        with open(har_path) as f:
            har = json.load(f)
        entries = har.get("log", {}).get("entries", [])
        # Find the entry whose request body contains our sentinel
        for e in entries:
            body = (e.get("request", {}).get("postData", {}) or {}).get("text", "") or ""
            if sentinel_prompt in body:
                req = e["request"]
                template = body.replace(sentinel_prompt, "{NEXUS_PROMPT_SLOT}")
                headers = {h["name"]: h["value"] for h in req.get("headers", [])
                           if h["name"].lower() not in ("content-length", "host")}
                # Try to locate response field
                resp_path = ""
                if sentinel_response:
                    resp_text = (e.get("response", {}).get("content", {}) or {}).get("text", "") or ""
                    try:
                        resp_path = _find_jsonpath_to_string(json.loads(resp_text), sentinel_response)
                    except Exception:
                        resp_path = ""
                return cls(
                    request_url=req["url"],
                    request_method=req["method"],
                    request_headers=headers,
                    body_template=template,
                    response_jsonpath=resp_path,
                    proxy=proxy,
                )
        raise ValueError(
            f"Sentinel prompt {sentinel_prompt!r} not found in any HAR entry. "
            f"Make sure the captured request used this exact text."
        )

    @classmethod
    def from_raw_http(cls, raw_request: str, sentinel_prompt: str, base_url: str,
                      proxy: Optional[str] = None, response_jsonpath: str = "") -> "HARReplayAdapter":
        """Parse a Burp 'Copy as raw HTTP' string (request line + headers + blank + body)."""
        head, _, body = raw_request.partition("\r\n\r\n")
        if not body:
            head, _, body = raw_request.partition("\n\n")
        lines = head.splitlines()
        method, path, _ = lines[0].split(maxsplit=2)
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip().lower() not in ("content-length", "host"):
                    headers[k.strip()] = v.strip()
        if sentinel_prompt not in body:
            raise ValueError(f"Sentinel {sentinel_prompt!r} not found in request body")
        template = body.replace(sentinel_prompt, "{NEXUS_PROMPT_SLOT}")
        url = base_url.rstrip("/") + path
        return cls(
            request_url=url, request_method=method,
            request_headers=headers, body_template=template,
            response_jsonpath=response_jsonpath, proxy=proxy,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_jsonpath(data: Any, path: str) -> str:
    """Dot-path with numeric indices: 'data.choices.0.message.content'."""
    if not path:
        return json.dumps(data) if not isinstance(data, str) else data
    cur: Any = data
    for part in path.split("."):
        if cur is None:
            return ""
        if part.isdigit() and isinstance(cur, list):
            idx = int(part)
            cur = cur[idx] if idx < len(cur) else None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return ""
    if isinstance(cur, str):
        return cur
    return json.dumps(cur) if cur is not None else ""


def _find_jsonpath_to_string(data: Any, target: str, path: str = "") -> str:
    """Search a JSON tree for a string containing `target`. Return dot-path to it."""
    if isinstance(data, str) and target in data:
        return path
    if isinstance(data, dict):
        for k, v in data.items():
            sub = path + "." + k if path else k
            r = _find_jsonpath_to_string(v, target, sub)
            if r:
                return r
    elif isinstance(data, list):
        for i, v in enumerate(data):
            sub = path + "." + str(i) if path else str(i)
            r = _find_jsonpath_to_string(v, target, sub)
            if r:
                return r
    return ""


def _join_ndjson_response_field(body: str) -> str:
    chunks: List[str] = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Common token-streaming field names
        for key in ("response", "delta", "text", "content", "token"):
            v = obj.get(key)
            if isinstance(v, str):
                chunks.append(v)
                break
        if obj.get("done") or obj.get("finish_reason"):
            break
    return "".join(chunks)
