"""
js_surface_mapper.py — Async JS attack surface extractor, adapted from CAI.

Extracts from JS bundles (inline + external assets):
  - API endpoint paths  (/api/users, /graphql, /admin/…)
  - Full URLs (cross-origin origins)
  - GraphQL endpoints + operation names + persisted query hashes
  - WebSocket / SSE endpoints
  - Source-map contents (optional)
  - High-value keyword hints (admin, billing, debug, rbac, …)

Integrated into Crawler as a Phase 0 step to maximise insertion point
discovery before any active checks run.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns (ported from CAI js_surface_mapper.py)
# ---------------------------------------------------------------------------

_FULL_URL_RE      = re.compile(r"https?://[^\s\"'<>\\)]{5,200}")
_WS_URL_RE        = re.compile(r"wss?://[^\s\"'<>\\)]{5,200}")
_GQL_ENDPOINT_RE  = re.compile(r"/graphql\b|/gql\b", re.IGNORECASE)
_GQL_OPNAME_RE    = re.compile(r'operationName\s*[:=]\s*["\']([A-Za-z0-9_]{2,})["\']')
_GQL_OP_RE        = re.compile(r'\b(query|mutation|subscription)\s+([A-Za-z0-9_]{2,})')
_PERSISTED_RE     = re.compile(r'sha256Hash\s*[:=]\s*["\']([a-fA-F0-9]{16,64})["\']')
_SOURCE_MAP_RE    = re.compile(r'^\s*//#\s*sourceMappingURL\s*=\s*(\S+)\s*$', re.MULTILINE)

_PATH_ENDPOINT_RE = re.compile(
    r"(?<![A-Za-z0-9_])/(?:"
    r"api|graphql|gql|v\d+|admin|internal|export|download|uploads|files|"
    r"report|reports|billing|oauth|auth|login|logout|session|sessions|"
    r"token|tokens|users|user|account|accounts|tenant|tenants|org|orgs|"
    r"organization|organizations|project|projects|team|teams|workspace|workspaces|"
    r"invoice|invoices|payment|checkout|order|orders|cart|carts|subscription|subscriptions|"
    r"feature|features|flag|flags|debug|preview|staging|webhook|webhooks|"
    r"secret|secrets|config|configuration|management|manage|dashboard|panel"
    r")(?:[A-Za-z0-9_/\-.?=&%]*)"
)

_HIGH_VALUE = [
    "admin", "entitlement", "featureflag", "feature_flag", "flag", "debug",
    "internal", "staging", "preview", "billing", "invoice", "payment", "export",
    "report", "impersonate", "impersonation", "role", "permission", "rbac",
    "tenant", "organization", "workspace", "secret", "apikey", "api_key",
    "webhook", "management", "dashboard",
]


# ---------------------------------------------------------------------------
# HTML parser — collects script srcs and inline content
# ---------------------------------------------------------------------------

class _ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.script_srcs: List[str] = []
        self.inline_scripts: List[str] = []
        self.link_hrefs: List[str] = []
        self._in_script = False
        self._buf: List[str] = []

    def handle_starttag(self, tag: str, attrs):
        d = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "script":
            src = d.get("src", "").strip()
            if src:
                self.script_srcs.append(src)
            else:
                self._in_script = True
                self._buf = []
        elif tag.lower() == "link":
            rel = d.get("rel", "").lower()
            as_  = d.get("as", "").lower()
            href = d.get("href", "").strip()
            if href and (rel in ("modulepreload", "preload") or as_ == "script"):
                self.link_hrefs.append(href)

    def handle_endtag(self, tag: str):
        if tag.lower() == "script" and self._in_script:
            content = "".join(self._buf).strip()
            if content:
                self.inline_scripts.append(content)
            self._in_script = False
            self._buf = []

    def handle_data(self, data: str):
        if self._in_script:
            self._buf.append(data)


# ---------------------------------------------------------------------------
# Extraction result container
# ---------------------------------------------------------------------------

@dataclass
class SurfaceResult:
    base_url:          str
    origins:           Set[str]          = field(default_factory=set)
    endpoints:         Set[str]          = field(default_factory=set)
    graphql_endpoints: Set[str]          = field(default_factory=set)
    graphql_ops:       Set[str]          = field(default_factory=set)
    persisted_hashes:  Set[str]          = field(default_factory=set)
    ws_endpoints:      Set[str]          = field(default_factory=set)
    high_value:        Set[str]          = field(default_factory=set)
    errors:            List[str]         = field(default_factory=list)
    evidence:          Dict[str, List[str]] = field(default_factory=dict)

    def merge(self, other: "SurfaceResult") -> None:
        self.origins           |= other.origins
        self.endpoints         |= other.endpoints
        self.graphql_endpoints |= other.graphql_endpoints
        self.graphql_ops       |= other.graphql_ops
        self.persisted_hashes  |= other.persisted_hashes
        self.ws_endpoints      |= other.ws_endpoints
        self.high_value        |= other.high_value
        self.errors.extend(other.errors)
        for k, v in other.evidence.items():
            self.evidence.setdefault(k, []).extend(v)

    def to_dict(self) -> dict:
        return {
            "base_url":          self.base_url,
            "origins":           sorted(o for o in self.origins if o),
            "endpoints":         sorted(self.endpoints),
            "graphql_endpoints": sorted(self.graphql_endpoints),
            "graphql_ops":       sorted(self.graphql_ops),
            "persisted_hashes":  sorted(self.persisted_hashes),
            "ws_endpoints":      sorted(self.ws_endpoints),
            "high_value":        sorted(self.high_value),
            "errors":            self.errors,
            "evidence":          {k: v[:3] for k, v in self.evidence.items()},
        }


# ---------------------------------------------------------------------------
# Core extractor
# ---------------------------------------------------------------------------

def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""


def _extract_from_text(text: str, label: str, base_origin: str) -> SurfaceResult:
    r = SurfaceResult(base_url=base_origin)
    if not text:
        return r

    for url in _FULL_URL_RE.findall(text):
        r.origins.add(_origin(url))
        if _GQL_ENDPOINT_RE.search(url):
            r.graphql_endpoints.add(url)

    for url in _WS_URL_RE.findall(text):
        r.ws_endpoints.add(url)
        r.origins.add(_origin(url))

    for path in _PATH_ENDPOINT_RE.findall(text):
        if path.startswith("/") and len(path) > 2:
            r.endpoints.add(path)
            if _GQL_ENDPOINT_RE.search(path):
                r.graphql_endpoints.add(urljoin(base_origin + "/", path))
            r.evidence.setdefault(path, []).append(label)

    for op in _GQL_OPNAME_RE.findall(text):
        r.graphql_ops.add(op)
    for _, op in _GQL_OP_RE.findall(text):
        r.graphql_ops.add(op)

    for h in _PERSISTED_RE.findall(text):
        r.persisted_hashes.add(h)

    low = text.lower()
    for s in _HIGH_VALUE:
        if s in low:
            r.high_value.add(s)

    return r


# ---------------------------------------------------------------------------
# Async surface mapper
# ---------------------------------------------------------------------------

class JsSurfaceMapper:
    """
    Async JS attack surface mapper.

    Call `run(client, base_url)` to get a `SurfaceResult` containing
    all discovered endpoints, GraphQL ops, WebSocket URLs, and high-value hints.
    """

    def __init__(
        self,
        max_assets: int = 40,
        max_bytes_per_asset: int = 2_000_000,
        include_sourcemaps: bool = False,
        same_origin_only: bool = True,
        timeout: float = 10.0,
        entry_paths: Optional[List[str]] = None,
    ):
        self.max_assets       = max_assets
        self.max_bytes        = max_bytes_per_asset
        self.include_sm       = include_sourcemaps
        self.same_origin_only = same_origin_only
        self.timeout          = timeout
        self.entry_paths      = entry_paths or ["/"]

    async def run(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        cookies: Optional[dict] = None,
    ) -> SurfaceResult:
        base_url     = base_url.rstrip("/")
        base_origin  = _origin(base_url) or base_url
        result       = SurfaceResult(base_url=base_url, origins={base_origin})
        seen_assets: Set[str] = set()
        assets: List[str]     = []

        # ── Phase 1: parse HTML entry pages ──────────────────────────────────
        for path in self.entry_paths:
            entry_url = (
                path if path.startswith("http")
                else urljoin(base_url + "/", path.lstrip("/"))
            )
            html, err = await self._fetch(client, entry_url, cookies)
            if err:
                result.errors.append(err)
                continue

            parser = _ScriptParser()
            parser.feed(html)

            # Inline scripts
            for idx, inline in enumerate(parser.inline_scripts):
                sub = _extract_from_text(inline, f"{entry_url}#inline{idx+1}", base_origin)
                result.merge(sub)

            # External JS assets
            for src in parser.script_srcs + parser.link_hrefs:
                full = src if src.startswith("http") else urljoin(entry_url, src)
                if full not in seen_assets:
                    if self.same_origin_only and _origin(full) not in ("", base_origin):
                        continue
                    seen_assets.add(full)
                    assets.append(full)
                    if len(assets) >= self.max_assets:
                        break

        # ── Phase 2: fetch JS assets concurrently ────────────────────────────
        sem = asyncio.Semaphore(8)

        async def _process_asset(asset_url: str):
            async with sem:
                js, err = await self._fetch(client, asset_url, cookies)
                if err:
                    result.errors.append(err)
                    return
                sub = _extract_from_text(js, asset_url, base_origin)
                result.merge(sub)

                # Source maps
                if self.include_sm:
                    for sm_ref in _SOURCE_MAP_RE.findall(js):
                        sm_url = (
                            sm_ref if sm_ref.startswith("http")
                            else urljoin(asset_url, sm_ref)
                        )
                        sm_text, sm_err = await self._fetch(client, sm_url, cookies)
                        if sm_err:
                            result.errors.append(sm_err)
                            continue
                        try:
                            sm_json = json.loads(sm_text)
                            for idx, src_content in enumerate(
                                (sm_json.get("sourcesContent") or [])[:50]
                            ):
                                sub2 = _extract_from_text(
                                    src_content or "", f"{sm_url}#src{idx+1}", base_origin
                                )
                                result.merge(sub2)
                        except Exception as exc:
                            result.errors.append(f"{sm_url}: sourcemap parse error: {exc}")

        await asyncio.gather(*[_process_asset(a) for a in assets[:self.max_assets]])

        logger.info(
            "[js-surface] %s → %d endpoints, %d gql ops, %d ws, %d high-value hints",
            base_url,
            len(result.endpoints),
            len(result.graphql_ops),
            len(result.ws_endpoints),
            len(result.high_value),
        )
        return result

    async def _fetch(
        self,
        client: httpx.AsyncClient,
        url: str,
        cookies: Optional[dict],
    ) -> Tuple[str, Optional[str]]:
        try:
            headers = {}
            if cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
            resp = await client.get(url, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
            # Read up to max_bytes
            content = resp.content[: self.max_bytes]
            return content.decode(errors="replace"), None
        except Exception as exc:
            return "", f"{url} → {exc}"
