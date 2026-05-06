"""
BaseScanCheck — ABC every vulnerability check must subclass.

Pattern mirrors BurpSuite's IScanCheck:
  - check_passive(crawl_result) → list[CheckResult]
  - check_active(insertion_point, client) → list[CheckResult]

Only override the methods that make sense for your check type.
"""
from abc import ABC, abstractmethod
from typing import Optional
import difflib

import httpx

from nexus.models import (
    CheckResult,
    CheckType,
    CrawlResult,
    Evidence,
    InsertionPoint,
)


class BaseScanCheck(ABC):
    # Every subclass declares these at class level
    check_id: str = ""
    check_type: CheckType = CheckType.ACTIVE
    name: str = ""
    description: str = ""

    @classmethod
    def reset(cls) -> None:
        """
        Reset all per-scan state so this check can fire again on the next target.
        CheckRunner calls this at the start of every run(). Subclasses that use
        class-level _attempted flags benefit automatically; override if you need
        to reset additional state.
        """
        cls._attempted = False

    async def check_passive(
        self,
        crawl_result: CrawlResult,
    ) -> list[CheckResult]:
        """
        Analyse a CrawlResult without sending any additional requests.
        Override in PASSIVE checks.
        """
        return []

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        """
        Send probe requests via *client* against *insertion_point*.
        Override in ACTIVE/OAST checks.
        """
        return []

    # ------------------------------------------------------------------
    # Helper utilities available to all checks
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Content-Type gating helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _ct_is_html(content_type: str) -> bool:
        """Return True if the content-type indicates an HTML page."""
        ct = content_type.lower()
        return "html" in ct or "xhtml" in ct

    @staticmethod
    def _ct_is_json(content_type: str) -> bool:
        ct = content_type.lower()
        return "json" in ct or "javascript" in ct

    @staticmethod
    def _ct_is_xml(content_type: str) -> bool:
        ct = content_type.lower()
        return "xml" in ct

    @staticmethod
    def _ct_is_binary(content_type: str) -> bool:
        ct = content_type.lower()
        return any(k in ct for k in (
            "image/", "audio/", "video/", "font/",
            "application/pdf", "application/zip",
            "application/octet-stream",
        ))

    def _build_url(self, ip: InsertionPoint, payload: str) -> str:
        """Inject *payload* into a QUERY_PARAM or PATH_SEGMENT insertion point."""
        from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

        parsed = urlparse(ip.url)
        if ip.ip_type.value in ("QUERY_PARAM",):
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[ip.name] = [payload]
            new_query = urlencode(
                {k: v[0] for k, v in params.items()}, quote_via=lambda s, *_: s
            )
            return urlunparse(parsed._replace(query=new_query))
        return ip.url

    def _build_request_line(
        self,
        method: str,
        url: str,
        headers: dict,
        body: Optional[str] = None,
    ) -> str:
        """Format a raw HTTP request string for Evidence.request_raw."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        lines = [f"{method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        if body:
            lines.append(f"Content-Length: {len(body)}")
            lines.append("")
            lines.append(body)
        return "\n".join(lines)

    def _poc_curl(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        body: Optional[str] = None,
    ) -> str:
        """Generate a curl one-liner PoC."""
        parts = [f"curl -s -i -X {method}"]
        if headers:
            for k, v in headers.items():
                if k.lower() not in ("user-agent",):
                    parts.append(f"-H '{k}: {v}'")
        if body:
            parts.append(f"-d '{body}'")
        parts.append(f"'{url}'")
        return " ".join(parts)

    # ------------------------------------------------------------------
    # Differential / response-comparison helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _responses_differ(benign_body: str, probe_body: str, threshold: float = 0.05) -> bool:
        """
        Return True if the probe response differs meaningfully from the benign baseline.
        Uses SequenceMatcher ratio: 1.0 = identical, 0.0 = completely different.
        threshold=0.05 means we require at least 5% content change.
        """
        ratio = difflib.SequenceMatcher(None, benign_body, probe_body).ratio()
        return ratio < (1.0 - threshold)

    @staticmethod
    def _canary_only_in_probe(benign_body: str, probe_body: str, canary: str) -> bool:
        """
        Return True if canary appears in probe response but NOT in the baseline.
        This is the gold standard for injection confirmation.
        """
        return canary not in benign_body and canary in probe_body

    @staticmethod
    def _response_length_diff_pct(benign_body: str, probe_body: str) -> float:
        """Return percentage length difference between two responses (0.0–1.0)."""
        if not benign_body:
            return 1.0 if probe_body else 0.0
        return abs(len(probe_body) - len(benign_body)) / max(len(benign_body), 1)

    @staticmethod
    def _fmt_response(resp: httpx.Response, body_limit: int = 3000) -> tuple[str, int, float]:
        """Format an httpx.Response into raw HTTP/1.1 text.

        Returns (raw_text, content_length_bytes, elapsed_ms).
        """
        status = resp.status_code
        reason = getattr(resp, "reason_phrase", "")
        content = resp.content          # bytes
        content_len = len(content)
        elapsed_ms = 0.0
        if hasattr(resp, "elapsed") and resp.elapsed is not None:
            elapsed_ms = resp.elapsed.total_seconds() * 1000

        headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        body_text = resp.text
        truncated = content_len > body_limit
        body_preview = body_text[:body_limit]
        tail = f"\n... [{content_len - body_limit} more bytes truncated]" if truncated else ""

        raw = (
            f"HTTP/1.1 {status} {reason}\n"
            f"{headers_str}\n\n"
            f"{body_preview}{tail}"
        )
        return raw, content_len, elapsed_ms

    def _make_evidence(
        self,
        request_raw: str = "",
        response: Optional[httpx.Response] = None,
        baseline: Optional[httpx.Response] = None,
        payload: str = "",
        poc_curl: str = "",
        highlighted_evidence: str = "",
        oast_callback: str = "",
    ) -> Evidence:
        """Build a fully-populated Evidence object.

        Args:
            request_raw:          The full HTTP/1.1 request text (attack request).
            response:             The httpx.Response from the attack request.
            baseline:             The httpx.Response from the benign baseline request.
            payload:              The injection payload string.
            poc_curl:             A curl one-liner that reproduces the finding.
            highlighted_evidence: The exact bytes/snippet from the response proving the vuln.
            oast_callback:        OAST/Collaborator callback URL if applicable.
        """
        resp_raw, resp_len, resp_ms = ("", 0, 0.0)
        resp_status = 0
        if response is not None:
            resp_raw, resp_len, resp_ms = self._fmt_response(response)
            resp_status = response.status_code

        base_raw, base_len, base_ms = ("", 0, 0.0)
        base_status = 0
        if baseline is not None:
            base_raw, base_len, base_ms = self._fmt_response(baseline, body_limit=1000)
            base_status = baseline.status_code

        return Evidence(
            request_raw=request_raw,
            response_raw=resp_raw,
            response_status=resp_status,
            response_length=resp_len,
            response_time_ms=resp_ms,
            baseline_raw=base_raw,
            baseline_status=base_status,
            baseline_length=base_len,
            baseline_time_ms=base_ms,
            length_delta=resp_len - base_len,
            highlighted_evidence=highlighted_evidence,
            payload=payload,
            poc_curl=poc_curl,
            oast_callback=oast_callback,
        )
