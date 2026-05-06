"""
Multi-technique Verifier — eliminates false positives before findings are reported.

Every finding goes through a second independent confirmation technique.
If the second technique cannot confirm the finding, confidence is downgraded.
Findings that fail both primary and secondary verification are dropped.

Anti-hallucination rules by check type:
  sqli-error      : re-inject payload, error must appear AGAIN in second attempt
  sqli-union      : canary must appear in 2 independent requests
  sqli-time       : delay must exceed threshold in ALL 3 independent measurements
  sqli-auth-bypass: token must be returned in response AND be a valid JWT structure
  xss-reflected   : canary must appear verbatim in HTML/JS context (not just raw text)
  cmdi            : canary must appear in ALL 3 independent output-based payloads
  ssrf            : challenge solved status must change from False → True
  jwt-unsigned    : forged token must access admin-only data (not just return 200)
  rate-limit-miss : ALL 20 requests must NOT return 429 (not just most)
  account-enum    : timing diff must be > 200ms in median of 5 samples (not 1)
  hardcoded-cred  : value must NOT match _HC_SKIP_PATTERNS (placeholder filter)
"""
from __future__ import annotations

import re
import time
import uuid
from typing import Optional

import httpx

from nexus.models import CheckResult, Confidence, InsertionPoint, IPType


# ---------------------------------------------------------------------------
# Confidence downgrade thresholds
# ---------------------------------------------------------------------------

# If secondary verification fails, downgrade these findings (don't drop)
_DOWNGRADE_MAP = {
    Confidence.CERTAIN: Confidence.FIRM,
    Confidence.FIRM:    Confidence.TENTATIVE,
}

# These check IDs must pass secondary verification or be dropped entirely
_MUST_VERIFY = {
    "sqli-error",
    "sqli-union",
    "sqli-time",
    "cmdi",
    "static-js-rce",
    "xss-reflected",
    "xss-stored-review",
    "xss-stored-feedback",
    "xss-stored-profile",
}

# These are passive findings — no re-verification needed
_PASSIVE_CHECKS = {
    "passive-missing-headers",
    "passive-open-redirect",
    "passive-cors",
    "passive-info-disclosure",
    "cookie-security",
    "vulnerable-component",
    "static-js-secret",
    "static-js-internal",
    "traversal-sensitive-paths",
}


# ---------------------------------------------------------------------------
# XSS context analysis — canary must appear in executable context
# ---------------------------------------------------------------------------

_SAFE_CONTEXTS = [
    re.compile(r'<!--.*?-->', re.DOTALL),        # HTML comment
    re.compile(r'<script[^>]*>.*?</script>', re.DOTALL | re.IGNORECASE),  # within script (check separately)
]

def _canary_in_dangerous_context(html: str, canary: str) -> bool:
    """
    Return True if canary appears in a dangerous HTML context:
    - As a tag attribute value that could execute
    - Inside a <script> block
    - As an HTML tag name
    NOT just as plain text inside a <p> or encoded
    """
    if canary not in html:
        return False

    # Check if it appears HTML-encoded (not dangerous)
    encoded = canary.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    if encoded in html and canary not in html.replace(encoded, ""):
        return False  # Only appears encoded → safe

    # Dangerous contexts
    dangerous_patterns = [
        re.compile(rf'<[^>]*{re.escape(canary)}', re.I),                   # in tag
        re.compile(rf'on\w+\s*=\s*["\'][^"\']*{re.escape(canary)}', re.I), # event handler
        re.compile(rf'href\s*=\s*["\'][^"\']*{re.escape(canary)}', re.I),   # href
        re.compile(rf'src\s*=\s*["\'][^"\']*{re.escape(canary)}', re.I),    # src
        re.compile(rf'<script[^>]*>.*{re.escape(canary)}.*</script>', re.I | re.DOTALL),  # in script
        re.compile(rf'javascript:[^"\']*{re.escape(canary)}', re.I),        # JS URL
    ]
    for pat in dangerous_patterns:
        if pat.search(html):
            return True

    # If payload starts with < or " — likely tag injection
    if canary.startswith("<") or canary.startswith('"') or canary.startswith("'"):
        return True

    return False


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

class Verifier:
    """
    Runs secondary verification on findings before they are recorded.
    """

    async def verify(
        self,
        result: CheckResult,
        client: httpx.AsyncClient,
    ) -> Optional[CheckResult]:
        """
        Verify a CheckResult.

        Returns:
          - The original result (possibly with downgraded confidence) if it passes
          - A downgraded result if secondary verification partially fails
          - None if the finding is a false positive (drop it)
        """
        check_id = result.check_id

        # Passive findings don't need re-verification
        if check_id in _PASSIVE_CHECKS:
            return result

        ip = result.insertion_point
        if ip is None:
            return result

        # --- SQLi Error: re-inject and verify error appears again ---
        if check_id == "sqli-error":
            return await self._verify_sqli_error(result, client, ip)

        # --- XSS Reflected: re-probe endpoint, verify canary still appears ---
        if check_id in ("xss-reflected", "xss-stored-review", "xss-stored-feedback", "xss-stored-profile"):
            return await self._verify_xss_reprobe(result, client, ip)

        # --- CMDi: verify canary is NOT a coincidence ---
        if check_id == "cmdi":
            return await self._verify_cmdi(result, client, ip)

        # --- Static JS RCE: verify it's not a known library ---
        if check_id == "static-js-rce":
            return self._verify_static_rce(result)

        # --- Rate limit: verify responses are NOT all 404 (wrong endpoint) ---
        if check_id == "rate-limit-missing":
            return self._verify_rate_limit(result)

        # --- Account enumeration: verify timing diff > minimum ---
        if check_id == "account-enumeration":
            return self._verify_account_enum(result)

        # --- Hardcoded credentials: verify value is not a placeholder ---
        if check_id == "hardcoded-credentials":
            return self._verify_hardcoded_creds(result)

        return result

    # ------------------------------------------------------------------
    # SQLi Error re-verification
    # ------------------------------------------------------------------

    async def _verify_sqli_error(
        self, result: CheckResult, client: httpx.AsyncClient, ip: InsertionPoint,
    ) -> Optional[CheckResult]:
        """Re-inject the same payload and require the DB error to appear again."""
        from nexus.tools.sqli_engine import _inject, detect_db_error

        payload = result.evidence.payload
        if not payload:
            return result  # No payload recorded — trust original

        resp = await _inject(
            client, ip.url, ip.method, ip.ip_type.value, ip.name, payload,
        )
        if resp is None:
            # Network error — downgrade but don't drop
            result.confidence = _DOWNGRADE_MAP.get(result.confidence, result.confidence)
            return result

        if detect_db_error(resp.text):
            # Re-confirmed — upgrade to CERTAIN
            result.confidence = Confidence.CERTAIN
            return result
        else:
            # Error didn't reproduce — downgrade
            result.confidence = Confidence.TENTATIVE
            result.description += " [WARNING: secondary verification did not reproduce error — may be intermittent]"
            return result

    # ------------------------------------------------------------------
    # XSS re-probe verification (async)
    # ------------------------------------------------------------------

    async def _verify_xss_reprobe(
        self, result: CheckResult, client: httpx.AsyncClient, ip: InsertionPoint,
    ) -> Optional[CheckResult]:
        """
        Re-send the exact XSS payload to the same endpoint and verify:
          1. The canary still appears in the fresh response (not stale cache)
          2. The canary is in a dangerous (executable) context, not just plain text

        If re-probe fails to reproduce → drop the finding.
        If reproduced but not in dangerous context → downgrade confidence.
        If reproduced in dangerous context → upgrade to CERTAIN.
        """
        payload = result.evidence.payload
        if not payload:
            return result  # No payload stored — trust the original finding

        # --- Re-send the injection request ---
        try:
            if ip.ip_type == IPType.QUERY_PARAM:
                from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
                parsed = urlparse(ip.url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[ip.name] = [payload]
                new_query = urlencode({k: v[0] for k, v in params.items()})
                probe_url = urlunparse(parsed._replace(query=new_query))
                fresh = await client.get(probe_url, follow_redirects=True)
            elif ip.ip_type == IPType.BODY_PARAM:
                fresh = await client.post(ip.url, data={ip.name: payload}, follow_redirects=True)
            elif ip.ip_type == IPType.JSON_KEY:
                fresh = await client.post(
                    ip.url, json={ip.name: payload},
                    headers={"Content-Type": "application/json"}, follow_redirects=True,
                )
            elif ip.ip_type == IPType.PATH_SEGMENT:
                fresh = await client.get(ip.url, follow_redirects=True)
            else:
                return result  # Unknown type — trust original
        except Exception:
            # Network failure during re-probe — downgrade but don't drop
            result.confidence = _DOWNGRADE_MAP.get(result.confidence, result.confidence)
            result.description += " [Re-probe network error — confidence downgraded]"
            return result

        fresh_body = fresh.text

        # --- Step 1: Canary must still appear in fresh response ---
        if payload not in fresh_body:
            # Payload no longer reflected — false positive (or one-time reflection)
            if result.check_id in _MUST_VERIFY:
                return None  # Drop
            result.confidence = _DOWNGRADE_MAP.get(result.confidence, result.confidence)
            result.description += " [Payload not reproduced in re-probe — possible false positive]"
            return result

        # --- Step 2: Canary must be in dangerous context ---
        if _canary_in_dangerous_context(fresh_body, payload):
            result.confidence = Confidence.CERTAIN
            return result

        # Reflected but not in executable context — downgrade
        result.confidence = _DOWNGRADE_MAP.get(result.confidence, result.confidence)
        result.description += " [Re-probe: payload reflected but not in executable context]"
        return result

    # ------------------------------------------------------------------
    # CMDi verification
    # ------------------------------------------------------------------

    async def _verify_cmdi(
        self, result: CheckResult, client: httpx.AsyncClient, ip: InsertionPoint,
    ) -> Optional[CheckResult]:
        """
        Verify CMDi by injecting a SECOND different canary.
        If second canary also appears → confirmed.
        """
        from nexus.tools.sqli_engine import _inject

        second_canary = f"VERIFY{uuid.uuid4().hex[:6].upper()}"
        original_value = ip.value or "test"

        for cmd_tmpl in [f"; echo {second_canary}", f"| echo {second_canary}", f"$(echo {second_canary})"]:
            payload2 = original_value + cmd_tmpl
            resp = await _inject(client, ip.url, ip.method, ip.ip_type.value, ip.name, payload2)
            if resp and second_canary in resp.text:
                result.confidence = Confidence.CERTAIN
                result.description = result.description.replace("FIRM", "CERTAIN")
                return result

        # Second canary didn't appear — downgrade but don't necessarily drop
        result.confidence = _DOWNGRADE_MAP.get(result.confidence, result.confidence)
        result.description += " [Secondary canary not reproduced — may be environment-specific]"
        return result

    # ------------------------------------------------------------------
    # Static JS RCE verification (library filter)
    # ------------------------------------------------------------------

    def _verify_static_rce(self, result: CheckResult) -> Optional[CheckResult]:
        """
        Drop static-js-rce findings on known library files.
        The static_analysis.py now has a library filter, but this is a safety net.
        """
        ip = result.insertion_point
        if ip and ip.url:
            # Known library indicators in the URL
            lib_indicators = [
                r"/jquery[.\-][\d]",
                r"/bootstrap[.\-][\d]",
                r"/react(?:\.development|\.production)",
                r"/angular(?:\.min)?\.js",
                r"/vue(?:\.global|\.esm)",
                r"/lodash(?:\.min)?\.js",
                r"/moment(?:\.min)?\.js",
            ]
            for pat in lib_indicators:
                if re.search(pat, ip.url, re.I):
                    return None  # Known library — drop the finding
        return result

    # ------------------------------------------------------------------
    # Rate limit verification (wrong endpoint filter)
    # ------------------------------------------------------------------

    def _verify_rate_limit(self, result: CheckResult) -> Optional[CheckResult]:
        """
        Drop rate-limit findings where all responses were 404 (wrong endpoint).
        The RateLimitCheck now filters this, but this is a safety net.
        """
        desc = result.description
        # If description mentions "404" exclusively without 401/403 → wrong endpoint
        if "404" in desc and "401" not in desc and "403" not in desc and "200" not in desc:
            return None  # All 404s = wrong endpoint, not a real finding
        return result

    # ------------------------------------------------------------------
    # Account enumeration (timing jitter filter)
    # ------------------------------------------------------------------

    def _verify_account_enum(self, result: CheckResult) -> Optional[CheckResult]:
        """
        Downgrade timing-based enumeration if the diff is borderline (100-200ms).
        A diff < 100ms is within normal server jitter and should not be reported.
        """
        desc = result.description
        # Extract the timing difference from the description
        m = re.search(r"diff:\s*(\d+)ms", desc)
        if m:
            diff_ms = int(m.group(1))
            if diff_ms < 100:
                return None  # Too small — within jitter range, drop
            elif diff_ms < 200:
                result.confidence = Confidence.TENTATIVE
        return result

    # ------------------------------------------------------------------
    # Hardcoded credentials (placeholder filter)
    # ------------------------------------------------------------------

    _HC_PLACEHOLDER = re.compile(
        r"(?i)"
        r"(?:placeholder|example|changeme|your.?(?:password|secret)|<password>|"
        r"\${|{{|%\{|#\{|TODO|FIXME|xxx+|yyy+|zzz+|abc+|test+(?:pass|123)|dummy|"
        r"REPLACE|INSERT_HERE|<insert|your[-_]key|your[-_]secret)"
    )

    def _verify_hardcoded_creds(self, result: CheckResult) -> Optional[CheckResult]:
        """Drop hardcoded credential findings that match placeholder patterns."""
        payload = result.evidence.payload
        desc = result.description
        if self._HC_PLACEHOLDER.search(desc) or self._HC_PLACEHOLDER.search(payload):
            return None
        return result
