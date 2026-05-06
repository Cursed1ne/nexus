"""
Static Analysis Check — scans JS bundles served by the target for:
  - eval() / vm.runInNewContext() → RCE code paths
  - child_process.exec / execSync / spawn → OS command execution
  - Hardcoded secrets (JWT secrets, API keys, passwords)
  - Dangerous template rendering patterns
  - Internal service URLs / IP addresses leaked in JS

This check does NOT send attack payloads — it reads what the server serves.
"""
import re
from typing import Optional
from urllib.parse import urlparse, urljoin

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

# ---- Dangerous code patterns ----
_RCE_PATTERNS: list[tuple[str, str, Severity, float]] = [
    # (regex, description, severity, cvss)
    (r"eval\s*\((?!false|true|null|undefined|\"|\')[^)]{0,200}\)",
     "eval() with dynamic argument — potential RCE if user-controlled", Severity.CRITICAL, 9.8),
    (r"vm\.runInNewContext\s*\(",
     "vm.runInNewContext() — Node.js VM sandbox escape risk", Severity.CRITICAL, 9.8),
    (r"child_process['\"]?\s*\)?\s*\.\s*(exec|execSync|spawn|spawnSync|fork)\s*\(",
     "child_process execution method — OS command injection risk", Severity.CRITICAL, 9.8),
    (r"require\s*\(\s*['\"]child_process['\"]\s*\)",
     "child_process module imported — check for dynamic exec", Severity.HIGH, 8.5),
    (r"Function\s*\(\s*['\"]return|new\s+Function\s*\(",
     "new Function() constructor — code injection risk", Severity.HIGH, 8.5),
    (r"notevil\.eval\s*\(",
     "notevil.eval() — VM sandbox escape (CVE pattern)", Severity.CRITICAL, 9.8),
    (r"\.exec\s*\(\s*(?:req|body|params|query|input|data|cmd|command)",
     "exec() called with HTTP input — command injection", Severity.CRITICAL, 9.8),
    (r"dangerouslySetInnerHTML\s*=\s*\{\s*\{",
     "React dangerouslySetInnerHTML — XSS risk", Severity.HIGH, 7.5),
    # Template injection
    (r"pug\.render\s*\(|ejs\.render\s*\(|\.render\s*\([^)]{0,50}(?:req|body|param)",
     "Template engine rendering user input", Severity.CRITICAL, 9.8),
    (r"nunjucks\.renderString\s*\(|handlebars\.compile\s*\(",
     "Template engine compile/renderString — SSTI risk", Severity.HIGH, 8.5),
]

# ---- Hardcoded secret patterns ----
_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"['\"]?jwt[_\-]?secret['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
     "JWT secret hardcoded"),
    (r"['\"]?secret[_\-]?key['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
     "Secret key hardcoded"),
    (r"['\"]?api[_\-]?key['\"]?\s*[:=]\s*['\"]([^'\"]{16,})['\"]",
     "API key hardcoded"),
    (r"['\"]?password['\"]?\s*[:=]\s*['\"]([^'\"]{6,})['\"]",
     "Hardcoded password"),
    (r"Bearer\s+([A-Za-z0-9_\-\.]{50,})",
     "Hardcoded Bearer token"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
     "Private key in source"),
    (r"['\"]?admin[_\-]?email['\"]?\s*[:=]\s*['\"]([^'\"@]+@[^'\"]+)['\"]",
     "Admin email hardcoded"),
]

# ---- Internal resource patterns ----
_INTERNAL_PATTERNS: list[tuple[str, str]] = [
    (r"http://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)(?::\d+)?/[^\s'\"]{5,}",
     "Internal URL in source"),
    (r"169\.254\.169\.254",
     "AWS metadata IP in source — SSRF risk"),
    (r"/etc/(?:passwd|shadow|hosts|crontab)",
     "Sensitive file path in source"),
    (r"\/proc\/(?:self|[0-9]+)\/",
     "Linux /proc path in source"),
]


# ---- Known vendor/library file patterns — skip RCE scanning on these ----
# Also matches any JS file under /vendor/, /libs/, /node_modules/ paths.
_KNOWN_LIBRARY_PATTERNS = re.compile(
    r"(?i)"
    r"(?:/vendor/|/node_modules/|/libs?/|/bower_components/|/static/vendor/)"  # vendor paths
    r"|/"
    r"(?:jquery[.\-][\d.]+(?:\.min)?\.js"
    r"|bootstrap[.\-][\d.]+(?:\.min)?\.js"
    r"|react(?:\.development|\.production\.min)?\.js"
    r"|react-dom(?:\.development|\.production\.min)?\.js"
    r"|vue(?:\.global|\.esm[^/]*)?(?:\.min)?\.js"
    r"|angular(?:\.min)?\.js"
    r"|lodash(?:\.min)?\.js"
    r"|underscore(?:\.min)?\.js"
    r"|moment(?:\.min)?\.js"
    r"|axios(?:\.min)?\.js"
    r"|popper(?:\.min)?\.js"
    r"|d3(?:\.min)?\.js"
    r"|chart\.js"
    r"|backbone(?:\.min)?\.js"
    r"|ember(?:\.min)?\.js"
    r"|knockout(?:\.min)?\.js"
    r"|require(?:js)?(?:\.min)?\.js"  # RequireJS — uses eval() internally for AMD
    r"|[a-z]+[.\-][\d]+\.[\d]+\.[\d]+(?:\.min)?\.js"  # any semver-named bundle
    r")"
)


class StaticJsAnalysisCheck(BaseScanCheck):
    """
    Downloads JS bundles served by the target and scans for dangerous code patterns.
    Detects eval RCE, hardcoded secrets, and internal URLs.
    Skips known vendor/library files (jQuery, Bootstrap, React, etc.) for RCE patterns
    to avoid false positives from minified library internals.
    """
    check_id = "static-js-rce"
    check_type = CheckType.PASSIVE
    name = "Static JS Analysis (RCE / Secret Detection)"
    description = "Scans downloaded JS bundles for eval(), child_process, hardcoded secrets, and internal URLs"

    async def check_passive(self, crawl_result: CrawlResult) -> list[CheckResult]:
        results: list[CheckResult] = []
        ct = crawl_result.content_type.lower()

        # Only scan JS files
        is_js = (
            "javascript" in ct or
            crawl_result.url.endswith(".js") or
            crawl_result.url.endswith(".mjs")
        )
        if not is_js:
            return results

        body = crawl_result.body
        if not body or len(body) < 100:
            return results

        url = crawl_result.url

        # Skip RCE pattern scanning for known vendor/library files — they contain
        # internal uses of eval() and exec() that are not vulnerabilities.
        # Still scan for hardcoded secrets and internal URLs.
        is_library_file = bool(_KNOWN_LIBRARY_PATTERNS.search(url))

        # --- RCE patterns (skipped for known libraries) ---
        if not is_library_file:
            for pattern, desc, severity, cvss in _RCE_PATTERNS:
                for m in re.finditer(pattern, body, re.IGNORECASE | re.DOTALL):
                    snippet = m.group(0)[:120].replace("\n", " ")
                    # Build a fake insertion point for the JS file
                    ip = InsertionPoint(
                        url=url, method="GET",
                        ip_type=IPType.HEADER, name="(js-bundle)",
                        value="",
                        context={"file": url}
                    )
                    results.append(CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.FIRM,
                        severity=severity,
                        cvss=cvss,
                        description=(
                            f"Dangerous code pattern in JS bundle: {desc}. "
                            f"Snippet: {snippet!r}. "
                            f"File: {url}"
                        ),
                        evidence=self._make_evidence(
                            request_raw=f"GET {url} HTTP/1.1",
                            response=None,
                            payload=pattern,
                            poc_curl=f"curl -s '{url}' | grep -o '{snippet[:40]}...'",
                        ),
                        insertion_point=ip,
                    ))
                    break  # one finding per pattern per file

        # --- Secret patterns ---
        for pattern, desc in _SECRET_PATTERNS:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                captured = m.group(1) if m.lastindex else m.group(0)
                # Redact partially
                redacted = captured[:4] + "***" + captured[-2:] if len(captured) > 6 else "***"
                ip = InsertionPoint(
                    url=url, method="GET",
                    ip_type=IPType.HEADER, name="(js-bundle)",
                    value="",
                )
                results.append(CheckResult(
                    check_id="static-js-secret",
                    vulnerable=True,
                    confidence=Confidence.FIRM,
                    severity=Severity.CRITICAL,
                    cvss=9.1,
                    description=(
                        f"{desc} found in JS bundle {url}. "
                        f"Value (redacted): {redacted}"
                    ),
                    evidence=self._make_evidence(
                        request_raw=f"GET {url} HTTP/1.1",
                        response=None,
                        payload=pattern,
                        poc_curl=f"curl -s '{url}' | grep -oE '{desc}'",
                    ),
                    insertion_point=ip,
                ))
                break

        # --- Internal URL patterns ---
        for pattern, desc in _INTERNAL_PATTERNS:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                ip = InsertionPoint(
                    url=url, method="GET",
                    ip_type=IPType.HEADER, name="(js-bundle)",
                    value="",
                )
                results.append(CheckResult(
                    check_id="static-js-internal",
                    vulnerable=True,
                    confidence=Confidence.TENTATIVE,
                    severity=Severity.MEDIUM,
                    cvss=5.3,
                    description=(
                        f"{desc} in JS bundle {url}: {m.group(0)[:80]}"
                    ),
                    evidence=self._make_evidence(
                        request_raw=f"GET {url} HTTP/1.1",
                        response=None,
                        payload=m.group(0),
                        poc_curl=f"curl -s '{url}' | grep -o '{m.group(0)[:40]}'",
                    ),
                    insertion_point=ip,
                ))

        return results

    def _make_evidence(self, request_raw, response, payload, poc_curl):
        from nexus.models import Evidence
        resp_snippet = ""
        if response and hasattr(response, "text"):
            resp_snippet = response.text[:500]
        return Evidence(
            request_raw=request_raw or "",
            response_raw=resp_snippet,
            payload=payload or "",
            poc_curl=poc_curl or "",
        )
