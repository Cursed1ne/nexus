"""
Passive checks — analyse CrawlResult without sending any additional requests.

Checks:
  - MissingSecurityHeadersCheck  : CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.
  - OpenRedirectCheck            : follow redirect chains for off-origin targets
  - CorsCheck                    : permissive CORS (Access-Control-Allow-Origin: *)
  - InformationDisclosureCheck   : server banners, stack traces, debug pages
"""
import re
from urllib.parse import urlparse

from nexus.models import (
    CheckResult,
    CheckType,
    Confidence,
    CrawlResult,
    Evidence,
    Severity,
)
from .base import BaseScanCheck

# ---------------------------------------------------------------------------
# 1. Missing Security Headers
# ---------------------------------------------------------------------------

_REQUIRED_HEADERS = [
    (
        "Strict-Transport-Security",
        Severity.MEDIUM,
        6.1,
        "Missing HSTS header — connection not enforced over HTTPS.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        ["https://owasp.org/www-project-web-security-testing-guide/"],
    ),
    (
        "Content-Security-Policy",
        Severity.MEDIUM,
        5.4,
        "Missing Content-Security-Policy header — XSS mitigations absent.",
        "Define a strict CSP to restrict script sources.",
        ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
    ),
    (
        "X-Content-Type-Options",
        Severity.LOW,
        4.3,
        "Missing X-Content-Type-Options header — MIME-sniffing possible.",
        "Add: X-Content-Type-Options: nosniff",
        [],
    ),
    (
        "X-Frame-Options",
        Severity.LOW,
        4.3,
        "Missing X-Frame-Options header — clickjacking possible.",
        "Add: X-Frame-Options: DENY (or SAMEORIGIN)",
        ["https://owasp.org/www-community/attacks/Clickjacking"],
    ),
    (
        "Referrer-Policy",
        Severity.INFO,
        0.0,
        "Missing Referrer-Policy header.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
        [],
    ),
    (
        "Permissions-Policy",
        Severity.INFO,
        0.0,
        "Missing Permissions-Policy header.",
        "Add a Permissions-Policy to restrict browser feature access.",
        [],
    ),
]


class MissingSecurityHeadersCheck(BaseScanCheck):
    check_id = "passive-missing-headers"
    check_type = CheckType.PASSIVE
    name = "Missing Security Headers"
    description = "Checks for absent security-related HTTP response headers"

    async def check_passive(self, crawl_result: CrawlResult) -> list[CheckResult]:
        results = []
        lower_headers = {k.lower(): v for k, v in crawl_result.headers.items()}

        # Skip dirsearch stub CrawlResults — they have no real response headers
        if "_dirsearch_stub" in lower_headers:
            return results

        for hdr, severity, cvss, desc, solution, refs in _REQUIRED_HEADERS:
            if hdr.lower() not in lower_headers:
                evidence = Evidence(
                    request_raw=f"GET {crawl_result.url} HTTP/1.1",
                    response_raw=_headers_snippet(crawl_result.headers),
                    payload="",
                    poc_curl=f"curl -si '{crawl_result.url}' | grep -i {hdr}",
                )
                results.append(
                    CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=severity,
                        cvss=cvss,
                        description=desc,
                        evidence=evidence,
                        insertion_point=None,
                    )
                )

        return results


# ---------------------------------------------------------------------------
# 2. Open Redirect (passive — look for redirect chains)
# ---------------------------------------------------------------------------

class OpenRedirectCheck(BaseScanCheck):
    check_id = "passive-open-redirect"
    check_type = CheckType.PASSIVE
    name = "Open Redirect (Passive)"
    description = "Detects redirects that cross origins in redirect chain"

    async def check_passive(self, crawl_result: CrawlResult) -> list[CheckResult]:
        if not crawl_result.redirect_chain:
            return []

        origin = urlparse(crawl_result.url.split("?")[0])
        for redir_url in crawl_result.redirect_chain:
            redir = urlparse(redir_url)
            if redir.netloc and redir.netloc != origin.netloc:
                evidence = Evidence(
                    request_raw=f"GET {crawl_result.url} HTTP/1.1",
                    response_raw=f"Location: {redir_url}\n" + _headers_snippet(crawl_result.headers),
                    payload="",
                    poc_curl=f"curl -sI '{crawl_result.url}'",
                )
                return [
                    CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.TENTATIVE,
                        severity=Severity.MEDIUM,
                        cvss=5.4,
                        description=(
                            f"Potential open redirect: {crawl_result.url!r} "
                            f"redirects to off-origin {redir_url!r}"
                        ),
                        evidence=evidence,
                        insertion_point=None,
                    )
                ]
        return []


# ---------------------------------------------------------------------------
# 3. CORS misconfiguration
# ---------------------------------------------------------------------------

class CorsCheck(BaseScanCheck):
    check_id = "passive-cors"
    check_type = CheckType.PASSIVE
    name = "CORS Misconfiguration"
    description = "Detects overly permissive CORS headers"

    async def check_passive(self, crawl_result: CrawlResult) -> list[CheckResult]:
        results = []
        lower = {k.lower(): v for k, v in crawl_result.headers.items()}

        acao = lower.get("access-control-allow-origin", "")
        acac = lower.get("access-control-allow-credentials", "false").lower()

        if acao == "*" and acac == "true":
            # ACAO: * + credentials is invalid per spec but some servers emit it
            results.append(self._make_result(
                crawl_result,
                Severity.HIGH,
                8.1,
                "CORS wildcard with credentials: Access-Control-Allow-Origin: * combined with Allow-Credentials: true. "
                "Allows any origin to make credentialed cross-site requests.",
                Confidence.CERTAIN,
            ))
        elif acao == "*":
            results.append(self._make_result(
                crawl_result,
                Severity.MEDIUM,
                5.3,
                "CORS wildcard: Access-Control-Allow-Origin: * permits any origin to read responses.",
                Confidence.CERTAIN,
            ))

        return results

    def _make_result(
        self, cr: CrawlResult, severity: Severity, cvss: float, desc: str, conf: Confidence
    ) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            vulnerable=True,
            confidence=conf,
            severity=severity,
            cvss=cvss,
            description=desc,
            evidence=Evidence(
                request_raw=f"GET {cr.url} HTTP/1.1",
                response_raw=_headers_snippet(cr.headers),
                poc_curl=f"curl -sI -H 'Origin: https://evil.com' '{cr.url}'",
            ),
            insertion_point=None,
        )


# ---------------------------------------------------------------------------
# 4. Information Disclosure
# ---------------------------------------------------------------------------

_STACK_TRACE_PATTERNS = [
    re.compile(r"at \w[\w.]+\([\w./]+:\d+\)"),        # Java/Node stack trace
    re.compile(r"Traceback \(most recent call last\)"),  # Python
    re.compile(r"PHP (Fatal|Parse|Warning) error", re.IGNORECASE),
    re.compile(r"Microsoft OLE DB Provider", re.IGNORECASE),
    re.compile(r"on line \d+", re.IGNORECASE),
    re.compile(r"Debug mode"),
    re.compile(r"<b>Warning</b>:.*php", re.IGNORECASE | re.DOTALL),
]

_SERVER_VERSION_PATTERN = re.compile(
    r"(Apache/[\d.]+|nginx/[\d.]+|IIS/[\d.]+|PHP/[\d.]+|Express/[\d.]+)",
    re.IGNORECASE,
)


class InformationDisclosureCheck(BaseScanCheck):
    check_id = "passive-info-disclosure"
    check_type = CheckType.PASSIVE
    name = "Information Disclosure"
    description = "Detects server version banners and stack traces in responses"

    async def check_passive(self, crawl_result: CrawlResult) -> list[CheckResult]:
        results = []

        # Stack trace in body
        for pattern in _STACK_TRACE_PATTERNS:
            if pattern.search(crawl_result.body):
                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.CERTAIN,
                    severity=Severity.MEDIUM,
                    cvss=5.3,
                    description="Stack trace / debug information leaked in response body.",
                    evidence=Evidence(
                        request_raw=f"GET {crawl_result.url} HTTP/1.1",
                        response_raw=crawl_result.body[:2000],
                    ),
                    insertion_point=None,
                ))
                break

        # Server version banner in headers
        server_hdr = crawl_result.headers.get("server", "") + " " + crawl_result.headers.get("x-powered-by", "")
        m = _SERVER_VERSION_PATTERN.search(server_hdr)
        if m:
            results.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.CERTAIN,
                severity=Severity.INFO,
                cvss=0.0,
                description=f"Server version disclosed in header: {m.group(0)!r}",
                evidence=Evidence(
                    request_raw=f"GET {crawl_result.url} HTTP/1.1",
                    response_raw=_headers_snippet(crawl_result.headers),
                ),
                insertion_point=None,
            ))

        return results


# ---------------------------------------------------------------------------
# 5. Directory Listing
# ---------------------------------------------------------------------------

_DIR_LISTING_PATTERN = re.compile(
    r"Index of /|Directory Listing For /|Parent Directory|"
    r"\[To Parent Directory\]|<title>Index of",
    re.IGNORECASE,
)


class DirectoryListingCheck(BaseScanCheck):
    """
    Detects web server directory listing (Apache 'Index of /', IIS, Nginx autoindex).
    Exposes source code, backups, configs, and sensitive files.
    """
    check_id = "passive-dir-listing"
    check_type = CheckType.PASSIVE
    name = "Directory Listing Enabled"
    description = "Web server exposes directory contents — files accessible without auth"

    async def check_passive(self, crawl_result: CrawlResult) -> list[CheckResult]:
        if not _DIR_LISTING_PATTERN.search(crawl_result.body):
            return []

        # Extract listed filenames for evidence
        from urllib.parse import urlparse as _up
        path = _up(crawl_result.url).path or "/"
        snippet = crawl_result.body[:500]

        return [CheckResult(
            check_id=self.check_id,
            vulnerable=True,
            confidence=Confidence.CERTAIN,
            severity=Severity.MEDIUM,
            cvss=5.3,
            description=(
                f"Directory listing enabled at {crawl_result.url}. "
                f"Directory contents are publicly browsable — source files, "
                f"backups, and configuration files may be accessible."
            ),
            evidence=Evidence(
                request_raw=f"GET {path} HTTP/1.1",
                response_raw=snippet,
            ),
            insertion_point=None,
        )]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _headers_snippet(headers: dict) -> str:
    return "\n".join(f"{k}: {v}" for k, v in headers.items())
