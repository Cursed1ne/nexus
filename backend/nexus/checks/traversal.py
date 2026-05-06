"""
Path Traversal / Local File Read check.

Detects:
  - Directory traversal via URL path segments
  - LFI in query parameters (file=, path=, include=, etc.)
  - Null-byte injection
  - Direct access to sensitive files (/ftp/, /.git/, /backup/, etc.)
"""
import re
from typing import Optional

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

# Signatures of successful file reads
_UNIX_PASSWD_PATTERN = re.compile(r"root:.*:0:0:", re.MULTILINE)
_WIN_SYSTEM_PATTERN = re.compile(r"\[boot loader\]|\[drivers\]|WINDOWS.*System32", re.IGNORECASE)
_PROC_SELF_PATTERN = re.compile(r"Name:\s+\w+\nUmask:", re.MULTILINE)
_GIT_HEAD_PATTERN = re.compile(r"ref: refs/heads/")
_PACKAGE_JSON_PATTERN = re.compile(r'"name"\s*:\s*"[^"]+"\s*,\s*"version"\s*:\s*"[\d.]+')
_SENSITIVE_CONTENT_PATTERNS = [
    (_UNIX_PASSWD_PATTERN,    "Unix /etc/passwd"),
    (_WIN_SYSTEM_PATTERN,     "Windows system.ini"),
    (_PROC_SELF_PATTERN,      "Linux /proc/self/status"),
    (_GIT_HEAD_PATTERN,       ".git/HEAD"),
    (_PACKAGE_JSON_PATTERN,   "package.json"),
]

_LFI_PAYLOADS = [
    # Unix
    ("../../etc/passwd",               "/etc/passwd"),
    ("../../../etc/passwd",            "/etc/passwd"),
    ("../../../../etc/passwd",         "/etc/passwd"),
    ("/etc/passwd",                    "/etc/passwd"),
    ("../../../etc/shadow",            "/etc/shadow"),
    ("../../../../proc/self/status",   "/proc/self"),
    # Windows
    ("..\\..\\windows\\system.ini",    "windows/system.ini"),
    ("../../windows/win.ini",          "windows/win.ini"),
    # Null byte (older PHP/CGI)
    ("../../etc/passwd\x00",           "/etc/passwd (null byte)"),
    # App-specific
    ("../../../../package.json",       "package.json"),
    ("../../../package.json",          "package.json"),
]

# Sensitive paths to probe directly via GET
_SENSITIVE_DIRECT_PATHS = [
    "/ftp/",
    "/ftp/acquisitions.md",
    "/ftp/package.json.bak",
    "/ftp/coupons_2013.md.bak",
    "/ftp/quarantine/",
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/package.json",
    "/web.config",
    "/server.js",
    "/app.js",
    "/config.js",
    "/backup/",
    "/admin/",
    "/debug/",
    "/.DS_Store",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/phpinfo.php",
    "/info.php",
    "/.htaccess",
    # Additional high-value paths
    "/encryptionkeys/",
    "/support/logs/",
    "/api-docs",
    "/swagger.json",
    "/metrics",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/.gitlab-ci.yml",
    "/Dockerfile",
    "/docker-compose.yml",
    "/.npmrc",
    "/yarn.lock",
]

# Params commonly used for file inclusion
_FILE_PARAM_NAMES = {
    "file", "path", "page", "include", "require", "document",
    "folder", "root", "dir", "load", "template", "view",
    "layout", "source", "resource", "content", "module",
    "conf", "download", "filename", "redirect",
    # PHP-style image/file params (showimage.php?file=, image.php?img=, etc.)
    "img", "image", "filepath", "pic", "photo", "show", "display",
    "open", "read", "fetch", "retrieve", "get", "cat",
}


class PathTraversalCheck(BaseScanCheck):
    check_id = "traversal-lfi"
    check_type = CheckType.ACTIVE
    name = "Path Traversal / Local File Inclusion"
    description = "Detects directory traversal and LFI via path manipulation"

    async def check_passive(self, crawl_result) -> list[CheckResult]:
        """Passive: flag FTP/backup directories and sensitive file access."""
        results = []
        url = crawl_result.url

        for path in ["/ftp/", "/.git/", "/backup/", "/.env", "/phpinfo", "/server-status"]:
            if path in url and crawl_result.status_code == 200:
                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.CERTAIN,
                    severity=Severity.HIGH,
                    cvss=7.5,
                    description=f"Sensitive path accessible: {url!r} returned HTTP 200",
                    evidence=self._make_evidence(
                        request_raw=f"GET {url} HTTP/1.1",
                        response=None,
                        poc_curl=self._poc_curl("GET", url),
                    ),
                    insertion_point=None,
                ))
        return results

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        results = []

        # Only try LFI on params that are commonly file-related
        if insertion_point.ip_type not in (IPType.QUERY_PARAM, IPType.BODY_PARAM, IPType.PATH_SEGMENT):
            return []

        is_file_param = insertion_point.name.lower() in _FILE_PARAM_NAMES
        is_path_segment = insertion_point.ip_type == IPType.PATH_SEGMENT

        if not (is_file_param or is_path_segment):
            # Still probe a few universal payloads
            payloads_to_try = _LFI_PAYLOADS[:3]
        else:
            payloads_to_try = _LFI_PAYLOADS

        for payload, description in payloads_to_try:
            try:
                resp, req_raw, curl = await self._send_probe(client, insertion_point, payload)
            except Exception:
                continue

            matched = _detect_file_content(resp.text)
            if matched:
                evidence = self._make_evidence(
                    request_raw=req_raw,
                    response=resp,
                    payload=payload,
                    poc_curl=curl,
                )
                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.CERTAIN,
                    severity=Severity.HIGH,
                    cvss=7.5,
                    description=(
                        f"Path traversal confirmed — leaked {matched}. "
                        f"Payload {payload!r} in parameter {insertion_point.name!r}"
                    ),
                    evidence=evidence,
                    insertion_point=insertion_point,
                ))
                break

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
            req_raw = self._build_request_line("GET", url, headers)
            curl = self._poc_curl("GET", url)
            resp = await client.get(url)
        elif ip.ip_type == IPType.BODY_PARAM:
            url = ip.url
            form_data = {ip.name: payload}
            body_str = f"{ip.name}={payload}"
            req_raw = self._build_request_line("POST", url, headers, body_str)
            curl = self._poc_curl("POST", url, headers, body_str)
            resp = await client.post(url, data=form_data)
        elif ip.ip_type == IPType.PATH_SEGMENT:
            # Replace the last path segment
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(ip.url)
            parts = parsed.path.rsplit("/", 1)
            new_path = parts[0] + "/" + payload if len(parts) > 1 else payload
            new_url = urlunparse(parsed._replace(path=new_path))
            req_raw = self._build_request_line("GET", new_url, headers)
            curl = self._poc_curl("GET", new_url)
            resp = await client.get(new_url)
        else:
            raise ValueError(f"Unsupported: {ip.ip_type}")

        return resp, req_raw, curl


class DirectoryDisclosureCheck(BaseScanCheck):
    """Probe well-known sensitive paths directly — no insertion point needed."""
    check_id = "traversal-sensitive-paths"
    check_type = CheckType.PASSIVE
    name = "Sensitive Path Exposure"
    description = "Checks for exposed FTP directories, .git, .env, backup files"

    async def check_passive(self, crawl_result) -> list[CheckResult]:
        results = []
        url = crawl_result.url

        # Detect directory listing
        if crawl_result.status_code == 200 and (
            "<title>Index of" in crawl_result.body or
            "Directory listing" in crawl_result.body or
            ("/ftp/" in url and "acquisitions" in crawl_result.body.lower())
        ):
            severity = Severity.HIGH if "/ftp/" in url else Severity.MEDIUM
            desc = f"Directory listing / sensitive file exposed at {url}"
            if "acquisitions" in crawl_result.body.lower() or "confidential" in crawl_result.body.lower():
                severity = Severity.HIGH
                desc = f"Confidential document accessible at {url}"

            results.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.CERTAIN,
                severity=severity,
                cvss=7.5,
                description=desc,
                evidence=self._make_evidence(
                    request_raw=f"GET {url} HTTP/1.1",
                    response=None,
                    poc_curl=self._poc_curl("GET", url),
                ),
                insertion_point=None,
            ))

        # Detect .env / config leak
        if crawl_result.status_code == 200 and any(
            pattern in crawl_result.body
            for pattern in ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "DATABASE_URL", "JWT_SECRET"]
        ):
            results.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.CERTAIN,
                severity=Severity.CRITICAL,
                cvss=9.1,
                description=f"Environment/config file with secrets exposed at {url}",
                evidence=self._make_evidence(
                    request_raw=f"GET {url} HTTP/1.1",
                    response=None,
                    poc_curl=self._poc_curl("GET", url),
                ),
                insertion_point=None,
            ))

        # Detect .git exposure
        if crawl_result.status_code == 200 and _GIT_HEAD_PATTERN.search(crawl_result.body):
            results.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.CERTAIN,
                severity=Severity.HIGH,
                cvss=7.5,
                description=f".git repository exposed at {url} — full source code recoverable",
                evidence=self._make_evidence(
                    request_raw=f"GET {url} HTTP/1.1",
                    response=None,
                    poc_curl=self._poc_curl("GET", url),
                ),
                insertion_point=None,
            ))

        # Detect encryption keys directory
        if crawl_result.status_code == 200 and (
            "encryptionkeys" in url.lower() and
            (".pem" in crawl_result.body or ".key" in crawl_result.body or
             "encryption" in crawl_result.body.lower())
        ):
            results.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.CERTAIN,
                severity=Severity.CRITICAL,
                cvss=9.5,
                description=f"Encryption keys directory exposed at {url} — private keys may be downloadable",
                evidence=self._make_evidence(
                    request_raw=f"GET {url} HTTP/1.1",
                    response=None,
                    poc_curl=self._poc_curl("GET", url),
                ),
                insertion_point=None,
            ))

        # Detect server logs exposure
        if crawl_result.status_code == 200 and (
            "support/logs" in url.lower() and
            (".log" in crawl_result.body or "access" in crawl_result.body.lower())
        ):
            results.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.CERTAIN,
                severity=Severity.HIGH,
                cvss=7.5,
                description=f"Server access logs exposed at {url} — request history and tokens may be readable",
                evidence=self._make_evidence(
                    request_raw=f"GET {url} HTTP/1.1",
                    response=None,
                    poc_curl=self._poc_curl("GET", url),
                ),
                insertion_point=None,
            ))

        # Detect Dockerfile / CI config exposure
        if crawl_result.status_code == 200 and any(
            pattern in crawl_result.body
            for pattern in ["FROM node:", "FROM python:", "EXPOSE ", "RUN npm", "stages:", "pipeline:"]
        ):
            results.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.CERTAIN,
                severity=Severity.MEDIUM,
                cvss=5.3,
                description=f"DevOps configuration exposed at {url} — infrastructure details leaked",
                evidence=self._make_evidence(
                    request_raw=f"GET {url} HTTP/1.1",
                    response=None,
                    poc_curl=self._poc_curl("GET", url),
                ),
                insertion_point=None,
            ))

        return results


def _detect_file_content(text: str) -> Optional[str]:
    for pattern, label in _SENSITIVE_CONTENT_PATTERNS:
        if pattern.search(text):
            return label
    return None
