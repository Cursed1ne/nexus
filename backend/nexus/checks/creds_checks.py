"""
Credential Discovery and Brute Force Checks

  - HardcodedCredentialsCheck : PASSIVE — scans HTML/JS source for hardcoded
      passwords, default credentials, commented-out credentials, and form
      field default values that expose credentials.

  - LoginBruteforceCheck      : ACTIVE — reads wordlists from ScanContext and
      attempts login against every discovered login endpoint. Stores successful
      credentials back into ScanContext for downstream checks.

  - AuthenticatedRescanCheck  : ACTIVE — after credentials are found, re-probes
      sensitive endpoints with the active session to find auth-gated findings.
"""
import re
import time
from urllib.parse import urlparse

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

# Lazy import to avoid circular dependency (nexus.checks → nexus.engine → nexus.checks)
def _get_ctx():
    from nexus.engine.scan_context import get_ctx
    return get_ctx()

def _make_session(**kwargs):
    from nexus.engine.scan_context import ActiveSession
    return ActiveSession(**kwargs)

def _make_credential(**kwargs):
    from nexus.engine.scan_context import FoundCredential
    return FoundCredential(**kwargs)


# ---------------------------------------------------------------------------
# Hardcoded credential patterns to scan in HTML/JS source
# ---------------------------------------------------------------------------

_HC_PATTERNS: list[tuple[str, str, Severity, float]] = [
    # (regex, description, severity, cvss)

    # HTML comments with credentials
    (r"<!--[^>]*(?:password|passwd|pwd|secret|admin|credentials?)[^>]*:\s*([^\s<>\"']{3,50})[^>]*-->",
     "Credentials in HTML comment", Severity.CRITICAL, 9.1),

    # Input field default values with password-like names
    (r'<input[^>]+(?:name|id)=["\']?(?:password|passwd|pwd|pass)["\']?[^>]+value=["\']([^"\']{4,100})["\']',
     "Default password value in HTML form input", Severity.HIGH, 8.1),
    (r'<input[^>]+value=["\']([^"\']{4,100})["\'][^>]+(?:name|id)=["\']?(?:password|passwd|pwd)["\']?',
     "Default password value in HTML form input", Severity.HIGH, 8.1),

    # JavaScript credential assignments
    (r'(?:var|let|const|window\.|self\.)\s+(?:password|passwd|pwd|secret|admin_pass|apikey|api_key)\s*=\s*["\']([^"\']{4,100})["\']',
     "Hardcoded password/secret in JavaScript variable", Severity.CRITICAL, 9.1),
    (r'["\']?(?:password|passwd|secret)["\']?\s*:\s*["\']([^"\']{4,100})["\']',
     "Hardcoded password in JS object literal", Severity.HIGH, 8.5),

    # Basic auth credentials in URL
    (r'https?://([^:@\s]+):([^@\s]{4,100})@[^\s"\'<>]+',
     "Credentials embedded in URL (Basic Auth)", Severity.CRITICAL, 9.8),

    # Common default credential patterns
    (r'(?i)(?:admin|root|administrator|user)\s*[:/]\s*(?:admin|password|pass|123456|1234|root|toor|secret)',
     "Default credential pair found in source", Severity.CRITICAL, 9.1),

    # PHP/Python/Node config credential patterns
    (r'(?:DB_PASS(?:WORD)?|DATABASE_PASSWORD|MYSQL_PASS(?:WORD)?|POSTGRES_PASS(?:WORD)?)\s*[=:]\s*["\']?([^"\';\s]{4,100})',
     "Database password in application config", Severity.CRITICAL, 9.1),
    (r'(?:SECRET_KEY|JWT_SECRET|APP_SECRET|AUTH_SECRET)\s*[=:]\s*["\']([^"\']{8,100})["\']',
     "Application secret key hardcoded", Severity.HIGH, 8.5),
]

# Patterns that indicate a false positive (skip these)
_HC_SKIP_PATTERNS = re.compile(
    r'(?i)'
    r'(?:placeholder|example|changeme|your.?(?:password|secret)|<password>|\${|{{|%\{|#\{|TODO|FIXME|xxx+|yyy+|zzz+|abc+|test+(?:pass|123)|dummy)'
)


class HardcodedCredentialsCheck(BaseScanCheck):
    """
    Passive scan of HTML page source and JS bundles for hardcoded credentials,
    default form values, and exposed secrets.
    """
    check_id = "hardcoded-credentials"
    check_type = CheckType.PASSIVE
    name = "Hardcoded Credentials / Secrets in Source"
    description = (
        "Scans HTML and JS source for hardcoded passwords, default form values, "
        "commented-out credentials, and embedded secrets"
    )

    async def check_passive(self, crawl_result: CrawlResult) -> list[CheckResult]:
        results: list[CheckResult] = []
        body = crawl_result.body
        if not body or len(body) < 50:
            return results

        ct = crawl_result.content_type.lower()
        url = crawl_result.url
        is_js = "javascript" in ct or url.endswith(".js") or url.endswith(".mjs")
        is_html = "html" in ct or url.endswith(".html") or url.endswith(".htm")

        if not (is_js or is_html):
            return results

        seen: set[str] = set()

        for pattern, desc, severity, cvss in _HC_PATTERNS:
            for m in re.finditer(pattern, body, re.IGNORECASE | re.DOTALL):
                # Extract the credential value (last capturing group or full match)
                value = m.group(m.lastindex) if m.lastindex else m.group(0)
                value = value.strip()

                # Skip obvious placeholder/example values
                if _HC_SKIP_PATTERNS.search(value):
                    continue
                if len(value) < 3:
                    continue

                # Deduplicate
                key = f"{desc}:{value[:20]}"
                if key in seen:
                    continue
                seen.add(key)

                snippet = m.group(0)[:150].replace("\n", " ").strip()
                redacted = value[:3] + "***" + value[-2:] if len(value) > 5 else "***"

                ip = InsertionPoint(
                    url=url, method="GET",
                    ip_type=IPType.HEADER, name="(source-scan)",
                    value="",
                )

                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.FIRM,
                    severity=severity,
                    cvss=cvss,
                    description=(
                        f"{desc} at {url}. "
                        f"Value (partial): {redacted!r}. "
                        f"Context: {snippet!r}"
                    ),
                    evidence=self._make_evidence(
                        request_raw=f"GET {url} HTTP/1.1",
                        response=None,
                        payload=pattern,
                        poc_curl=(
                            f"# View the page source:\n"
                            f"curl -s '{url}' | grep -i '{desc.split()[0].lower()}'"
                        ),
                    ),
                    insertion_point=ip,
                ))

                # Store in ScanContext if it looks like username:password pair
                if ":" in value and "@" not in value:
                    parts = value.split(":", 1)
                    if len(parts) == 2 and len(parts[1]) >= 3:
                        _get_ctx().add_credential(
                            username=parts[0].strip(),
                            password=parts[1].strip(),
                            source="hardcoded-source",
                            context=url,
                        )

        return results

    def _make_evidence(self, request_raw, response, payload, poc_curl):
        from nexus.models import Evidence
        return Evidence(
            request_raw=request_raw or "",
            response_raw="",
            payload=payload or "",
            poc_curl=poc_curl or "",
        )


# ---------------------------------------------------------------------------
# Login Brute Force using ScanContext wordlists
# ---------------------------------------------------------------------------

# Built-in mini wordlist — used when no external list is provided
_DEFAULT_USERS = [
    "admin", "administrator", "root", "user", "test", "guest", "info",
    "support", "operator", "manager", "demo",
]
_DEFAULT_PASSWORDS = [
    "admin", "password", "123456", "12345678", "admin123", "Password1",
    "letmein", "qwerty", "123456789", "welcome", "monkey", "1234",
    "1234567890", "password1", "iloveyou", "admin1234", "root", "toor",
    "test", "guest", "pass", "login", "hello", "changeme", "default",
]


class LoginBruteforceCheck(BaseScanCheck):
    """
    Attempts login against discovered login endpoints using wordlists from
    ScanContext (loaded from --userlist/--passlist files). Falls back to a
    built-in mini list when no external wordlist is provided.

    Successful credentials are stored in ScanContext.found_credentials and
    an active session is created in ScanContext.active_sessions.
    """
    check_id = "login-bruteforce"
    check_type = CheckType.ACTIVE
    name = "Login Brute Force / Default Credentials"
    description = (
        "Tests login endpoints with wordlist-based brute force. "
        "Uses provided --userlist/--passlist or built-in default credential list."
    )

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        if not any(k in url_lower for k in ("login", "auth", "signin")):
            return []
        if not any(k in insertion_point.name.lower() for k in ("email", "user", "password", "pass")):
            return []
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        ctx = _get_ctx()
        login_url = insertion_point.url
        parsed = urlparse(login_url)

        # Build credential combinations to try
        users = ctx.wordlist_users if ctx.wordlist_users else _DEFAULT_USERS
        passwords = ctx.wordlist_passwords if ctx.wordlist_passwords else _DEFAULT_PASSWORDS

        # Limit attempts to avoid lockout — max 200 combinations
        pairs: list[tuple[str, str]] = []
        for u in users[:20]:
            for p in passwords[:10]:
                pairs.append((u, p))

        use_json = insertion_point.ip_type == IPType.JSON_KEY
        user_field = insertion_point.name
        pass_field = "password"  # default; refine from context if available
        if hasattr(insertion_point, "context") and isinstance(insertion_point.context, dict):
            pass_field = insertion_point.context.get("pass_field", "password")

        results: list[CheckResult] = []

        for username, password in pairs:
            # Small delay to avoid triggering rate limits that exist
            await _async_sleep(0.05)

            try:
                if use_json:
                    resp = await client.post(
                        login_url,
                        json={user_field: username, pass_field: password},
                        headers={"Content-Type": "application/json"},
                    )
                else:
                    resp = await client.post(
                        login_url,
                        data={user_field: username, pass_field: password},
                    )
            except Exception:
                continue

            # Success indicators
            success = False
            token = ""
            cookie = ""
            auth_type = ""

            if resp.status_code == 200:
                body = resp.text
                # JSON token response
                try:
                    data = resp.json()
                    token = (
                        data.get("token") or
                        data.get("access_token") or
                        data.get("accessToken") or
                        (data.get("authentication") or {}).get("token") or
                        ""
                    )
                    if token:
                        success = True
                        auth_type = "bearer"
                except Exception:
                    pass

                # Cookie-based session
                if not success:
                    set_cookie = resp.headers.get("set-cookie", "")
                    if set_cookie and any(
                        k in set_cookie.lower()
                        for k in ("session", "token", "auth", "sid", "connect.sid")
                    ):
                        cookie = set_cookie.split(";")[0]
                        success = True
                        auth_type = "cookie"

                # Redirect after login = success
                if not success and resp.history and resp.status_code == 200:
                    success = True
                    auth_type = "redirect"

            if not success:
                # Check for redirect to dashboard/home = login success
                if resp.status_code in (301, 302):
                    loc = resp.headers.get("location", "")
                    if any(k in loc.lower() for k in ("dashboard", "home", "admin", "profile", "account")):
                        success = True
                        auth_type = "redirect"

            if success:
                # Store in ScanContext
                ctx.add_credential(
                    username=username,
                    password=password,
                    source="brute-force",
                    context=login_url,
                )

                if token or cookie:
                    ctx.add_session(_make_session(
                        token=token,
                        cookie=cookie,
                        auth_type=auth_type,
                        base_url=f"{parsed.scheme}://{parsed.netloc}",
                        credential=_make_credential(
                            username=username,
                            password=password,
                            source="brute-force",
                            context=login_url,
                        ),
                    ))

                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.CERTAIN,
                    severity=Severity.CRITICAL,
                    cvss=9.8,
                    description=(
                        f"Login successful with default/common credentials! "
                        f"Username: {username!r}, Password: {password!r} "
                        f"at {login_url}. "
                        f"Auth type: {auth_type}. "
                        f"Attacker can log in without any prior knowledge."
                    ),
                    evidence=self._make_evidence(
                        request_raw=(
                            f"POST {parsed.path} HTTP/1.1\n"
                            f"Host: {parsed.netloc}\n"
                            f"Content-Type: application/json\n\n"
                            f'{{{user_field!r}: {username!r}, {pass_field!r}: {password!r}}}'
                        ),
                        response=resp,
                        payload=f"{username}:{password}",
                        poc_curl=(
                            f"curl -s -X POST '{login_url}' "
                            f"-H 'Content-Type: application/json' "
                            f"-d '{{\"email\":\"{username}\",\"password\":\"{password}\"}}'"
                        ),
                    ),
                    insertion_point=insertion_point,
                ))
                break  # Stop on first success to avoid noise

        return results

    def _make_evidence(self, request_raw, response, payload, poc_curl):
        from nexus.models import Evidence
        resp_snippet = ""
        if response and hasattr(response, "text"):
            resp_snippet = response.text[:200]
        return Evidence(
            request_raw=request_raw or "",
            response_raw=resp_snippet,
            payload=payload or "",
            poc_curl=poc_curl or "",
        )


async def _async_sleep(seconds: float):
    import asyncio
    await asyncio.sleep(seconds)
