"""
SessionAuthenticator — resolves an AuthConfig into a live ActiveSession
before the scan starts.

Supported auth modes (tried in priority order):

  A. Paste session   — user copies cookie/token from browser DevTools
     session_cookie: "connect.sid=abc123; other=val"
     bearer_token:   "eyJhbGci..."

  B. Form / JSON login  — classic username+password POST
     login_url, username, password, user_field, pass_field, content_type

  C. Login + OTP/TOTP   — two-step: login first, then submit TOTP code
     Same as (B) + totp_secret (Base32) or static otp_code + otp_url

  D. OAuth 2.0 ROPC     — Resource Owner Password Credentials grant
     oauth_token_url, client_id, [client_secret], oauth_username,
     oauth_password, [scope]
     → POST grant_type=password → returns access_token as Bearer

  E. OAuth Authorization Code (manual)
     User completed the browser dance, paste the resulting token/cookie
     back as (A). We cannot automate the browser redirect.

Usage:
    auth_cfg = AuthConfig(session_cookie="connect.sid=s%3Aabc...")
    session = await SessionAuthenticator().resolve(auth_cfg, client)
    ctx.add_session(session)
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import httpx

from nexus.engine.scan_context import ActiveSession

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AuthConfig — plain dataclass, serialisable from API JSON
# ---------------------------------------------------------------------------

@dataclass
class AuthConfig:
    # ---- Mode A: paste an existing session directly ----
    session_cookie: str = ""      # "connect.sid=abc; csrf=xyz"
    bearer_token: str = ""        # raw JWT / opaque token (no "Bearer " prefix)

    # ---- Mode B/C: form or JSON login ----
    login_url: str = ""           # e.g. "http://target/rest/user/login"
    username: str = ""
    password: str = ""
    user_field: str = "email"     # field name for username in the request body
    pass_field: str = "password"
    content_type: str = "json"    # "json" | "form"
    # Where to find the token in a JSON login response.
    # Supports dot-path: "data.token", "authentication.token"
    token_path: str = "token"
    # Cookie name to extract from Set-Cookie if no token in body
    cookie_name: str = ""         # leave empty = use the whole Set-Cookie string

    # ---- Mode C: OTP/TOTP second factor ----
    totp_secret: str = ""         # Base32 TOTP secret  (e.g. from app QR code)
    otp_code: str = ""            # static OTP code (if TOTP secret not available)
    otp_url: str = ""             # URL to POST the OTP to (defaults to login_url)
    otp_field: str = "otp"        # field name for the OTP code

    # ---- Mode D: OAuth 2.0 ROPC ----
    oauth_token_url: str = ""     # https://auth.example.com/oauth/token
    client_id: str = ""
    client_secret: str = ""       # optional for public clients
    oauth_username: str = ""      # may be same as username above
    oauth_password: str = ""      # may be same as password above
    oauth_scope: str = ""         # e.g. "openid profile"

    # ---- Extra headers applied to every authenticated request ----
    extra_headers: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

class SessionAuthenticator:
    """Turns an AuthConfig into an ActiveSession (bearer token or cookie)."""

    async def resolve(
        self,
        cfg: AuthConfig,
        client: httpx.AsyncClient,
    ) -> Optional[ActiveSession]:
        """
        Returns an ActiveSession on success, None if all methods fail.
        The caller should log and continue unauthenticated on None.
        """
        # ---- Mode A: pre-built session ----
        if cfg.bearer_token:
            logger.info("[auth] Using pre-supplied Bearer token")
            return ActiveSession(
                token=cfg.bearer_token,
                auth_type="bearer",
                extra_headers={**cfg.extra_headers,
                               "Authorization": f"Bearer {cfg.bearer_token}"},
            )

        if cfg.session_cookie:
            logger.info("[auth] Using pre-supplied session cookie")
            return ActiveSession(
                cookie=cfg.session_cookie,
                auth_type="cookie",
                extra_headers={**cfg.extra_headers,
                               "Cookie": cfg.session_cookie},
            )

        # ---- Mode D: OAuth ROPC (try before form login — cleaner token) ----
        if cfg.oauth_token_url and cfg.client_id:
            session = await self._oauth_ropc(cfg, client)
            if session:
                return session

        # ---- Mode B/C: form / JSON login ----
        if cfg.login_url and cfg.username:
            session = await self._form_login(cfg, client)
            if session:
                return session

        logger.warning("[auth] No valid auth config provided — scanning unauthenticated")
        return None

    # ------------------------------------------------------------------
    # OAuth 2.0 Resource Owner Password Credentials Grant
    # ------------------------------------------------------------------

    async def _oauth_ropc(
        self, cfg: AuthConfig, client: httpx.AsyncClient
    ) -> Optional[ActiveSession]:
        payload = {
            "grant_type": "password",
            "client_id": cfg.client_id,
            "username": cfg.oauth_username or cfg.username,
            "password": cfg.oauth_password or cfg.password,
        }
        if cfg.client_secret:
            payload["client_secret"] = cfg.client_secret
        if cfg.oauth_scope:
            payload["scope"] = cfg.oauth_scope

        try:
            resp = await client.post(
                cfg.oauth_token_url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            body = resp.json()
        except Exception as exc:
            logger.warning("[auth] OAuth ROPC failed: %s", exc)
            return None

        token = body.get("access_token") or body.get("token")
        if not token:
            logger.warning("[auth] OAuth ROPC: no access_token in response: %s",
                           list(body.keys()))
            return None

        token_type = body.get("token_type", "Bearer")
        logger.info("[auth] OAuth ROPC succeeded — token_type=%s", token_type)
        return ActiveSession(
            token=token,
            auth_type="bearer",
            extra_headers={**cfg.extra_headers,
                           "Authorization": f"{token_type} {token}"},
        )

    # ------------------------------------------------------------------
    # Form / JSON login  (+ optional TOTP second factor)
    # ------------------------------------------------------------------

    async def _form_login(
        self, cfg: AuthConfig, client: httpx.AsyncClient
    ) -> Optional[ActiveSession]:
        body: dict = {cfg.user_field: cfg.username, cfg.pass_field: cfg.password}

        try:
            # Use follow_redirects=False so we can capture Set-Cookie from the 302
            # before the redirect strips it.  Then manually follow up to 5 hops.
            if cfg.content_type == "form":
                resp = await client.post(cfg.login_url, data=body,
                                         follow_redirects=False)
            else:
                resp = await client.post(cfg.login_url, json=body,
                                         follow_redirects=False)

            # Collect all cookies set across the redirect chain
            all_cookies: dict[str, str] = {}
            hops = 0
            while resp.status_code in (301, 302, 303, 307, 308) and hops < 5:
                for sc in resp.headers.get_list("set-cookie"):
                    kv = sc.split(";")[0].strip()
                    if "=" in kv:
                        k, _, v = kv.partition("=")
                        all_cookies[k.strip()] = v.strip()
                location = resp.headers.get("location", "")
                if not location:
                    break
                from urllib.parse import urljoin
                next_url = urljoin(str(resp.url), location)
                resp = await client.get(next_url, follow_redirects=False,
                                         cookies=all_cookies)
                hops += 1

            # Final response cookies too
            for sc in resp.headers.get_list("set-cookie"):
                kv = sc.split(";")[0].strip()
                if "=" in kv:
                    k, _, v = kv.partition("=")
                    all_cookies[k.strip()] = v.strip()

            # Attach aggregated cookies so _extract_session can see them
            if all_cookies and not resp.headers.get("set-cookie"):
                # Synthesise a combined cookie header for the extractor
                combined = "; ".join(f"{k}={v}" for k, v in all_cookies.items())
                # Monkey-patch the headers view so _extract_session picks it up
                resp.headers["x-nexus-aggregated-cookies"] = combined

            # Store for later use in _extract_session
            self._aggregated_cookies = all_cookies

        except Exception as exc:
            logger.warning("[auth] Login request failed: %s", exc)
            return None

        # Check if server wants OTP before accepting login
        needs_otp = (
            resp.status_code in (401, 403, 200)
            and any(k in resp.text.lower()
                    for k in ("otp", "2fa", "totp", "mfa", "one-time",
                              "verification code", "authenticator"))
        )

        if needs_otp or cfg.totp_secret or cfg.otp_code:
            logger.info("[auth] Server requires OTP — submitting second factor")
            resp = await self._submit_otp(cfg, client, resp)
            if resp is None:
                return None

        if resp.status_code >= 400:
            logger.warning("[auth] Login failed — HTTP %d: %.200s",
                           resp.status_code, resp.text)
            return None

        return self._extract_session(cfg, resp)

    # ------------------------------------------------------------------
    # OTP / TOTP second factor
    # ------------------------------------------------------------------

    async def _submit_otp(
        self,
        cfg: AuthConfig,
        client: httpx.AsyncClient,
        first_resp: httpx.Response,
    ) -> Optional[httpx.Response]:
        code = self._get_otp_code(cfg)
        if not code:
            logger.warning("[auth] OTP required but no totp_secret or otp_code provided")
            return None

        # Carry cookies from the first response so session is linked
        cookies = dict(first_resp.cookies)
        otp_url = cfg.otp_url or cfg.login_url
        otp_body = {cfg.otp_field: code}

        # Some apps want the credentials again with the OTP in the same request
        if cfg.username:
            otp_body[cfg.user_field] = cfg.username
            otp_body[cfg.pass_field] = cfg.password

        try:
            if cfg.content_type == "form":
                resp = await client.post(otp_url, data=otp_body, cookies=cookies)
            else:
                resp = await client.post(otp_url, json=otp_body, cookies=cookies)
        except Exception as exc:
            logger.warning("[auth] OTP submission failed: %s", exc)
            return None

        logger.info("[auth] OTP submitted — HTTP %d", resp.status_code)
        return resp

    def _get_otp_code(self, cfg: AuthConfig) -> str:
        """Generate TOTP from secret or return static code."""
        if cfg.totp_secret:
            try:
                import pyotp  # optional dependency
                totp = pyotp.TOTP(cfg.totp_secret)
                code = totp.now()
                logger.info("[auth] Generated TOTP code: %s", code)
                return code
            except ImportError:
                logger.error("[auth] pyotp not installed — run: pip install pyotp")
            except Exception as exc:
                logger.warning("[auth] TOTP generation failed: %s", exc)
        return cfg.otp_code

    # ------------------------------------------------------------------
    # Session extraction from login response
    # ------------------------------------------------------------------

    def _extract_session(
        self, cfg: AuthConfig, resp: httpx.Response
    ) -> Optional[ActiveSession]:
        """
        Try to extract a usable session token from a login response.
        Priority:
          1. JSON body token at cfg.token_path  (e.g. "data.token")
          2. Any "token" / "access_token" key anywhere in JSON body
          3. Set-Cookie header (cfg.cookie_name or first session cookie)
          4. Authorization header in the response (rare but happens)
        """
        # 1 & 2 — JSON body
        try:
            body = resp.json()
            token = self._dig(body, cfg.token_path)
            if not token:
                # Fallback: search common keys at any depth
                token = self._find_token_in_dict(body)
            if token:
                logger.info("[auth] Extracted Bearer token from JSON response body")
                return ActiveSession(
                    token=token,
                    auth_type="bearer",
                    extra_headers={**cfg.extra_headers,
                                   "Authorization": f"Bearer {token}"},
                )
        except Exception:
            pass

        # 3 — Aggregated cookies from redirect chain (collected in _form_login)
        agg_cookies: dict = getattr(self, "_aggregated_cookies", {})
        if agg_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in agg_cookies.items())
            logger.info("[auth] Using aggregated redirect-chain cookies: %.80s…", cookie_str)
            return ActiveSession(
                cookie=cookie_str,
                auth_type="cookie",
                extra_headers={**cfg.extra_headers, "Cookie": cookie_str},
            )

        # 3b — Set-Cookie from final response
        set_cookie = resp.headers.get("set-cookie", "")
        if set_cookie:
            if cfg.cookie_name:
                # Extract specific cookie value
                m = re.search(
                    rf"{re.escape(cfg.cookie_name)}=([^;]+)", set_cookie
                )
                cookie_str = (f"{cfg.cookie_name}={m.group(1)}" if m
                              else set_cookie.split(";")[0])
            else:
                # Use all cookies as a cookie string
                cookie_str = "; ".join(
                    c.split(";")[0].strip()
                    for c in resp.headers.get_list("set-cookie")
                    if c
                )
            if cookie_str:
                logger.info("[auth] Using Set-Cookie session: %.60s...", cookie_str)
                return ActiveSession(
                    cookie=cookie_str,
                    auth_type="cookie",
                    extra_headers={**cfg.extra_headers,
                                   "Cookie": cookie_str},
                )

        # 4 — Authorization header in response (unusual but seen in some APIs)
        auth_header = resp.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:]
            logger.info("[auth] Extracted Bearer token from response Authorization header")
            return ActiveSession(
                token=token,
                auth_type="bearer",
                extra_headers={**cfg.extra_headers,
                               "Authorization": f"Bearer {token}"},
            )

        logger.warning("[auth] Could not extract token or cookie from login response "
                       "(HTTP %d). Check token_path / cookie_name settings.",
                       resp.status_code)
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dig(obj: dict, path: str) -> str:
        """Navigate a dot-path like 'data.token' through nested dicts."""
        parts = path.split(".")
        cur = obj
        for part in parts:
            if not isinstance(cur, dict):
                return ""
            cur = cur.get(part, "")
        return str(cur) if cur else ""

    @staticmethod
    def _find_token_in_dict(obj: dict, _depth: int = 0) -> str:
        """Recursively search for common token key names in a JSON response."""
        if _depth > 4:
            return ""
        _TOKEN_KEYS = {"token", "access_token", "accessToken", "jwt",
                       "auth_token", "authToken", "id_token", "idToken"}
        for k, v in obj.items():
            if k in _TOKEN_KEYS and isinstance(v, str) and len(v) > 10:
                return v
            if isinstance(v, dict):
                found = SessionAuthenticator._find_token_in_dict(v, _depth + 1)
                if found:
                    return found
        return ""
