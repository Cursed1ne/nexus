#!/usr/bin/env python3
"""
NEXUS CLI — Neural EXploitation Unified System
===============================================
Command-line interface for the NEXUS LLM security framework.

Usage:
  nexus scan       --target ollama://localhost:11434 --model llama3
  nexus attack     --target openai://gpt-4 --attacks prompt_injection jailbreak
  nexus scan       --target penny://www.priceline.com --api-key "COOKIE_STRING"
  nexus recon      --host 192.168.1.0
  nexus fingerprint --target ollama://localhost:11434
  nexus ctf        --scenario 01 --target openai://gpt-4
  nexus lvd        --list / --search injection / --stats
  nexus score      --vector "LVSS:1.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/AL:F/DP:S/MA:N"

Target types:
  openai://model          OpenAI API (needs OPENAI_API_KEY)
  anthropic://model       Anthropic API (needs ANTHROPIC_API_KEY)
  ollama://host/model     Local Ollama instance
  penny://hostname        Priceline Penny / enterprise chatbot (needs --api-key with cookies)
  https://custom-url      Any custom HTTP endpoint
"""

import argparse
import os
import sys
import json
from typing import Optional

from dotenv import load_dotenv
load_dotenv()


def _ollama_pick_model(host: str, proxy: str = "") -> str:
    """
    Query /api/tags to list available models, print them, and return the first one.
    Falls back to 'llama3' if the endpoint is unreachable.
    """
    import httpx
    try:
        kwargs: dict = {"timeout": 6}
        if proxy:
            kwargs["proxy"] = proxy
            kwargs["verify"] = False
        resp = httpx.get(f"{host}/api/tags", **kwargs)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            if models:
                print(f"[*] Ollama models available: {', '.join(models)}")
                print(f"[*] Using: {models[0]}  (pass ollama://{host.replace('http://', '')}/model-name to choose)")
                return models[0]
    except Exception:
        pass
    return "llama3"


def build_target(target_str: str, api_key: str = "", model: str = "", proxy: str = "",
                 session_args: Optional[dict] = None):
    """Parse a target string like 'openai://gpt-4' into an LLMTarget.

    proxy: HTTP proxy URL (e.g. 'http://127.0.0.1:8080' for Burp Suite).
           All LLM traffic will be routed through this proxy.
    session_args: extra kwargs for session:// targets (cookies, upload, chat_url, etc.)
    """
    from nexus.core.target import LLMTarget, TargetType, openai_target, anthropic_target, ollama_target, penny_target

    target = None

    # ── session:// — authenticated web session + optional file upload ──────────
    if target_str.startswith("session://"):
        from nexus.core.web_session_target import web_session_target
        base_url = target_str[len("session://"):]
        if not base_url.startswith("http"):
            base_url = "https://" + base_url
        sa = session_args or {}
        target = web_session_target(
            base_url=base_url,
            cookies=sa.get("cookies") or api_key or os.environ.get("SESSION_COOKIES", ""),
            upload_file=sa.get("upload_file", ""),
            upload_url=sa.get("upload_url", ""),
            upload_field=sa.get("upload_field", "file"),
            upload_extra_fields=sa.get("upload_extra_fields"),
            upload_id_path=sa.get("upload_id_path", ""),
            csrf_url=sa.get("csrf_url", ""),
            csrf_path=sa.get("csrf_path", ""),
            csrf_header=sa.get("csrf_header", "X-CSRF-Token"),
            chat_url=sa.get("chat_url", ""),
            chat_field=sa.get("chat_field", "message"),
            chat_body_template=sa.get("chat_body_template", ""),
            chat_response_path=sa.get("chat_response_path", ""),
            extra_headers=sa.get("extra_headers"),
            proxy_url=proxy or "",
            timeout=sa.get("timeout", 60),
        )
        print(f"[*] Session target: {base_url}")
        if sa.get("upload_file"):
            print(f"[*] Pre-flight upload: {sa['upload_file']} → {sa.get('upload_url', '?')}")
        if sa.get("cookies") or api_key:
            print(f"[*] Cookie auth: {len(sa.get('cookies') or api_key)} chars")
        return target

    if target_str.startswith("openai://"):
        model_name = model or target_str.replace("openai://", "") or "gpt-4o"
        key = api_key or os.environ.get("OPENAI_API_KEY", "")
        target = openai_target("openai", model=model_name, api_key=key)

    elif target_str.startswith("anthropic://"):
        model_name = model or target_str.replace("anthropic://", "") or "claude-sonnet-4-6"
        key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        target = anthropic_target("anthropic", model=model_name, api_key=key)

    elif target_str.startswith("ollama://"):
        rest = target_str.replace("ollama://", "")
        if "/" in rest:
            host_part, model_part = rest.rsplit("/", 1)
        else:
            host_part = rest
            model_part = model or _ollama_pick_model(f"http://{host_part}", proxy)
        target = ollama_target("ollama", model=model_part, host=f"http://{host_part}")

    elif target_str.startswith("penny://"):
        # penny://www.priceline.com  --api-key "full_cookie_string"
        host = target_str.replace("penny://", "").rstrip("/")
        base_url = f"https://{host}" if not host.startswith("http") else host
        cookies = api_key or os.environ.get("PENNY_COOKIES", "")
        # Extract cguid from PL_CINFO cookie if present
        cguid = ""
        if "PL_CINFO=" in cookies:
            import re
            m = re.search(r"PL_CINFO=([^;~]+)", cookies)
            if m:
                cguid = m.group(1)
        target = penny_target(
            name="penny",
            base_url=base_url,
            cookies=cookies,
            cguid=cguid,
        )

    else:
        if target_str.startswith("http://") or target_str.startswith("https://"):
            # Strip query params — they belong to the web UI page, not the API
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(target_str)
            base_url = urlunparse(parsed._replace(query="", fragment=""))
            clean_origin = f"{parsed.scheme}://{parsed.netloc}"

            # Warn early if the path looks like telemetry / analytics rather than AI
            _warn_non_ai_url(parsed.path, parsed.netloc)

            cookies = (session_args or {}).get("cookies") or api_key or ""

            # Auto-upgrade: if cookies provided, use WebSessionTarget (skips framework
            # auto-detection which would probe the site without auth and get 403s)
            if cookies:
                from nexus.core.web_session_target import web_session_target
                sa = session_args or {}

                # If no chat_url given, probe common AI API paths on this origin
                chat_url = sa.get("chat_url", "")
                if not chat_url:
                    chat_url = _probe_chat_endpoint(clean_origin, cookies, proxy or "")
                    if chat_url:
                        print(f"[+] Auto-detected chat endpoint: {chat_url}")
                    else:
                        print(f"[!] Could not auto-detect chat endpoint.")
                        print(f"    Use Burp Suite with --proxy http://127.0.0.1:8080 and")
                        print(f"    browse the site to capture the API call, then re-run with:")
                        print(f"    --chat-url /api/path/to/chat")
                        chat_url = "/api/v2/generate"  # best guess fallback

                target = web_session_target(
                    base_url=clean_origin,
                    cookies=cookies,
                    upload_file=sa.get("upload_file", ""),
                    upload_url=sa.get("upload_url", ""),
                    upload_field=sa.get("upload_field", "file"),
                    upload_extra_fields=sa.get("upload_extra_fields"),
                    upload_id_path=sa.get("upload_id_path", ""),
                    csrf_url=sa.get("csrf_url", ""),
                    csrf_path=sa.get("csrf_path", ""),
                    csrf_header=sa.get("csrf_header", "X-CSRF-Token"),
                    chat_url=chat_url,
                    chat_field=sa.get("chat_field", "prompt"),
                    chat_body_template=sa.get("chat_body_template", ""),
                    chat_response_path=sa.get("chat_response_path", ""),
                    extra_headers=sa.get("extra_headers"),
                    proxy_url=proxy or "",
                    timeout=sa.get("timeout", 60),
                )
                print(f"[*] Web session target: {clean_origin}")
                if base_url != target_str:
                    print(f"[*] (query params stripped from URL — using origin only)")
            else:
                from nexus.recon.framework_detector import detect_and_build_target
                target = detect_and_build_target(
                    url=base_url,
                    api_key=api_key,
                    model_override=model,
                    proxy_url=proxy or None,
                )
        else:
            # Unknown scheme — fall back to OpenAI-compat with the URL as-is
            target = LLMTarget(
                name="custom",
                target_type=TargetType.CUSTOM,
                base_url=target_str,
                model=model or "default",
                api_key=api_key,
            )

    # Apply proxy if specified (WebSessionTarget handles proxy in __post_init__)
    from nexus.core.web_session_target import WebSessionTarget
    if proxy and not isinstance(target, WebSessionTarget):
        if hasattr(target, 'proxy_url') and not target.proxy_url:
            target.proxy_url = proxy
            target.__post_init__()
            print(f"[*] Proxy: all traffic routed through {proxy}")

    return target


def _warn_non_ai_url(path: str, netloc: str) -> None:
    """
    Print a clear warning when the URL path looks like telemetry / analytics / CDN
    rather than an AI chat or generation API.  Does NOT abort — just informs.
    """
    path_lower = path.lower()

    # Known non-AI path patterns (analytics, telemetry, data collection, CDN)
    NON_AI_PATTERNS = [
        ("experienceedge", "Adobe Experience Edge / Analytics data-collection endpoint — NOT an AI API"),
        ("/collect",        "Data-collection / telemetry endpoint — NOT an AI API"),
        ("/v1/collect",     "Analytics collect endpoint — NOT an AI API"),
        ("/analytics",      "Analytics endpoint — NOT an AI API"),
        ("/telemetry",      "Telemetry endpoint — NOT an AI API"),
        ("/tracking",       "Tracking endpoint — NOT an AI API"),
        ("/pixel",          "Tracking pixel — NOT an AI API"),
        ("/beacon",         "Beacon endpoint — NOT an AI API"),
        ("/dcs/",           "Adobe DCS (Data Collection Server) — NOT an AI API"),
        ("/b/ss/",          "Adobe Analytics image beacon — NOT an AI API"),
    ]

    for fragment, reason in NON_AI_PATTERNS:
        if fragment.lower() in path_lower or fragment.lower() in netloc.lower():
            print()
            print("=" * 65)
            print(f"  [!] WARNING — Wrong target URL")
            print(f"  {reason}")
            print(f"  Path: {path}")
            print()
            print("  This URL will return empty JSON or an HTTP error — it")
            print("  does not expose an AI model to attack.")
            print()
            print("  To find the real Firefly AI endpoint:")
            print("    1. Open Burp Suite → Proxy → Intercept OFF")
            print("    2. Set browser proxy to 127.0.0.1:8080")
            print("    3. Go to firefly.adobe.com, generate one image")
            print("    4. In Burp HTTP History, find the POST with JSON body")
            print("       containing 'prompt' or 'numVariations' etc.")
            print("    5. Re-run: nexus scan \\")
            print("         --target 'https://firefly.adobe.com' \\")
            print("         --cookies '...' \\")
            print("         --chat-url '/the/real/api/path' \\")
            print("         --proxy http://127.0.0.1:8080")
            print("=" * 65)
            print()
            break


def _is_ai_response(body: str, ct: str) -> bool:
    """True when the response body looks like an AI API response (not a web page)."""
    if "text/html" in ct:
        return False
    stripped = body.lstrip()
    if stripped.startswith(("<!doctype", "<html", "<!DOCTYPE", "<HTML")):
        return False
    # Must look like JSON or event-stream
    if "application/json" in ct or "text/event-stream" in ct:
        return True
    # Fallback: starts with JSON-like characters
    return stripped.startswith(("{", "[", "data:"))


def _extract_paths_from_js(origin: str, cookies: str, proxy: str = "") -> list:
    """
    Fetch the app's root page, find all <script src> JS bundles,
    then grep each bundle for API path patterns.
    Returns a deduplicated list of candidate paths found in JS.
    """
    import httpx
    import re

    client_kwargs: dict = {
        "headers": {
            "Cookie": cookies,
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        },
        "timeout": 12,
        "follow_redirects": True,
    }
    if proxy:
        client_kwargs["proxy"] = proxy
        client_kwargs["verify"] = False

    found: list = []

    try:
        with httpx.Client(**client_kwargs) as client:
            # Fetch the root page
            root = client.get(origin)
            if root.status_code != 200:
                return found

            html = root.text
            # Find all script src paths
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)

            for src in script_srcs[:15]:  # limit to first 15 bundles
                if not src.startswith("http"):
                    src = origin.rstrip("/") + "/" + src.lstrip("/")
                try:
                    js_resp = client.get(src, timeout=10)
                    if js_resp.status_code != 200:
                        continue
                    js_text = js_resp.text

                    # Extract string literals that look like API paths
                    # Match: "/api/...", "/v1/...", "/service/...", "/internal/...", etc.
                    api_paths = re.findall(
                        r'["\`](\/(api|v\d|services?|internal|assistant|ai|chat|query|generate|llm|gpt|copilot|ask|prompt|completions?|inference|infer|predict)[^"\'` \t\n\\]{3,80})["\`]',
                        js_text,
                        re.IGNORECASE,
                    )
                    for match in api_paths:
                        path = match[0]
                        # Filter out obvious non-endpoints (static assets, fonts, images)
                        if re.search(r'\.(js|css|png|jpg|svg|woff|ico|map)$', path, re.IGNORECASE):
                            continue
                        if path not in found:
                            found.append(path)
                except Exception:
                    continue
    except Exception:
        pass

    return found


def _pull_burp_ai_endpoints(burp_api: str = "http://127.0.0.1:1337") -> list:
    """
    Pull HTTP history from Burp Suite's REST API and return paths that look
    like AI API calls (POST + JSON body containing 'prompt', 'message', etc.)

    Burp's REST API is available at http://127.0.0.1:1337/v0.1/ by default.
    The user must enable it: Burp → Extensions → BurpSuite REST API → enable.
    """
    import httpx
    import json as _json

    candidates: list = []
    try:
        resp = httpx.get(f"{burp_api}/v0.1/proxy/history", timeout=5)
        if resp.status_code != 200:
            return candidates

        items = resp.json()
        if not isinstance(items, list):
            items = items.get("messages", [])

        AI_BODY_SIGNALS = ["prompt", "message", "query", "input", "text", "content",
                           "numVariations", "num_variants", "instruction", "userMessage"]

        for item in items:
            req = item.get("request", {})
            method = req.get("method", "")
            path = req.get("path", "")
            body = req.get("body", "")
            ct = req.get("headers", {}).get("content-type", "")

            if method.upper() != "POST":
                continue
            if "application/json" not in ct and "text/plain" not in ct:
                continue

            # Check if request body contains AI-like fields
            body_lower = body.lower() if isinstance(body, str) else ""
            if any(sig in body_lower for sig in AI_BODY_SIGNALS):
                if path and path not in candidates:
                    candidates.append(path)

    except Exception:
        pass

    return candidates


def _probe_chat_endpoint(origin: str, cookies: str, proxy: str = "") -> str:
    """
    Multi-strategy AI endpoint discovery:
      1. Pull from Burp history (if proxy is Burp and its REST API is reachable)
      2. Extract paths from JS bundles on the page
      3. Probe a fallback list of known AI API paths

    Returns the first confirmed path, or "" if nothing found.
    """
    import httpx

    client_kwargs: dict = {
        "headers": {
            "Cookie": cookies,
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        "timeout": 8,
        "follow_redirects": False,
    }
    if proxy:
        client_kwargs["proxy"] = proxy
        client_kwargs["verify"] = False

    CONFIRMS = {200, 201, 400, 401, 403, 405, 422}

    def _probe_path(client, path: str) -> bool:
        """Return True if the path looks like a real API endpoint."""
        try:
            resp = client.post(
                origin.rstrip("/") + path,
                json={"prompt": "test", "query": "test", "message": "test"},
            )
            if resp.status_code not in CONFIRMS:
                return False
            return _is_ai_response(resp.text[:300], resp.headers.get("content-type", ""))
        except Exception:
            return False

    # ── Strategy 1: Burp history ──────────────────────────────────────────────
    if proxy and "8080" in proxy:
        burp_api_port = proxy.replace("8080", "1337").rstrip("/")
        burp_paths = _pull_burp_ai_endpoints(burp_api_port)
        if burp_paths:
            print(f"[+] Burp history: {len(burp_paths)} candidate AI endpoint(s) found")
            with httpx.Client(**client_kwargs) as client:
                for path in burp_paths:
                    if _probe_path(client, path):
                        print(f"    Confirmed (from Burp): {path}")
                        return path

    # ── Strategy 2: JS bundle scanning ───────────────────────────────────────
    print("[*] Scanning JS bundles for API paths...")
    js_paths = _extract_paths_from_js(origin, cookies, proxy)
    if js_paths:
        print(f"[+] JS bundles: {len(js_paths)} candidate path(s) found")
        with httpx.Client(**client_kwargs) as client:
            for path in js_paths:
                if _probe_path(client, path):
                    print(f"    Confirmed (from JS): {path}")
                    return path

    # ── Strategy 3: fallback probe list ──────────────────────────────────────
    FALLBACK_PATHS = [
        # Generic OpenAI-compat (most common)
        "/v1/chat/completions",
        "/v1/completions",
        # Adobe Firefly patterns
        "/api/v3/generate",
        "/api/v2/generate",
        "/api/v1/generate",
        "/api/v3/images/generate",
        "/api/v2/images/generate",
        "/api/v2/chat",
        "/api/v1/chat",
        "/api/chat",
        "/api/v1/ai/chat",
        "/api/ai/query",
        # LangServe / custom
        "/api/v1/documents/chat",
        "/chat/invoke",
        "/invoke",
        "/query",
        "/ask",
        "/generate",
        "/assistant",
        "/assistant/v1/chat",
        "/assistant/v2/query",
        "/services/ai/chat",
        "/services/chat",
        "/internal/ai",
        "/copilot/chat",
        "/llm/chat",
    ]

    with httpx.Client(**client_kwargs) as client:
        for path in FALLBACK_PATHS:
            if _probe_path(client, path):
                print(f"[+] Confirmed (probe): {path}")
                return path

    return ""


def cmd_discover(args):
    """Discover AI endpoints on a target without running attacks."""
    from urllib.parse import urlparse

    target_str = args.target
    cookies = getattr(args, 'cookies', '') or getattr(args, 'api_key', '') or ""
    proxy = getattr(args, 'proxy', '') or ""

    parsed = urlparse(target_str if target_str.startswith("http") else "https://" + target_str)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    print(f"\n[*] AI Endpoint Discovery: {origin}")
    print(f"[*] Strategies: Burp history → JS bundle scan → path probe\n")

    # Strategy 1: Burp
    if proxy and "8080" in proxy:
        burp_api_port = proxy.replace("8080", "1337").rstrip("/")
        print(f"[*] Checking Burp REST API at {burp_api_port}...")
        burp_paths = _pull_burp_ai_endpoints(burp_api_port)
        if burp_paths:
            print(f"[+] Burp history found {len(burp_paths)} AI candidate(s):")
            for p in burp_paths:
                print(f"    POST {p}")
        else:
            print("    (no AI calls in Burp history yet — browse the app first)")

    # Strategy 2: JS bundles
    print(f"\n[*] Scanning JS bundles on {origin}...")
    js_paths = _extract_paths_from_js(origin, cookies, proxy)
    if js_paths:
        print(f"[+] JS bundles revealed {len(js_paths)} API path(s):")
        for p in js_paths[:30]:
            print(f"    {p}")
    else:
        print("    (no API paths found in JS bundles)")

    # Strategy 3: Probe
    print(f"\n[*] Probing known AI endpoint patterns...")
    import httpx
    client_kwargs: dict = {
        "headers": {
            "Cookie": cookies,
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        "timeout": 6,
        "follow_redirects": False,
    }
    if proxy:
        client_kwargs["proxy"] = proxy
        client_kwargs["verify"] = False

    PROBE_PATHS = [
        "/v1/chat/completions", "/v1/completions",
        "/api/v3/generate", "/api/v2/generate", "/api/v1/generate",
        "/api/v3/images/generate", "/api/v2/images/generate",
        "/api/v2/chat", "/api/v1/chat", "/api/chat",
        "/api/v1/ai/chat", "/api/ai/query", "/api/v1/documents/chat",
        "/chat/invoke", "/invoke", "/query", "/ask", "/generate",
        "/assistant", "/assistant/v1/chat", "/assistant/v2/query",
        "/services/ai/chat", "/services/chat",
        "/internal/ai", "/copilot/chat", "/llm/chat",
    ]

    confirmed = []
    with httpx.Client(**client_kwargs) as client:
        for path in PROBE_PATHS:
            try:
                resp = client.post(
                    origin.rstrip("/") + path,
                    json={"prompt": "test", "query": "test", "message": "test"},
                )
                status = resp.status_code
                ct = resp.headers.get("content-type", "")
                body_snippet = resp.text[:120].replace("\n", " ")
                if status in {200, 201, 400, 401, 403, 405, 422}:
                    ai_like = _is_ai_response(resp.text[:300], ct)
                    marker = "[AI]" if ai_like else "    "
                    print(f"  {marker} {status} POST {path}  ({ct[:40]})")
                    if ai_like:
                        confirmed.append(path)
                        print(f"         body: {body_snippet}")
            except Exception:
                pass

    print()
    if confirmed:
        print(f"[+] CONFIRMED AI endpoints ({len(confirmed)}):")
        for p in confirmed:
            print(f"    {p}")
        print()
        print("  Run attacks with:")
        print(f"    nexus scan \\")
        print(f"      --target '{origin}' \\")
        print(f"      --cookies '...' \\")
        print(f"      --chat-url '{confirmed[0]}' \\")
        if proxy:
            print(f"      --proxy {proxy} \\")
        print(f"      --output /tmp/findings.json")
    else:
        print("[!] No AI endpoints confirmed by probing.")
        print("    Next step: browse the app through Burp, trigger an AI call,")
        print("    then re-run: nexus discover --target ... --proxy http://127.0.0.1:8080")
    print()


def _apply_timeout(target, args):
    """Apply --timeout override if specified."""
    timeout = getattr(args, 'timeout', 0)
    if timeout > 0:
        target.timeout = timeout
        if hasattr(target, '__post_init__'):
            target.__post_init__()  # Recreate httpx client with new timeout


def _session_args_from_args(args) -> Optional[dict]:
    """Build session_args dict from CLI args for session:// targets or https:// + cookies."""
    has_session_scheme = args.target.startswith("session://")
    has_cookies = bool(getattr(args, 'cookies', ''))
    has_session_flags = any([
        getattr(args, 'upload', ''),
        getattr(args, 'chat_url', ''),
        has_cookies,
    ])
    if not (has_session_scheme or has_session_flags):
        return None
    sa: dict = {}
    if getattr(args, 'cookies', ''):
        sa['cookies'] = args.cookies
    if getattr(args, 'upload', ''):
        sa['upload_file'] = args.upload
    if getattr(args, 'upload_url', ''):
        sa['upload_url'] = args.upload_url
    if getattr(args, 'upload_field', ''):
        sa['upload_field'] = args.upload_field
    if getattr(args, 'upload_id_path', ''):
        sa['upload_id_path'] = args.upload_id_path
    if getattr(args, 'csrf_url', ''):
        sa['csrf_url'] = args.csrf_url
    if getattr(args, 'csrf_header', ''):
        sa['csrf_header'] = args.csrf_header
    if getattr(args, 'chat_url', ''):
        sa['chat_url'] = args.chat_url
    if getattr(args, 'chat_field', ''):
        sa['chat_field'] = args.chat_field
    if getattr(args, 'chat_body', ''):
        sa['chat_body_template'] = args.chat_body
    if getattr(args, 'chat_response_path', ''):
        sa['chat_response_path'] = args.chat_response_path
    return sa


def cmd_scan(args):
    """Full automated security scan."""
    from nexus.core.agent import NexusAgent
    from nexus.reporting.reporter import NexusReporter

    sa = _session_args_from_args(args)
    target = build_target(args.target, args.api_key, args.model, getattr(args, 'proxy', ''),
                          session_args=sa)

    # Verify session pre-flight before running attacks
    if sa is not None:
        from nexus.core.web_session_target import WebSessionTarget
        if isinstance(target, WebSessionTarget):
            ok, msg = target.run_preflight_only()
            if not ok:
                print(f"[!] Pre-flight failed: {msg}")
                print("[!] Check your --cookies, --upload-url, and --chat-url flags.")
                return
            print(f"[+] Pre-flight OK: {msg}")

    _apply_timeout(target, args)
    agent = NexusAgent(
        target=target,
        attack_budget=args.budget,
        verbose=not args.quiet,
        require_confirmation=args.interactive,
    )

    attack_types = args.attacks if args.attacks else None
    session = agent.run(attack_types=attack_types)

    reporter = NexusReporter(session)
    reporter.print_summary()

    if args.output:
        if args.output.endswith(".md"):
            reporter.save_markdown(args.output)
        elif args.output.endswith(".html"):
            reporter.save_html(args.output)
        else:
            reporter.save_json(args.output)
            # Also auto-generate HTML alongside JSON
            html_path = args.output.rsplit(".", 1)[0] + ".html"
            reporter.save_html(html_path)
    else:
        # No --output: auto-save both formats to /tmp
        import tempfile, os
        base = "/tmp/nexus-report"
        reporter.save_json(base + ".json")
        reporter.save_html(base + ".html")
        print(f"[nexus] Open report: open {base}.html")


def cmd_attack(args):
    """Run specific attack module(s)."""
    from nexus.attacks import get_attack, list_attacks
    from nexus.core.session import ExploitSession
    from nexus.reporting.reporter import NexusReporter

    if not args.attacks:
        print(f"Available attacks: {', '.join(list_attacks())}")
        return

    sa = _session_args_from_args(args)
    target = build_target(args.target, args.api_key, args.model, getattr(args, 'proxy', ''),
                          session_args=sa)

    if sa is not None:
        from nexus.core.web_session_target import WebSessionTarget
        if isinstance(target, WebSessionTarget):
            ok, msg = target.run_preflight_only()
            if not ok:
                print(f"[!] Pre-flight failed: {msg}")
                return
            print(f"[+] Pre-flight OK: {msg}")

    _apply_timeout(target, args)
    session = ExploitSession(target_name=target.name)

    for attack_name in args.attacks:
        attack_cls = get_attack(attack_name)
        if not attack_cls:
            print(f"[!] Unknown attack: {attack_name}. Available: {', '.join(list_attacks())}")
            continue

        print(f"[*] Running: {attack_name}")
        attack = attack_cls(budget=args.budget)
        findings = attack.run(target, session)
        print(f"    Findings: {len(findings)}")

    reporter = NexusReporter(session)
    reporter.print_summary()

    if args.output:
        if args.output.endswith(".html"):
            reporter.save_html(args.output)
        elif args.output.endswith(".md"):
            reporter.save_markdown(args.output)
        else:
            reporter.save_json(args.output)
            html_path = args.output.rsplit(".", 1)[0] + ".html"
            reporter.save_html(html_path)


def cmd_recon(args):
    """AI recon: live program discovery, attack surface search, agent deep recon, host scan."""

    quiet = getattr(args, 'quiet', False)
    verbose = getattr(args, 'verbose', False)
    output = getattr(args, 'output', None)

    # ── How-to-find guide ────────────────────────────────────────────────────
    if getattr(args, 'how_to_find', False):
        from nexus.recon.ai_programs import print_how_to_find
        print_how_to_find()
        return

    # ── Bug bounty program discovery (static + live search) ──────────────────
    if getattr(args, 'programs', False):
        from nexus.recon.ai_programs import AIBountyDirectory
        from nexus.recon.live_search import LiveDiscoveryEngine

        d = AIBountyDirectory()
        keyword = getattr(args, 'search', None) or "AI"
        live = getattr(args, 'live', False)

        # Always show static database first
        if getattr(args, 'attack', None):
            static = d.for_attack_type(args.attack)
            print(f"\n[*] Static DB: {len(static)} programs relevant to '{args.attack}'")
        elif getattr(args, 'platform', None):
            static = d.by_platform(args.platform)
            print(f"\n[*] Static DB: {len(static)} programs on '{args.platform}'")
        else:
            static = d.search(keyword) if keyword != "AI" else d.all()
            print(f"\n[*] Static DB: {len(static)} programs (keyword='{keyword}')")

        d.print_list(static, verbose=verbose)

        # Live search across platforms
        if live:
            print(f"\n[*] Live search: querying HackerOne, Bugcrowd, Intigriti, web...")
            engine = LiveDiscoveryEngine(
                github_token=os.environ.get("GITHUB_TOKEN", ""),
                shodan_key=getattr(args, 'shodan_key', '') or '',
                verbose=not quiet,
            )
            live_programs = engine.discover_programs(keyword=keyword)
            if live_programs:
                print(f"\n[+] Live discovery: {len(live_programs)} additional program(s) found\n")
                _print_live_programs(live_programs, verbose=verbose)
                # Merge into directory for output
                for lp in live_programs:
                    try:
                        d._programs.append(lp.to_nexus_program())
                    except Exception:
                        pass
            else:
                print("[-] Live search returned no new programs (rate-limited or no results)")

        if output:
            results = d.for_attack_type(args.attack) if getattr(args, 'attack', None) else d.all()
            with open(output, "w") as f:
                f.write(d.to_json(results))
            print(f"[nexus] Saved {len(results)} programs to {output}")

        # Auto-scan discovered targets
        if getattr(args, 'auto_scan', False) and live_programs:
            _auto_scan_discovered(live_programs, args)
        return

    # ── AI attack surface: live search (DuckDuckGo + GitHub + Shodan) ────────
    if getattr(args, 'surface', None):
        from nexus.recon.ai_surface import AISurfaceRecon
        from nexus.recon.live_search import LiveDiscoveryEngine

        print(f"\n[*] AI attack surface recon: {args.surface}")

        # Active HTTP fingerprinting (existing)
        recon = AISurfaceRecon(
            target=args.surface,
            shodan_api_key=getattr(args, 'shodan_key', '') or '',
            verbose=not quiet,
        )
        report = recon.run_all()
        print(report.summary())

        # Live search for exposed endpoints
        if getattr(args, 'live', False) or True:   # always run live search
            print("[*] Live search: DuckDuckGo + GitHub + Shodan dork execution...")
            engine = LiveDiscoveryEngine(
                github_token=os.environ.get("GITHUB_TOKEN", ""),
                shodan_key=getattr(args, 'shodan_key', '') or '',
                verbose=not quiet,
            )
            domain = args.surface.replace("https://", "").replace("http://", "").split("/")[0]
            live_results = engine.search_exposed_endpoints(domain=domain)
            _print_live_surface(live_results)

            # Auto-suggest attack commands for found endpoints
            _suggest_attacks_from_surface(live_results, args)

        if output:
            with open(output, "w") as f:
                f.write(report.to_json())
            print(f"[nexus] Surface report saved to {output}")
        return

    # ── Print all dorks ───────────────────────────────────────────────────────
    if getattr(args, 'dorks', False):
        from nexus.recon.ai_surface import print_all_dorks
        print_all_dorks()
        return

    # ── AI agent deep recon ───────────────────────────────────────────────────
    if getattr(args, 'agent', None):
        from nexus.recon.ai_agent_recon import AIAgentRecon, print_agent_recon_guide

        if args.agent == "guide":
            print_agent_recon_guide()
            return

        # If it looks like a bug bounty platform URL, warn and recon the AI product instead
        BB_PLATFORMS = ("hackerone.com", "bugcrowd.com", "intigriti.com", "yeswehack.com")
        if any(p in args.agent for p in BB_PLATFORMS):
            print(f"[!] '{args.agent}' is a bug bounty platform, not an AI agent endpoint.")
            print("[!] Run 'nexus recon --programs' to browse programs.")
            print("[!] To recon an AI agent, provide the actual product URL:")
            print("    nexus recon --agent https://chat.openai.com")
            print("    nexus recon --agent https://claude.ai")
            return

        recon = AIAgentRecon(
            target_url=args.agent,
            api_key=getattr(args, 'api_key', '') or '',
            model_hint=getattr(args, 'model', '') or '',
            verbose=not quiet,
            deep=getattr(args, 'deep', False),
        )
        surface = recon.recon()
        print(surface.attack_plan())

        # Auto-run if requested
        if getattr(args, 'auto_scan', False) and surface.recommended_attacks:
            p1_attacks = [a["attack"] for a in surface.recommended_attacks if a["priority"] == "P1"]
            if p1_attacks:
                print(f"\n[*] Auto-scanning with P1 attacks: {', '.join(p1_attacks)}")
                _run_attacks_on_target(args.agent,
                                       getattr(args, 'api_key', ''),
                                       p1_attacks,
                                       budget=getattr(args, 'budget', 30))

        if output:
            with open(output, "w") as f:
                json.dump(surface.to_dict(), f, indent=2)
            print(f"[nexus] Agent surface map saved to {output}")
        return

    # ── Network host scan (original behaviour) ────────────────────────────────
    if not getattr(args, 'host', None):
        print("[!] Specify a recon mode:")
        print("    nexus recon --host 192.168.1.1          # scan host for AI endpoints")
        print("    nexus recon --surface target.com         # enumerate AI attack surface")
        print("    nexus recon --agent https://app.com      # deep recon AI agent")
        print("    nexus recon --programs                   # list AI bug bounty programs")
        print("    nexus recon --dorks                      # print Shodan/GitHub dorks")
        return

    from nexus.recon.scanner import LLMScanner
    scanner = LLMScanner(timeout=args.timeout)
    print(f"[*] Scanning {args.host}...")
    scanner.scan_host(args.host)
    print(scanner.report())


# ── Recon helper functions ─────────────────────────────────────────────────────

def _print_live_programs(programs, verbose=False):
    BOLD = "\033[1m"; RESET = "\033[0m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    PLATFORM_COLOR = {"hackerone": GREEN, "bugcrowd": YELLOW, "intigriti": "\033[96m",
                      "github": "\033[94m", "direct": "\033[37m"}
    for p in programs:
        col = PLATFORM_COLOR.get(p.platform, "")
        print(f"  {BOLD}{p.name}{RESET}  [{col}{p.platform.upper()}{RESET}]  {p.reward_range}")
        print(f"    {p.url}")
        if verbose and p.scope_hints:
            for hint in p.scope_hints[:3]:
                if hint:
                    print(f"    • {hint[:120]}")
        print()


def _print_live_surface(results: dict):
    BOLD = "\033[1m"; RESET = "\033[0m"; RED = "\033[91m"; YELLOW = "\033[93m"
    if not results:
        print("  [-] No exposed endpoints found via live search")
        return
    print(f"\n{BOLD}  Live Search Results:{RESET}")
    for category, hits in results.items():
        if not hits:
            continue
        print(f"\n  {BOLD}{category}{RESET} ({len(hits)} result(s)):")
        for h in hits[:3]:
            risk_col = RED if "shodan_live" in h.source else YELLOW
            print(f"    {risk_col}[{h.source}]{RESET} {h.title}")
            print(f"      {h.url}")
            if h.snippet:
                print(f"      {h.snippet[:100]}")


def _suggest_attacks_from_surface(results: dict, args):
    """Print nexus attack commands for each exposed endpoint found."""
    BOLD = "\033[1m"; RESET = "\033[0m"; CYAN = "\033[96m"; DIM = "\033[2m"
    suggestions = []
    attacked = set()
    for category, hits in results.items():
        for h in hits:
            url = h.url
            # Skip: empty URL, shodan links (not live endpoints), github (code only), duplicates
            if not url or not url.startswith("http") or url in attacked or "shodan_link" in h.source:
                continue
            if "github" in category.lower():
                continue
            attacked.add(url)
            if "mlflow" in category.lower():
                attacks = "prompt_injection rag_poisoning data_extraction"
                note = "MLflow model registry — RAG poisoning + data exfil priority"
            elif "ollama" in category.lower():
                attacks = "prompt_injection jailbreak model_dos model_file_security"
                note = "Exposed Ollama — unauthenticated model API"
            elif "gradio" in category.lower():
                attacks = "prompt_injection structured_injection jailbreak"
                note = "Gradio ML interface — structured injection priority"
            elif "langchain" in category.lower() or "langserve" in category.lower():
                attacks = "prompt_injection rag_poisoning tool_harness multi_agent"
                note = "LangChain/LangServe — tool harness + RAG priority"
            elif "mcp" in category.lower():
                attacks = "mcp_injection workspace_poisoning tool_harness prompt_injection"
                note = "MCP server — evil server + confused deputy attacks"
            elif "vllm" in category.lower() or "tgi" in category.lower():
                attacks = "prompt_injection jailbreak model_dos token_level_attack"
                note = "vLLM/TGI inference server"
            else:
                attacks = "prompt_injection jailbreak system_prompt_leak data_extraction"
                note = "Generic LLM endpoint — baseline sweep"
            suggestions.append((url, attacks, note, h.title))

    if not suggestions:
        print(f"\n  {DIM}[no actionable endpoints found — use Shodan links above for manual search]{RESET}")
        return

    print(f"\n{BOLD}  Suggested NEXUS commands for found targets:{RESET}")
    for url, attacks, note, title in suggestions:
        print(f"\n  {CYAN}# {note}{RESET}")
        if title:
            print(f"  {DIM}# {title[:80]}{RESET}")
        print(f"  nexus scan --target {url} \\")
        print(f"             --attacks {attacks} \\")
        print(f"             --budget 30 --output /tmp/nexus-$(date +%s).json")


def _auto_scan_discovered(programs, args):
    """Run nexus scan against each discovered program's URL."""
    import subprocess, sys
    for p in programs[:3]:  # limit auto-scan to first 3
        print(f"\n[*] Auto-scanning: {p.name} ({p.url})")
        cmd = [sys.executable, "-m", "nexus", "scan", "--target", p.url,
               "--budget", "20", "--quiet"]
        if getattr(args, 'api_key', ''):
            cmd += ["--api-key", args.api_key]
        result = subprocess.run(cmd, capture_output=False)


def _run_attacks_on_target(target_url: str, api_key: str, attacks: list, budget: int = 30):
    """Run specified attacks against a target and print summary."""
    from nexus.core.session import ExploitSession
    from nexus.attacks import get_attack
    from nexus.reporting.reporter import NexusReporter

    target = build_target(target_url, api_key)
    session = ExploitSession(target_name=target.name)

    for attack_name in attacks:
        cls = get_attack(attack_name)
        if not cls:
            continue
        print(f"  [*] Running {attack_name}...")
        attack = cls(budget=budget // len(attacks))
        findings = attack.run(target, session)
        print(f"      → {len(findings)} finding(s)")

    reporter = NexusReporter(session)
    reporter.print_summary()
    reporter.save_json("/tmp/nexus-recon-autoscan.json")
    reporter.save_html("/tmp/nexus-recon-autoscan.html")
    print(f"[nexus] Auto-scan report: open /tmp/nexus-recon-autoscan.html")


def cmd_fingerprint(args):
    """Fingerprint an LLM endpoint."""
    from nexus.recon.fingerprint import LLMFingerprinter

    target = build_target(args.target, args.api_key, args.model, getattr(args, 'proxy', ''))
    fp = LLMFingerprinter(target)
    print(f"[*] Fingerprinting {target.name}...")
    result = fp.fingerprint()
    print(fp.summary())

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[*] Full results saved to {args.output}")


def cmd_ctf(args):
    """Run a CTF scenario."""
    scenarios = {
        "01": "nexus.scenarios.scenario_01_basic_injection",
        "02": "nexus.scenarios.scenario_02_rag_attack",
        "03": "nexus.scenarios.scenario_03_multi_agent",
    }

    if args.list:
        print("Available CTF Scenarios:")
        print("  01 — Basic Prompt Injection         [Beginner,  100pts]")
        print("  02 — RAG Indirect Injection          [Intermediate, 250pts]")
        print("  03 — Multi-Agent Privilege Escalation [Advanced, 500pts]")
        return

    if not args.scenario:
        print("[!] Specify a scenario with --scenario 01|02|03")
        return

    if args.scenario not in scenarios:
        print(f"[!] Unknown scenario: {args.scenario}. Use --list to see available.")
        return

    import importlib
    mod = importlib.import_module(scenarios[args.scenario])
    target = build_target(args.target, args.api_key, args.model, getattr(args, 'proxy', ''))
    mode = "interactive" if args.interactive else "automated"
    solved = mod.run(target, mode=mode)
    sys.exit(0 if solved else 1)


def cmd_lvd(args):
    """Query the LLM Vulnerability Database."""
    from nexus.database.lvd import LVD

    db = LVD()

    if args.stats:
        stats = db.stats()
        print(json.dumps(stats, indent=2))
        return

    if args.search:
        results = db.search(args.search)
        print(f"Found {len(results)} entries for '{args.search}':")
        for entry in results:
            print(f"  {entry}")
        return

    if args.owasp:
        results = db.by_owasp(args.owasp)
        print(f"{len(results)} entries for OWASP {args.owasp}:")
        for entry in results:
            print(f"  {entry}")
        return

    if args.severity:
        results = db.by_severity(args.severity)
        print(f"{len(results)} {args.severity} entries:")
        for entry in results:
            print(f"  {entry}")
        return

    # List all
    print(f"LVD — {db.stats()['total']} entries:")
    for entry in sorted(db.all, key=lambda e: e.lvss_score, reverse=True):
        print(f"  {entry}")


def cmd_score(args):
    """Calculate an LVSS score from a vector string."""
    from nexus.scoring.lvss import LVSSVector, LVSSScorer

    if args.vector:
        try:
            vector = LVSSVector.from_string(args.vector)
            score = LVSSScorer.calculate(vector)
            print(LVSSScorer.describe(score, vector))
        except Exception as e:
            print(f"[!] Failed to parse vector: {e}")
        return

    # Interactive scoring
    print("LVSS Interactive Scorer")
    print("Defaults shown in brackets. Press Enter to accept.\n")

    def ask(prompt, default):
        val = input(f"  {prompt} [{default}]: ").strip()
        return val or default

    from nexus.scoring.lvss import (
        AttackVector, AttackComplexity, PrivilegesRequired,
        UserInteraction, Scope, Impact, AlignmentBypass,
        DataPersistence, MultiAgentImpact, LVSSVector
    )

    try:
        vector = LVSSVector(
            attack_vector=AttackVector(ask("Attack Vector (N/A/L/P)", "N")),
            attack_complexity=AttackComplexity(ask("Attack Complexity (L/H)", "L")),
            privileges_required=PrivilegesRequired(ask("Privileges Required (N/L/H)", "N")),
            user_interaction=UserInteraction(ask("User Interaction (N/R)", "N")),
            scope=Scope(ask("Scope (U/C)", "U")),
            confidentiality=Impact(ask("Confidentiality (N/L/H)", "N")),
            integrity=Impact(ask("Integrity (N/L/H)", "N")),
            availability=Impact(ask("Availability (N/L/H)", "N")),
            alignment_bypass=AlignmentBypass(ask("Alignment Bypass (N/P/F)", "N")),
            data_persistence=DataPersistence(ask("Data Persistence (N/S/P)", "N")),
            multi_agent_impact=MultiAgentImpact(ask("Multi-Agent Impact (N/S/C)", "N")),
        )
        score = LVSSScorer.calculate(vector)
        print(f"\n{LVSSScorer.describe(score, vector)}")
    except Exception as e:
        print(f"[!] Error: {e}")


def cmd_mcp_test(args):
    """Run MCP security tests or generate config for manual testing."""
    from nexus.mcp.test_runner import (
        run_automated_tests,
        generate_claude_code_config,
        generate_cursor_config,
    )

    if args.setup_claude:
        outdir = generate_claude_code_config()
        print(f"\n[+] Claude Code test configs generated in: {outdir}")
        print(f"[+] Run the test:  bash {outdir}/run-test.sh")
        return

    if args.setup_cursor:
        path = generate_cursor_config(args.project_dir or ".")
        print(f"\n[+] Cursor MCP config written to: {path}")
        print(f"[+] Open the project in Cursor and try MCP tools")
        return

    if args.target:
        results = run_automated_tests(
            target_str=args.target,
            budget_per_scenario=args.budget,
            timeout=args.timeout,
        )
        from nexus.reporting.html_report import generate_html_report
        report_path = generate_html_report(results, args.output or "/tmp/nexus-mcp-report.html")
        print(f"\n[+] HTML report: {report_path}")
        print(f"[+] Open: open {report_path}")
        return

    print("[!] Specify --target for automated test, or --setup-claude / --setup-cursor")


def cmd_report(args):
    """Generate HTML report from JSON results."""
    from nexus.reporting.html_report import (
        generate_html_report,
        generate_html_report_from_session,
        _is_session_format,
    )

    def _render(data, out_path):
        if _is_session_format(data):
            path = generate_html_report_from_session(data, out_path)
        else:
            path = generate_html_report(data, out_path)
        print(f"[+] Report generated: {path}")
        return path

    if args.json_input:
        with open(args.json_input) as f:
            data = json.load(f)
        _render(data, args.output or "/tmp/nexus-report.html")
        return

    # Try scan output first, then MCP test output
    for default_path in ("/tmp/nexus-report.json", "/tmp/nexus-mcp-test-results.json"):
        if os.path.exists(default_path):
            with open(default_path) as f:
                data = json.load(f)
            _render(data, args.output or "/tmp/nexus-report.html")
            return

    print("[!] No results found. Run a scan first or specify --json-input")


def cmd_list_attacks(args):
    """List all available attack modules."""
    from nexus.attacks import list_attacks, get_attack
    print("Available NEXUS Attack Modules:")
    for name in list_attacks():
        cls = get_attack(name)
        desc = getattr(cls, "DESCRIPTION", "")
        owasp = getattr(cls, "OWASP", "")
        print(f"  {name:<28} [{owasp}] {desc}")


def main():
    parser = argparse.ArgumentParser(
        prog="nexus",
        description="NEXUS — Neural EXploitation Unified System for LLM Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "For authorized security research only.\n"
            "Inspired by Alias Robotics: CAI, RVD, RSF, Aztarna, RVSS, RCTF"
        ),
    )
    parser.add_argument("--version", action="version", version="nexus 0.1.0")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # Shared proxy help text
    _proxy_help = "Route traffic through HTTP proxy (e.g. http://127.0.0.1:8080 for Burp Suite)"

    # Shared session flags (for session:// targets)
    def _add_session_args(p):
        g = p.add_argument_group("session:// auth & upload (for web app targets)")
        g.add_argument("--cookies",
                       help='Browser session cookies (paste from DevTools → Network → Request Headers). '
                            'Example: "ims_user_id=xxx; s_fid=yyy; adobe_id=zzz"')
        g.add_argument("--upload", metavar="FILE",
                       help="File to upload before AI is accessible (PDF, image, etc.)")
        g.add_argument("--upload-url", dest="upload_url", metavar="PATH",
                       help="API path for file upload. Example: /api/v1/documents")
        g.add_argument("--upload-field", dest="upload_field", default="file", metavar="FIELD",
                       help="Form field name for the uploaded file (default: file)")
        g.add_argument("--upload-id-path", dest="upload_id_path", default="", metavar="JSONPATH",
                       help="Dot-path to extract context ID from upload response. "
                            "Example: 'document_id' or 'data.id' or 'assets.0.assetId'")
        g.add_argument("--csrf-url", dest="csrf_url", default="", metavar="PATH",
                       help="GET this URL first to fetch a CSRF token")
        g.add_argument("--csrf-header", dest="csrf_header", default="X-CSRF-Token", metavar="HEADER",
                       help="Header name to send the CSRF token in (default: X-CSRF-Token)")
        g.add_argument("--chat-url", dest="chat_url", metavar="PATH",
                       help="API path for the AI chat endpoint. Example: /api/v1/chat")
        g.add_argument("--chat-field", dest="chat_field", default="message", metavar="FIELD",
                       help="JSON field name for the prompt text (default: message)")
        g.add_argument("--chat-body", dest="chat_body", default="", metavar="JSON_TEMPLATE",
                       help='Full JSON body template. Use {prompt} and {context_id}. '
                            'Example: \'{"query":"{prompt}","docId":"{context_id}"}\'')
        g.add_argument("--chat-response-path", dest="chat_response_path", default="", metavar="JSONPATH",
                       help="Dot-path to extract AI text from chat response. Example: data.message")

    # --- scan ---
    scan_p = subparsers.add_parser("scan", help="Full automated security scan")
    scan_p.add_argument("--target", required=True,
                        help="Target: openai://model, anthropic://model, ollama://host/model, "
                             "penny://host, session://host (web app with auth)")
    scan_p.add_argument("--model", default="", help="Model override")
    scan_p.add_argument("--api-key", default="", dest="api_key",
                        help="API key, or full cookie string for penny:// targets")
    scan_p.add_argument("--proxy", default="", help=_proxy_help)
    scan_p.add_argument("--attacks", nargs="*", help="Specific attacks to run")
    scan_p.add_argument("--budget", type=int, default=50, help="Total attack budget")
    scan_p.add_argument("--timeout", type=int, default=0, help="Request timeout override (seconds, 0=use default)")
    scan_p.add_argument("--output", help="Save report to file (.json, .html, or .md). JSON also auto-generates .html alongside.")
    scan_p.add_argument("--quiet", action="store_true")
    scan_p.add_argument("--interactive", action="store_true", help="Confirm each attack")
    _add_session_args(scan_p)

    # --- attack ---
    atk_p = subparsers.add_parser("attack", help="Run specific attack module(s)")
    atk_p.add_argument("--target", required=True)
    atk_p.add_argument("--model", default="")
    atk_p.add_argument("--api-key", default="", dest="api_key")
    atk_p.add_argument("--proxy", default="", help=_proxy_help)
    atk_p.add_argument("--attacks", nargs="+", required=True)
    atk_p.add_argument("--budget", type=int, default=10)
    atk_p.add_argument("--timeout", type=int, default=0, help="Request timeout override (seconds, 0=use default)")
    atk_p.add_argument("--output", help="Save JSON report")
    _add_session_args(atk_p)

    # --- recon ---
    rec_p = subparsers.add_parser(
        "recon",
        help="AI recon: bug bounty programs, attack surface, agent deep recon, host scan",
    )
    # Network scan (original)
    rec_p.add_argument("--host", help="Scan host/IP for exposed AI endpoints")
    rec_p.add_argument("--timeout", type=int, default=5)

    # Attack surface enumeration
    rec_p.add_argument("--surface", metavar="DOMAIN",
                       help="Enumerate AI attack surface for a domain (active scan + dorks)")
    rec_p.add_argument("--shodan-key", dest="shodan_key", default="",
                       help="Shodan API key for live queries")
    rec_p.add_argument("--dorks", action="store_true",
                       help="Print all AI-specific Shodan/GitHub/Censys dorks and exit")

    # Agent deep recon
    rec_p.add_argument("--agent", metavar="URL",
                       help="Deep recon a live AI agent — map LLM, tools, memory, trust boundaries")
    rec_p.add_argument("--deep", action="store_true",
                       help="Run extended probe set (more inference calls)")
    rec_p.add_argument("--model", default="", help="Model hint for inference probes")
    rec_p.add_argument("--api-key", default="", dest="api_key",
                       help="API key for authenticated agent endpoints")

    # Bug bounty programs
    rec_p.add_argument("--programs", action="store_true",
                       help="List AI bug bounty / VDP programs")
    rec_p.add_argument("--search", metavar="QUERY",
                       help="Search programs by keyword (e.g. 'rag', 'mcp', 'agent')")
    rec_p.add_argument("--platform", metavar="PLATFORM",
                       help="Filter by platform: hackerone, bugcrowd, github, direct")
    rec_p.add_argument("--attack", metavar="ATTACK_TYPE",
                       help="Show programs relevant to a NEXUS attack type")
    rec_p.add_argument("--how-to-find", dest="how_to_find", action="store_true",
                       help="Guide to finding AI bug bounty programs not in the directory")
    rec_p.add_argument("--verbose", "-v", action="store_true",
                       help="Verbose output (show full scope details)")

    # Live search & auto-scan
    rec_p.add_argument("--live", action="store_true",
                       help="Execute live searches (DuckDuckGo, GitHub API, Bugcrowd, HackerOne)")
    rec_p.add_argument("--auto-scan", dest="auto_scan", action="store_true",
                       help="Auto-run nexus attacks against discovered targets")
    rec_p.add_argument("--budget", type=int, default=30,
                       help="Attack budget for --auto-scan (default: 30)")

    # Common output
    rec_p.add_argument("--output", help="Save results to JSON file")
    rec_p.add_argument("--quiet", "-q", action="store_true")

    # --- fingerprint ---
    fp_p = subparsers.add_parser("fingerprint", help="Fingerprint an LLM endpoint")
    fp_p.add_argument("--target", required=True)
    fp_p.add_argument("--model", default="")
    fp_p.add_argument("--api-key", default="", dest="api_key")
    fp_p.add_argument("--proxy", default="", help=_proxy_help)
    fp_p.add_argument("--output", help="Save fingerprint JSON")

    # --- ctf ---
    ctf_p = subparsers.add_parser("ctf", help="Run CTF training scenarios")
    ctf_p.add_argument("--scenario", help="Scenario number: 01, 02, 03")
    ctf_p.add_argument("--target", default="ollama://localhost:11434/llama3")
    ctf_p.add_argument("--model", default="")
    ctf_p.add_argument("--api-key", default="", dest="api_key")
    ctf_p.add_argument("--proxy", default="", help=_proxy_help)
    ctf_p.add_argument("--interactive", action="store_true")
    ctf_p.add_argument("--list", action="store_true")

    # --- lvd ---
    lvd_p = subparsers.add_parser("lvd", help="Query LLM Vulnerability Database")
    lvd_p.add_argument("--list", action="store_true")
    lvd_p.add_argument("--search", help="Search query")
    lvd_p.add_argument("--owasp", help="Filter by OWASP category (e.g. LLM01)")
    lvd_p.add_argument("--severity", help="Filter by severity (CRITICAL/HIGH/MEDIUM/LOW)")
    lvd_p.add_argument("--stats", action="store_true")

    # --- score ---
    score_p = subparsers.add_parser("score", help="Calculate LVSS score")
    score_p.add_argument("--vector", help="LVSS vector string")

    # --- mcp-test ---
    mcp_p = subparsers.add_parser("mcp-test", help="MCP security testing (evil server, confused deputy)")
    mcp_p.add_argument("--target", help="LLM target for automated test (e.g. ollama://localhost:11434/qwen3:14b)")
    mcp_p.add_argument("--budget", type=int, default=10, help="Max queries per scenario")
    mcp_p.add_argument("--timeout", type=int, default=180, help="Request timeout (seconds)")
    mcp_p.add_argument("--setup-claude", action="store_true", help="Generate Claude Code test config")
    mcp_p.add_argument("--setup-cursor", action="store_true", help="Generate Cursor MCP config")
    mcp_p.add_argument("--project-dir", help="Project dir for Cursor config")
    mcp_p.add_argument("--output", help="Report output path")

    # --- report ---
    rpt_p = subparsers.add_parser("report", help="Generate HTML report with charts")
    rpt_p.add_argument("--json-input", help="JSON results file to convert to HTML report")
    rpt_p.add_argument("--output", help="Output HTML path")

    # --- discover ---
    disc_p = subparsers.add_parser(
        "discover",
        help="Discover AI API endpoints on a target (Burp history + JS scan + probe)",
    )
    disc_p.add_argument("--target", required=True,
                        help="Target URL or hostname, e.g. https://app.example.com")
    disc_p.add_argument("--cookies", default="", metavar="COOKIE_STRING",
                        help="Browser session cookies for authenticated discovery")
    disc_p.add_argument("--api-key", default="", dest="api_key",
                        help="Alias for --cookies")
    disc_p.add_argument("--proxy", default="",
                        help="HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)")

    # --- attacks ---
    subparsers.add_parser("attacks", help="List available attack modules")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "scan": cmd_scan,
        "attack": cmd_attack,
        "recon": cmd_recon,
        "fingerprint": cmd_fingerprint,
        "ctf": cmd_ctf,
        "lvd": cmd_lvd,
        "score": cmd_score,
        "mcp-test": cmd_mcp_test,
        "report": cmd_report,
        "discover": cmd_discover,
        "attacks": cmd_list_attacks,
    }

    handler = dispatch.get(args.command)
    if handler:
        try:
            handler(args)
        except KeyboardInterrupt:
            print("\n[!] Interrupted.")
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
