#!/usr/bin/env python3
"""
NEXUS Scanner CLI
=================
Direct command-line interface — no server required.
Runs the full scan engine in-process and streams findings to stdout.

Usage:
  python scan.py http://localhost:3000
  python scan.py http://target.com --pages 100 --out report.json
  python scan.py http://target.com --severity CRITICAL HIGH --out report.html
  python scan.py http://target.com --checks sqli-error xss-reflected
  python scan.py --list-checks

Authenticated scans:
  # Paste existing session (copy from browser DevTools → Application → Cookies)
  python scan.py http://target.com --cookie "connect.sid=s%3Aabc123..."
  python scan.py http://target.com --token "eyJhbGciOiJIUzI1NiIsInR5..."

  # Auto-login with credentials
  python scan.py http://target.com --login-url http://target.com/rest/user/login \\
      --username admin@example.com --password s3cr3t

  # Auto-login with credentials (form POST, custom field names)
  python scan.py http://target.com --login-url http://target.com/login \\
      --username admin --password s3cr3t --user-field userName --content-type form

  # Login + TOTP 2FA  (get the Base32 secret from the app's QR code setup screen)
  python scan.py http://target.com --login-url http://target.com/login \\
      --username admin@example.com --password s3cr3t \\
      --totp-secret JBSWY3DPEHPK3PXP

  # OAuth 2.0 Resource Owner Password Credentials grant
  python scan.py http://target.com \\
      --oauth-token-url https://auth.example.com/oauth/token \\
      --client-id myapp --client-secret xyz \\
      --username user@example.com --password s3cr3t
"""
import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path

# Ensure backend/ is on sys.path
_here = Path(__file__).parent
if str(_here) not in sys.path:
    sys.path.insert(0, str(_here))

import argparse

import httpx

from nexus.crawler.crawler import Crawler
from nexus.engine.authenticator import AuthConfig, SessionAuthenticator
from nexus.engine.check_runner import CheckRunner
from nexus.engine.agent_loop import NexusAgent
from nexus.engine.swarm import NexusSwarm
from nexus.engine.knowledge import KnowledgeStore
from nexus.engine.proxy import resolve_proxy
from nexus.engine.auth_flow import run_auth_flow as _run_auth_flow
from nexus.engine.scan_context import ActiveSession
from nexus.checks import ALL_CHECKS
from nexus.models import Finding, Severity, InsertionPoint, IPType


# ANSI colours
_R = "\033[0;31m"   # red
_Y = "\033[1;33m"   # yellow
_G = "\033[0;32m"   # green
_B = "\033[0;34m"   # blue
_C = "\033[0;36m"   # cyan
_W = "\033[1;37m"   # white bold
_X = "\033[0m"      # reset

_SEV_COLOR = {
    "CRITICAL": "\033[1;31m",   # bold red
    "HIGH":     "\033[0;31m",   # red
    "MEDIUM":   "\033[1;33m",   # bold yellow
    "LOW":      "\033[0;36m",   # cyan
    "INFO":     "\033[0;37m",   # grey
}


def _col(sev: str, text: str) -> str:
    return f"{_SEV_COLOR.get(sev, '')}{text}{_X}"


def _banner():
    import sys; sys.stdout.reconfigure(line_buffering=True)
    print(f"""{_B}
  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝{_X}
  {_W}Neural EXploitation Unified System{_X} — Web Scanner v3.1
  {_C}{len(ALL_CHECKS)} checks · OWASP Top 10 · API Top 10 · HackTricks · CVE detection{_X}
  {_C}Dirsearch · XSS bypass engine · CSV/CSP · Think-then-exploit · Kill chain{_X}
""")


def _list_checks():
    _banner()
    print(f"{'CHECK ID':<35} {'TYPE':<8} {'SEVERITY':<10} NAME")
    print("─" * 80)
    for c in ALL_CHECKS:
        sev = "varies"
        typ = c.check_type.value
        print(f"{_C}{c.check_id:<35}{_X} {typ:<8} {sev:<10} {c.name}")
    print(f"\nTotal: {len(ALL_CHECKS)} checks")


def _finding_line(f: Finding) -> str:
    sev = f.severity.value
    conf = f.confidence.value
    url = f.insertion_point.url
    param = f.insertion_point.name
    desc = f.description[:100] + ("…" if len(f.description) > 100 else "")
    return (
        f"  {_col(sev, f'[{sev:<8}]')} "
        f"{_B}[{conf:<8}]{_X} "
        f"{_W}{f.check_id:<30}{_X} "
        f"{_G}{url}{_X} [{param}]\n"
        f"    {desc}"
    )


async def run_scan(
    target_url: str,
    max_pages: int = 50,
    request_timeout: float = 20.0,
    severity_filter: list[str] | None = None,
    check_filter: list[str] | None = None,
    out_path: str | None = None,
    verbose: bool = False,
    wordlist_users: list[str] | None = None,
    wordlist_passwords: list[str] | None = None,
    # Auth params — all optional
    cookie: str | None = None,
    token: str | None = None,
    login_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
    user_field: str = "email",
    pass_field: str = "password",
    content_type: str = "json",
    token_path: str = "token",
    totp_secret: str | None = None,
    otp_code: str | None = None,
    otp_url: str | None = None,
    otp_field: str = "otp",
    oauth_token_url: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    oauth_scope: str | None = None,
    # Auto-registration: auto-create a test account when no auth is supplied
    auto_register: bool = False,
    # Proxy params — all optional
    proxy_url: str | None = None,
    intercept: bool = False,
    intercept_port: int = 8082,
    intercept_web_port: int = 8083,
    # Dirsearch params
    dirsearch_wordlist: list[str] | None = None,
    dirsearch_extensions: list[str] | None = None,
    dirsearch_recurse: int = 1,
):
    _banner()
    print(f"  {_W}Target :{_X} {target_url}")
    print(f"  {_W}Pages  :{_X} {max_pages}")
    print(f"  {_W}Checks :{_X} {len(ALL_CHECKS)} registered")
    if wordlist_users:
        print(f"  {_W}Users  :{_X} {len(wordlist_users)} loaded")
    if wordlist_passwords:
        print(f"  {_W}Passes :{_X} {len(wordlist_passwords)} loaded")
    print(f"  {_W}Started:{_X} {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print()

    # ── Proxy setup ──────────────────────────────────────────────────────────
    proxy_mgr = None
    try:
        active_proxy_url, proxy_mgr = resolve_proxy(
            proxy_url=proxy_url,
            intercept=intercept,
            proxy_port=intercept_port,
            web_port=intercept_web_port,
        )
    except RuntimeError as e:
        print(f"{_R}[proxy] {e}{_X}")
        active_proxy_url = None

    if active_proxy_url:
        print(f"  {_W}Proxy  :{_X} {active_proxy_url}")
        if intercept:
            print(f"  {_W}Web UI :{_X} {_C}http://127.0.0.1:{intercept_web_port}{_X}  ← open this to watch / intercept traffic")
        print()

    # ── Phase 0: Resolve authentication ─────────────────────────────────────
    injected_session = None
    auth_headers: dict = {}

    _has_auth = any([cookie, token, login_url, oauth_token_url])
    if _has_auth:
        cfg = AuthConfig(
            session_cookie=cookie or "",
            bearer_token=token or "",
            login_url=login_url or "",
            username=username or "",
            password=password or "",
            user_field=user_field,
            pass_field=pass_field,
            content_type=content_type,
            token_path=token_path,
            totp_secret=totp_secret or "",
            otp_code=otp_code or "",
            otp_url=otp_url or "",
            otp_field=otp_field,
            oauth_token_url=oauth_token_url or "",
            client_id=client_id or "",
            client_secret=client_secret or "",
            oauth_username=username or "",
            oauth_password=password or "",
            oauth_scope=oauth_scope or "",
        )
        print(f"{_G}[0/2] Resolving authentication…{_X}")
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=20.0, verify=False
        ) as auth_client:
            injected_session = await SessionAuthenticator().resolve(cfg, auth_client)

        if injected_session:
            auth_headers = injected_session.extra_headers
            print(f"      {_G}Auth OK{_X} — type={injected_session.auth_type}")
        else:
            print(f"      {_Y}Auth FAILED — continuing unauthenticated{_X}")
        print()

    # ── Phase 0.5: Auto-register test account (when no auth supplied) ──────
    if auto_register and not _has_auth:
        print(f"{_G}[0/2] Auto-registering test account…{_X}")
        try:
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=15.0, verify=False
            ) as _ar_client:
                _ar_session = await _run_auth_flow(
                    base_url=target_url,
                    client=_ar_client,
                    verbose=verbose,
                    injected_username=username,
                    injected_password=password,
                )
            if _ar_session and _ar_session.authenticated:
                # Convert auth_flow.AuthSession → scan_context.ActiveSession
                _cookie_str = "; ".join(
                    f"{k}={v}" for k, v in _ar_session.cookies.items()
                )
                injected_session = ActiveSession(
                    token=_ar_session.token,
                    cookie=_cookie_str,
                    auth_type="cookie" if _ar_session.cookies else "bearer",
                    base_url=target_url,
                    extra_headers=_ar_session.auth_headers(),
                )
                auth_headers = injected_session.extra_headers
                print(f"      {_G}Auto-auth OK{_X} — method={_ar_session.method} "
                      f"user={_ar_session.credentials.username}")
            else:
                print(f"      {_Y}Auto-auth FAILED — continuing unauthenticated{_X}")
        except Exception as _ar_err:
            print(f"      {_Y}Auto-auth error: {_ar_err}{_X}")
        print()

    findings: list[Finding] = []
    t_start = time.monotonic()

    def _on_finding(f: Finding):
        if severity_filter and f.severity.value not in severity_filter:
            return
        findings.append(f)
        print(_finding_line(f))
        print()

    _has_proxy = bool(active_proxy_url)
    _total_phases = 2 + int(_has_auth) + int(_has_proxy and intercept)
    _phase = [0]   # mutable counter

    def _next_phase(label: str):
        _phase[0] += 1
        print(f"{_G}[{_phase[0]}/{_total_phases}] {label}{_X}")

    # ── Phase 1 (or 2): Crawl ────────────────────────────────────────────────
    _next_phase("Crawling target…")
    crawler = Crawler(
        target_url=target_url,
        max_pages=max_pages,
        extra_headers=auth_headers,
        auth_token=injected_session.token if injected_session else None,
        proxy_url=active_proxy_url,
    )
    crawl_results, insertion_points = await crawler.crawl()

    # Inject login-form insertion points so sqli-auth-bypass always tests the login URL
    if login_url:
        _login_ips_added = set(
            (ip.url, ip.name) for ip in insertion_points
            if ip.url == login_url
        )
        for _field_name in (user_field, pass_field):
            if (login_url, _field_name) not in _login_ips_added:
                insertion_points.append(InsertionPoint(
                    url=login_url,
                    method="POST",
                    ip_type=IPType.BODY_PARAM,
                    name=_field_name,
                    value="",
                    context={"login_pass_field": pass_field, "login_user_field": user_field},
                ))

    print(f"      {len(crawl_results)} pages · {len(insertion_points)} insertion points found")
    print()

    # ── Phase 2 (or 3): Audit ────────────────────────────────────────────────
    checks = ALL_CHECKS
    if check_filter:
        checks = [c for c in ALL_CHECKS if c.check_id in check_filter]
        if not checks:
            print(f"{_R}No checks matched filter: {check_filter}{_X}")
            if proxy_mgr:
                proxy_mgr.stop()
            return

    _ds_info = f" + dirsearch({len(dirsearch_wordlist or [])} extra paths)"
    _next_phase(f"Agent loop: {len(checks)} checks · ReACT · Exploit-verify · Learning{_ds_info}…")

    # Print knowledge base status
    kb = KnowledgeStore.get()
    kb_stats = kb.stats()
    print(f"  {_W}Knowledge base:{_X} {kb_stats['confirmed_exploits']} proven exploits · "
          f"{kb_stats['fp_patterns']} FP patterns · {kb_stats['scans']} scans learned from")
    print()

    session_id = f"cli-{int(time.time())}"
    # Use CAI-style swarm (ThoughtAgent → ScanAgent[3 parallel streams] → ExploitAgent)
    agent = NexusSwarm(
        session_id=session_id,
        on_finding=_on_finding,
        request_timeout=request_timeout,
        check_filter=check_filter,
        injected_session=injected_session,
        proxy_url=active_proxy_url,
        dirsearch_wordlist=dirsearch_wordlist,
        dirsearch_extensions=dirsearch_extensions or [],
        dirsearch_recurse=dirsearch_recurse,
    )
    try:
        all_findings = await agent.run(crawl_results, insertion_points)
    finally:
        if proxy_mgr:
            proxy_mgr.stop()
            print(f"\n  {_Y}[proxy] mitmweb stopped{_X}")

    # Apply check filter to all_findings too (on_finding may have filtered some)
    if severity_filter:
        all_findings = [f for f in all_findings if f.severity.value in severity_filter]

    elapsed = time.monotonic() - t_start

    # ── Think Phase Summary ──────────────────────────────────────────────────
    # Support both NexusSwarm and legacy NexusAgent
    tp = None
    plan = None
    thought_log = []
    if isinstance(agent, NexusSwarm):
        # Swarm exposes tech profile via the thought agent's last context
        tp = getattr(agent._thought, '_last_tp', None)
        thought_log = getattr(agent, '_last_thought_log', [])
    else:
        plan = getattr(agent, '_last_attack_plan', None)
        if plan:
            tp = plan.tech_profile

    if tp:
        print(f"\n{_W}  THINK PHASE RESULTS{_X}")
        print(f"  {_C}Runtime   :{_X} {tp.runtime}")
        print(f"  {_C}Framework :{_X} {tp.framework}")
        print(f"  {_C}Database  :{_X} {tp.database}")
        print(f"  {_C}Auth      :{_X} {tp.auth_type}")
        print(f"  {_C}API Style :{_X} {tp.api_style}")
        if tp.cms != "none":
            print(f"  {_C}CMS       :{_X} {tp.cms}")
        if verbose and tp.signals:
            print(f"  {_C}Signals   :{_X} {', '.join(tp.signals[:8])}")
        if verbose and thought_log:
            print(f"\n  {_W}Agent Thoughts:{_X}")
            for line in thought_log:
                print(f"  → {line}")
        print()

    # ── Scan Summary ─────────────────────────────────────────────────────────
    print("─" * 72)
    print(f"\n{_W}  SCAN COMPLETE{_X} — {elapsed:.1f}s")
    print(f"  Target      : {target_url}")
    print(f"  Pages crawled: {len(crawl_results)}")
    print(f"  Total findings: {len(all_findings)}\n")

    by_sev: dict[str, int] = {}
    for f in all_findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = by_sev.get(sev, 0)
        if n:
            print(f"  {_col(sev, f'{sev:<9}')} : {n}")

    # ── Output ───────────────────────────────────────────────────────────────
    if out_path:
        report = {
            "target": target_url,
            "scanned_at": datetime.utcnow().isoformat(),
            "elapsed_sec": round(elapsed, 2),
            "pages_crawled": len(crawl_results),
            "summary": {"total": len(all_findings), "by_severity": by_sev},
            "findings": [f.to_dict() for f in all_findings],
        }

        # Embed tech profile into report if available
        if plan:
            tp = plan.tech_profile
            report["tech_profile"] = {
                "runtime": tp.runtime,
                "framework": tp.framework,
                "database": tp.database,
                "auth_type": tp.auth_type,
                "api_style": tp.api_style,
                "cms": tp.cms,
                "signals": tp.signals,
            }
            report["attack_plan"] = [
                {"check_id": pc.check.check_id, "priority": pc.priority,
                 "rationale": pc.rationale, "boosted": pc.boosted}
                for pc in plan.ordered() if pc.priority > 0
            ]

        p = Path(out_path)
        if p.suffix == ".html":
            p.write_text(_render_html(report))
        else:
            p.write_text(json.dumps(report, indent=2))
        print(f"\n  {_G}Report saved to: {out_path}{_X}")

    print()
    return all_findings


def _esc(s: str) -> str:
    """HTML-escape a string for safe embedding in HTML."""
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _evidence_cell(ev: dict) -> str:
    """Render evidence as Burp-style request / baseline / response tabs."""
    import html as _html

    req  = ev.get("request_raw", "")
    resp = ev.get("response_raw", "")
    base = ev.get("baseline_raw", "")
    curl = ev.get("poc_curl", "")
    hi   = ev.get("highlighted_evidence", "")

    r_status  = ev.get("response_status", 0)
    r_len     = ev.get("response_length", 0)
    r_ms      = ev.get("response_time_ms", 0.0)
    b_status  = ev.get("baseline_status", 0)
    b_len     = ev.get("baseline_length", 0)
    b_ms      = ev.get("baseline_time_ms", 0.0)
    delta     = ev.get("length_delta", 0)

    # Delta badge
    delta_sign = f"+{delta}" if delta > 0 else str(delta)
    delta_cls  = "delta-pos" if delta > 0 else ("delta-neg" if delta < 0 else "delta-zero")

    meta_line = ""
    if r_status:
        meta_line = (
            f'<div class="ev-meta">'
            f'Status: <b>{r_status}</b> | '
            f'Length: <b>{r_len}</b> bytes | '
            f'Time: <b>{r_ms:.0f}ms</b>'
        )
        if b_status:
            meta_line += (
                f' &nbsp;←&nbsp; Baseline: '
                f'<b>{b_status}</b> / <b>{b_len}</b>B / <b>{b_ms:.0f}ms</b> | '
                f'Δ: <span class="{delta_cls}"><b>{delta_sign} bytes</b></span>'
            )
        meta_line += "</div>"

    hi_html = ""
    if hi:
        hi_html = f'<div class="ev-label">Evidence</div><pre class="ev-highlight">{_esc(hi)}</pre>'

    req_html  = f'<div class="ev-label">Request</div><pre>{_esc(req)}</pre>'  if req  else ""
    base_html = f'<div class="ev-label">Baseline Response</div><pre class="ev-base">{_esc(base[:800])}</pre>' if base else ""
    resp_html = f'<div class="ev-label">Attack Response</div><pre class="ev-resp">{_esc(resp[:1500])}</pre>' if resp else ""
    curl_html = f'<div class="ev-label">cURL Reproducer</div><pre class="ev-curl">{_esc(curl)}</pre>'       if curl else ""

    inner = meta_line + hi_html + req_html + base_html + resp_html + curl_html
    return f'<details><summary>Show Evidence</summary><div class="ev-block">{inner}</div></details>'


def _render_html(report: dict) -> str:
    rows = ""
    for f in report["findings"]:
        ip = f["insertion_point"]
        sev = f["severity"]
        rows += (
            f'<tr class="{sev}">'
            f'<td class="{sev}">{sev}</td>'
            f"<td>{f['confidence']}</td>"
            f"<td>{f['check_id']}</td>"
            f"<td>{_esc(ip['url'])}</td>"
            f"<td>{_esc(ip['name'])}</td>"
            f"<td>{f['cvss']}</td>"
            f"<td>{_esc(f['description'][:150])}…</td>"
            f"<td>{_evidence_cell(f['evidence'])}</td>"
            f"<td>{_esc(f['solution'][:120])}</td>"
            f"</tr>\n"
        )
    summary = report["summary"]
    sev_badges = " ".join(
        f'<span class="badge {s}">{s}: {n}</span>'
        for s, n in summary.get("by_severity", {}).items()
    )

    # Tech profile section
    tp = report.get("tech_profile", {})
    tech_html = ""
    if tp:
        fields = [
            ("Runtime",   tp.get("runtime", "unknown")),
            ("Framework", tp.get("framework", "unknown")),
            ("Database",  tp.get("database", "unknown")),
            ("Auth",      tp.get("auth_type", "unknown")),
            ("API Style", tp.get("api_style", "rest")),
        ]
        if tp.get("cms", "none") != "none":
            fields.append(("CMS", tp["cms"]))
        badges_html = "".join(
            f'<span class="tech-badge">{k}: <strong>{v}</strong></span>'
            for k, v in fields
        )
        signals = tp.get("signals", [])
        signals_html = ""
        if signals:
            signals_html = (
                f'<div class="signals">Signals: '
                + " ".join(f'<code>{s}</code>' for s in signals[:10])
                + ("…" if len(signals) > 10 else "")
                + "</div>"
            )
        tech_html = f'<div class="tech-profile"><strong>Target Profile:</strong> {badges_html}{signals_html}</div>'

    # Attack plan section
    plan_items = report.get("attack_plan", [])
    plan_html = ""
    if plan_items:
        rows_html = "".join(
            f'<tr><td>{p["check_id"]}</td>'
            f'<td class="pri{"high" if p["priority"]>=80 else "med" if p["priority"]>=50 else "low"}">'
            f'{p["priority"]}</td>'
            f'<td>{"⬆ " if p.get("boosted") else ""}{p["rationale"]}</td></tr>'
            for p in plan_items[:15]
        )
        plan_html = (
            f'<details class="plan-details"><summary>Attack Plan ({len(plan_items)} checks)</summary>'
            f'<table class="plan-table"><thead><tr><th>Check</th><th>Priority</th><th>Rationale</th></tr></thead>'
            f'<tbody>{rows_html}</tbody></table></details>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NEXUS Report — {report['target']}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; margin: 0; }}
  h1 {{ color: #58a6ff; margin-bottom: 4px; }}
  .meta {{ color: #8b949e; margin-bottom: 1.5rem; font-size: .9em; }}
  .badges {{ margin-bottom: 1.5rem; }}
  .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; margin-right: 8px; font-weight: bold; }}
  table {{ border-collapse: collapse; width: 100%; font-size: .85em; }}
  th {{ background: #161b22; padding: 8px 12px; text-align: left; border: 1px solid #30363d; position: sticky; top: 0; }}
  td {{ border: 1px solid #21262d; padding: 6px 10px; vertical-align: top; max-width: 300px; word-break: break-word; }}
  tr:hover td {{ background: #161b22; }}
  .CRITICAL {{ color: #ff5555; }} .badge.CRITICAL {{ background: #4a1a1a; color: #ff5555; }}
  .HIGH {{ color: #ff7b72; }}     .badge.HIGH {{ background: #3a1a1a; color: #ff7b72; }}
  .MEDIUM {{ color: #e3b341; }}   .badge.MEDIUM {{ background: #3a2e00; color: #e3b341; }}
  .LOW {{ color: #79c0ff; }}      .badge.LOW {{ background: #0d2036; color: #79c0ff; }}
  .INFO {{ color: #8b949e; }}     .badge.INFO {{ background: #1c2128; color: #8b949e; }}
  pre {{ background: #161b22; padding: 8px; overflow-x: auto; font-size: .8em; color: #e6edf3; border-radius: 4px; max-height: 300px; overflow-y: auto; }}
  details summary {{ cursor: pointer; color: #58a6ff; }}
  .ev-block {{ border: 1px solid #30363d; border-radius: 6px; padding: 8px; margin-top: 6px; }}
  .ev-label {{ font-size: .72em; font-weight: bold; color: #58a6ff; margin: 8px 0 2px; text-transform: uppercase; letter-spacing: .05em; }}
  .ev-meta {{ font-size: .78em; color: #8b949e; margin-bottom: 6px; padding: 4px 8px; background: #161b22; border-radius: 4px; }}
  .ev-meta b {{ color: #c9d1d9; }}
  .ev-highlight {{ border-left: 3px solid #ff5555; background: #1a0f0f; color: #ff9999; }}
  .ev-base {{ border-left: 3px solid #388bfd; background: #0d1b2e; }}
  .ev-resp {{ border-left: 3px solid #3fb950; background: #0d1f0f; }}
  .ev-curl {{ border-left: 3px solid #e3b341; background: #1c1700; }}
  .delta-pos {{ color: #ff7b72; }}
  .delta-neg {{ color: #3fb950; }}
  .delta-zero {{ color: #8b949e; }}
  .tech-profile {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 10px 14px; margin-bottom: 1rem; font-size: .85em; }}
  .tech-badge {{ display: inline-block; background: #0d2036; border: 1px solid #1f6feb; border-radius: 4px; padding: 2px 8px; margin: 2px; font-size: .82em; }}
  .signals {{ margin-top: 6px; color: #8b949e; font-size: .8em; }}
  .signals code {{ background: #0d1117; padding: 1px 5px; border-radius: 3px; margin: 2px; color: #79c0ff; }}
  .plan-details {{ margin-bottom: 1rem; }}
  .plan-details summary {{ color: #58a6ff; cursor: pointer; margin-bottom: 6px; }}
  .plan-table {{ font-size: .8em; width: 100%; border-collapse: collapse; }}
  .plan-table td, .plan-table th {{ border: 1px solid #21262d; padding: 4px 8px; }}
  .plan-table th {{ background: #161b22; }}
  .pri.high {{ color: #ff5555; font-weight: bold; }}
  .pri.med  {{ color: #e3b341; }}
  .pri.low  {{ color: #8b949e; }}
</style>
</head>
<body>
<h1>NEXUS Scan Report</h1>
<div class="meta">
  Target: <strong>{report['target']}</strong> &nbsp;|&nbsp;
  Scanned: {report['scanned_at']} &nbsp;|&nbsp;
  Duration: {report['elapsed_sec']}s &nbsp;|&nbsp;
  Pages: {report['pages_crawled']} &nbsp;|&nbsp;
  Findings: {summary['total']}
</div>
{tech_html}
{plan_html}
<div class="badges">{sev_badges}</div>
<table>
<thead><tr>
  <th>Severity</th><th>Confidence</th><th>Check ID</th>
  <th>URL</th><th>Param</th><th>CVSS</th>
  <th>Description</th><th>Evidence (Request / Response / Diff)</th><th>Remediation</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(
        prog="nexus-scan",
        description="NEXUS Web Application Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "━━━ Basic Usage ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  python scan.py http://localhost:3000\n"
            "  python scan.py http://target.com --pages 100 --out report.html\n"
            "  python scan.py http://target.com --severity CRITICAL HIGH\n"
            "  python scan.py http://target.com --checks sqli-error xss-reflected\n"
            "  python scan.py --list-checks\n"
            "\n"
            "━━━ Authenticated Scans ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  # Paste session cookie (from browser DevTools → Application → Cookies)\n"
            '  python scan.py http://localhost:3000 --cookie "connect.sid=s%3Aabc123..."\n'
            "\n"
            "  # Paste Bearer token (from browser DevTools → Network → Authorization header)\n"
            '  python scan.py http://localhost:3000 --token "eyJhbGciOiJIUzI1NiIsInR5..."\n'
            "\n"
            "  # Auto-login: scanner logs in before scanning\n"
            "  python scan.py http://localhost:3000 \\\n"
            "      --login-url http://localhost:3000/rest/user/login \\\n"
            "      --username admin@juice-sh.op --password admin123\n"
            "\n"
            "  # Auto-login with custom field names (form POST)\n"
            "  python scan.py http://localhost:4000 \\\n"
            "      --login-url http://localhost:4000/login \\\n"
            "      --username admin --password password \\\n"
            "      --user-field userName --content-type form\n"
            "\n"
            "  # Login + TOTP 2FA (get Base32 secret from app QR code setup page)\n"
            "  python scan.py http://target.com \\\n"
            "      --login-url http://target.com/login \\\n"
            "      --username admin@target.com --password s3cr3t \\\n"
            "      --totp-secret JBSWY3DPEHPK3PXP\n"
            "\n"
            "  # OAuth 2.0 ROPC (API-first apps with /oauth/token endpoint)\n"
            "  python scan.py http://target.com \\\n"
            "      --oauth-token-url https://auth.target.com/oauth/token \\\n"
            "      --client-id myapp --client-secret xyz \\\n"
            "      --username user@target.com --password s3cr3t\n"
            "\n"
            "━━━ Token path examples ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "  Juice Shop response:  {\"authentication\":{\"token\":\"...\"}}\n"
            '  --token-path authentication.token\n'
            "  NodeGoat response:    {\"token\":\"...\"}\n"
            '  --token-path token   (default)\n'
        ),
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target URL (e.g. http://localhost:3000)",
    )
    parser.add_argument(
        "--pages", "-p",
        type=int, default=50,
        metavar="N",
        help="Max pages to crawl (default: 50)",
    )
    parser.add_argument(
        "--out", "-o",
        metavar="FILE",
        help="Save report to FILE (.json or .html)",
    )
    parser.add_argument(
        "--severity", "-s",
        nargs="+",
        metavar="SEV",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Only report these severity levels",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float, default=20.0,
        metavar="SECS",
        help="Per-request timeout in seconds (default: 20)",
    )
    parser.add_argument(
        "--checks", "-c",
        nargs="+",
        metavar="CHECK_ID",
        help="Run only specific check IDs (see --list-checks)",
    )
    parser.add_argument(
        "--list-checks", "-l",
        action="store_true",
        help="List all available checks and exit",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show verbose output (attack plan, tech signals)",
    )
    parser.add_argument(
        "--userlist", "-U",
        metavar="FILE",
        help="File with usernames/emails for brute force (one per line)",
    )
    parser.add_argument(
        "--passlist", "-P",
        metavar="FILE",
        help="File with passwords for brute force (one per line)",
    )
    parser.add_argument(
        "--wordlist", "-w",
        metavar="FILE",
        help="user:password pairs (one per line) OR passwords only (uses built-in userlist)",
    )

    # ── Auth group ────────────────────────────────────────────────────────────
    auth = parser.add_argument_group(
        "authentication",
        "Supply credentials so the scanner can reach protected pages.\n"
        "Use ONE of: --cookie / --token (paste), --login-url (auto-login), "
        "or --oauth-token-url (OAuth ROPC).",
    )
    auth.add_argument(
        "--cookie",
        metavar="COOKIE_STRING",
        help='Paste session cookie from browser (e.g. "connect.sid=s%%3Aabc123...")',
    )
    auth.add_argument(
        "--token",
        metavar="JWT_OR_TOKEN",
        help="Paste Bearer token from browser (without 'Bearer ' prefix)",
    )
    auth.add_argument(
        "--login-url",
        metavar="URL",
        help="Login endpoint — scanner will POST credentials and extract the token",
    )
    auth.add_argument(
        "--username",
        metavar="USER",
        help="Username / email for auto-login or OAuth ROPC",
    )
    auth.add_argument(
        "--password",
        metavar="PASS",
        help="Password for auto-login or OAuth ROPC",
    )
    auth.add_argument(
        "--user-field",
        metavar="FIELD",
        default="email",
        help="Request body field name for the username (default: email)",
    )
    auth.add_argument(
        "--pass-field",
        metavar="FIELD",
        default="password",
        help="Request body field name for the password (default: password)",
    )
    auth.add_argument(
        "--content-type",
        metavar="TYPE",
        default="json",
        choices=["json", "form"],
        help="Login request body format: json (default) or form",
    )
    auth.add_argument(
        "--token-path",
        metavar="DOT_PATH",
        default="token",
        help='Dot-path to token in JSON login response (default: token). '
             'Juice Shop example: authentication.token',
    )
    auth.add_argument(
        "--totp-secret",
        metavar="BASE32_SECRET",
        help="Base32 TOTP secret key — scanner generates a live OTP code (requires: pip install pyotp)",
    )
    auth.add_argument(
        "--otp-code",
        metavar="CODE",
        help="Static OTP code if you cannot provide --totp-secret",
    )
    auth.add_argument(
        "--otp-url",
        metavar="URL",
        help="URL to POST the OTP code to (defaults to --login-url if not set)",
    )
    auth.add_argument(
        "--otp-field",
        metavar="FIELD",
        default="otp",
        help="Request body field name for the OTP code (default: otp)",
    )
    auth.add_argument(
        "--oauth-token-url",
        metavar="URL",
        help="OAuth 2.0 token endpoint for ROPC grant (e.g. https://auth.example.com/oauth/token)",
    )
    auth.add_argument(
        "--client-id",
        metavar="ID",
        help="OAuth 2.0 client_id",
    )
    auth.add_argument(
        "--client-secret",
        metavar="SECRET",
        help="OAuth 2.0 client_secret (optional for public clients)",
    )
    auth.add_argument(
        "--oauth-scope",
        metavar="SCOPE",
        help='OAuth 2.0 scope (e.g. "openid profile")',
    )
    auth.add_argument(
        "--auto-register",
        action="store_true",
        default=False,
        help=(
            "Auto-register a test account on the target and use it for authenticated scanning. "
            "Tries common signup forms automatically. Falls back to manual instructions if it fails."
        ),
    )
    auth.add_argument(
        "--no-auto-register",
        dest="auto_register",
        action="store_false",
        help="Disable auto-registration (default: disabled).",
    )

    # ── Proxy group ────────────────────────────────────────────────────────────
    proxy = parser.add_argument_group(
        "proxy / traffic interception",
        "Route scanner traffic through a proxy so you can watch and manipulate it.\n"
        "Use --proxy-url for an already-running proxy (Burp/ZAP/mitmproxy).\n"
        "Use --intercept to have NEXUS start its own mitmweb instance automatically.",
    )
    proxy.add_argument(
        "--proxy-url",
        metavar="URL",
        help=(
            "Forward all scanner traffic through this proxy URL.\n"
            "Examples:\n"
            "  Burp Suite :  http://127.0.0.1:8080\n"
            "  ZAP        :  http://127.0.0.1:8090\n"
            "  mitmproxy  :  http://127.0.0.1:8080"
        ),
    )
    proxy.add_argument(
        "--intercept",
        action="store_true",
        help=(
            "Start a built-in mitmweb proxy and open its web UI.\n"
            "Requires: pip install mitmproxy\n"
            "Traffic viewer opens at http://127.0.0.1:8083"
        ),
    )
    proxy.add_argument(
        "--intercept-port",
        type=int,
        default=8082,
        metavar="PORT",
        help="Listener port for the built-in proxy (default: 8082)",
    )
    proxy.add_argument(
        "--intercept-web-port",
        type=int,
        default=8083,
        metavar="PORT",
        help="Web UI port for the built-in proxy (default: 8083)",
    )

    # ── Dirsearch group ────────────────────────────────────────────────────────
    dirsearch_grp = parser.add_argument_group(
        "directory discovery",
        "Brute-force discover hidden paths before auditing.\n"
        "NEXUS probes 150+ built-in paths automatically.\n"
        "Use --dir-wordlist to add extra words (one per line).\n"
        "Use --dir-ext to try path+extension variants (e.g. .php .bak).\n"
        "Examples:\n"
        "  --dir-wordlist mywords.txt\n"
        "  --dir-ext .php .bak .old\n"
        "  --dir-no-recurse     (disable subdirectory recursion)",
    )
    dirsearch_grp.add_argument(
        "--dir-wordlist",
        metavar="FILE",
        help="File with extra paths to probe (one per line, no leading /)",
    )
    dirsearch_grp.add_argument(
        "--dir-ext",
        nargs="+",
        metavar="EXT",
        help="File extensions to append to discovered paths (e.g. .php .bak .old)",
    )
    dirsearch_grp.add_argument(
        "--dir-no-recurse",
        action="store_true",
        help="Disable recursive probing into discovered directories",
    )

    args = parser.parse_args()

    if args.list_checks:
        _list_checks()
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    # Load wordlists
    wordlist_users: list[str] = []
    wordlist_passwords: list[str] = []

    if args.wordlist:
        p = Path(args.wordlist)
        if p.exists():
            lines = [l.strip() for l in p.read_text().splitlines() if l.strip()]
            # If lines contain ":" treat as user:pass pairs, else treat as passwords
            if any(":" in l for l in lines[:5]):
                for line in lines:
                    if ":" in line:
                        u, _, pw = line.partition(":")
                        wordlist_users.append(u.strip())
                        wordlist_passwords.append(pw.strip())
            else:
                wordlist_passwords = lines
        else:
            print(f"{_R}Wordlist file not found: {args.wordlist}{_X}")

    if args.userlist:
        p = Path(args.userlist)
        if p.exists():
            wordlist_users = [l.strip() for l in p.read_text().splitlines() if l.strip()]
        else:
            print(f"{_R}User list file not found: {args.userlist}{_X}")

    if args.passlist:
        p = Path(args.passlist)
        if p.exists():
            wordlist_passwords = [l.strip() for l in p.read_text().splitlines() if l.strip()]
        else:
            print(f"{_R}Password list file not found: {args.passlist}{_X}")

    # Load dirsearch wordlist
    extra_dir_words: list[str] = []
    if args.dir_wordlist:
        p = Path(args.dir_wordlist)
        if p.exists():
            extra_dir_words = [l.strip() for l in p.read_text().splitlines()
                               if l.strip() and not l.startswith("#")]
        else:
            print(f"{_R}Dir wordlist not found: {args.dir_wordlist}{_X}")

    asyncio.run(run_scan(
        target_url=args.target,
        max_pages=args.pages,
        request_timeout=args.timeout,
        severity_filter=args.severity,
        check_filter=args.checks,
        out_path=args.out,
        verbose=args.verbose,
        wordlist_users=wordlist_users or None,
        wordlist_passwords=wordlist_passwords or None,
        # Auth
        cookie=args.cookie,
        token=args.token,
        login_url=args.login_url,
        username=args.username,
        password=args.password,
        user_field=args.user_field,
        pass_field=args.pass_field,
        content_type=args.content_type,
        token_path=args.token_path,
        totp_secret=args.totp_secret,
        otp_code=args.otp_code,
        otp_url=args.otp_url,
        otp_field=args.otp_field,
        oauth_token_url=args.oauth_token_url,
        client_id=args.client_id,
        client_secret=args.client_secret,
        oauth_scope=args.oauth_scope,
        auto_register=args.auto_register,
        # Proxy
        proxy_url=args.proxy_url,
        intercept=args.intercept,
        intercept_port=args.intercept_port,
        intercept_web_port=args.intercept_web_port,
        # Dirsearch
        dirsearch_wordlist=extra_dir_words or None,
        dirsearch_extensions=args.dir_ext or [],
        dirsearch_recurse=0 if args.dir_no_recurse else 1,
    ))


if __name__ == "__main__":
    main()
