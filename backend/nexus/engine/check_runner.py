"""
CheckRunner — two-phase scan engine (no LLM required).

Phase 1: Passive checks against every CrawlResult
Phase 2: Active checks against every InsertionPoint

Also runs:
  - Direct sensitive path probes (FTP, .git, etc.)
  - JSON API insertion point discovery from JS-extracted endpoints
  - Auth endpoint detection for bypass checks
"""
import asyncio
import logging
import uuid
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import urlparse

import httpx

from nexus.checks import ALL_CHECKS, BaseScanCheck
from nexus.engine.guardrails import guarded_body, InjectionDetector
from nexus.engine.scan_context import reset_ctx, ActiveSession
from nexus.engine.think import Fingerprinter, AttackPlanner, AttackPlan, PlannedCheck
from nexus.engine.verifier import Verifier
from nexus.tools.dirsearch import DirSearchEngine
from nexus.models import (
    CheckResult,
    CheckType,
    CrawlResult,
    Finding,
    InsertionPoint,
    IPType,
)

logger = logging.getLogger(__name__)

_ACTIVE_CONCURRENCY = 20  # Raised from 6 — remote targets need higher concurrency

# Paths to probe directly on every scan target
_SENSITIVE_PROBE_PATHS = [
    "/ftp/",
    "/ftp/acquisitions.md",
    "/ftp/coupons_2013.md.bak",
    "/ftp/package.json.bak",
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/package.json",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/admin",
    "/debug",
    "/metrics",
    "/health",
    "/api-docs",
    "/swagger.json",
    "/openapi.json",
    "/phpinfo.php",
]

# Common login/auth endpoints to test for SQLi auth bypass + brute-force
# Generic patterns first, then Juice Shop-specific
_AUTH_ENDPOINTS = [
    ("/rest/user/login",       "POST", ["email", "password"]),
    ("/api/login",             "POST", ["email", "password"]),
    ("/login",                 "POST", ["email", "password", "username"]),
    ("/auth/login",            "POST", ["email", "password"]),
    ("/auth/signin",           "POST", ["email", "password"]),
    ("/signin",                "POST", ["email", "password"]),
    ("/sign-in",               "POST", ["email", "password"]),
    ("/api/auth",              "POST", ["email", "password"]),
    ("/api/auth/login",        "POST", ["email", "password"]),
    ("/api/v1/auth/login",     "POST", ["email", "password"]),
    ("/user/login",            "POST", ["email", "password"]),
    ("/users/login",           "POST", ["email", "password"]),
    ("/account/login",         "POST", ["email", "password"]),
    ("/wp-login.php",          "POST", ["log", "pwd"]),             # WordPress
    ("/wp-admin/",             "POST", ["log", "pwd"]),             # WordPress admin
    ("/admin/login",           "POST", ["username", "password"]),
    ("/administrator",         "POST", ["username", "password"]),
    # NodeGoat: userName field (not email)
    ("/login",                 "POST", ["userName", "password"]),
    # VAmPI
    ("/users/v1/login",        "POST", ["username", "password"]),
    # PHP-based apps (testphp.vulnweb.com, DVWA, etc.)
    ("/login.php",             "POST", ["uname", "pass", "username", "password", "email"]),
    ("/signin.php",            "POST", ["username", "password", "email"]),
    ("/user/login.php",        "POST", ["username", "password"]),
    ("/account/login.php",     "POST", ["username", "password"]),
]

# Search/query endpoints to test for SQLi + XSS
_SEARCH_ENDPOINTS = [
    ("/rest/products/search",  "GET",  ["q"]),
    ("/search",                "GET",  ["q", "query", "s", "term", "keyword"]),
    ("/api/search",            "GET",  ["q", "query"]),
    ("/products",              "GET",  ["q", "search", "name", "filter"]),
    ("/api/products",          "GET",  ["q", "search", "name"]),
    ("/items",                 "GET",  ["q", "search", "name"]),
    ("/api/items",             "GET",  ["q", "name"]),
    ("/catalogue",             "GET",  ["q", "search"]),
    # DVWA SQLi
    ("/vulnerabilities/sqli/", "GET",  ["id"]),
    # DVNA
    ("/usersearch",            "GET",  ["login"]),
    # PHP-based apps (testphp.vulnweb.com uses POST searchFor, also GET id)
    ("/search.php",            "GET",  ["searchFor", "q", "search", "query", "keyword"]),
    ("/search.php",            "POST", ["searchFor", "q", "search"]),
    ("/listproducts.php",      "GET",  ["cat", "id", "category"]),
    ("/artists.php",           "GET",  ["artist"]),
    ("/product.php",           "GET",  ["pic", "id"]),
    ("/showimage.php",         "GET",  ["file", "pic", "img", "image"]),
    ("/userinfo.php",          "GET",  ["username", "user", "id"]),
    ("/cart.php",              "GET",  ["act", "id"]),
]

# Profile / user settings endpoints (SSTI + XSS + mass assignment)
_PROFILE_ENDPOINTS = [
    ("/profile",               "POST", ["username"]),
    ("/api/Users",             "POST", ["username", "email"]),
    ("/rest/user/profile",     "POST", ["username"]),
    ("/account/profile",       "POST", ["username", "name"]),
    ("/api/user/profile",      "POST", ["username", "bio", "name"]),
    ("/user/settings",         "POST", ["username", "name"]),
    ("/settings",              "POST", ["username", "name"]),
    ("/api/me",                "PUT",  ["username", "name", "bio"]),
    ("/api/profile",           "PUT",  ["username", "name"]),
    # NodeGoat contributions — eval() on these fields
    ("/contributions",         "POST", ["preTax", "afterTax", "roth"]),
    # PHP-style profile/user info
    ("/userinfo.php",          "GET",  ["username"]),
    ("/profile.php",           "POST", ["username", "name", "email"]),
    ("/secured/newuser.php",   "POST", ["uname", "email", "pass", "username", "password"]),
    ("/signup.php",            "POST", ["uname", "email", "pass", "fname", "lname"]),
    ("/register.php",          "POST", ["username", "email", "password", "pass"]),
]

# Review/feedback endpoints (NoSQL injection + Stored XSS)
_REVIEW_ENDPOINTS = [
    ("/rest/products/1/reviews",   "PATCH", ["author", "message"]),
    ("/api/Feedbacks",             "POST",  ["comment", "UserId"]),
    ("/rest/memories",             "GET",   ["title", "caption"]),
    ("/api/reviews",               "POST",  ["comment", "author", "body"]),
    ("/reviews",                   "POST",  ["comment", "body", "text"]),
    ("/api/comments",              "POST",  ["comment", "body", "content"]),
    ("/comments",                  "POST",  ["comment", "body"]),
    ("/feedback",                  "POST",  ["message", "comment", "body"]),
    ("/api/feedback",              "POST",  ["message", "comment"]),
    ("/contact",                   "POST",  ["message", "body", "name"]),
    # PHP-based guestbook/comment forms (testphp.vulnweb.com style)
    ("/guestbook.php",             "POST",  ["name", "comment", "text", "message", "email"]),
    ("/comment.php",               "POST",  ["name", "comment", "body"]),
    ("/post.php",                  "POST",  ["title", "body", "content"]),
    ("/forum.php",                 "POST",  ["subject", "body", "message"]),
]

# Complaint / contact endpoints
_COMPLAINT_ENDPOINTS = [
    ("/api/Complaints",            "POST",  ["message"]),
    ("/api/complaints",            "POST",  ["message", "body"]),
    ("/contact",                   "POST",  ["message"]),
    ("/api/contact",               "POST",  ["message"]),
]

# B2B / XML endpoints to test for XXE
_B2B_ENDPOINTS = [
    ("/b2b/v2/orders",             "POST",  ["orderLines"]),
    ("/api/import",                "POST",  ["data"]),
    ("/api/upload",                "POST",  ["file"]),
    ("/upload",                    "POST",  ["file"]),
    ("/import",                    "POST",  ["data"]),
]

# Image upload / URL endpoints to test for SSRF
_IMAGE_UPLOAD_ENDPOINTS = [
    ("/profile/image/url",         "POST",  ["imageUrl"]),
    ("/api/profile/image",         "POST",  ["url", "imageUrl"]),
    ("/upload/url",                "POST",  ["url"]),
    ("/webhook",                   "POST",  ["url", "callback_url", "hook_url"]),
    ("/api/webhook",               "POST",  ["url", "callback_url"]),
    ("/api/fetch",                 "POST",  ["url", "target"]),
    ("/api/proxy",                 "GET",   ["url", "target"]),
    ("/proxy",                     "GET",   ["url"]),
]

# Command injection endpoints — DVWA /exec, DVNA /ping
_CMDI_ENDPOINTS = [
    ("/vulnerabilities/exec/", "POST", ["ip"]),        # DVWA
    ("/ping",                  "POST", ["address"]),   # DVNA
    ("/ping",                  "GET",  ["address"]),
    ("/api/ping",              "POST", ["host", "address"]),
    ("/network/ping",          "POST", ["host", "ip"]),
    ("/tools/ping",            "POST", ["host", "ip"]),
    ("/diagnostic",            "POST", ["host"]),
    ("/trace",                 "POST", ["host"]),
]

# Open redirect endpoints — DVNA /redirect
_REDIRECT_ENDPOINTS = [
    ("/redirect",              "GET",  ["url", "to", "next", "target"]),  # DVNA
    ("/go",                    "GET",  ["url", "to", "next"]),
    ("/out",                   "GET",  ["url", "to"]),
    ("/external",              "GET",  ["url", "to"]),
]

# Debug / admin API endpoints — VAmPI, Spring actuators
_DEBUG_ENDPOINTS = [
    ("/users/v1/_debug",       "GET",  []),             # VAmPI
    ("/actuator",              "GET",  []),              # Spring Boot
    ("/actuator/env",          "GET",  []),
    ("/actuator/beans",        "GET",  []),
    ("/actuator/mappings",     "GET",  []),
    ("/api/debug",             "GET",  []),
    ("/debug/users",           "GET",  []),
    ("/admin/users",           "GET",  []),
]

# VAmPI-style user/book REST API paths for BOLA/BFLA testing
_API_RESOURCE_ENDPOINTS = [
    ("/users/v1",              "GET",  []),              # VAmPI user list
    ("/books/v1",              "GET",  []),              # VAmPI book list
    ("/allocations",           "GET",  ["userId"]),      # NodeGoat
    ("/api/Baskets",           "GET",  ["id"]),          # Juice Shop
    ("/api/Users",             "GET",  ["id"]),          # Juice Shop
]

# Registration endpoints — used by checks that need to create test accounts
_REGISTER_ENDPOINTS = [
    ("/api/Users",                 "POST",  ["email", "password", "passwordRepeat"]),
    ("/api/register",              "POST",  ["email", "password"]),
    ("/register",                  "POST",  ["email", "password", "username"]),
    ("/signup",                    "POST",  ["email", "password", "username"]),
    ("/sign-up",                   "POST",  ["email", "password", "username"]),
    ("/api/auth/register",         "POST",  ["email", "password"]),
    ("/api/v1/register",           "POST",  ["email", "password"]),
    ("/users",                     "POST",  ["email", "password"]),
    ("/api/users",                 "POST",  ["email", "password"]),
]


class CheckRunner:
    def __init__(
        self,
        session_id: str,
        checks: Optional[list[BaseScanCheck]] = None,
        on_finding: Optional[Callable[[Finding], None]] = None,
        request_timeout: float = 20.0,
        wordlist_users: Optional[list[str]] = None,
        wordlist_passwords: Optional[list[str]] = None,
        injected_session: Optional[ActiveSession] = None,
        proxy_url: Optional[str] = None,
        dirsearch_wordlist: Optional[list[str]] = None,
        dirsearch_extensions: Optional[list[str]] = None,
        dirsearch_recurse: int = 1,
    ):
        self.session_id = session_id
        self.checks = checks if checks is not None else ALL_CHECKS
        self.on_finding = on_finding
        self.request_timeout = request_timeout
        self.wordlist_users = wordlist_users or []
        self.wordlist_passwords = wordlist_passwords or []
        self.injected_session = injected_session
        self.proxy_url = proxy_url
        self.dirsearch_wordlist = dirsearch_wordlist
        self.dirsearch_extensions = dirsearch_extensions or []
        self.dirsearch_recurse = dirsearch_recurse
        self._findings: list[Finding] = []
        self._seen_keys: set = set()
        self._base_url: str = ""
        self._attack_plan: AttackPlan | None = None

    async def run(
        self,
        crawl_results: list[CrawlResult],
        insertion_points: list[InsertionPoint],
    ) -> list[Finding]:
        # Determine base URL from crawl results
        if crawl_results:
            parsed = urlparse(crawl_results[0].url)
            self._base_url = f"{parsed.scheme}://{parsed.netloc}"

        # ---- Reset ScanContext singleton for this scan session ----
        ctx = reset_ctx(base_url=self._base_url,
                        injected_session=self.injected_session)
        if self.wordlist_users:
            ctx.wordlist_users = self.wordlist_users
        if self.wordlist_passwords:
            ctx.wordlist_passwords = self.wordlist_passwords
        if self.injected_session:
            logger.info("[%s] Pre-seeded ScanContext with injected %s session",
                        self.session_id, self.injected_session.auth_type)

        # ---- Guardrail: sanitize crawl result bodies before analysis ----
        injection_count = 0
        for cr in crawl_results:
            inj = InjectionDetector.check(cr.body)
            if inj:
                injection_count += 1
                cr.body = guarded_body(cr.body, url=cr.url)
        if injection_count:
            logger.warning("[guardrail] %d crawl results contained prompt injection attempts", injection_count)

        # ---- Reset all check state from any previous scan session ----
        for check in self.checks:
            check.reset()

        # ════════════════════════════════════════════════════════════
        # THINK PHASE — fingerprint target, build prioritised plan
        # ════════════════════════════════════════════════════════════
        logger.info("[%s] Think phase: fingerprinting target from %d pages",
                    self.session_id, len(crawl_results))
        fingerprinter = Fingerprinter()
        tech_profile = fingerprinter.analyse(crawl_results)
        logger.info("[%s] Tech profile: %s", self.session_id, tech_profile.summary())
        logger.info("[%s] Signals detected: %s", self.session_id, ", ".join(tech_profile.signals[:12]))

        planner = AttackPlanner()
        self._attack_plan = planner.plan(tech_profile, self.checks, insertion_points)

        # Log the plan
        ordered = self._attack_plan.ordered()
        skipped = self._attack_plan.skip_count()
        logger.info("[%s] Attack plan: %d checks to run, %d skipped",
                    self.session_id, len(ordered) - skipped, skipped)
        for pc in ordered[:10]:  # log top 10
            if pc.priority > 0:
                logger.info("[%s]   [%3d] %s — %s",
                            self.session_id, pc.priority, pc.check.check_id, pc.rationale)

        # ════════════════════════════════════════════════════════════
        # EXPLOIT PHASE 1: Passive checks (analyse crawl data)
        # ════════════════════════════════════════════════════════════
        logger.info("[%s] Exploit phase 1: passive checks on %d pages",
                    self.session_id, len(crawl_results))
        passive_planned = [pc for pc in ordered
                           if pc.check.check_type == CheckType.PASSIVE and pc.priority > 0]
        for pc in passive_planned:
            for cr in crawl_results:
                try:
                    results = await pc.check.check_passive(cr)
                    for r in results:
                        await self._record(r, cr.url)  # no client — passive, no re-verify needed
                        # Adaptive replanning after each passive finding
                        planner.adapt(self._attack_plan, r.check_id)
                except Exception as exc:
                    logger.debug("Passive %s on %s: %s", pc.check.check_id, cr.url, exc)

        # ════════════════════════════════════════════════════════════
        # EXPLOIT PHASE 2: Active checks in priority order
        # ════════════════════════════════════════════════════════════
        logger.info("[%s] Exploit phase 2: active checks (priority-ordered)",
                    self.session_id)

        # Merge auth headers if a session was injected
        _base_headers: dict = {
            "User-Agent": "Mozilla/5.0 (compatible; NexusScanner/1.0)",
            "Accept": "text/html,application/json,*/*;q=0.8",
        }
        if self.injected_session:
            _base_headers.update(self.injected_session.extra_headers or ctx.auth_headers())

        _client_kwargs: dict = dict(
            follow_redirects=True,
            timeout=self.request_timeout,
            verify=False,
            headers=_base_headers,
        )
        if self.proxy_url:
            _client_kwargs["proxy"] = self.proxy_url
            logger.info("[%s] All check traffic routed through proxy: %s",
                        self.session_id, self.proxy_url)

        async with httpx.AsyncClient(**_client_kwargs) as client:
            sem = asyncio.Semaphore(_ACTIVE_CONCURRENCY)

            # ── Phase 0 (within active): dirsearch path discovery ──────────
            dirsearch_ips: list[InsertionPoint] = []
            dirsearch_crs: list[CrawlResult] = []
            if self._base_url:
                auth_headers_for_ds: dict = {}
                if self.injected_session:
                    auth_headers_for_ds = self.injected_session.extra_headers or ctx.auth_headers()
                ds_engine = DirSearchEngine(
                    base_url=self._base_url,
                    extra_wordlist=self.dirsearch_wordlist,
                    auth_headers=auth_headers_for_ds,
                    extensions=self.dirsearch_extensions,
                )
                try:
                    ds_result = await ds_engine.run(client)
                    dirsearch_ips = ds_result.insertion_points
                    dirsearch_crs = ds_result.crawl_results
                    logger.info(
                        "[%s] Dirsearch found %d paths → %d new insertion points",
                        self.session_id, len(ds_result.found), len(dirsearch_ips),
                    )
                    # Recurse into discovered directories (skip files with extensions)
                    if self.dirsearch_recurse > 0:
                        dirs = [
                            dr.path for dr in ds_result.found
                            if dr.status in (200, 403)
                            and "." not in (dr.path.split("/")[-1] or "")  # only dirs, not files
                        ]
                        extra_dirs = await ds_engine.recurse(client, dirs, self.dirsearch_recurse)
                        for dr in extra_dirs:
                            _, extra_ips = ds_engine._to_crawl_and_ips(dr)
                            dirsearch_ips.extend(extra_ips)
                except Exception as exc:
                    logger.warning("[%s] Dirsearch failed: %s", self.session_id, exc)

                # Run passive checks on newly discovered pages
                passive_checks = [c for c in self.checks if c.check_type == CheckType.PASSIVE]
                for cr in dirsearch_crs:
                    for check in passive_checks:
                        try:
                            results = await check.check_passive(cr)
                            for r in results:
                                await self._record(r, cr.url)
                        except Exception:
                            pass

            # Build synthetic insertion points once
            synthetic_ips = await self._build_synthetic_insertion_points(client)
            all_ips = insertion_points + synthetic_ips + dirsearch_ips

            # Run active checks in priority order — high-priority checks run first.
            # After each check group, re-evaluate plan (kills may elevate follow-ups).
            active_planned = sorted(
                [pc for pc in self._attack_plan.planned_checks
                 if pc.check.check_type in (CheckType.ACTIVE, CheckType.OAST)
                 and pc.priority > 0],
                key=lambda p: p.priority, reverse=True,
            )

            total_checks = len(active_planned)
            for _check_idx, pc in enumerate(active_planned, 1):
                import sys as _sys
                print(f"    checking {pc.check.check_id} [{_check_idx}/{total_checks}] vs {len(all_ips)} IPs…", flush=True)
                tasks = [
                    self._run_active_planned(sem, pc, ip, client, planner)
                    for ip in all_ips
                ]
                await asyncio.gather(*tasks, return_exceptions=True)

                # Re-sort remaining checks after each executed check
                active_planned = sorted(
                    [p for p in active_planned if p.check.check_id != pc.check.check_id],
                    key=lambda p: p.priority, reverse=True,
                )

            # Probe sensitive paths (passive analysis of known URLs)
            await self._probe_sensitive_paths(client)

        logger.info("[%s] Audit complete — %d findings", self.session_id, len(self._findings))
        return self._findings

    def get_attack_plan(self) -> AttackPlan | None:
        """Return the attack plan built during the last run() call."""
        return self._attack_plan

    async def _run_active(
        self,
        sem: asyncio.Semaphore,
        check: BaseScanCheck,
        ip: InsertionPoint,
        client: httpx.AsyncClient,
    ):
        async with sem:
            try:
                results = await check.check_active(ip, client)
                for r in results:
                    await self._record(r, ip.url, client)
            except Exception as exc:
                logger.debug("Active %s on %s[%s]: %s", check.check_id, ip.url, ip.name, exc)

    async def _run_active_planned(
        self,
        sem: asyncio.Semaphore,
        pc: PlannedCheck,
        ip: InsertionPoint,
        client: httpx.AsyncClient,
        planner: AttackPlanner,
    ):
        """Run a PlannedCheck and trigger kill-chain boosts on findings."""
        async with sem:
            try:
                results = await pc.check.check_active(ip, client)
                for r in results:
                    await self._record(r, ip.url, client)
                    # Adaptive replanning: boost follow-up checks
                    if self._attack_plan:
                        planner.adapt(self._attack_plan, r.check_id)
                        logger.debug("[%s] Kill chain: %s found → boosted related checks",
                                     self.session_id, r.check_id)
            except Exception as exc:
                logger.debug("Active %s on %s[%s]: %s",
                             pc.check.check_id, ip.url, ip.name, exc)

    async def _build_synthetic_insertion_points(
        self, client: httpx.AsyncClient
    ) -> list[InsertionPoint]:
        """
        Create InsertionPoints for known-pattern endpoints not found by crawling.
        All probes run CONCURRENTLY (asyncio.gather) to avoid adding 30+ seconds
        of sequential I/O before any check runs, especially against remote targets.
        """
        if not self._base_url:
            return []

        ips: list[InsertionPoint] = []
        _seen_paths: set[str] = set()
        # Cache the homepage body — used to detect redirect-to-homepage false positives
        _homepage_body: str = ""
        try:
            _hp = await client.get(self._base_url + "/")
            _homepage_body = _hp.text[:2000]
        except Exception:
            pass

        def _is_real_endpoint(resp: httpx.Response) -> bool:
            if resp.status_code in (404, 405, 410):
                return False
            if _homepage_body and len(_homepage_body) > 100:
                if len(resp.text) > 500 and resp.text[:500] == _homepage_body[:500]:
                    return False
            final_url = str(resp.url)
            if final_url.rstrip("/") == self._base_url.rstrip("/"):
                return False
            # Skip endpoints that return a broken/error body (PHP Fatal error,
            # DB access denied, etc.). These are non-functional and generate FPs.
            body_start = resp.text[:300]
            if any(sig in body_start for sig in (
                "Fatal error",
                "Access denied for user",
                "mysqli_sql_exception",
                "Warning: mysqli",
                "Connection refused",
                "SQLSTATE",
            )):
                return False
            return True

        def _add_ips(url: str, method: str, params: list[str], ep_type: str,
                     ip_type: IPType) -> None:
            for param in params:
                dedup_key = f"{method}:{url}:{param}"
                if dedup_key not in _seen_paths:
                    _seen_paths.add(dedup_key)
                    ips.append(InsertionPoint(
                        url=url, method=method,
                        ip_type=ip_type,
                        name=param, value="test",
                        context={"synthetic": True, "endpoint_type": ep_type},
                    ))

        # Build the full list of (probe_coro, on_success_callback) tasks.
        # All probes run CONCURRENTLY with asyncio.gather — this was sequential before
        # which caused 30+ second delays against remote targets.
        probe_tasks: list = []

        async def _probe_json(path, method, params, ep_type, ip_type):
            url = self._base_url + path
            try:
                r = await client.request(method, url,
                    json={p: "test" for p in params},
                    headers={"Content-Type": "application/json"},
                )
                if _is_real_endpoint(r):
                    _add_ips(url, method, params, ep_type, ip_type)
            except Exception:
                pass

        async def _probe_form(path, method, params, ep_type, ip_type, data_val="test"):
            url = self._base_url + path
            try:
                r = await client.request(method, url,
                    data={p: data_val for p in params} if params else {},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if _is_real_endpoint(r):
                    _add_ips(url, method, params or ["ip"], ep_type, ip_type)
            except Exception:
                pass

        async def _probe_get(path, method, params, ep_type, ip_type, query=""):
            url = self._base_url + path
            target_url = f"{url}{query}" if query else url
            try:
                r = await client.request(method, target_url)
                if _is_real_endpoint(r):
                    _add_ips(url, method, params, ep_type, ip_type)
            except Exception:
                pass

        async def _probe_xml(path, method):
            url = self._base_url + path
            try:
                r = await client.request(method, url,
                    content="<test/>",
                    headers={"Content-Type": "application/xml"},
                )
                if _is_real_endpoint(r):
                    ips.append(InsertionPoint(
                        url=url, method=method,
                        ip_type=IPType.BODY_PARAM,
                        name="orderLines", value="<test/>",
                        context={"synthetic": True, "endpoint_type": "b2b_xml"},
                    ))
            except Exception:
                pass

        async def _probe_debug(path):
            url = self._base_url + path
            try:
                r = await client.get(url)
                if _is_real_endpoint(r):
                    ips.append(InsertionPoint(
                        url=url, method="GET",
                        ip_type=IPType.HEADER, name="_debug_probe", value="",
                        context={"synthetic": True, "endpoint_type": "debug"},
                    ))
            except Exception:
                pass

        async def _probe_api(path, method, params):
            url = self._base_url + path
            try:
                r = await client.request(method, url)
                if _is_real_endpoint(r):
                    for param in (params or ["id"]):
                        dedup_key = f"{method}:{url}:{param}"
                        if dedup_key not in _seen_paths:
                            _seen_paths.add(dedup_key)
                            ips.append(InsertionPoint(
                                url=url, method=method,
                                ip_type=IPType.QUERY_PARAM,
                                name=param, value="1",
                                context={"synthetic": True, "endpoint_type": "api_resource"},
                            ))
            except Exception:
                pass

        async def _probe_review(path, method, params):
            url = self._base_url + path
            try:
                r = await client.request(method, url,
                    json={p: "test" for p in params},
                    headers={"Content-Type": "application/json"},
                )
                if _is_real_endpoint(r):
                    for param in params:
                        dedup_key = f"{method}:{url}:{param}"
                        if dedup_key not in _seen_paths:
                            _seen_paths.add(dedup_key)
                            ips.append(InsertionPoint(
                                url=url, method=method,
                                ip_type=IPType.JSON_KEY,
                                name=param, value="test",
                                context={"synthetic": True, "endpoint_type": "review"},
                            ))
            except Exception:
                pass

        async def _probe_ssrf(path, method, params):
            url = self._base_url + path
            try:
                r = await client.request(method, url,
                    data={p: "test" for p in params},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if _is_real_endpoint(r):
                    for param in params:
                        ips.append(InsertionPoint(
                            url=url, method=method,
                            ip_type=IPType.BODY_PARAM,
                            name=param, value="test",
                            context={"synthetic": True, "endpoint_type": "image_upload"},
                        ))
            except Exception:
                pass

        # Collect all probe coroutines
        for path, method, params in _AUTH_ENDPOINTS:
            probe_tasks.append(_probe_json(path, method, params, "auth", IPType.JSON_KEY))
        for path, method, params in _SEARCH_ENDPOINTS:
            probe_tasks.append(_probe_get(path, method, params, "search", IPType.QUERY_PARAM, "?q=test"))
        for path, method, params in _PROFILE_ENDPOINTS:
            ip_type = IPType.BODY_PARAM if method in ("POST", "PUT") else IPType.QUERY_PARAM
            probe_tasks.append(_probe_json(path, method, params, "profile", ip_type))
        for path, method, params in _REVIEW_ENDPOINTS:
            probe_tasks.append(_probe_review(path, method, params))
        for path, method, _params in _B2B_ENDPOINTS:
            probe_tasks.append(_probe_xml(path, method))
        for path, method, params in _IMAGE_UPLOAD_ENDPOINTS:
            probe_tasks.append(_probe_ssrf(path, method, params))
        for path, method, params in _CMDI_ENDPOINTS:
            ip_type = IPType.BODY_PARAM if method == "POST" else IPType.QUERY_PARAM
            probe_tasks.append(_probe_form(path, method, params, "cmdi", ip_type, "127.0.0.1"))
        for path, method, params in _REDIRECT_ENDPOINTS:
            probe_tasks.append(_probe_get(path, method, params, "redirect", IPType.QUERY_PARAM, "?url=http://example.com"))
        for path, _method, _params in _DEBUG_ENDPOINTS:
            probe_tasks.append(_probe_debug(path))
        for path, method, params in _API_RESOURCE_ENDPOINTS:
            probe_tasks.append(_probe_api(path, method, params))

        # Run all probes concurrently
        await asyncio.gather(*probe_tasks, return_exceptions=True)

        logger.info("[%s] Synthesised %d insertion points for known endpoints",
                    self.session_id, len(ips))
        return ips

    async def _probe_sensitive_paths(self, client: httpx.AsyncClient):
        """Probe sensitive paths concurrently and run passive checks on responses."""
        if not self._base_url:
            return

        passive_checks = [c for c in self.checks if c.check_type == CheckType.PASSIVE]
        if not passive_checks:
            return  # Skip probing if no passive checks to run

        # Detect SPA catch-all: probe a canary non-existent path first.
        # If the canary returns 200 with the same body as the homepage, all
        # 200 responses from sensitive-path probing are SPA false positives.
        spa_canary_body = ""
        try:
            import uuid
            canary_path = f"/nexus-canary-{uuid.uuid4().hex[:12]}"
            r_home = await client.get(self._base_url + "/")
            r_canary = await client.get(self._base_url + canary_path)
            if r_canary.status_code == 200 and r_home.status_code == 200:
                if r_canary.text[:300] == r_home.text[:300]:
                    spa_canary_body = r_canary.text[:500]
                    logger.info(
                        "[check_runner] SPA catch-all detected at %s — "
                        "sensitive-path probing will skip matching 200 responses",
                        self._base_url,
                    )
        except Exception:
            pass

        async def _probe_one(path: str):
            url = self._base_url + path
            try:
                resp = await client.get(url)
                # Skip SPA catch-all false positives
                if spa_canary_body and resp.status_code == 200:
                    if resp.text[:300] == spa_canary_body[:300]:
                        return
                # Guardrail: detect and sanitize prompt injections in web responses
                safe_body = guarded_body(resp.text, url=url)
                cr = CrawlResult(
                    url=url,
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=safe_body,
                    content_type=resp.headers.get("content-type", ""),
                )
                for check in passive_checks:
                    try:
                        results = await check.check_passive(cr)
                        for r in results:
                            await self._record(r, url)
                    except Exception:
                        pass
            except Exception:
                pass

        await asyncio.gather(*[_probe_one(p) for p in _SENSITIVE_PROBE_PATHS],
                             return_exceptions=True)

    async def _record(
        self,
        result: CheckResult,
        fallback_url: str,
        client: Optional[httpx.AsyncClient] = None,
    ):
        if not result.vulnerable:
            return

        # Secondary verification — drops false positives, downgrades uncertain findings
        if client is not None:
            verified = await Verifier().verify(result, client)
            if verified is None:
                logger.debug("[%s] Verifier dropped %s on %s (false positive)",
                             self.session_id, result.check_id, fallback_url)
                return
            result = verified

        ip = result.insertion_point
        check_obj = next((c for c in self.checks if c.check_id == result.check_id), None)
        is_passive = check_obj and check_obj.check_type == CheckType.PASSIVE

        if is_passive:
            key = (result.check_id, result.description[:60])
        else:
            key = (
                result.check_id,
                ip.url if ip else fallback_url,
                ip.name if ip else "",
            )

        if key in self._seen_keys:
            return
        self._seen_keys.add(key)

        if ip is None:
            ip = InsertionPoint(
                url=fallback_url, method="GET",
                ip_type=IPType.HEADER, name="(passive)", value="",
            )

        finding = Finding(
            id=str(uuid.uuid4()),
            session_id=self.session_id,
            check_id=result.check_id,
            severity=result.severity,
            confidence=result.confidence,
            cvss=result.cvss,
            description=result.description,
            insertion_point=ip,
            evidence=result.evidence,
            steps_to_reproduce=_steps(result),
            solution=_solution(result.check_id),
            references=_references(result.check_id),
            created_at=datetime.utcnow().isoformat(),
        )
        self._findings.append(finding)
        logger.info(
            "[%s] FINDING %s [%s/%s] %s — %s %s",
            self.session_id, finding.id[:8],
            finding.severity.value, finding.confidence.value,
            finding.check_id, ip.url, ip.name,
        )

        if self.on_finding:
            try:
                self.on_finding(finding)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------

_SOLUTIONS: dict[str, str] = {
    "sqli-error": "Use parameterised queries / prepared statements. Never concatenate user input into SQL.",
    "sqli-time": "Use parameterised queries. Confirm with error-based or UNION-based payloads.",
    "sqli-auth-bypass": "Use parameterised queries. Never build SQL from user-provided login credentials.",
    "xss-reflected": "HTML-encode all user output. Implement a strict Content-Security-Policy.",
    "ssti-eval": "Never pass user-controlled input to eval(), vm.runInNewContext(), or template engines.",
    "ssti-profile-eval": "Sanitise username fields. Never render user input through eval() or Pug/EJS templates unsafely.",
    "traversal-lfi": "Validate and whitelist file paths. Never pass user input directly to file open operations.",
    "traversal-sensitive-paths": "Block access to sensitive paths via server config (FTP, .git, .env, backup).",
    "passive-missing-headers": "Add the missing security header to all HTTP responses.",
    "passive-open-redirect": "Validate redirect targets against an allowlist.",
    "passive-cors": "Restrict CORS to specific trusted origins.",
    "passive-info-disclosure": "Remove server version headers. Suppress stack traces from HTTP responses.",
    "ssrf": "Validate and whitelist allowed URL schemes and hosts. Never fetch user-supplied URLs server-side.",
    "jwt-unsigned": "Reject JWTs with alg=none. Use a strong secret and verify signature on every request.",
    "admin-chain": "Implement proper role-based access control. Rotate JWT secrets. Remove debug/admin APIs from production.",
    "mass-assignment": "Whitelist allowed fields during object creation. Never accept role/isAdmin from user input.",
    "nosql-login": "Use typed queries. Never pass raw user input to MongoDB operators. Validate input types strictly.",
    "nosql-reviews": "Validate PATCH body fields. Use parameterized neDB queries. Check ownership before updating.",
    "idor-basket": "Validate that the authenticated user owns the requested resource. Never rely solely on sequential IDs.",
    "idor-user-data": "Implement resource ownership checks. Use opaque IDs instead of sequential integers.",
    "xxe-b2b": "Disable external entity processing in XML parsers. Use JSON instead of XML where possible.",
    "static-js-rce": "Remove eval() and dynamic code execution. Use static template rendering. Sanitize all user-controlled inputs.",
    "static-js-secret": "Never hardcode secrets in source code. Use environment variables and secret managers.",
    "static-js-internal": "Remove internal URLs from client-side code. Use API proxies to hide internal topology.",
    "xss-stored-review": "HTML-encode all user content before rendering. Implement CSP. Sanitize stored data on read.",
    "xss-stored-feedback": "Sanitize feedback on storage and retrieval. Implement CSP. Encode all user-supplied output.",
    "xss-stored-profile": "Sanitize username and profile fields. Encode user-supplied values in all rendering contexts.",
    "weak-password-hash": "Use bcrypt, Argon2, or scrypt with per-user salts. Migrate existing MD5/SHA1 hashes immediately.",
    "account-enumeration": "Return identical responses for valid and invalid usernames. Add constant-time comparison.",
    "prototype-pollution": "Use Object.create(null) for data containers. Validate and sanitize JSON keys. Use schema validation.",
    "http-verb-tampering": "Explicitly whitelist allowed HTTP methods per route. Remove X-HTTP-Method-Override support.",
    "csrf": "Implement CSRF tokens on all state-changing endpoints. Use SameSite=Strict cookies. Validate Origin header.",
    "rate-limit-missing": "Add rate limiting (e.g., express-rate-limit) to login/register. Implement account lockout after N failures.",
    # Phase 3 additions
    "cmdi": "Never pass user input to shell commands. Use language APIs instead of OS commands. Whitelist allowed characters. Use subprocess with argument arrays (no shell=True).",
    "cookie-security": "Set Secure flag on all cookies. Set HttpOnly on session tokens. Set SameSite=Strict or Lax to prevent CSRF. Use __Secure- and __Host- cookie prefixes.",
    "host-header-injection": "Validate Host header against a whitelist of allowed domains. Use absolute URLs for password reset links from config, not from Host header.",
    "cve-2021-44228-log4shell": "Upgrade Log4j to 2.17.1+. Set log4j2.formatMsgNoLookups=true. Remove JndiLookup class from classpath as mitigation.",
    "cve-2014-6271-shellshock": "Update bash to patched version. Disable CGI or migrate to non-CGI execution models. Filter function definitions in environment variables.",
    "cve-2022-22965-spring4shell": "Upgrade Spring Framework to 5.3.18+ or 5.2.20+. Use Java 8 or Tomcat with SecurityManager. Bind only whitelisted properties.",
    "cve-2017-5638-struts-ognl": "Upgrade Struts2 to 2.5.33+. Disable Jakarta Multipart parser or switch to alternative. Apply vendor security patches immediately.",
    "vulnerable-component": "Update the identified component to the latest secure version. Subscribe to security advisories (CVE/NVD). Use dependency scanning in CI/CD (OWASP Dependency-Check, Snyk, Dependabot).",
    "ssrf-generic": "Validate and whitelist allowed URL schemes and hosts. Block private IP ranges (RFC1918) and cloud metadata endpoints. Use an egress proxy.",
    "insecure-deserialization": "Never deserialize untrusted data. Use integrity checks (HMAC) before deserializing. Replace Java serialization with JSON/Protobuf. Use deserialization filters (Java 9+ ObjectInputFilter).",
    "hardcoded-credentials": "Remove all hardcoded credentials from source code. Use environment variables and secret managers (Vault, AWS Secrets Manager). Rotate any exposed credentials immediately.",
    "login-bruteforce": "Use strong unique passwords. Implement account lockout after N failures. Enable MFA. Use rate limiting and CAPTCHA on login endpoints.",
    "sqli-boolean": "Use parameterised queries / prepared statements. Never concatenate user input into SQL. Boolean-blind SQLi allows full DB extraction character by character.",
    "crlf-injection": "Sanitize all user input that is reflected in response headers. Never allow newline characters (\\r\\n) in header values. Use frameworks that prevent header injection.",
    "mass-assignment": "Whitelist allowed fields on every model. Never pass raw request parameters to ORM constructors. Explicitly define what fields users can set.",
    "insecure-file-upload": "Validate file extension server-side (allowlist only). Validate MIME type from file magic bytes, not Content-Type header. Store uploads outside web root. Rename on upload.",
    "clickjacking": "Add X-Frame-Options: DENY or SAMEORIGIN to all HTML responses. Alternatively use CSP: frame-ancestors 'none'. Apply via middleware for all routes.",
    "open-redirect-active": "Validate redirect destinations against an exact-match allowlist. Never trust user-supplied redirect URLs. Use relative paths or route names instead of full URLs.",
    "password-reset-poisoning": "Generate reset links using a configured absolute base URL, never from Host header. Validate Host header against a whitelist. Use X-Forwarded-Host only if explicitly trusted.",
    "race-condition": "Use atomic database operations. Implement optimistic or pessimistic locking. Use Redis/distributed locks for rate-limited operations. Check-then-act must be atomic.",
    "business-logic": "Validate all numerical inputs server-side: reject negative quantities, enforce minimum prices. Implement server-side coupon usage tracking with unique-use constraints.",
    "graphql": "Disable introspection in production. Implement query depth and complexity limits. Apply authorization checks in every resolver. Use persisted queries.",
    "ldap-injection": "Use parameterised LDAP queries (DN and filter escaping). Never concatenate user input into LDAP filter strings. Use a well-tested LDAP library with input escaping.",
    "http-param-pollution": "Server should use a consistent parameter handling strategy. WAF rules should apply to all instances of a parameter. Parse parameters in a predictable, documented order.",
    "web-cache-poisoning": "Mark all user-controlled headers as cache keys. Use Vary header for any header that changes response. Disable caching for authenticated or dynamic responses.",
    "ssi-injection": "Disable SSI directives in web server config. Use X-XSS-Protection and Content-Security-Policy. Never render user content with SSI processing enabled.",
    "http-request-smuggling": "Use HTTP/2 end-to-end. Ensure frontend and backend agree on Transfer-Encoding handling. Configure load balancer to normalize ambiguous requests. Upgrade all proxies.",
    "2fa-bypass": "Rate-limit OTP attempts (max 3-5 per minute). Invalidate OTP after single use. Require re-authentication if 2FA step skipped. Monitor for concurrent session anomalies.",
    "oauth": "Require state parameter on all OAuth authorization requests. Validate redirect_uri exactly against whitelist. Use PKCE. Never pass tokens in URL fragments or query strings.",
    "oauth-missing-state": "Always include and validate the state parameter in OAuth flows. Without it, attackers can initiate CSRF-based account linking.",
    "oauth-open-redirect": "Validate redirect_uri against an exact-match allowlist. Reject any redirect_uri that is not pre-registered.",
    # API checks (api_checks.py)
    "ssjs-injection": "Never pass user-controlled input to eval() or vm.runInNewContext(). Use JSON.parse() for data. Validate numeric fields server-side before any computation.",
    "bola": "Implement object-level authorization on every API endpoint. Verify that the authenticated user owns or has permission to access the requested resource. Use opaque UUIDs instead of sequential IDs.",
    "bfla": "Implement function-level authorization checks. Verify user role before processing privileged operations. Never trust client-supplied role claims.",
    "debug-endpoint": "Remove all debug, diagnostic, and admin-only endpoints from production builds. Protect any remaining admin APIs with strong authentication and IP allowlisting.",
    "sensitive-api-path": "Remove debug and actuator endpoints from production. Apply authentication to all management APIs. Enumerate and audit all exposed internal paths.",
    "cmdi-ext": "Never pass user input to OS shell commands. Use language-native APIs (e.g., fs.readFile, subprocess with argument arrays). Whitelist valid characters. Use subprocess with shell=False in Python.",
    "csv-injection": "Sanitize all fields that may appear in CSV exports. Prefix cells starting with =, +, -, @, \\t, or \\n with a single apostrophe ('). Alternatively, wrap all fields in double quotes and escape double quotes by doubling them.",
    "csp-bypass": "Define a strict Content-Security-Policy header with: script-src 'self' (no wildcards, no unsafe-inline, no unsafe-eval). Add a nonce or hash for inline scripts. Avoid allowlisting CDN domains with JSONP endpoints. Add a report-uri directive to monitor violations.",
}

_REFERENCES: dict[str, list[str]] = {
    "sqli-error":       ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"],
    "sqli-time":        ["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
    "sqli-auth-bypass": ["https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF"],
    "xss-reflected":    ["https://owasp.org/www-community/attacks/xss/", "https://cwe.mitre.org/data/definitions/79.html"],
    "ssti-eval":        ["https://portswigger.net/web-security/server-side-template-injection", "https://cwe.mitre.org/data/definitions/94.html"],
    "ssti-profile-eval": ["https://portswigger.net/web-security/server-side-template-injection"],
    "traversal-lfi":    ["https://owasp.org/www-community/attacks/Path_Traversal", "https://cwe.mitre.org/data/definitions/22.html"],
    "traversal-sensitive-paths": ["https://cwe.mitre.org/data/definitions/538.html"],
    "passive-missing-headers": ["https://owasp.org/www-project-secure-headers/"],
    "passive-cors":     ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
    "passive-info-disclosure": ["https://cwe.mitre.org/data/definitions/200.html"],
    "ssrf": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery", "https://cwe.mitre.org/data/definitions/918.html"],
    "jwt-unsigned": ["https://portswigger.net/web-security/jwt/algorithm-confusion", "https://cwe.mitre.org/data/definitions/347.html"],
    "xss-stored-review": ["https://owasp.org/www-community/attacks/xss/#stored-xss-attacks", "https://cwe.mitre.org/data/definitions/79.html"],
    "xss-stored-feedback": ["https://owasp.org/www-community/attacks/xss/#stored-xss-attacks"],
    "xss-stored-profile": ["https://owasp.org/www-community/attacks/xss/#stored-xss-attacks"],
    "weak-password-hash": ["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure", "https://cwe.mitre.org/data/definitions/916.html"],
    "account-enumeration": ["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account"],
    "prototype-pollution": ["https://portswigger.net/web-security/prototype-pollution", "https://cwe.mitre.org/data/definitions/1321.html"],
    "http-verb-tampering": ["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"],
    "csrf": ["https://owasp.org/www-community/attacks/csrf", "https://cwe.mitre.org/data/definitions/352.html"],
    "rate-limit-missing": ["https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures", "https://cwe.mitre.org/data/definitions/307.html"],
    # Phase 3 additions
    "cmdi": ["https://owasp.org/www-community/attacks/Command_Injection", "https://cwe.mitre.org/data/definitions/78.html"],
    "cookie-security": ["https://owasp.org/www-community/controls/SecureCookieAttribute", "https://cwe.mitre.org/data/definitions/614.html", "https://cwe.mitre.org/data/definitions/1004.html"],
    "host-header-injection": ["https://portswigger.net/web-security/host-header", "https://cwe.mitre.org/data/definitions/116.html"],
    "cve-2021-44228-log4shell": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "https://www.lunasec.io/docs/blog/log4j-zero-day/"],
    "cve-2014-6271-shellshock": ["https://nvd.nist.gov/vuln/detail/CVE-2014-6271", "https://cwe.mitre.org/data/definitions/78.html"],
    "cve-2022-22965-spring4shell": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965", "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement"],
    "cve-2017-5638-struts-ognl": ["https://nvd.nist.gov/vuln/detail/CVE-2017-5638", "https://cwiki.apache.org/confluence/display/WW/S2-045"],
    "vulnerable-component": ["https://owasp.org/www-project-top-ten/2021/A06_2021-Vulnerable_and_Outdated_Components", "https://nvd.nist.gov/"],
    "ssrf-generic": ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery", "https://cwe.mitre.org/data/definitions/918.html"],
    "insecure-deserialization": ["https://owasp.org/www-project-top-ten/2021/A08_2021-Software_and_Data_Integrity_Failures", "https://cwe.mitre.org/data/definitions/502.html"],
    "hardcoded-credentials": ["https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures", "https://cwe.mitre.org/data/definitions/798.html"],
    "login-bruteforce": ["https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures", "https://cwe.mitre.org/data/definitions/307.html"],
    "sqli-boolean": ["https://owasp.org/www-community/attacks/Blind_SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"],
    "crlf-injection": ["https://owasp.org/www-community/vulnerabilities/CRLF_Injection", "https://cwe.mitre.org/data/definitions/93.html"],
    "mass-assignment": ["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/20-Testing_for_Mass_Assignment", "https://cwe.mitre.org/data/definitions/915.html"],
    "insecure-file-upload": ["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload", "https://cwe.mitre.org/data/definitions/434.html"],
    "clickjacking": ["https://owasp.org/www-community/attacks/Clickjacking", "https://cwe.mitre.org/data/definitions/1021.html"],
    "open-redirect-active": ["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet", "https://cwe.mitre.org/data/definitions/601.html"],
    "password-reset-poisoning": ["https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning", "https://cwe.mitre.org/data/definitions/640.html"],
    "race-condition": ["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Unexpected_File_Types", "https://cwe.mitre.org/data/definitions/362.html"],
    "business-logic": ["https://portswigger.net/web-security/logic-flaws", "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/"],
    "graphql": ["https://portswigger.net/web-security/graphql", "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"],
    "ldap-injection": ["https://owasp.org/www-community/attacks/LDAP_Injection", "https://cwe.mitre.org/data/definitions/90.html"],
    "http-param-pollution": ["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution", "https://cwe.mitre.org/data/definitions/235.html"],
    "web-cache-poisoning": ["https://portswigger.net/web-security/web-cache-poisoning", "https://cwe.mitre.org/data/definitions/913.html"],
    "ssi-injection": ["https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection", "https://cwe.mitre.org/data/definitions/97.html"],
    "http-request-smuggling": ["https://portswigger.net/web-security/request-smuggling", "https://cwe.mitre.org/data/definitions/444.html"],
    "2fa-bypass": ["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/", "https://portswigger.net/web-security/authentication/multi-factor"],
    "oauth": ["https://portswigger.net/web-security/oauth", "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_CSRF"],
    "oauth-missing-state": ["https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions", "https://tools.ietf.org/html/rfc6749#section-10.12"],
    "oauth-open-redirect": ["https://portswigger.net/web-security/oauth#flawed-redirect_uri-validation", "https://cwe.mitre.org/data/definitions/601.html"],
    # API checks (api_checks.py)
    "ssjs-injection": ["https://owasp.org/www-community/attacks/Direct_Dynamic_Code_Evaluation_Eval_Injection", "https://cwe.mitre.org/data/definitions/95.html"],
    "bola": ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/", "https://cwe.mitre.org/data/definitions/639.html"],
    "bfla": ["https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/", "https://cwe.mitre.org/data/definitions/285.html"],
    "debug-endpoint": ["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration", "https://cwe.mitre.org/data/definitions/200.html"],
    "sensitive-api-path": ["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration", "https://cwe.mitre.org/data/definitions/538.html"],
    "cmdi-ext": ["https://owasp.org/www-community/attacks/Command_Injection", "https://cwe.mitre.org/data/definitions/78.html"],
    "csv-injection": ["https://owasp.org/www-community/attacks/CSV_Injection", "https://cwe.mitre.org/data/definitions/1236.html"],
    "csp-bypass": ["https://portswigger.net/web-security/cross-site-scripting/content-security-policy", "https://csp.withgoogle.com/docs/strict-csp.html", "https://cwe.mitre.org/data/definitions/693.html"],
}


def _steps(result: CheckResult) -> str:
    ip = result.insertion_point
    if not ip:
        return ""
    lines = [
        f"1. Target: {ip.url}",
        f"2. Parameter: {ip.name} ({ip.ip_type.value})",
        f"3. Payload: {result.evidence.payload!r}",
    ]
    if result.evidence.poc_curl:
        lines.append(f"4. PoC:\n   {result.evidence.poc_curl}")
    return "\n".join(lines)


def _solution(check_id: str) -> str:
    return _SOLUTIONS.get(check_id, "Refer to OWASP guidelines for remediation.")


def _references(check_id: str) -> list[str]:
    return _REFERENCES.get(check_id, [])
