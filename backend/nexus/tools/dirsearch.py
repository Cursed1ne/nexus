"""
dirsearch.py — Async directory/path brute-force discovery engine.

Strategy mirrors DirBuster/dirsearch:
  1. Load wordlist (built-in + optional custom)
  2. Probe in async batches with concurrency limit
  3. Detect interesting responses: 200, 201, 204, 301, 302, 403, 500
  4. Reject redirect-to-homepage false positives (same body prefix)
  5. Return discovered paths as CrawlResult + InsertionPoint items

The module is self-contained — integrates with CheckRunner as a
pre-scan phase that feeds new InsertionPoints into the audit engine.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from nexus.models import CrawlResult, InsertionPoint, IPType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------
_CONCURRENCY = 20          # parallel probes
_REQUEST_TIMEOUT = 8.0     # per-request timeout

# ---------------------------------------------------------------------------
# Status codes considered "interesting" (endpoint exists or protected)
# ---------------------------------------------------------------------------
_INTERESTING_CODES = {200, 201, 204, 206, 301, 302, 307, 308, 400, 401, 403, 405, 500}
# Codes that mean "definitely not there"
_NOT_FOUND_CODES = {404, 410, 501, 502, 503, 504}

# ---------------------------------------------------------------------------
# Built-in wordlist — covers common web app paths
# Structured as: (path, hint) where hint drives InsertionPoint param guesses
# ---------------------------------------------------------------------------
_WORDLIST: list[tuple[str, str]] = [
    # Admin / management
    ("/admin",                  "admin"),
    ("/admin/",                 "admin"),
    ("/admin/login",            "auth"),
    ("/admin/dashboard",        "admin"),
    ("/administrator",          "admin"),
    ("/manage",                 "admin"),
    ("/management",             "admin"),
    ("/panel",                  "admin"),
    ("/control",                "admin"),
    ("/backend",                "admin"),
    ("/cpanel",                 "admin"),
    ("/wp-admin",               "admin"),
    ("/wp-admin/",              "admin"),
    ("/wp-login.php",           "auth"),
    ("/phpmyadmin",             "admin"),
    ("/phpmyadmin/",            "admin"),
    ("/adminer",                "admin"),
    ("/adminer.php",            "admin"),
    ("/manager",                "admin"),
    ("/console",                "admin"),

    # Auth
    ("/login",                  "auth"),
    ("/logout",                 "auth"),
    ("/register",               "auth"),
    ("/signup",                 "auth"),
    ("/signin",                 "auth"),
    ("/auth",                   "auth"),
    ("/auth/login",             "auth"),
    ("/auth/logout",            "auth"),
    ("/auth/register",          "auth"),
    ("/oauth",                  "auth"),
    ("/oauth/authorize",        "auth"),
    ("/oauth/token",            "auth"),
    ("/sso",                    "auth"),
    ("/saml",                   "auth"),
    ("/token",                  "auth"),
    ("/forgot-password",        "auth"),
    ("/reset-password",         "auth"),
    ("/change-password",        "auth"),
    ("/verify",                 "auth"),

    # API
    ("/api",                    "api"),
    ("/api/",                   "api"),
    ("/api/v1",                 "api"),
    ("/api/v1/",                "api"),
    ("/api/v2",                 "api"),
    ("/api/v2/",                "api"),
    ("/api/v3",                 "api"),
    ("/api/users",              "api"),
    ("/api/user",               "api"),
    ("/api/admin",              "api"),
    ("/api/login",              "auth"),
    ("/api/register",           "auth"),
    ("/api/token",              "auth"),
    ("/api/health",             "api"),
    ("/api/status",             "api"),
    ("/api/docs",               "api"),
    ("/api/swagger",            "api"),
    ("/api/openapi",            "api"),
    ("/api/debug",              "admin"),
    ("/api/config",             "admin"),
    ("/rest",                   "api"),
    ("/rest/",                  "api"),
    ("/graphql",                "api"),
    ("/graphiql",               "api"),
    ("/playground",             "api"),
    ("/v1",                     "api"),
    ("/v2",                     "api"),
    ("/v3",                     "api"),

    # User / profile
    ("/profile",                "profile"),
    ("/user",                   "profile"),
    ("/users",                  "profile"),
    ("/account",                "profile"),
    ("/settings",               "profile"),
    ("/me",                     "profile"),
    ("/dashboard",              "profile"),
    ("/home",                   "profile"),

    # Search / data
    ("/search",                 "search"),
    ("/find",                   "search"),
    ("/query",                  "search"),
    ("/lookup",                 "search"),
    ("/filter",                 "search"),

    # Upload / media
    ("/upload",                 "upload"),
    ("/uploads",                "upload"),
    ("/file",                   "upload"),
    ("/files",                  "upload"),
    ("/media",                  "upload"),
    ("/images",                 "upload"),
    ("/static",                 "upload"),
    ("/assets",                 "upload"),
    ("/download",               "upload"),
    ("/downloads",              "upload"),

    # Config / debug
    ("/config",                 "admin"),
    ("/configuration",          "admin"),
    ("/debug",                  "admin"),
    ("/trace",                  "admin"),
    ("/info",                   "admin"),
    ("/status",                 "admin"),
    ("/health",                 "admin"),
    ("/healthz",                "admin"),
    ("/ping",                   "admin"),
    ("/metrics",                "admin"),
    ("/actuator",               "admin"),
    ("/actuator/health",        "admin"),
    ("/actuator/env",           "admin"),
    ("/actuator/mappings",      "admin"),
    ("/env",                    "admin"),
    ("/environment",            "admin"),

    # Source / sensitive files
    ("/.git/HEAD",              "sensitive"),
    ("/.git/config",            "sensitive"),
    ("/.env",                   "sensitive"),
    ("/.env.local",             "sensitive"),
    ("/.env.production",        "sensitive"),
    ("/package.json",           "sensitive"),
    ("/composer.json",          "sensitive"),
    ("/requirements.txt",       "sensitive"),
    ("/web.config",             "sensitive"),
    ("/config.php",             "sensitive"),
    ("/config.js",              "sensitive"),
    ("/wp-config.php",          "sensitive"),
    ("/robots.txt",             "sensitive"),
    ("/sitemap.xml",            "sensitive"),
    ("/.htaccess",              "sensitive"),
    ("/.htpasswd",              "sensitive"),
    ("/crossdomain.xml",        "sensitive"),
    ("/security.txt",           "sensitive"),
    ("/.well-known/security.txt", "sensitive"),
    ("/server-status",          "sensitive"),
    ("/server-info",            "sensitive"),
    ("/phpinfo.php",            "sensitive"),
    ("/info.php",               "sensitive"),
    ("/test.php",               "sensitive"),
    ("/backup",                 "sensitive"),
    ("/backup.sql",             "sensitive"),
    ("/database.sql",           "sensitive"),
    ("/dump.sql",               "sensitive"),
    ("/data.sql",               "sensitive"),
    ("/db.sql",                 "sensitive"),
    ("/backup.zip",             "sensitive"),
    ("/backup.tar.gz",          "sensitive"),
    ("/old",                    "sensitive"),
    ("/old/",                   "sensitive"),
    ("/bak",                    "sensitive"),
    ("/tmp",                    "sensitive"),
    ("/temp",                   "sensitive"),
    ("/test",                   "sensitive"),

    # Docs / swagger
    ("/docs",                   "api"),
    ("/swagger",                "api"),
    ("/swagger-ui",             "api"),
    ("/swagger-ui.html",        "api"),
    ("/swagger/index.html",     "api"),
    ("/openapi.json",           "api"),
    ("/openapi.yaml",           "api"),
    ("/api-docs",               "api"),
    ("/api-docs/",              "api"),
    ("/redoc",                  "api"),
    ("/postman",                "api"),

    # Payment / checkout
    ("/checkout",               "profile"),
    ("/cart",                   "profile"),
    ("/order",                  "profile"),
    ("/orders",                 "profile"),
    ("/payment",                "profile"),
    ("/invoice",                "profile"),

    # Newsletter / unsubscribe
    ("/unsubscribe",            "profile"),
    ("/newsletter",             "profile"),
    ("/subscribe",              "profile"),

    # OWASP Juice Shop specific paths
    ("/ftp/",                   "sensitive"),
    ("/ftp/acquisitions.md",    "sensitive"),
    ("/b2b/v2",                 "api"),
    ("/rest/admin/application-configuration", "admin"),
    ("/rest/user/who-am-i",     "api"),
    ("/rest/products/search",   "search"),
    ("/rest/basket",            "api"),
    ("/rest/memories",          "api"),

    # Spring Boot / Java
    ("/actuator/beans",         "admin"),
    ("/actuator/metrics",       "admin"),
    ("/actuator/loggers",       "admin"),
    ("/actuator/threaddump",    "admin"),
    ("/actuator/heapdump",      "admin"),
    ("/actuator/httptrace",     "admin"),
    ("/actuator/auditevents",   "admin"),

    # Django
    ("/admin/",                 "admin"),
    ("/__debug__/",             "admin"),
    ("/django-admin/",          "admin"),

    # Rails
    ("/rails/info/properties",  "admin"),
    ("/rails/info/routes",      "admin"),

    # Node / Express
    ("/_debug",                 "admin"),
    ("/node_modules/",          "sensitive"),
]

# Params to inject per hint type — used to create InsertionPoints
_HINT_PARAMS: dict[str, list[str]] = {
    "auth":      ["email", "username", "password", "token", "code"],
    "api":       ["id", "q", "search", "filter", "page", "limit"],
    "profile":   ["id", "user", "userId", "email", "name"],
    "search":    ["q", "query", "search", "term", "keyword", "s"],
    "upload":    ["file", "filename", "path", "url"],
    "admin":     ["id", "action", "key", "value", "debug"],
    "sensitive": [],
}


@dataclass
class DirResult:
    path: str
    status: int
    content_type: str
    body_length: int
    redirect_url: str = ""
    interesting: bool = True
    hint: str = ""
    body: str = ""   # first 300 chars of response body (for broken-page detection)


@dataclass
class DirsearchResult:
    found: list[DirResult] = field(default_factory=list)
    crawl_results: list[CrawlResult] = field(default_factory=list)
    insertion_points: list[InsertionPoint] = field(default_factory=list)
    duration_s: float = 0.0
    total_probed: int = 0


class DirSearchEngine:
    """
    Async directory brute-force engine.

    Usage::

        engine = DirSearchEngine(base_url="https://example.com")
        result = await engine.run(client=httpx_async_client)
        # result.insertion_points ready for CheckRunner
    """

    def __init__(
        self,
        base_url: str,
        extra_wordlist: Optional[list[str]] = None,
        concurrency: int = _CONCURRENCY,
        auth_headers: Optional[dict] = None,
        extensions: Optional[list[str]] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.concurrency = concurrency
        self.auth_headers = auth_headers or {}
        self.extensions = extensions or []     # e.g. [".php", ".asp", ".bak"]
        self._custom_words = extra_wordlist or []

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    async def run(self, client: Optional[httpx.AsyncClient] = None) -> DirsearchResult:
        own_client = client is None
        if own_client:
            client = httpx.AsyncClient(
                follow_redirects=False,
                timeout=_REQUEST_TIMEOUT,
                verify=False,
                headers={
                    "User-Agent": "Mozilla/5.0 NEXUS-DirSearch/3.0",
                    **self.auth_headers,
                },
            )

        t0 = time.monotonic()
        result = DirsearchResult()

        try:
            homepage_body = await self._fetch_homepage(client)
            # Detect SPA catch-all: probe a canary non-existent path.
            # If it returns 200 with the same body, the site returns 200 for all routes.
            canary_body = await self._fetch_canary_404(client, homepage_body)
            wordlist = self._build_wordlist()
            result.total_probed = len(wordlist)

            sem = asyncio.Semaphore(self.concurrency)
            tasks = [
                self._probe(client, path, hint, homepage_body, sem, canary_body)
                for path, hint in wordlist
            ]
            raw = await asyncio.gather(*tasks, return_exceptions=True)

            for item in raw:
                if isinstance(item, DirResult):
                    result.found.append(item)
                    cr, ips = self._to_crawl_and_ips(item)
                    if cr:
                        result.crawl_results.append(cr)
                    result.insertion_points.extend(ips)

        finally:
            result.duration_s = time.monotonic() - t0
            if own_client:
                await client.aclose()

        logger.info(
            "[dirsearch] %s — probed %d paths, found %d in %.1fs",
            self.base_url, result.total_probed, len(result.found), result.duration_s,
        )
        return result

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    async def _fetch_homepage(self, client: httpx.AsyncClient) -> str:
        try:
            r = await client.get(self.base_url + "/")
            return r.text[:2000]
        except Exception:
            return ""

    async def _fetch_canary_404(self, client: httpx.AsyncClient, homepage_body: str) -> str:
        """Probe a random non-existent path to detect SPA catch-all 200s.

        If the canary path returns HTTP 200 with a body matching the homepage,
        the site is an SPA that catches all routes — store the fingerprint so
        _probe() can skip these false-positive 200s.
        """
        import uuid
        canary = f"/nexus-canary-{uuid.uuid4().hex[:12]}"
        try:
            r = await client.get(self.base_url + canary)
            if r.status_code == 200:
                body = r.text
                # If canary body matches homepage within 80% — it's a catch-all SPA
                if homepage_body and body[:300] == homepage_body[:300]:
                    logger.info(
                        "[dirsearch] SPA catch-all detected at %s — "
                        "200-for-all-routes mode active, will suppress matching results",
                        self.base_url,
                    )
                    return body[:500]
        except Exception:
            pass
        return ""

    def _build_wordlist(self) -> list[tuple[str, str]]:
        """Merge built-in + custom words + extension variants."""
        words: list[tuple[str, str]] = list(_WORDLIST)

        for w in self._custom_words:
            if not w.startswith("/"):
                w = "/" + w
            words.append((w.strip(), "api"))

        # Extension mutations on custom words
        for ext in self.extensions:
            for path, hint in list(_WORDLIST):
                if "." not in path.split("/")[-1]:
                    words.append((path + ext, hint))

        # Deduplicate
        seen: set[str] = set()
        deduped: list[tuple[str, str]] = []
        for path, hint in words:
            if path not in seen:
                seen.add(path)
                deduped.append((path, hint))

        return deduped

    async def _probe(
        self,
        client: httpx.AsyncClient,
        path: str,
        hint: str,
        homepage_body: str,
        sem: asyncio.Semaphore,
        canary_body: str = "",
    ) -> DirResult | Exception:
        async with sem:
            url = self.base_url + path
            try:
                r = await client.get(url, headers=self.auth_headers)
                status = r.status_code

                if status in _NOT_FOUND_CODES:
                    return Exception(f"404 {path}")

                # Redirect-to-homepage false positive check
                body = r.text
                if homepage_body and len(homepage_body) > 100:
                    if body[:500] == homepage_body[:500] and status in (301, 302):
                        return Exception(f"homepage-redirect {path}")

                # SPA catch-all false positive: 200 with same body as canary non-existent path
                if canary_body and status == 200:
                    if body[:300] == canary_body[:300]:
                        return Exception(f"spa-catchall {path}")

                # Final URL same as base URL (after redirects if follow_redirects enabled)?
                # Here we don't follow, so check location header
                location = r.headers.get("location", "")
                if location:
                    norm_loc = location.rstrip("/").split("?")[0]
                    norm_base = self.base_url.rstrip("/")
                    if norm_loc == norm_base or norm_loc in ("/", "/#/", "/?"):
                        return Exception(f"redirect-to-root {path}")

                ct = r.headers.get("content-type", "")
                return DirResult(
                    path=path,
                    status=status,
                    content_type=ct,
                    body_length=len(body),
                    redirect_url=location,
                    interesting=True,
                    hint=hint,
                    body=body[:300],
                )
            except (httpx.ConnectError, httpx.TimeoutException, asyncio.TimeoutError):
                return Exception(f"timeout/connect {path}")
            except Exception as e:
                return e

    def _to_crawl_and_ips(
        self, dr: DirResult
    ) -> tuple[Optional[CrawlResult], list[InsertionPoint]]:
        url = self.base_url + dr.path
        ips: list[InsertionPoint] = []

        # Build CrawlResult
        # Note: headers={} here — passive checks that need headers (clickjacking, missing-headers)
        # should NOT fire on dirsearch-discovered paths because we don't fetch full headers.
        # Passive checks only run on crawler CrawlResults (which have real headers) and
        # on _probe_sensitive_paths() results (which fetch full responses).
        cr = CrawlResult(
            url=url,
            status_code=dr.status,
            content_type=dr.content_type,
            body=dr.body or "",
            headers={"_dirsearch_stub": "1"},  # sentinel: passive header checks skip stubs
        )

        # Don't create IPs for sensitive/static paths or non-injectable statuses.
        # 403 = forbidden/directory — can't inject params; 5xx = broken.
        if dr.hint == "sensitive":
            return cr, []
        if dr.status in (301, 302, 307, 308, 403, 500):
            return cr, []
        # Skip PHP fatal error pages — endpoint is broken, no real injection surface
        body_start = (dr.body or "")[:300]
        if any(sig in body_start for sig in (
            "Fatal error", "Access denied for user",
            "mysqli_sql_exception", "Warning: mysqli",
        )):
            return cr, []

        params = _HINT_PARAMS.get(dr.hint, ["id", "q"])
        for param in params:
            method = "POST" if dr.hint == "auth" else "GET"
            ip_type = IPType.JSON_KEY if dr.hint == "auth" else IPType.QUERY_PARAM
            ips.append(InsertionPoint(
                url=url,
                method=method,
                ip_type=ip_type,
                name=param,
                value="test",
                context={
                    "source": "dirsearch",
                    "hint": dr.hint,
                    "status": dr.status,
                },
            ))

        return cr, ips

    # -----------------------------------------------------------------------
    # Recursive discovery — follow discovered dirs one level deep
    # -----------------------------------------------------------------------
    async def recurse(
        self,
        client: httpx.AsyncClient,
        found_dirs: list[str],
        depth: int = 1,
    ) -> list[DirResult]:
        """
        Given a list of discovered directory paths, probe common sub-paths
        inside each up to `depth` levels.
        """
        if depth <= 0:
            return []

        sub_words = [
            "login", "admin", "api", "config", "debug",
            "users", "user", "profile", "settings", "token",
            "upload", "uploads", "files", "export", "import",
        ]

        all_results: list[DirResult] = []
        homepage_body = await self._fetch_homepage(client)
        canary_body = await self._fetch_canary_404(client, homepage_body)
        sem = asyncio.Semaphore(self.concurrency)

        for base_path in found_dirs:
            base_path = base_path.rstrip("/")
            tasks = [
                self._probe(client, f"{base_path}/{sub}", "api", homepage_body, sem, canary_body)
                for sub in sub_words
            ]
            raw = await asyncio.gather(*tasks, return_exceptions=True)
            for item in raw:
                if isinstance(item, DirResult):
                    all_results.append(item)

        return all_results


async def run_dirsearch(
    base_url: str,
    auth_headers: Optional[dict] = None,
    extra_wordlist: Optional[list[str]] = None,
    extensions: Optional[list[str]] = None,
    recurse_depth: int = 1,
    client: Optional[httpx.AsyncClient] = None,
) -> DirsearchResult:
    """
    Convenience wrapper. Returns DirsearchResult with insertion_points
    ready for CheckRunner.

    Example::

        result = await run_dirsearch(
            "https://juice-shop.example.com",
            auth_headers={"Authorization": "Bearer TOKEN"},
            recurse_depth=1,
        )
        runner.add_insertion_points(result.insertion_points)
    """
    engine = DirSearchEngine(
        base_url=base_url,
        extra_wordlist=extra_wordlist,
        concurrency=20,
        auth_headers=auth_headers,
        extensions=extensions,
    )
    own = client is None
    if own:
        client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=_REQUEST_TIMEOUT,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 NEXUS-DirSearch/3.0"},
        )
    try:
        result = await engine.run(client)

        if recurse_depth > 0:
            dirs = [dr.path for dr in result.found if dr.status in (200, 403)]
            extra = await engine.recurse(client, dirs, recurse_depth)
            for dr in extra:
                result.found.append(dr)
                cr, ips = engine._to_crawl_and_ips(dr)
                if cr:
                    result.crawl_results.append(cr)
                result.insertion_points.extend(ips)

        return result
    finally:
        if own:
            await client.aclose()
