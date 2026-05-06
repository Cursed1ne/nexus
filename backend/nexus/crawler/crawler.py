"""
Async httpx-based crawler — SPA-aware version.

Improvements over Phase 1:
  - Extracts API endpoints from JavaScript bundles (Angular/React SPAs)
  - Probes discovered API endpoints with GET/POST/OPTIONS
  - Extracts InsertionPoints from JSON responses (JSON body params)
  - Handles Cookie-based auth tokens
  - Detects form-based profiles (POST with application/x-www-form-urlencoded)
"""
import asyncio
import logging
import re
import time
from typing import Optional
from urllib.parse import urljoin, urlparse, urldefrag, urlencode, parse_qs, urlunparse

import httpx
from bs4 import BeautifulSoup

from nexus.models import CrawlResult, InsertionPoint, IPType
from nexus.tools.js_surface_mapper import JsSurfaceMapper

logger = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# Regex patterns to extract API endpoints from JS bundles
_JS_ENDPOINT_PATTERNS = [
    re.compile(r'"(/(?:api|rest|b2b|v\d+|graphql)[^"]{2,100})"'),
    re.compile(r"'(/(?:api|rest|b2b|v\d+|graphql)[^']{2,100})'"),
    re.compile(r"`(/(?:api|rest|b2b|v\d+|graphql)[^`]{2,100})`"),
    # Template literal with params
    re.compile(r'"(/(?:api|rest|b2b)[^"${]{2,80})"'),
]

# Common API/path patterns to probe automatically
_COMMON_PATHS = [
    "/api/", "/rest/", "/graphql", "/v1/", "/v2/",
    "/login", "/register", "/search", "/upload",
    "/admin", "/debug", "/config", "/health",
    "/ftp/", "/profile",
    # PHP-extension paths (testphp.vulnweb.com, DVWA, etc.)
    "/login.php", "/register.php", "/signup.php", "/search.php",
    "/guestbook.php", "/comment.php", "/userinfo.php",
    "/listproducts.php", "/product.php", "/showimage.php",
    "/cart.php", "/secured/newuser.php",
]

# Common query parameters worth injecting into
_COMMON_PARAMS = ["q", "search", "id", "name", "email", "user", "page", "limit",
                  "sort", "filter", "query", "input", "data", "value", "token",
                  "redirect", "url", "next", "return", "callback", "file", "path"]


def _same_origin(base: str, url: str) -> bool:
    b = urlparse(base)
    u = urlparse(url)
    return b.scheme == u.scheme and b.netloc == u.netloc


def _normalise(url: str) -> str:
    url, _ = urldefrag(url)
    return url.rstrip("/")


class Crawler:
    def __init__(
        self,
        target_url: str,
        max_pages: int = 50,
        concurrency: int = 5,
        timeout: float = 10.0,
        extra_headers: Optional[dict] = None,
        auth_token: Optional[str] = None,
        proxy_url: Optional[str] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.timeout = timeout
        self.auth_token = auth_token
        self.proxy_url = proxy_url
        self.headers = {**DEFAULT_HEADERS, **(extra_headers or {})}
        if auth_token:
            # extra_headers may already contain Authorization if set by SessionAuthenticator
            if "Authorization" not in self.headers:
                self.headers["Authorization"] = f"Bearer {auth_token}"
        self._visited: set[str] = set()
        self._queue: asyncio.Queue = asyncio.Queue()
        self._results: list[CrawlResult] = []
        self._insertion_points: list[InsertionPoint] = []
        self._sem = asyncio.Semaphore(concurrency)
        self._js_endpoints: set[str] = set()

    async def crawl(self) -> tuple[list[CrawlResult], list[InsertionPoint]]:
        await self._queue.put((self.target_url, "GET", None, {}))

        client_kwargs: dict = dict(
            headers=self.headers,
            follow_redirects=True,
            timeout=self.timeout,
            verify=False,
        )
        if self.proxy_url:
            client_kwargs["proxy"] = self.proxy_url

        async with httpx.AsyncClient(**client_kwargs) as client:
            # ── Phase 0: JS Surface Mapper (CAI-style deep JS extraction) ────
            js_mapper = JsSurfaceMapper(
                max_assets=40,
                include_sourcemaps=False,
                same_origin_only=True,
                timeout=self.timeout,
                entry_paths=["/"],
            )
            cookies = {}
            if self.auth_token:
                cookies["token"] = self.auth_token
            surface = await js_mapper.run(client, self.target_url, cookies=cookies or None)

            # Feed JS-discovered endpoints into the crawl queue
            for ep in surface.endpoints:
                if "{" in ep or "$" in ep:
                    continue
                url = self.target_url + ep if ep.startswith("/") else ep
                norm = _normalise(url)
                if norm not in self._visited:
                    self._queue.put_nowait((url, "GET", None, {}))
                    # Also probe with common params
                    for param in _COMMON_PARAMS[:3]:
                        url_p = url + f"?{param}=test"
                        self._queue.put_nowait((url_p, "GET", None, {}))

            # Feed WebSocket origins as crawlable pages
            for ws_url in surface.ws_endpoints:
                http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
                if _same_origin(self.target_url, http_url):
                    norm = _normalise(http_url)
                    if norm not in self._visited:
                        self._queue.put_nowait((http_url, "GET", None, {}))

            logger.info(
                "[crawler][js-surface] +%d endpoints, %d ws, %d gql ops from JS",
                len(surface.endpoints), len(surface.ws_endpoints), len(surface.graphql_ops),
            )

            # ── Initial crawl pass ────────────────────────────────────────────
            workers = [
                asyncio.create_task(self._worker(client))
                for _ in range(self.concurrency)
            ]
            await self._queue.join()

            # After crawl, probe JS-extracted API endpoints
            await self._probe_js_endpoints(client)
            await self._queue.join()

            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

        # Deduplicate insertion points
        seen_ip_keys: set[tuple] = set()
        unique_ips = []
        for ip in self._insertion_points:
            key = (ip.url, ip.method, ip.ip_type.value, ip.name)
            if key not in seen_ip_keys:
                seen_ip_keys.add(key)
                unique_ips.append(ip)

        self._insertion_points = unique_ips

        logger.info(
            "Crawl complete: %d pages, %d unique insertion points",
            len(self._results),
            len(self._insertion_points),
        )
        return self._results, self._insertion_points

    async def _worker(self, client: httpx.AsyncClient):
        while True:
            url, method, body, headers = await self._queue.get()
            try:
                await self._fetch(client, url, method, body, headers)
            except Exception as exc:
                logger.debug("Worker error for %s: %s", url, exc)
            finally:
                self._queue.task_done()

    async def _fetch(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        body: Optional[dict],
        extra_headers: dict,
    ):
        norm = _normalise(url)
        if norm in self._visited:
            return
        if len(self._visited) >= self.max_pages:
            return
        if not _same_origin(self.target_url, url):
            return

        self._visited.add(norm)

        async with self._sem:
            t0 = time.monotonic()
            try:
                if method == "POST" and body:
                    resp = await client.post(url, data=body, headers=extra_headers)
                else:
                    resp = await client.get(url, headers=extra_headers)

                elapsed = (time.monotonic() - t0) * 1000
                content_type = resp.headers.get("content-type", "")
                body_text = resp.text

                result = CrawlResult(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=body_text,
                    content_type=content_type,
                    redirect_chain=[str(r.url) for r in resp.history],
                    response_time_ms=elapsed,
                )
                self._results.append(result)

                ips = extract_insertion_points(result)
                self._insertion_points.extend(ips)

                if "text/html" in content_type:
                    self._enqueue_links(str(resp.url), body_text)

                # Extract JS endpoints from script responses
                if "javascript" in content_type or url.endswith(".js"):
                    new_eps = _extract_js_endpoints(body_text, self.target_url)
                    self._js_endpoints.update(new_eps)

                # Also extract script tags from HTML and queue JS files
                if "text/html" in content_type:
                    self._enqueue_js_files(str(resp.url), body_text)

            except httpx.RequestError as exc:
                elapsed = (time.monotonic() - t0) * 1000
                self._results.append(
                    CrawlResult(
                        url=url,
                        status_code=0,
                        headers={},
                        body="",
                        response_time_ms=elapsed,
                        error=str(exc),
                    )
                )

    def _enqueue_links(self, base_url: str, html: str):
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all(["a", "form"]):
                if tag.name == "a":
                    href = tag.get("href", "")
                    if href and not href.startswith(("#", "javascript:", "mailto:")):
                        full = urljoin(base_url, href)
                        norm = _normalise(full)
                        if norm not in self._visited and _same_origin(self.target_url, full):
                            self._queue.put_nowait((full, "GET", None, {}))
                elif tag.name == "form":
                    action = tag.get("action", base_url)
                    method = (tag.get("method", "GET") or "GET").upper()
                    full = urljoin(base_url, action)
                    if not _same_origin(self.target_url, full):
                        continue
                    fields = {}
                    for inp in tag.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if name:
                            fields[name] = inp.get("value", "test")
                    norm = _normalise(full)
                    if norm not in self._visited:
                        self._queue.put_nowait((full, method, fields or None, {}))
        except Exception as exc:
            logger.debug("Link extraction error: %s", exc)

    def _enqueue_js_files(self, base_url: str, html: str):
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("script", src=True):
                src = tag.get("src", "")
                if src:
                    full = urljoin(base_url, src)
                    if _same_origin(self.target_url, full):
                        norm = _normalise(full)
                        if norm not in self._visited:
                            self._queue.put_nowait((full, "GET", None, {}))
        except Exception:
            pass

    async def _probe_js_endpoints(self, client: httpx.AsyncClient):
        """Probe all endpoints discovered in JS bundles."""
        for ep in self._js_endpoints:
            # Skip if has template variable
            if "{" in ep or "}" in ep or "$" in ep:
                continue
            url = self.target_url + ep if ep.startswith("/") else ep
            # Add with query params if endpoint has no params
            parsed = urlparse(url)
            if not parsed.query:
                # Try GET baseline
                norm = _normalise(url)
                if norm not in self._visited:
                    self._queue.put_nowait((url, "GET", None, {}))

                # For REST endpoints that typically take params, inject common ones
                for param in _COMMON_PARAMS[:4]:
                    url_with_param = url + f"?{param}=test"
                    norm2 = _normalise(url_with_param)
                    if norm2 not in self._visited:
                        self._queue.put_nowait((url_with_param, "GET", None, {}))
            else:
                norm = _normalise(url)
                if norm not in self._visited:
                    self._queue.put_nowait((url, "GET", None, {}))

        # Also probe common paths
        for path in _COMMON_PATHS:
            url = self.target_url + path
            norm = _normalise(url)
            if norm not in self._visited:
                self._queue.put_nowait((url, "GET", None, {}))


def _extract_js_endpoints(js_content: str, base_url: str) -> set[str]:
    """Extract API endpoint paths from a JavaScript bundle."""
    endpoints: set[str] = set()
    for pattern in _JS_ENDPOINT_PATTERNS:
        for match in pattern.findall(js_content):
            path = match.strip()
            # Clean up template literals
            if "${" in path:
                path = re.sub(r'\$\{[^}]+\}', 'PARAM', path)
            if len(path) > 3 and not any(
                ext in path for ext in [".png", ".jpg", ".gif", ".css", ".woff", ".ico"]
            ):
                endpoints.add(path)
    return endpoints


def extract_insertion_points(result: CrawlResult) -> list[InsertionPoint]:
    """Parse a CrawlResult and return all actionable InsertionPoints."""
    points: list[InsertionPoint] = []
    parsed = urlparse(result.url)
    method = "GET"

    # 1. Query parameters
    if parsed.query:
        for part in parsed.query.split("&"):
            if "=" in part:
                name, _, value = part.partition("=")
                if name:
                    points.append(InsertionPoint(
                        url=result.url, method=method,
                        ip_type=IPType.QUERY_PARAM, name=name, value=value,
                    ))

    # 2. Cookies
    for cookie_hdr_name in ("set-cookie", "Set-Cookie"):
        cookie_header = result.headers.get(cookie_hdr_name, "")
        if cookie_header:
            for cookie_part in cookie_header.split(";"):
                cookie_part = cookie_part.strip()
                if "=" in cookie_part and not any(
                    cookie_part.lower().startswith(k)
                    for k in ("path", "domain", "expires", "max-age", "samesite", "secure", "httponly")
                ):
                    name, _, value = cookie_part.partition("=")
                    points.append(InsertionPoint(
                        url=result.url, method=method,
                        ip_type=IPType.COOKIE, name=name.strip(), value=value.strip(),
                    ))

    # 3. JSON body params from JSON API responses
    if "json" in result.content_type and result.body:
        _extract_json_insertion_points(result, points)

    # 4. HTML form inputs
    if "text/html" in result.content_type and result.body:
        _extract_form_insertion_points(result, points)

    # 5. Path segment (numeric ID)
    path_parts = [p for p in parsed.path.split("/") if p]
    if path_parts:
        last = path_parts[-1]
        if re.search(r"^\d+$", last):
            points.append(InsertionPoint(
                url=result.url, method=method,
                ip_type=IPType.PATH_SEGMENT, name="path_id", value=last,
                context={"path": parsed.path},
            ))

    # 6. Add common query params to API endpoints if none found
    if not points and any(p in result.url for p in ["/api/", "/rest/", "/search"]):
        for param in _COMMON_PARAMS[:5]:
            points.append(InsertionPoint(
                url=result.url if "?" not in result.url else result.url.split("?")[0],
                method="GET", ip_type=IPType.QUERY_PARAM, name=param, value="test",
            ))

    return points


def _extract_json_insertion_points(result: CrawlResult, points: list[InsertionPoint]):
    """Extract POST body InsertionPoints from JSON API responses."""
    import json as _json
    try:
        data = _json.loads(result.body)
        # Look for typical REST CRUD patterns
        base_url = result.url.split("?")[0]

        def _flatten(obj, prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key = f"{prefix}.{k}" if prefix else k
                    if isinstance(v, (str, int, float, bool)):
                        points.append(InsertionPoint(
                            url=base_url, method="POST",
                            ip_type=IPType.JSON_KEY, name=k, value=str(v),
                            context={"full_key": key, "original_type": type(v).__name__},
                        ))
                    elif isinstance(v, dict):
                        _flatten(v, key)
            elif isinstance(obj, list) and obj:
                _flatten(obj[0], prefix)

        _flatten(data)
    except Exception:
        pass


def _extract_form_insertion_points(result: CrawlResult, points: list[InsertionPoint]):
    try:
        soup = BeautifulSoup(result.body, "html.parser")
        for form in soup.find_all("form"):
            form_action = form.get("action", result.url)
            form_method = (form.get("method", "GET") or "GET").upper()
            form_url = urljoin(result.url, form_action)
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                itype = inp.get("type", "text").lower()
                if itype in ("hidden", "submit", "button", "image", "reset", "file"):
                    continue
                value = inp.get("value", "")
                ip_type = IPType.QUERY_PARAM if form_method == "GET" else IPType.BODY_PARAM
                points.append(InsertionPoint(
                    url=form_url, method=form_method,
                    ip_type=ip_type, name=name, value=value,
                    context={"form_action": form_action, "input_type": itype},
                ))
    except Exception:
        pass
