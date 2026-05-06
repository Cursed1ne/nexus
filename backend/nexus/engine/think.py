"""
Think Engine — fingerprint the target, build a prioritised attack plan.

Flow:
  1. Fingerprinter.analyse(crawl_results) → TechProfile
  2. AttackPlanner.plan(tech_profile, checks, insertion_points) → AttackPlan
  3. CheckRunner executes AttackPlan in priority order
  4. AttackPlanner.adapt(plan, new_finding) → re-scores remaining checks

No LLM required — pure rule-based signal scoring.
Phase 3 will swap the rule engine for an LLM planner that reads the same
TechProfile and produces the same AttackPlan interface.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nexus.models import CrawlResult, InsertionPoint, CheckResult
    from nexus.checks.base import BaseScanCheck


# ---------------------------------------------------------------------------
# Tech Profile
# ---------------------------------------------------------------------------

@dataclass
class TechProfile:
    """
    What we know about the target after passive fingerprinting.
    Each field is a confidence string or None if unknown.
    """
    # Runtime / language
    runtime: str = "unknown"         # node | php | java | python | ruby | dotnet | unknown
    # Web framework
    framework: str = "unknown"       # express | laravel | spring | flask | rails | django | asp.net | unknown
    # Database hint
    database: str = "unknown"        # sqlite | mysql | postgresql | mongodb | mssql | unknown
    # Auth mechanism observed
    auth_type: str = "unknown"       # jwt | session-cookie | basic | none | unknown
    # API style
    api_style: str = "rest"          # rest | graphql | soap | html
    # CMS detected
    cms: str = "none"                # wordpress | drupal | joomla | none
    # Server software
    server: str = "unknown"          # nginx | apache | iis | express | unknown

    # ── Extended profile fields added for deeper scoring ─────────────────────
    # WAF / protection layer
    waf: str = "none"                # cloudflare | akamai | awswaf | sucuri | imperva | none | unknown
    # CDN
    cdn: str = "none"                # cloudflare | fastly | cloudfront | akamai | none | unknown
    # Frontend JS framework
    js_framework: str = "unknown"    # react | angular | vue | jquery | unknown
    # Feature flags derived from page structure
    has_login_form: bool = False      # Login form detected in crawled pages
    has_file_upload: bool = False     # File upload input detected
    has_search_form: bool = False     # Search form / q param detected
    has_csv_export: bool = False      # CSV download links detected
    has_graphql: bool = False         # GraphQL endpoint confirmed
    has_swagger: bool = False         # Swagger/OpenAPI docs found
    has_jwt_in_response: bool = False # JWT token observed in API response
    has_debug_info: bool = False      # Stack traces / debug headers observed
    has_cors_wildcard: bool = False   # CORS * observed
    is_spa: bool = False              # Single page app (Angular/React routing)
    uses_json_api: bool = False       # JSON content-type in responses
    # Insertion point stats (populated by AttackPlanner.plan)
    ip_count: int = 0
    ip_types: list[str] = field(default_factory=list)  # "query_param", "json_key", etc.

    # Specific signals used in scoring
    signals: list[str] = field(default_factory=list)
    # Raw notes for display
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        parts = [
            f"Runtime: {self.runtime}",
            f"Framework: {self.framework}",
            f"DB: {self.database}",
            f"Auth: {self.auth_type}",
            f"API: {self.api_style}",
        ]
        if self.cms != "none":
            parts.append(f"CMS: {self.cms}")
        if self.waf != "none":
            parts.append(f"WAF: {self.waf}")
        if self.cdn != "none":
            parts.append(f"CDN: {self.cdn}")
        if self.js_framework != "unknown":
            parts.append(f"JS: {self.js_framework}")
        features = []
        if self.has_login_form:   features.append("login")
        if self.has_file_upload:  features.append("upload")
        if self.has_search_form:  features.append("search")
        if self.has_csv_export:   features.append("csv-export")
        if self.has_graphql:      features.append("graphql")
        if self.has_swagger:      features.append("swagger")
        if self.has_debug_info:   features.append("debug-info!")
        if self.has_cors_wildcard:features.append("cors-wildcard")
        if features:
            parts.append(f"Features: [{', '.join(features)}]")
        return " | ".join(parts)


# ---------------------------------------------------------------------------
# Fingerprinter
# ---------------------------------------------------------------------------

class Fingerprinter:
    """
    Analyses crawl results and HTTP headers to build a TechProfile.
    Runs entirely on data already collected — no extra requests.
    """

    # Header → (signal_name, runtime, framework, db)
    _SERVER_SIGS: list[tuple[re.Pattern, str, str, str]] = [
        (re.compile(r"express",        re.I), "header:x-powered-by:express",  "node",   "express",  "unknown"),
        (re.compile(r"php",            re.I), "header:x-powered-by:php",      "php",    "unknown",  "unknown"),
        (re.compile(r"ASP\.NET",       re.I), "header:x-powered-by:asp.net",  "dotnet", "asp.net",  "unknown"),
        (re.compile(r"servlet",        re.I), "header:x-powered-by:servlet",  "java",   "unknown",  "unknown"),
        (re.compile(r"werkzeug",       re.I), "header:server:werkzeug",       "python", "flask",    "unknown"),
        (re.compile(r"gunicorn",       re.I), "header:server:gunicorn",       "python", "unknown",  "unknown"),
        (re.compile(r"uvicorn",        re.I), "header:server:uvicorn",        "python", "unknown",  "unknown"),
        (re.compile(r"nginx",          re.I), "header:server:nginx",          "unknown","unknown",  "unknown"),
        (re.compile(r"apache",         re.I), "header:server:apache",         "unknown","unknown",  "unknown"),
        (re.compile(r"IIS",            re.I), "header:server:iis",            "dotnet", "asp.net",  "unknown"),
    ]

    _COOKIE_SIGS: list[tuple[re.Pattern, str, str, str, str]] = [
        (re.compile(r"PHPSESSID",      re.I), "cookie:PHPSESSID",    "php",    "unknown",   "session-cookie"),
        (re.compile(r"JSESSIONID",     re.I), "cookie:JSESSIONID",   "java",   "unknown",   "session-cookie"),
        (re.compile(r"ASP\.NET_Session",re.I),"cookie:asp.net",      "dotnet", "asp.net",   "session-cookie"),
        (re.compile(r"rack\.session",  re.I), "cookie:rack",         "ruby",   "rails",     "session-cookie"),
        (re.compile(r"connect\.sid",   re.I), "cookie:connect.sid",  "node",   "express",   "session-cookie"),
        (re.compile(r"laravel_session",re.I), "cookie:laravel",      "php",    "laravel",   "session-cookie"),
        (re.compile(r"wordpress_",     re.I), "cookie:wordpress",    "php",    "wordpress", "session-cookie"),
        (re.compile(r"wp-settings",    re.I), "cookie:wp-settings",  "php",    "wordpress", "session-cookie"),
        (re.compile(r"token=ey",       re.I), "cookie:jwt-token",    "unknown","unknown",   "jwt"),
        (re.compile(r"__cf_bm|cf_clearance", re.I), "cookie:cloudflare", "unknown","unknown","unknown"),
        (re.compile(r"_abck|ak_bmsc", re.I),         "cookie:akamai",     "unknown","unknown","unknown"),
    ]

    _URL_SIGS: list[tuple[re.Pattern, str]] = [
        (re.compile(r"/wp-(?:admin|content|json|login)",re.I), "url:wordpress"),
        (re.compile(r"/drupal|/sites/default",          re.I), "url:drupal"),
        (re.compile(r"/joomla|/administrator",          re.I), "url:joomla"),
        (re.compile(r"\.php\b",                         re.I), "url:php-extension"),
        (re.compile(r"\.aspx\b|\.asmx\b",               re.I), "url:aspx-extension"),
        (re.compile(r"\.jsp\b|\.do\b",                  re.I), "url:jsp-extension"),
        (re.compile(r"/graphql\b",                      re.I), "url:graphql"),
        (re.compile(r"/soap|/wsdl",                     re.I), "url:soap"),
        (re.compile(r"/rest/|/api/v[0-9]",              re.I), "url:rest-api"),
        (re.compile(r"/struts|\.action\b",               re.I), "url:struts"),
        (re.compile(r"/actuator\b",                     re.I), "url:spring-actuator"),
        (re.compile(r"/swagger|/api-docs|/openapi",     re.I), "url:swagger"),
        (re.compile(r"/export|/download|/report",       re.I), "url:csv-export-candidate"),
        (re.compile(r"format=csv|export=1|\\.csv",      re.I), "url:csv-download"),
        (re.compile(r"/upload|/import",                 re.I), "url:file-upload"),
        (re.compile(r"/login|/signin|/auth",            re.I), "url:login-endpoint"),
        (re.compile(r"/search|/find|/query",            re.I), "url:search-endpoint"),
        (re.compile(r"/admin|/manage|/dashboard",       re.I), "url:admin-area"),
        (re.compile(r"/ftp/|\.bak|\.sql|\.env",         re.I), "url:sensitive-file"),
    ]

    _BODY_SIGS: list[tuple[re.Pattern, str, str | None]] = [
        # Error message patterns → DB type
        (re.compile(r"sqlite3|SQLite",          re.I), "body:sqlite-error",      "sqlite"),
        (re.compile(r"MySQL.*error|mysqlnd",    re.I), "body:mysql-error",       "mysql"),
        (re.compile(r"PostgreSQL.*ERROR",       re.I), "body:postgres-error",    "postgresql"),
        (re.compile(r"MongoDB.*Exception",      re.I), "body:mongodb-error",     "mongodb"),
        (re.compile(r"ORA-[0-9]{5}",            re.I), "body:oracle-error",      "oracle"),
        (re.compile(r"SQL Server.*error",       re.I), "body:mssql-error",       "mssql"),
        # Framework-specific body patterns
        (re.compile(r"at org\.springframework", re.I), "body:spring-stacktrace", None),
        (re.compile(r"laravel\.com|Illuminate", re.I), "body:laravel-debug",     None),
        (re.compile(r"Django.*Exception",       re.I), "body:django-debug",      None),
        (re.compile(r"Flask.*Traceback",        re.I), "body:flask-debug",       None),
        # JWT patterns
        (re.compile(r'"token"\s*:\s*"ey[A-Za-z0-9]',re.I), "body:jwt-response", None),
        (re.compile(r'"authentication"\s*:\s*\{', re.I),    "body:juice-shop-auth", None),
        # Debug / error disclosure
        (re.compile(r"Traceback \(most recent", re.I),  "body:python-traceback",  None),
        (re.compile(r"SyntaxError|ReferenceError|TypeError", re.I), "body:js-error", None),
        (re.compile(r"Fatal error|Warning:|Notice:", re.I), "body:php-error",     None),
        (re.compile(r"NullPointerException|ArrayIndexOutOfBounds", re.I), "body:java-exception", None),
        (re.compile(r"at node_modules|at Object\.<anonymous>", re.I), "body:node-stacktrace", None),
        # CORS wildcard
        (re.compile(r"access-control-allow-origin.*\*", re.I), "body:cors-wildcard", None),
    ]

    # WAF / CDN detection — checked against response headers
    _WAF_SIGS: list[tuple[re.Pattern, str, str]] = [
        # (header_pattern, waf_name, cdn_name)
        (re.compile(r"cloudflare",      re.I), "cloudflare",  "cloudflare"),
        (re.compile(r"__cf_bm|cf-ray",  re.I), "cloudflare",  "cloudflare"),
        (re.compile(r"x-check-cacheable|akamai", re.I), "akamai", "akamai"),
        (re.compile(r"x-amz-cf-id|cloudfront",  re.I), "none",  "cloudfront"),
        (re.compile(r"x-fastly-id|fastly",       re.I), "none",  "fastly"),
        (re.compile(r"x-sucuri-id|sucuri",        re.I), "sucuri", "none"),
        (re.compile(r"x-iinfo|incapsula|imperva", re.I), "imperva","none"),
        (re.compile(r"x-waf|x-denied-reason|barracuda", re.I), "barracuda", "none"),
        (re.compile(r"x-aws-waf|aws-waf",         re.I), "awswaf", "cloudfront"),
        (re.compile(r"x-cdn.*varnish|via.*varnish",re.I), "none", "varnish"),
    ]

    # HTML body patterns for feature detection
    _FEATURE_SIGS: list[tuple[re.Pattern, str]] = [
        (re.compile(r'<input[^>]+type=["\']?password', re.I),        "feature:login-form"),
        (re.compile(r'<input[^>]+type=["\']?file',     re.I),        "feature:file-upload"),
        (re.compile(r'<input[^>]+(?:name|id)=["\']?(?:q|search|query)', re.I), "feature:search-form"),
        (re.compile(r'href=["\'][^"\']*\.csv|download.*csv|export.*csv', re.I), "feature:csv-export"),
        (re.compile(r'angular|ng-app|ng-controller',  re.I),         "feature:angular"),
        (re.compile(r'react|ReactDOM|__REACT',         re.I),        "feature:react"),
        (re.compile(r'vue\.js|new Vue\(|vuex',         re.I),        "feature:vue"),
        (re.compile(r'jquery|jQuery\.',                re.I),        "feature:jquery"),
        (re.compile(r'swagger-ui|openapi|redoc',       re.I),        "feature:swagger"),
        (re.compile(r'"__typename"|"query"|"mutation"', re.I),       "feature:graphql"),
        (re.compile(r'type=module|webpack|__webpack',  re.I),        "feature:spa"),
    ]

    def analyse(self, crawl_results: list) -> TechProfile:
        profile = TechProfile()
        signals: list[str] = []
        notes: list[str] = []

        # Vote counters — most-seen wins
        runtime_votes: dict[str, int] = {}
        framework_votes: dict[str, int] = {}
        db_votes: dict[str, int] = {}
        auth_votes: dict[str, int] = {}
        waf_votes: dict[str, int] = {}
        cdn_votes: dict[str, int] = {}
        js_fw_votes: dict[str, int] = {}

        def _vote(d: dict, key: str, weight: int = 1):
            if key and key not in ("unknown", "none"):
                d[key] = d.get(key, 0) + weight

        def _sig(s: str):
            if s not in signals:
                signals.append(s)

        for cr in crawl_results:
            headers = cr.headers if hasattr(cr, "headers") else {}
            body = cr.body or ""
            url = cr.url

            # Normalise headers to lowercase for consistent lookup
            hdrs = {k.lower(): v for k, v in headers.items()}

            xpb        = hdrs.get("x-powered-by", "")
            server_hdr = hdrs.get("server", "")
            cookies_hdr= hdrs.get("set-cookie", "")
            ct         = hdrs.get("content-type", "")

            # ── JSON API detection ─────────────────────────────────────────
            if "application/json" in ct:
                profile.uses_json_api = True
                _sig("header:json-api")

            # ── Server / runtime signals ───────────────────────────────────
            for pattern, sig, runtime, fw, _ in self._SERVER_SIGS:
                if pattern.search(xpb) or pattern.search(server_hdr):
                    _sig(sig)
                    _vote(runtime_votes, runtime, 3)
                    _vote(framework_votes, fw, 2)

            # ── Cookie signals ─────────────────────────────────────────────
            for pattern, sig, runtime, fw, auth in self._COOKIE_SIGS:
                if pattern.search(cookies_hdr):
                    _sig(sig)
                    _vote(runtime_votes, runtime, 2)
                    _vote(framework_votes, fw, 2)
                    _vote(auth_votes, auth, 2)
                    # Cloudflare/Akamai cookies → WAF/CDN
                    if "cloudflare" in sig:
                        _vote(waf_votes, "cloudflare", 3)
                        _vote(cdn_votes, "cloudflare", 3)
                    elif "akamai" in sig:
                        _vote(waf_votes, "akamai", 3)
                        _vote(cdn_votes, "akamai", 3)

            # ── Bearer token in response headers ──────────────────────────
            auth_hdr = hdrs.get("authorization", "")
            if "bearer" in auth_hdr.lower():
                _sig("header:bearer-token")
                _vote(auth_votes, "jwt", 3)

            # ── WAF / CDN detection ────────────────────────────────────────
            all_headers_str = " ".join(f"{k}: {v}" for k, v in hdrs.items())
            for pattern, waf, cdn in self._WAF_SIGS:
                if pattern.search(all_headers_str):
                    _sig(f"waf:{waf}" if waf != "none" else f"cdn:{cdn}")
                    _vote(waf_votes, waf, 3)
                    _vote(cdn_votes, cdn, 3)

            # CORS wildcard check
            cors_val = hdrs.get("access-control-allow-origin", "")
            if cors_val == "*":
                profile.has_cors_wildcard = True
                _sig("header:cors-wildcard")

            # ── URL signals ────────────────────────────────────────────────
            for pattern, sig in self._URL_SIGS:
                if pattern.search(url):
                    _sig(sig)
                    if "wordpress" in sig:
                        _vote(framework_votes, "wordpress", 5)
                        _vote(runtime_votes, "php", 4)
                        profile.cms = "wordpress"
                    elif "drupal" in sig:
                        profile.cms = "drupal"
                        _vote(runtime_votes, "php", 4)
                    elif "php-extension" in sig:
                        _vote(runtime_votes, "php", 2)
                    elif "aspx-extension" in sig:
                        _vote(runtime_votes, "dotnet", 3)
                        _vote(framework_votes, "asp.net", 3)
                    elif "jsp-extension" in sig:
                        _vote(runtime_votes, "java", 3)
                    elif "graphql" in sig:
                        profile.api_style = "graphql"
                        profile.has_graphql = True
                    elif "soap" in sig:
                        profile.api_style = "soap"
                    elif "struts" in sig:
                        _vote(runtime_votes, "java", 3)
                        _vote(framework_votes, "struts", 5)
                    elif "spring-actuator" in sig:
                        _vote(runtime_votes, "java", 3)
                        _vote(framework_votes, "spring", 5)
                    elif "swagger" in sig:
                        profile.has_swagger = True
                    elif "csv-export" in sig or "csv-download" in sig:
                        profile.has_csv_export = True
                    elif "file-upload" in sig:
                        profile.has_file_upload = True
                    elif "login-endpoint" in sig:
                        profile.has_login_form = True
                    elif "search-endpoint" in sig:
                        profile.has_search_form = True
                    elif "admin-area" in sig:
                        _sig("url:admin-area")

            # ── Body signals ───────────────────────────────────────────────
            if body:
                for pattern, sig, db in self._BODY_SIGS:
                    if pattern.search(body):
                        _sig(sig)
                        if db:
                            _vote(db_votes, db, 3)
                        if "spring-stacktrace" in sig:
                            _vote(runtime_votes, "java", 3)
                            _vote(framework_votes, "spring", 4)
                            profile.has_debug_info = True
                        elif "laravel-debug" in sig:
                            _vote(runtime_votes, "php", 3)
                            _vote(framework_votes, "laravel", 4)
                            profile.has_debug_info = True
                        elif "django-debug" in sig:
                            _vote(runtime_votes, "python", 3)
                            _vote(framework_votes, "django", 4)
                            profile.has_debug_info = True
                        elif "flask-debug" in sig:
                            _vote(runtime_votes, "python", 3)
                            _vote(framework_votes, "flask", 4)
                            profile.has_debug_info = True
                        elif "python-traceback" in sig:
                            _vote(runtime_votes, "python", 2)
                            profile.has_debug_info = True
                        elif "php-error" in sig:
                            _vote(runtime_votes, "php", 2)
                            profile.has_debug_info = True
                        elif "java-exception" in sig:
                            _vote(runtime_votes, "java", 2)
                            profile.has_debug_info = True
                        elif "node-stacktrace" in sig:
                            _vote(runtime_votes, "node", 2)
                            profile.has_debug_info = True
                        elif "js-error" in sig:
                            _vote(runtime_votes, "node", 1)
                        elif "jwt-response" in sig or "juice-shop-auth" in sig:
                            _vote(auth_votes, "jwt", 3)
                            _vote(runtime_votes, "node", 2)
                            profile.has_jwt_in_response = True
                        elif "cors-wildcard" in sig:
                            profile.has_cors_wildcard = True

                # ── Feature signals from HTML body ─────────────────────────
                for pattern, fsig in self._FEATURE_SIGS:
                    if pattern.search(body):
                        _sig(fsig)
                        if fsig == "feature:login-form":
                            profile.has_login_form = True
                        elif fsig == "feature:file-upload":
                            profile.has_file_upload = True
                        elif fsig == "feature:search-form":
                            profile.has_search_form = True
                        elif fsig == "feature:csv-export":
                            profile.has_csv_export = True
                        elif fsig == "feature:angular":
                            _vote(js_fw_votes, "angular", 3)
                            profile.is_spa = True
                        elif fsig == "feature:react":
                            _vote(js_fw_votes, "react", 3)
                            profile.is_spa = True
                        elif fsig == "feature:vue":
                            _vote(js_fw_votes, "vue", 3)
                            profile.is_spa = True
                        elif fsig == "feature:jquery":
                            _vote(js_fw_votes, "jquery", 1)
                        elif fsig == "feature:swagger":
                            profile.has_swagger = True
                        elif fsig == "feature:graphql":
                            profile.has_graphql = True
                        elif fsig == "feature:spa":
                            profile.is_spa = True

        # ── Resolve votes → profile ────────────────────────────────────────
        if runtime_votes:
            profile.runtime = max(runtime_votes, key=runtime_votes.get)
        if framework_votes:
            profile.framework = max(framework_votes, key=framework_votes.get)
        if db_votes:
            profile.database = max(db_votes, key=db_votes.get)
        if auth_votes:
            profile.auth_type = max(auth_votes, key=auth_votes.get)
        if waf_votes:
            profile.waf = max(waf_votes, key=waf_votes.get)
        if cdn_votes:
            profile.cdn = max(cdn_votes, key=cdn_votes.get)
        if js_fw_votes:
            profile.js_framework = max(js_fw_votes, key=js_fw_votes.get)

        # Deduplicate signals
        profile.signals = list(dict.fromkeys(signals))
        profile.notes = notes

        # ── Post-process: infer missing DB from runtime ────────────────────
        if profile.database == "unknown":
            if profile.runtime == "php":
                profile.database = "mysql"
            elif profile.runtime == "node":
                if any("nosql" in s for s in signals):
                    profile.database = "mongodb"

        # ── SPA / API style refinement ─────────────────────────────────────
        if profile.is_spa and profile.api_style == "rest":
            _sig("feature:spa-detected")
        if profile.has_graphql:
            profile.api_style = "graphql"

        # ── Add summary notes ───────────────────────────────────────────────
        if profile.waf not in ("none", "unknown"):
            notes.append(f"WAF detected: {profile.waf} — payloads may be blocked; scanner uses bypass techniques")
        if profile.has_debug_info:
            notes.append("Debug/error info visible in responses — information disclosure risk")
        if profile.has_cors_wildcard:
            notes.append("CORS wildcard (Access-Control-Allow-Origin: *) observed")
        if profile.has_swagger:
            notes.append("API documentation (Swagger/OpenAPI) found — enumerate all endpoints")
        if profile.has_csv_export:
            notes.append("CSV export links detected — CSV injection check prioritized")
        if profile.has_file_upload:
            notes.append("File upload forms detected — insecure upload check prioritized")
        profile.notes = notes

        return profile


# ---------------------------------------------------------------------------
# Check Priority Scoring
# ---------------------------------------------------------------------------

@dataclass
class PlannedCheck:
    """A check with its priority score and the rationale for that score."""
    check: "BaseScanCheck"
    priority: int          # 0-100; higher = run first
    rationale: str
    boosted: bool = False  # True if priority was raised during adaptive replanning


@dataclass
class AttackPlan:
    """
    Ordered list of checks to run.
    The planner produces this; CheckRunner consumes it.
    """
    tech_profile: TechProfile
    planned_checks: list[PlannedCheck] = field(default_factory=list)

    def ordered(self) -> list[PlannedCheck]:
        """Return checks sorted by priority descending."""
        return sorted(self.planned_checks, key=lambda p: p.priority, reverse=True)

    def skip_count(self) -> int:
        return sum(1 for p in self.planned_checks if p.priority == 0)

    def summary_lines(self) -> list[str]:
        lines = []
        for pc in self.ordered():
            if pc.priority > 0:
                marker = "⬆" if pc.boosted else " "
                lines.append(f"  {marker} [{pc.priority:3d}] {pc.check.check_id:<35} {pc.rationale}")
        skipped = self.skip_count()
        if skipped:
            lines.append(f"  [  0] ({skipped} checks skipped — not applicable to detected stack)")
        return lines


# ---------------------------------------------------------------------------
# Attack Planner
# ---------------------------------------------------------------------------

class AttackPlanner:
    """
    Assigns a priority score (0-100) to every check based on the TechProfile.

    Scoring rules:
      - Base score: every check starts at 50 (run everything by default)
      - Boosts: +N when signals match the check's target
      - Penalties: -N when signals contradict the check's target
      - Score 0: check is explicitly skipped (incompatible stack)

    Also handles adaptive replanning: when a finding arrives, boosts
    related follow-up checks.
    """

    def plan(
        self,
        tech_profile: TechProfile,
        checks: list["BaseScanCheck"],
        insertion_points: list["InsertionPoint"],
    ) -> AttackPlan:
        # Populate IP stats in profile for scoring
        tech_profile.ip_count = len(insertion_points)
        tech_profile.ip_types = list({ip.ip_type.value for ip in insertion_points})

        attack_plan = AttackPlan(tech_profile=tech_profile)

        for check in checks:
            priority, rationale = self._score(check.check_id, tech_profile, insertion_points)
            attack_plan.planned_checks.append(PlannedCheck(
                check=check,
                priority=priority,
                rationale=rationale,
            ))

        return attack_plan

    def adapt(self, plan: AttackPlan, finding_check_id: str) -> AttackPlan:
        """
        After a finding from `finding_check_id`, boost related follow-up checks.
        Called by CheckRunner as findings arrive.
        """
        boosts = _KILL_CHAIN_BOOSTS.get(finding_check_id, {})
        for pc in plan.planned_checks:
            boost = boosts.get(pc.check.check_id, 0)
            if boost:
                old = pc.priority
                pc.priority = min(100, pc.priority + boost)
                pc.boosted = True
                pc.rationale += f" [+{boost} boost from {finding_check_id}]"
        return plan

    def _score(
        self,
        check_id: str,
        tp: TechProfile,
        insertion_points: list,
    ) -> tuple[int, str]:
        """Returns (priority, rationale_string)."""
        base = 50
        boosts: list[str] = []
        penalties: list[str] = []

        rules = _SCORING_RULES.get(check_id)
        if rules is None:
            return base, "default priority (no specific rule)"

        score = base

        # Apply runtime rules
        runtime_rule = rules.get("runtime")
        if runtime_rule:
            if tp.runtime in runtime_rule.get("match", []):
                delta = runtime_rule.get("boost", 20)
                score += delta
                boosts.append(f"runtime={tp.runtime}(+{delta})")
            elif tp.runtime in runtime_rule.get("exclude", []):
                delta = runtime_rule.get("penalty", -100)
                score = max(0, score + delta)
                penalties.append(f"runtime={tp.runtime}({delta})")

        # Apply DB rules
        db_rule = rules.get("database")
        if db_rule:
            if tp.database in db_rule.get("match", []):
                delta = db_rule.get("boost", 20)
                score += delta
                boosts.append(f"db={tp.database}(+{delta})")
            elif tp.database in db_rule.get("exclude", []):
                delta = db_rule.get("penalty", -30)
                score = max(0, score + delta)
                penalties.append(f"db={tp.database}({delta})")

        # Apply auth rules
        auth_rule = rules.get("auth")
        if auth_rule:
            if tp.auth_type in auth_rule.get("match", []):
                delta = auth_rule.get("boost", 15)
                score += delta
                boosts.append(f"auth={tp.auth_type}(+{delta})")

        # Apply CDN rules (e.g. web-cache-poisoning is high value on CDN targets)
        cdn_rule = rules.get("cdn")
        if cdn_rule:
            if tp.cdn in cdn_rule.get("match", []):
                delta = cdn_rule.get("boost", 20)
                score += delta
                boosts.append(f"cdn={tp.cdn}(+{delta})")

        # Apply signal rules
        signal_rule = rules.get("signals")
        if signal_rule:
            for sig in tp.signals:
                for match_sig in signal_rule.get("match", []):
                    if match_sig in sig:
                        delta = signal_rule.get("boost", 10)
                        score += delta
                        boosts.append(f"signal:{match_sig}(+{delta})")
                        break

        # Apply insertion point rules
        ip_rule = rules.get("insertion_points")
        if ip_rule:
            required_names = ip_rule.get("require_param_names", [])
            if required_names:
                ip_names = [ip.name.lower() for ip in insertion_points]
                if any(r in name for r in required_names for name in ip_names):
                    delta = ip_rule.get("boost", 15)
                    score += delta
                    boosts.append(f"param-match(+{delta})")
                elif ip_rule.get("strict"):
                    score = max(0, score - 40)
                    penalties.append("required-param-missing(-40)")

        # Apply CMS rules
        cms_rule = rules.get("cms")
        if cms_rule:
            if tp.cms in cms_rule.get("match", []):
                delta = cms_rule.get("boost", 25)
                score += delta
                boosts.append(f"cms={tp.cms}(+{delta})")

        # Apply feature rules — new: profile flags from enhanced fingerprinting
        feature_rule = rules.get("features")
        if feature_rule:
            for flag, boost_val in feature_rule.items():
                if getattr(tp, flag, False):
                    score += boost_val
                    boosts.append(f"feature:{flag}(+{boost_val})")

        # WAF penalty — WAF-protected targets penalise checks that rely on plain payloads
        # (the check itself handles bypass; the planner just notes it)
        waf_rule = rules.get("waf_penalise")
        if waf_rule and tp.waf not in ("none", "unknown"):
            delta = waf_rule.get("penalty", -10)
            score = max(0, score + delta)
            penalties.append(f"waf={tp.waf}({delta})")

        score = max(0, min(100, score))

        rationale_parts = []
        if boosts:
            rationale_parts.append("boosted by: " + ", ".join(boosts))
        if penalties:
            rationale_parts.append("penalised: " + ", ".join(penalties))
        if not rationale_parts:
            rationale_parts.append("default")

        return score, "; ".join(rationale_parts)


# ---------------------------------------------------------------------------
# Kill chain boosts: when check A finds something, boost check B
# ---------------------------------------------------------------------------

_KILL_CHAIN_BOOSTS: dict[str, dict[str, int]] = {
    # SQLi auth bypass → immediately try to dump users, escalate
    "sqli-auth-bypass": {
        "admin-chain":       +30,
        "weak-password-hash": +25,
        "sqli-union":        +20,
        "jwt-unsigned":      +15,
        "idor-basket":       +10,
    },
    # JWT alg=none → check what admin-only endpoints expose
    "jwt-unsigned": {
        "admin-chain":       +30,
        "mass-assignment":   +20,
        "idor-basket":       +15,
    },
    # CMDi confirmed → try SSRF via the same param, escalate
    "cmdi": {
        "ssrf":              +25,
        "ssrf-generic":      +25,
        "traversal-lfi":     +15,
    },
    # SQLi error → try UNION exfil next
    "sqli-error": {
        "sqli-union":        +30,
        "sqli-auth-bypass":  +15,
    },
    # Admin chain (got admin) → check stored XSS, IDOR, CSRF aggressively
    "admin-chain": {
        "xss-stored-review":    +20,
        "xss-stored-feedback":  +20,
        "xss-stored-profile":   +20,
        "csrf":                 +15,
        "idor-basket":          +15,
        "http-verb-tampering":  +10,
    },
    # Brute force success → use session for everything
    "login-bruteforce": {
        "admin-chain":          +30,
        "idor-basket":          +20,
        "xss-stored-review":    +15,
        "xss-stored-feedback":  +15,
        "csrf":                 +15,
    },
    # Hardcoded creds found → try them
    "hardcoded-credentials": {
        "login-bruteforce":     +40,
        "sqli-auth-bypass":     +10,
    },
    # SSRF → try to reach cloud metadata, internal services
    "ssrf": {
        "ssrf-generic":         +20,
        "traversal-lfi":        +10,
    },
    # XSS → try stored variants too
    "xss-reflected": {
        "xss-stored-review":    +15,
        "xss-stored-feedback":  +15,
        "xss-stored-profile":   +15,
    },
    # Weak hash → escalate cracking → try cracked password in brute force
    "weak-password-hash": {
        "login-bruteforce":     +20,
    },
    # Debug endpoint found → check for more admin/actuator paths + sensitive data
    "debug-endpoint": {
        "sensitive-api-path":   +25,
        "hardcoded-credentials":+20,
        "traversal-lfi":        +15,
    },
    # File upload → try webshell + path traversal to retrieve it
    "insecure-file-upload": {
        "traversal-lfi":        +25,
        "cmdi":                 +20,
        "ssrf-generic":         +10,
    },
    # BOLA (IDOR) → check BFLA and admin chain
    "bola": {
        "bfla":                 +25,
        "idor-basket":          +15,
        "admin-chain":          +10,
    },
    # CSP absent/weak → XSS much more impactful
    "csp-bypass": {
        "xss-reflected":        +20,
        "xss-stored-review":    +15,
        "xss-stored-feedback":  +15,
        "xss-stored-profile":   +15,
    },
    # Prototype pollution → check XSS (PP can enable XSS) and admin chain
    "prototype-pollution": {
        "xss-reflected":        +15,
        "admin-chain":          +10,
    },
    # SSJS injection → can lead to RCE, check CMDi
    "ssjs-injection": {
        "cmdi":                 +25,
        "cmdi-ext":             +25,
        "traversal-lfi":        +15,
    },
}


# ---------------------------------------------------------------------------
# Per-check scoring rules
# ---------------------------------------------------------------------------
# Each entry: check_id → dict of dimension rules.
# Dimensions: runtime, database, auth, signals, insertion_points, cms

_SCORING_RULES: dict[str, dict] = {
    # ---- Injection -----------------------------------------------------------
    "sqli-error": {
        "database": {"match": ["sqlite", "mysql", "postgresql", "mssql", "oracle"], "boost": 20,
                     "exclude": ["mongodb"], "penalty": -40},
        "insertion_points": {"require_param_names": ["q", "query", "search", "id", "user", "email"], "boost": 10},
    },
    "sqli-union": {
        "database": {"match": ["sqlite", "mysql", "postgresql", "mssql"], "boost": 20,
                     "exclude": ["mongodb"], "penalty": -40},
    },
    "sqli-auth-bypass": {
        "database": {"match": ["sqlite", "mysql", "postgresql", "mssql"], "boost": 20,
                     "exclude": ["mongodb"], "penalty": -30},
        "insertion_points": {"require_param_names": ["email", "username", "user", "login"], "boost": 15},
    },
    "sqli-time": {
        "database": {"match": ["sqlite", "mysql", "postgresql", "mssql"], "boost": 15,
                     "exclude": ["mongodb"], "penalty": -40},
    },
    "nosql-login": {
        "database": {"match": ["mongodb"], "boost": 30, "exclude": ["sqlite", "mysql", "mssql"], "penalty": -40},
        "runtime":  {"match": ["node"], "boost": 15},
    },
    "nosql-reviews": {
        "database": {"match": ["mongodb"], "boost": 30, "exclude": ["sqlite", "mysql"], "penalty": -40},
        "runtime":  {"match": ["node"], "boost": 15},
    },
    "cmdi": {
        "runtime": {"match": ["node", "php", "python", "ruby"], "boost": 20},
        "insertion_points": {"require_param_names": ["q", "query", "cmd", "exec", "search", "file", "path"], "boost": 15},
    },
    "xxe-b2b": {
        "runtime":  {"match": ["java", "php", "dotnet"], "boost": 20},
        "api_style_match": True,  # handled by signals
        "signals":  {"match": ["url:soap", "url:rest-api"], "boost": 15},
    },
    "prototype-pollution": {
        "runtime": {"match": ["node"], "boost": 30, "exclude": ["php", "java", "python", "dotnet"], "penalty": -50},
    },
    "insecure-deserialization": {
        "runtime": {"match": ["java", "php", "dotnet"], "boost": 25,
                    "exclude": ["node", "python"], "penalty": -40},
    },
    # ---- Auth ----------------------------------------------------------------
    "jwt-unsigned": {
        "auth":   {"match": ["jwt"], "boost": 30},
        "signals": {"match": ["body:jwt-response", "cookie:jwt-token", "body:juice-shop-auth"], "boost": 20},
    },
    "sqli-auth-bypass": {
        "database": {"match": ["sqlite", "mysql", "postgresql", "mssql"], "boost": 20,
                     "exclude": ["mongodb"], "penalty": -30},
    },
    "account-enumeration": {
        "insertion_points": {"require_param_names": ["email", "username", "user"], "boost": 15, "strict": False},
    },
    "rate-limit-missing": {
        "insertion_points": {"require_param_names": ["email", "username", "user", "password"], "boost": 10},
    },
    "login-bruteforce": {
        "insertion_points": {"require_param_names": ["email", "username", "user", "password"], "boost": 10},
    },
    # ---- XSS -----------------------------------------------------------------
    "xss-reflected": {
        "insertion_points": {"require_param_names": ["q", "query", "search", "s", "name", "msg", "comment"], "boost": 20},
    },
    "xss-stored-review": {
        "runtime": {"match": ["node"], "boost": 10},
        "signals": {"match": ["body:juice-shop-auth", "url:rest-api"], "boost": 15},
    },
    "xss-stored-feedback": {
        "runtime": {"match": ["node"], "boost": 10},
    },
    "xss-stored-profile": {
        "runtime": {"match": ["node"], "boost": 10},
    },
    # ---- SSTI ----------------------------------------------------------------
    "ssti-profile-eval": {
        "runtime": {"match": ["node", "python", "ruby"], "boost": 25,
                    "exclude": ["java", "dotnet"], "penalty": -30},
    },
    "ssti-generic": {
        "runtime": {"match": ["python", "ruby", "php", "node"], "boost": 15},
    },
    # ---- SSRF ----------------------------------------------------------------
    "ssrf": {
        "signals": {"match": ["url:rest-api", "body:juice-shop-auth"], "boost": 20},
    },
    "ssrf-generic": {
        "insertion_points": {"require_param_names": ["url", "callback", "redirect", "imageUrl", "src", "target"], "boost": 25},
    },
    # ---- Access control ------------------------------------------------------
    "idor-basket": {
        "signals": {"match": ["url:rest-api", "body:juice-shop-auth"], "boost": 15},
    },
    "traversal-lfi": {
        "insertion_points": {"require_param_names": ["file", "path", "page", "template", "load", "read"], "boost": 25},
        "runtime": {"match": ["php", "python", "node", "ruby"], "boost": 10},
    },
    "http-verb-tampering": {
        "signals": {"match": ["url:rest-api"], "boost": 10},
    },
    "csrf": {
        "auth":   {"match": ["session-cookie"], "boost": 25},
    },
    "admin-chain": {
        "signals": {"match": ["body:juice-shop-auth", "url:rest-api"], "boost": 20},
    },
    # ---- CVEs ----------------------------------------------------------------
    "cve-2021-44228-log4shell": {
        "runtime": {"match": ["java"], "boost": 35, "exclude": ["node", "php", "python", "ruby"], "penalty": -60},
    },
    "cve-2014-6271-shellshock": {
        "server": {"match_any": True},  # any server, but CGI needed
        "signals": {"match": ["header:server:apache", "header:server:nginx"], "boost": 10},
        "runtime": {"exclude": ["node", "dotnet"], "penalty": -20},
    },
    "cve-2022-22965-spring4shell": {
        "runtime": {"match": ["java"], "boost": 35, "exclude": ["node", "php", "python", "ruby"], "penalty": -60},
        "signals": {"match": ["url:spring-actuator", "body:spring-stacktrace"], "boost": 20},
    },
    "cve-2017-5638-struts-ognl": {
        "runtime": {"match": ["java"], "boost": 35, "exclude": ["node", "php", "python", "ruby"], "penalty": -60},
        "signals": {"match": ["url:struts"], "boost": 30},
    },
    # ---- WordPress -----------------------------------------------------------
    "passive-missing-headers": {},  # always run, no scoring modifiers
    "passive-open-redirect":   {},
    "passive-cors":            {},
    "passive-info-disclosure": {},
    "cookie-security":         {},
    "vulnerable-component":    {},
    "hardcoded-credentials":   {},
    "traversal-sensitive-paths": {},
    "static-js-rce":           {},
    "weak-password-hash":      {},
    "host-header-injection":   {},

    # ---- New checks ----------------------------------------------------------
    "csv-injection": {
        "features":  {"has_csv_export": 30, "has_search_form": 5},
        "insertion_points": {"require_param_names": ["name", "username", "comment", "title", "description", "message", "content"], "boost": 10},
    },
    "csp-bypass": {
        # Passive — always run but boost when we see CORS wildcard or no debug headers
        "signals":  {"match": ["header:cors-wildcard", "feature:spa-detected"], "boost": 10},
    },
    "insecure-file-upload": {
        "features": {"has_file_upload": 30},
    },
    "open-redirect-active": {
        "features": {"has_search_form": 10, "has_login_form": 5},
        "insertion_points": {"require_param_names": ["redirect", "url", "next", "return", "callback", "redir", "target", "goto"], "boost": 20},
    },
    "debug-endpoint": {
        "features": {"has_debug_info": 20, "has_swagger": 10},
        "signals":  {"match": ["url:admin-area", "url:spring-actuator", "header:server:werkzeug"], "boost": 15},
    },
    "sensitive-api-path": {
        "features": {"has_swagger": 20, "has_debug_info": 10},
    },
    "clickjacking": {
        "features": {"has_login_form": 10},
    },
    "rate-limit-missing": {
        "features": {"has_login_form": 20},
        "insertion_points": {"require_param_names": ["email", "username", "user", "password"], "boost": 10},
    },
    "login-bruteforce": {
        "features": {"has_login_form": 15},
        "insertion_points": {"require_param_names": ["email", "username", "user", "password"], "boost": 10},
    },
    "mass-assignment": {
        "features": {"has_login_form": 5},
        "signals":  {"match": ["url:rest-api", "header:json-api"], "boost": 10},
    },
    "graphql": {
        "features": {"has_graphql": 40},
        "signals":  {"match": ["url:graphql", "feature:graphql"], "boost": 20},
    },
    "oauth": {
        "signals":  {"match": ["url:login-endpoint", "body:jwt-response"], "boost": 15},
        "features": {"has_login_form": 10, "has_jwt_in_response": 20},
    },
    "ssjs-injection": {
        "runtime":  {"match": ["node"], "boost": 30, "exclude": ["php", "java", "python", "dotnet"], "penalty": -50},
        "features": {"uses_json_api": 10},
    },
    "bola": {
        "signals":  {"match": ["url:rest-api", "header:json-api"], "boost": 15},
        "features": {"uses_json_api": 10},
    },
    "bfla": {
        "signals":  {"match": ["url:rest-api", "header:json-api"], "boost": 15},
        "features": {"uses_json_api": 10},
    },
    "cmdi-ext": {
        "runtime":  {"match": ["node", "php", "python", "ruby"], "boost": 15},
        "insertion_points": {"require_param_names": ["q", "cmd", "exec", "search", "file", "ip", "host", "domain"], "boost": 20},
    },
    "xss-reflected": {
        "features": {"has_search_form": 15},
        "insertion_points": {"require_param_names": ["q", "query", "search", "s", "name", "msg", "comment", "text", "input"], "boost": 15},
        "waf_penalise": {"penalty": -5},  # WAF may block some XSS but scanner uses bypass payloads
    },
    "2fa-bypass": {
        "features": {"has_login_form": 20},
        "signals":  {"match": ["cookie:jwt-token", "body:jwt-response", "url:login-endpoint"], "boost": 10},
    },
    "web-cache-poisoning": {
        "cdn":   {"match": ["cloudflare", "cloudfront", "akamai", "fastly"], "boost": 30},
    },
    "crlf-injection": {
        "features": {"has_search_form": 5, "is_spa": 5},
    },
}
