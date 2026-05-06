"""
SQLite persistence layer — zero extra dependencies beyond stdlib.

Tables:
  sessions  — one row per scan session
  findings  — one row per finding (JSON-encoded evidence + insertion_point)
"""
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from nexus.models import (
    Confidence,
    Evidence,
    Finding,
    InsertionPoint,
    IPType,
    ScanSession,
    ScanStatus,
    Severity,
)

_DB_PATH = Path(__file__).parent / "nexus_data.db"
_lock = threading.Lock()


@contextmanager
def _conn():
    con = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db():
    """Create tables if they don't exist."""
    with _conn() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id          TEXT PRIMARY KEY,
                target_url  TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'PENDING',
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL,
                max_pages   INTEGER NOT NULL DEFAULT 50,
                hitl_mode   INTEGER NOT NULL DEFAULT 0,
                pages_crawled INTEGER NOT NULL DEFAULT 0,
                findings_count INTEGER NOT NULL DEFAULT 0,
                error       TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS findings (
                id              TEXT PRIMARY KEY,
                session_id      TEXT NOT NULL REFERENCES sessions(id),
                check_id        TEXT NOT NULL,
                severity        TEXT NOT NULL,
                confidence      TEXT NOT NULL,
                cvss            REAL NOT NULL DEFAULT 0.0,
                description     TEXT NOT NULL,
                insertion_point TEXT NOT NULL,   -- JSON
                evidence        TEXT NOT NULL,   -- JSON
                steps_to_reproduce TEXT NOT NULL DEFAULT '',
                solution        TEXT NOT NULL DEFAULT '',
                references_json TEXT NOT NULL DEFAULT '[]',
                false_positive  INTEGER NOT NULL DEFAULT 0,
                created_at      TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        """)


# ---------------------------------------------------------------------------
# Session CRUD
# ---------------------------------------------------------------------------

def create_session(session: ScanSession) -> ScanSession:
    with _conn() as con:
        con.execute(
            """INSERT INTO sessions
               (id, target_url, status, created_at, updated_at,
                max_pages, hitl_mode, pages_crawled, findings_count, error)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                session.id,
                session.target_url,
                session.status.value,
                session.created_at,
                session.updated_at,
                session.max_pages,
                int(session.hitl_mode),
                session.pages_crawled,
                session.findings_count,
                session.error,
            ),
        )
    return session


def get_session(session_id: str) -> Optional[ScanSession]:
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
    return _row_to_session(row) if row else None


def update_session(session: ScanSession):
    with _conn() as con:
        con.execute(
            """UPDATE sessions SET
               status=?, updated_at=?, pages_crawled=?, findings_count=?, error=?
               WHERE id=?""",
            (
                session.status.value,
                datetime.utcnow().isoformat(),
                session.pages_crawled,
                session.findings_count,
                session.error,
                session.id,
            ),
        )


def list_sessions(limit: int = 50) -> list[ScanSession]:
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_session(r) for r in rows]


# ---------------------------------------------------------------------------
# Finding CRUD
# ---------------------------------------------------------------------------

def save_finding(finding: Finding):
    with _conn() as con:
        con.execute(
            """INSERT OR REPLACE INTO findings
               (id, session_id, check_id, severity, confidence, cvss,
                description, insertion_point, evidence,
                steps_to_reproduce, solution, references_json,
                false_positive, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                finding.id,
                finding.session_id,
                finding.check_id,
                finding.severity.value,
                finding.confidence.value,
                finding.cvss,
                finding.description,
                json.dumps({
                    "url": finding.insertion_point.url,
                    "method": finding.insertion_point.method,
                    "ip_type": finding.insertion_point.ip_type.value,
                    "name": finding.insertion_point.name,
                    "value": finding.insertion_point.value,
                    "context": finding.insertion_point.context,
                }),
                json.dumps({
                    "request_raw": finding.evidence.request_raw,
                    "response_raw": finding.evidence.response_raw,
                    "payload": finding.evidence.payload,
                    "poc_curl": finding.evidence.poc_curl,
                    "response_status": finding.evidence.response_status,
                    "oast_callback": finding.evidence.oast_callback,
                }),
                finding.steps_to_reproduce,
                finding.solution,
                json.dumps(finding.references),
                int(finding.false_positive),
                finding.created_at,
            ),
        )


def get_finding(finding_id: str) -> Optional[Finding]:
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
    return _row_to_finding(row) if row else None


def list_findings(
    session_id: Optional[str] = None,
    severity: Optional[str] = None,
    include_fp: bool = False,
    limit: int = 500,
) -> list[Finding]:
    query = "SELECT * FROM findings WHERE 1=1"
    params: list = []
    if session_id:
        query += " AND session_id=?"
        params.append(session_id)
    if severity:
        query += " AND severity=?"
        params.append(severity.upper())
    if not include_fp:
        query += " AND false_positive=0"
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with _conn() as con:
        rows = con.execute(query, params).fetchall()
    return [_row_to_finding(r) for r in rows]


def mark_false_positive(finding_id: str, is_fp: bool):
    with _conn() as con:
        con.execute(
            "UPDATE findings SET false_positive=? WHERE id=?",
            (int(is_fp), finding_id),
        )


# ---------------------------------------------------------------------------
# Row mappers
# ---------------------------------------------------------------------------

def _row_to_session(row) -> ScanSession:
    return ScanSession(
        id=row["id"],
        target_url=row["target_url"],
        status=ScanStatus(row["status"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        max_pages=row["max_pages"],
        hitl_mode=bool(row["hitl_mode"]),
        pages_crawled=row["pages_crawled"],
        findings_count=row["findings_count"],
        error=row["error"],
    )


def _row_to_finding(row) -> Finding:
    ip_data = json.loads(row["insertion_point"])
    ev_data = json.loads(row["evidence"])
    return Finding(
        id=row["id"],
        session_id=row["session_id"],
        check_id=row["check_id"],
        severity=Severity(row["severity"]),
        confidence=Confidence(row["confidence"]),
        cvss=row["cvss"],
        description=row["description"],
        insertion_point=InsertionPoint(
            url=ip_data["url"],
            method=ip_data["method"],
            ip_type=IPType(ip_data["ip_type"]),
            name=ip_data["name"],
            value=ip_data["value"],
            context=ip_data.get("context", {}),
        ),
        evidence=Evidence(
            request_raw=ev_data.get("request_raw", ""),
            response_raw=ev_data.get("response_raw", ""),
            payload=ev_data.get("payload", ""),
            poc_curl=ev_data.get("poc_curl", ""),
            response_status=ev_data.get("response_status", 0),
            oast_callback=ev_data.get("oast_callback", ""),
        ),
        steps_to_reproduce=row["steps_to_reproduce"],
        solution=row["solution"],
        references=json.loads(row["references_json"]),
        false_positive=bool(row["false_positive"]),
        created_at=row["created_at"],
    )
