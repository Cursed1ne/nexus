from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    CERTAIN = "CERTAIN"
    FIRM = "FIRM"
    TENTATIVE = "TENTATIVE"


class CheckType(str, Enum):
    PASSIVE = "PASSIVE"   # no requests sent, analyse baseline
    ACTIVE = "ACTIVE"     # sends payloads
    OAST = "OAST"         # out-of-band callback


class IPType(str, Enum):  # InsertionPoint types
    QUERY_PARAM = "QUERY_PARAM"
    BODY_PARAM = "BODY_PARAM"
    COOKIE = "COOKIE"
    HEADER = "HEADER"
    JSON_KEY = "JSON_KEY"
    PATH_SEGMENT = "PATH_SEGMENT"


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    CRAWLING = "CRAWLING"
    AUDITING = "AUDITING"
    COMPLETE = "COMPLETE"
    ERROR = "ERROR"


@dataclass
class InsertionPoint:
    url: str
    method: str           # GET POST PUT etc
    ip_type: IPType
    name: str             # param/header/cookie name
    value: str            # original value
    context: dict = field(default_factory=dict)


@dataclass
class Evidence:
    # ── Attack request ────────────────────────────────────────────────────────
    request_raw: str = ""           # Full HTTP/1.1 request text sent to server
    # ── Attack response ───────────────────────────────────────────────────────
    response_raw: str = ""          # Full HTTP/1.1 response (status + headers + body[:3000])
    response_status: int = 0
    response_length: int = 0        # Actual bytes received
    response_time_ms: float = 0.0   # Round-trip time in milliseconds
    # ── Baseline response (benign probe before payload) ───────────────────────
    baseline_raw: str = ""          # Baseline HTTP/1.1 response for diff
    baseline_status: int = 0
    baseline_length: int = 0
    baseline_time_ms: float = 0.0
    # ── Delta / proof ─────────────────────────────────────────────────────────
    length_delta: int = 0           # response_length - baseline_length (signed)
    highlighted_evidence: str = ""  # Exact snippet proving the vulnerability
    # ── PoC ──────────────────────────────────────────────────────────────────
    payload: str = ""
    poc_curl: str = ""
    oast_callback: str = ""


@dataclass
class CheckResult:
    check_id: str
    vulnerable: bool
    confidence: Confidence
    severity: Severity
    cvss: float
    description: str
    evidence: Evidence
    insertion_point: Optional[InsertionPoint] = None


@dataclass
class Finding:
    id: str
    session_id: str
    check_id: str
    severity: Severity
    confidence: Confidence
    cvss: float
    description: str
    insertion_point: InsertionPoint
    evidence: Evidence
    steps_to_reproduce: str = ""
    solution: str = ""
    references: list = field(default_factory=list)
    false_positive: bool = False
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "check_id": self.check_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "cvss": self.cvss,
            "description": self.description,
            "insertion_point": {
                "url": self.insertion_point.url,
                "method": self.insertion_point.method,
                "ip_type": self.insertion_point.ip_type.value,
                "name": self.insertion_point.name,
                "value": self.insertion_point.value,
                "context": self.insertion_point.context,
            },
            "evidence": {
                "request_raw": self.evidence.request_raw,
                "response_raw": self.evidence.response_raw,
                "response_status": self.evidence.response_status,
                "response_length": self.evidence.response_length,
                "response_time_ms": round(self.evidence.response_time_ms, 1),
                "baseline_raw": self.evidence.baseline_raw,
                "baseline_status": self.evidence.baseline_status,
                "baseline_length": self.evidence.baseline_length,
                "baseline_time_ms": round(self.evidence.baseline_time_ms, 1),
                "length_delta": self.evidence.length_delta,
                "highlighted_evidence": self.evidence.highlighted_evidence,
                "payload": self.evidence.payload,
                "poc_curl": self.evidence.poc_curl,
                "oast_callback": self.evidence.oast_callback,
            },
            "steps_to_reproduce": self.steps_to_reproduce,
            "solution": self.solution,
            "references": self.references,
            "false_positive": self.false_positive,
            "created_at": self.created_at,
        }


@dataclass
class CrawlResult:
    url: str
    status_code: int
    headers: dict
    body: str
    content_type: str = ""
    redirect_chain: list = field(default_factory=list)
    response_time_ms: float = 0.0
    error: str = ""


@dataclass
class ScanSession:
    id: str
    target_url: str
    status: ScanStatus
    created_at: str
    updated_at: str
    max_pages: int = 50
    hitl_mode: bool = False
    pages_crawled: int = 0
    findings_count: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target_url": self.target_url,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "max_pages": self.max_pages,
            "hitl_mode": self.hitl_mode,
            "pages_crawled": self.pages_crawled,
            "findings_count": self.findings_count,
            "error": self.error,
        }
