"""
ExploitSession - Tracks a complete red-team engagement against an LLM target.
Inspired by CAI's session management and RVD's vulnerability tracking.
"""

from __future__ import annotations

import uuid
import json
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """A single security finding discovered during the session."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    attack_type: str = ""
    severity: str = "UNKNOWN"       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    lvss_score: float = 0.0         # LVSS score (0-10)
    title: str = ""
    description: str = ""
    payload: str = ""
    response: str = ""
    owasp_category: str = ""        # e.g. LLM01, LLM02 ...
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    # Verification metadata — set by BaseAttack._add_finding()
    confidence: str = "LOW"         # HIGH / MEDIUM / LOW
    verified: bool = False          # True = hard evidence; False = pattern match only
    confidence_reason: str = ""     # human-readable explanation of confidence level

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "lvss_score": self.lvss_score,
            "title": self.title,
            "description": self.description,
            # Full payload and response — no truncation so report can show everything
            "payload": self.payload,
            "response": self.response,
            # Keep short snippet for backward compat with old report consumers
            "response_snippet": self.response[:400] + "…" if len(self.response) > 400 else self.response,
            "owasp_category": self.owasp_category,
            "timestamp": self.timestamp,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "verified": self.verified,
            "confidence_reason": self.confidence_reason,
        }


@dataclass
class ExploitSession:
    """
    A complete red-team engagement session.

    Analogous to RVD issue tracking but for live exploitation attempts.
    Records every interaction, finding, and result for the final report.
    """

    target_name: str
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    operator: str = "nexus-auto"
    notes: str = ""

    # Internals
    _started_at: float = field(default_factory=time.time, init=False, repr=False)
    _interactions: List[Dict[str, Any]] = field(default_factory=list, init=False)
    _findings: List[Finding] = field(default_factory=list, init=False)
    _attack_counts: Dict[str, int] = field(default_factory=dict, init=False)

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(
        self,
        attack_type: str,
        payload: str,
        response: str,
        success: bool,
        metadata: Optional[Dict] = None,
    ) -> None:
        """Log a single attack attempt."""
        self._attack_counts[attack_type] = self._attack_counts.get(attack_type, 0) + 1
        self._interactions.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "attack": attack_type,
            "payload": payload[:200],
            "response": response[:200],
            "success": success,
            **(metadata or {}),
        })

    def add_finding(self, finding: Finding) -> None:
        """Register a confirmed vulnerability finding."""
        self._findings.append(finding)
        logger.info(
            "[Session %s] Finding added: [%s] %s (LVSS %.1f)",
            self.session_id, finding.severity, finding.title, finding.lvss_score,
        )

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def findings(self) -> List[Finding]:
        return list(self._findings)

    @property
    def interactions(self) -> List[Dict]:
        return list(self._interactions)

    @property
    def duration_s(self) -> float:
        return round(time.time() - self._started_at, 2)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self._findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self._findings if f.severity == "HIGH")

    def summary(self) -> Dict[str, Any]:
        severity_counts: Dict[str, int] = {}
        for f in self._findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            "session_id": self.session_id,
            "target": self.target_name,
            "operator": self.operator,
            "duration_s": self.duration_s,
            "total_interactions": len(self._interactions),
            "total_findings": len(self._findings),
            "severity_breakdown": severity_counts,
            "attacks_used": self._attack_counts,
            "max_lvss": max((f.lvss_score for f in self._findings), default=0.0),
        }

    def to_json(self, indent: int = 2) -> str:
        data = {
            **self.summary(),
            "findings": [f.to_dict() for f in self._findings],
        }
        return json.dumps(data, indent=indent)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())
        logger.info("Session saved to %s", path)

    def __repr__(self) -> str:
        return (
            f"ExploitSession(id={self.session_id!r}, target={self.target_name!r}, "
            f"findings={len(self._findings)}, interactions={len(self._interactions)})"
        )
