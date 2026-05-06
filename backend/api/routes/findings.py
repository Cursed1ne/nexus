"""
GET   /api/findings          — list findings (filter: session_id, severity)
GET   /api/findings/{id}     — full finding with evidence
PATCH /api/findings/{id}     — {false_positive: true|false}
"""
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import db

router = APIRouter(prefix="/api", tags=["findings"])


@router.get("/findings")
async def list_findings(
    session_id: Optional[str] = None,
    severity: Optional[str] = None,
    include_fp: bool = False,
    limit: int = 500,
):
    findings = db.list_findings(
        session_id=session_id,
        severity=severity,
        include_fp=include_fp,
        limit=limit,
    )
    return [f.to_dict() for f in findings]


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str):
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(404, f"Finding {finding_id!r} not found")
    return finding.to_dict()


class FindingPatch(BaseModel):
    false_positive: bool


@router.patch("/findings/{finding_id}")
async def patch_finding(finding_id: str, patch: FindingPatch):
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(404, f"Finding {finding_id!r} not found")
    db.mark_false_positive(finding_id, patch.false_positive)
    return {"id": finding_id, "false_positive": patch.false_positive}
