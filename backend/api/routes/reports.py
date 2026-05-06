"""
GET /api/report/{session_id}  — full report JSON (HTML coming in Phase 4)
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

import db

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/report/{session_id}")
async def get_report(session_id: str, fmt: str = "json"):
    session = db.get_session(session_id)
    if not session:
        raise HTTPException(404, f"Session {session_id!r} not found")

    findings = db.list_findings(session_id=session_id, include_fp=False)

    severity_counts = {}
    for f in findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    report = {
        "session": session.to_dict(),
        "summary": {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "pages_crawled": session.pages_crawled,
        },
        "findings": [f.to_dict() for f in findings],
    }

    if fmt == "html":
        return HTMLResponse(_render_html(report))
    return report


def _render_html(report: dict) -> str:
    session = report["session"]
    summary = report["summary"]
    findings = report["findings"]

    rows = ""
    for f in findings:
        ip = f["insertion_point"]
        rows += (
            f"<tr>"
            f"<td>{f['severity']}</td>"
            f"<td>{f['confidence']}</td>"
            f"<td>{f['check_id']}</td>"
            f"<td>{ip['url']}</td>"
            f"<td>{ip['name']}</td>"
            f"<td>{f['description'][:120]}…</td>"
            f"</tr>\n"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NEXUS Report — {session['target_url']}</title>
<style>
  body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  h1 {{ color: #58a6ff; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #30363d; padding: 6px 12px; text-align: left; }}
  th {{ background: #161b22; }}
  .CRITICAL {{ color: #ff5555; }}
  .HIGH {{ color: #ff7b72; }}
  .MEDIUM {{ color: #e3b341; }}
  .LOW {{ color: #79c0ff; }}
  .INFO {{ color: #8b949e; }}
</style>
</head>
<body>
<h1>NEXUS Scan Report</h1>
<p>Target: <strong>{session['target_url']}</strong></p>
<p>Status: {session['status']} | Pages: {session['pages_crawled']} | Findings: {summary['total_findings']}</p>
<h2>Findings</h2>
<table>
<thead><tr>
  <th>Severity</th><th>Confidence</th><th>Check</th>
  <th>URL</th><th>Parameter</th><th>Description</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"""
