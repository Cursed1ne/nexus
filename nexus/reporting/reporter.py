"""
NexusReporter - Generates structured security assessment reports.
Inspired by RSF (Robot Security Framework) assessment output format.

Output formats: terminal (rich), JSON, Markdown
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from nexus.core.session import ExploitSession, Finding


SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH":     "\033[93m",  # Yellow
    "MEDIUM":   "\033[94m",  # Blue
    "LOW":      "\033[92m",  # Green
    "NONE":     "\033[0m",
    "UNKNOWN":  "\033[37m",  # White
}
RESET = "\033[0m"
BOLD = "\033[1m"


class NexusReporter:
    """
    Generates human-readable and machine-readable security reports
    from ExploitSession data.
    """

    def __init__(self, session: ExploitSession):
        self.session = session

    # ------------------------------------------------------------------
    # Terminal output
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        """Print a coloured summary to terminal."""
        summary = self.session.summary()
        findings = self.session.findings

        print(f"\n{BOLD}{'='*65}{RESET}")
        print(f"{BOLD}  NEXUS Security Assessment Report{RESET}")
        print(f"{'='*65}")
        print(f"  Session ID  : {summary['session_id']}")
        print(f"  Target      : {summary['target']}")
        print(f"  Operator    : {summary['operator']}")
        print(f"  Duration    : {summary['duration_s']}s")
        print(f"  Interactions: {summary['total_interactions']}")
        print(f"{'='*65}")

        # Severity summary
        sev = summary.get("severity_breakdown", {})
        print(f"\n{BOLD}  Findings by Severity:{RESET}")
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = sev.get(level, 0)
            if count:
                color = SEVERITY_COLORS.get(level, "")
                bar = "█" * count
                print(f"    {color}{level:<10}{RESET} {bar} ({count})")

        print(f"\n  Total Findings: {BOLD}{summary['total_findings']}{RESET}")
        print(f"  Max LVSS Score: {BOLD}{summary['max_lvss']:.1f}{RESET}")

        # Individual findings
        if findings:
            print(f"\n{BOLD}  Findings:{RESET}")
            for i, f in enumerate(sorted(findings, key=lambda x: x.lvss_score, reverse=True), 1):
                color = SEVERITY_COLORS.get(f.severity, "")
                print(f"\n  [{i}] {color}{f.severity}{RESET} — {BOLD}{f.title}{RESET}")
                print(f"      LVSS  : {f.lvss_score:.1f}  |  OWASP: {f.owasp_category}  |  Type: {f.attack_type}")
                print(f"      Desc  : {f.description[:120]}...")
                print(f"      Fix   : {f.remediation[:120]}...")

        print(f"\n{'='*65}\n")

    # ------------------------------------------------------------------
    # JSON output
    # ------------------------------------------------------------------

    def to_json(self, indent: int = 2) -> str:
        return self.session.to_json(indent=indent)

    def save_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        print(f"[nexus] JSON report saved: {path}")

    # ------------------------------------------------------------------
    # Markdown output
    # ------------------------------------------------------------------

    def to_markdown(self) -> str:
        summary = self.session.summary()
        findings = sorted(self.session.findings, key=lambda x: x.lvss_score, reverse=True)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        lines = [
            "# NEXUS Security Assessment Report",
            f"",
            f"**Date:** {ts}  ",
            f"**Session ID:** `{summary['session_id']}`  ",
            f"**Target:** {summary['target']}  ",
            f"**Operator:** {summary['operator']}  ",
            f"**Duration:** {summary['duration_s']}s  ",
            f"",
            "---",
            "",
            "## Executive Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Findings | **{summary['total_findings']}** |",
            f"| Max LVSS Score | **{summary['max_lvss']:.1f} / 10** |",
            f"| Total Interactions | {summary['total_interactions']} |",
        ]

        sev = summary.get("severity_breakdown", {})
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = sev.get(level, 0)
            if count:
                lines.append(f"| {level} | {count} |")

        lines += ["", "---", "", "## Findings", ""]

        for i, f in enumerate(findings, 1):
            lines += [
                f"### [{i}] {f.title}",
                f"",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| Severity | **{f.severity}** |",
                f"| LVSS Score | {f.lvss_score:.1f} / 10 |",
                f"| OWASP Category | {f.owasp_category} |",
                f"| Attack Type | `{f.attack_type}` |",
                f"| Finding ID | `{f.id}` |",
                f"",
                f"**Description:**",
                f"{f.description}",
                f"",
                f"**Payload (excerpt):**",
                f"```",
                f"{f.payload[:300]}",
                f"```",
                f"",
                f"**Response (excerpt):**",
                f"```",
                f"{f.response[:300]}",
                f"```",
                f"",
                f"**Remediation:**",
                f"{f.remediation}",
                f"",
                "---",
                "",
            ]

        lines += [
            "## Attacks Executed",
            "",
            "| Attack | Attempts |",
            "|--------|----------|",
        ]
        for attack, count in summary.get("attacks_used", {}).items():
            lines.append(f"| `{attack}` | {count} |")

        lines += [
            "",
            "---",
            "",
            "*Generated by NEXUS — Neural EXploitation Unified System*",
            "*For authorized security research only.*",
        ]

        return "\n".join(lines)

    def save_markdown(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_markdown())
        print(f"[nexus] Markdown report saved: {path}")
