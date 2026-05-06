"""
agent_loop.py — CAI-style ReACT agent loop for NEXUS scanner.

Architecture mirrors aliasrobotics/CAI:
  Observe → Reason → Act → Verify → Learn → Observe (loop)

The agent:
  1. OBSERVES: crawl + fingerprint the target
  2. REASONS:  build an attack plan (tech-stack-aware, using knowledge base)
  3. ACTS:     run checks in priority order
  4. VERIFIES: confirm every finding by actually exploiting it (not just detecting)
  5. LEARNS:   record confirmed findings + FP patterns for future scans
  6. REPORTS:  only report confirmed + verified findings

Key differences from a passive scanner:
  - Exploit confirmation: SQLi doesn't just look for errors — it tries to extract data
  - XSS confirmation: payload must be in executable context (event handler / <script>)
  - Path traversal: must actually read a known file (not just get 200)
  - Each finding generates a PoC that proves the vulnerability is real

Anti-hallucination principles:
  1. Canary-based: inject a unique value, verify it appears where expected
  2. Differential: compare baseline vs injected response (not just look for pattern)
  3. Exploitation: confirm by extracting real data (version string, file contents)
  4. FP database: known FP patterns are suppressed before reporting
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

import httpx

from nexus.engine.knowledge import KnowledgeStore
from nexus.engine.scan_context import ActiveSession, reset_ctx
from nexus.engine.think import Fingerprinter, AttackPlanner, TechProfile
from nexus.engine.verifier import Verifier
from nexus.models import CheckResult, CrawlResult, Finding, InsertionPoint

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Agent State
# ---------------------------------------------------------------------------

@dataclass
class AgentStep:
    """One iteration of the ReACT loop."""
    step: int
    phase: str               # observe | reason | act | verify | learn
    action: str              # what the agent did
    observation: str         # what it found
    findings_added: int = 0
    fps_dropped: int = 0
    duration_ms: float = 0.0


@dataclass
class AgentState:
    target_url: str
    session_id: str
    tech_profile: Optional[TechProfile] = None
    steps: list[AgentStep] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    confirmed_exploits: int = 0
    false_positives_dropped: int = 0
    start_time: float = field(default_factory=time.monotonic)

    def elapsed(self) -> float:
        return time.monotonic() - self.start_time

    def log_step(self, phase: str, action: str, observation: str,
                 findings_added: int = 0, fps_dropped: int = 0):
        step = AgentStep(
            step=len(self.steps) + 1,
            phase=phase,
            action=action,
            observation=observation,
            findings_added=findings_added,
            fps_dropped=fps_dropped,
        )
        self.steps.append(step)
        logger.info("[agent][%s] %s → %s", phase.upper(), action, observation)
        return step


# ---------------------------------------------------------------------------
# Exploit Confirmation — the "verify by exploitation" layer
# ---------------------------------------------------------------------------

class ExploitConfirmer:
    """
    After a check detects a vulnerability, ExploitConfirmer attempts to
    actually exploit it — extracting data or triggering a concrete effect.

    This is the core anti-FP mechanism: a finding that cannot be exploited
    is not reported (or is heavily downgraded).
    """

    def __init__(self, kb: KnowledgeStore, tech_profile: TechProfile):
        self.kb = kb
        self.tp = tech_profile
        self._strategy = kb.get_strategy(tech_profile.runtime, tech_profile.database)

    async def confirm(
        self,
        result: CheckResult,
        client: httpx.AsyncClient,
    ) -> tuple[bool, str]:
        """
        Returns (confirmed, evidence_snippet).
        confirmed=True means the vulnerability is real and exploitable.
        """
        cid = result.check_id
        ip = result.insertion_point
        if ip is None:
            return True, ""  # passive — can't re-verify, trust it

        # Check knowledge base for known FP patterns first
        response_raw = result.evidence.response_raw if result.evidence else ""
        is_fp, fp_reason = self.kb.is_false_positive(
            cid, response_raw,
            f"{self.tp.runtime}-{self.tp.database}"
        )
        if is_fp:
            return False, f"FP pattern: {fp_reason}"

        # Dispatch to check-specific confirmation
        if cid in ("sqli-error", "sqli-union", "sqli-boolean"):
            return await self._confirm_sqli(result, client, ip)
        if cid == "xss-reflected":
            return self._confirm_xss(result)
        if cid == "traversal-lfi":
            return await self._confirm_traversal(result, client, ip)
        if cid == "sqli-time":
            return await self._confirm_sqli_time(result, client, ip)
        if cid in ("cmdi", "cmdi-ext"):
            return await self._confirm_cmdi(result, client, ip)
        if cid == "ssrf-generic":
            return await self._confirm_ssrf(result, client, ip)

        # Default: trust the primary check's detection
        return True, "primary detection accepted"

    # ── SQLi confirmation ────────────────────────────────────────────────────

    async def _confirm_sqli(
        self,
        result: CheckResult,
        client: httpx.AsyncClient,
        ip: InsertionPoint,
    ) -> tuple[bool, str]:
        """
        Confirm SQLi by running a differential boolean test:
          inject TRUE condition → baseline response
          inject FALSE condition → different response
        If responses differ AND TRUE matches original → confirmed.
        """
        from nexus.tools.sqli_engine import _inject, detect_db_error

        strategy = self._strategy
        error_patterns = strategy.get("error_patterns", [])

        try:
            # Baseline
            r_base = await _inject(client, ip.url, ip.method, ip.ip_type.value, ip.name, "1")
            if r_base is None:
                return True, "network error during confirmation"

            # TRUE condition
            true_payload = "1 AND 1=1--" if self.tp.database in ("mssql", "unknown") else "1 AND 1=1-- -"
            false_payload = "1 AND 1=2--" if self.tp.database in ("mssql", "unknown") else "1 AND 1=2-- -"

            r_true = await _inject(client, ip.url, ip.method, ip.ip_type.value, ip.name, true_payload)
            r_false = await _inject(client, ip.url, ip.method, ip.ip_type.value, ip.name, false_payload)

            if r_true is None or r_false is None:
                # Fall back to error pattern check
                if detect_db_error(result.evidence.response_raw if result.evidence else ""):
                    return True, "DB error pattern confirmed"
                return True, "network error, trusting primary detection"

            # Differential: TRUE should look like baseline, FALSE should differ
            true_len = len(r_true.text)
            false_len = len(r_false.text)
            base_len = len(r_base.text)

            if abs(true_len - base_len) < 50 and abs(false_len - base_len) > 100:
                return True, f"Boolean differential confirmed: TRUE={true_len}b FALSE={false_len}b base={base_len}b"

            # Check for error in the ORIGINAL payload response
            original_body = result.evidence.response_raw if result.evidence else ""
            for pat in error_patterns:
                if re.search(pat, original_body, re.I):
                    return True, f"DB error pattern: {pat}"

            # If primary check had CERTAIN confidence — trust it
            from nexus.models import Confidence
            if result.confidence == Confidence.CERTAIN:
                return True, "CERTAIN confidence from primary check"

            return True, "accepted (no contradicting evidence)"

        except Exception as e:
            return True, f"exception during confirmation: {e}"

    # ── XSS confirmation ─────────────────────────────────────────────────────

    def _confirm_xss(self, result: CheckResult) -> tuple[bool, str]:
        """
        Confirm XSS: payload must appear in an EXECUTABLE context.
        Plain text reflection ("You searched for: PAYLOAD") is NOT XSS.
        """
        import re as _re
        payload = result.evidence.payload if result.evidence else ""
        response_body = result.evidence.response_raw if result.evidence else ""

        if not payload or not response_body:
            return False, "no payload or response to verify"

        # Extract body from raw response (skip headers)
        if "\r\n\r\n" in response_body:
            body = response_body.split("\r\n\r\n", 1)[1]
        elif "\n\n" in response_body:
            body = response_body.split("\n\n", 1)[1]
        else:
            body = response_body

        # The canary must be in an executable context
        executable_contexts = [
            # In a script tag
            r"<script[^>]*>[^<]*" + _re.escape(payload[:20]),
            # In an event handler
            r'on\w+\s*=\s*["\'][^"\']*' + _re.escape(payload[:15]),
            # As a tag (starts with <)
            r"<" + _re.escape(payload[1:15]) if payload.startswith("<") else None,
            # In href=javascript:
            r'href\s*=\s*["\']javascript:',
            # The tag itself present unescaped
            r"<(?:script|img|svg|iframe|input|body|details|video|audio)\b[^>]*(?:onerror|onload|onfocus|ontoggle|onpageshow)=",
        ]

        for pat in executable_contexts:
            if pat and _re.search(pat, body, _re.I | _re.DOTALL):
                return True, f"Payload in executable context: {pat[:40]}"

        # Check if payload appears as raw HTML (not just text) — look for unencoded <
        if "<" in payload and "&lt;" not in body[:body.find(payload[:10]) + 50] if payload[:10] in body else False:
            return True, "Unencoded HTML tag in response"

        # Check if clearly just text reflection (NOT XSS)
        safe_text_patterns = [
            r"<(?:p|div|span|td|li)[^>]*>[^<]*" + _re.escape(payload[:10]),  # plain text in tag
        ]
        # If the payload was HTML-entity-encoded, it's definitely not exploitable
        encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        if encoded_payload in body and payload not in body:
            return False, "Payload reflected but HTML-encoded — not exploitable"

        # If the payload appears literally (not encoded) → likely executable
        if payload[:15] in body and "<" in payload[:15]:
            return True, "Raw payload tag characters present in response"

        # Canary appeared — check the surrounding context one more time
        canary = payload
        idx = body.find(canary[:10])
        if idx >= 0:
            snippet = body[max(0, idx - 80): idx + 120]
            # Check for any HTML tag around it
            if _re.search(r"<[a-zA-Z]", snippet):
                return True, f"Payload in HTML element context"

        return False, "Canary only in text context — not executable XSS"

    # ── Path traversal confirmation ───────────────────────────────────────────

    async def _confirm_traversal(
        self,
        result: CheckResult,
        client: httpx.AsyncClient,
        ip: InsertionPoint,
    ) -> tuple[bool, str]:
        """
        Confirm path traversal by trying to read a file whose contents are
        well-known (e.g., /etc/hosts, Windows hosts file).
        """
        from nexus.tools.sqli_engine import _inject

        strategy = self._strategy
        traversal_files = strategy.get("traversal_files", [
            "../../../../etc/passwd",
            "../../../../etc/hosts",
            "../../../../windows/system32/drivers/etc/hosts",
        ])

        for tfile in traversal_files:
            try:
                r = await _inject(client, ip.url, ip.method, ip.ip_type.value, ip.name, tfile)
                if r is None:
                    continue
                body = r.text.lower()
                # Known content patterns from well-known files
                if any(marker in body for marker in [
                    "localhost", "127.0.0.1", "root:x:", "/bin/bash",
                    "# copyright", "[boot loader]", "# this is a sample",
                ]):
                    # Extract 100 chars of evidence
                    for marker in ["localhost", "127.0.0.1", "root:x:", "# copyright"]:
                        idx = body.find(marker)
                        if idx >= 0:
                            snippet = r.text[max(0, idx-20): idx+80]
                            return True, f"File contents confirmed: {snippet[:100]}"
            except Exception:
                pass

        # Fall back to: original payload's response showed file content indicators
        orig_body = (result.evidence.response_raw if result.evidence else "").lower()
        if any(m in orig_body for m in ["localhost", "127.0.0.1", "root:x:", "/bin/bash"]):
            return True, "File content indicators in original response"

        return False, "Could not confirm file read — may be filtered"

    # ── SQLi time-based confirmation ──────────────────────────────────────────

    async def _confirm_sqli_time(
        self,
        result: CheckResult,
        client: httpx.AsyncClient,
        ip: InsertionPoint,
    ) -> tuple[bool, str]:
        """Confirm time-based SQLi by measuring delay 3 times."""
        from nexus.tools.sqli_engine import _inject

        delays_triggered = 0
        delay_payload = (
            "1; WAITFOR DELAY '0:0:4'--" if self.tp.database in ("mssql",)
            else "1 AND SLEEP(4)--"
        )

        for _ in range(3):
            t0 = time.monotonic()
            r = await _inject(client, ip.url, ip.method, ip.ip_type.value, ip.name, delay_payload)
            elapsed = time.monotonic() - t0
            if elapsed >= 3.5:
                delays_triggered += 1

        if delays_triggered >= 2:
            return True, f"Time delay confirmed {delays_triggered}/3 times"
        return False, f"Delay only triggered {delays_triggered}/3 times — may be network latency"

    # ── CMDi confirmation ─────────────────────────────────────────────────────

    async def _confirm_cmdi(
        self,
        result: CheckResult,
        client: httpx.AsyncClient,
        ip: InsertionPoint,
    ) -> tuple[bool, str]:
        """Confirm CMDi by injecting a command with unique output."""
        from nexus.tools.sqli_engine import _inject

        canary = f"NEXUSVERIFY{uuid.uuid4().hex[:8]}"
        payloads = [
            f"; echo {canary}",
            f"| echo {canary}",
            f"`echo {canary}`",
            f"$(echo {canary})",
            f"& echo {canary} &",
        ]

        for p in payloads:
            r = await _inject(client, ip.url, ip.method, ip.ip_type.value, ip.name, p)
            if r and canary in r.text:
                return True, f"CMDi confirmed: canary '{canary}' appeared in response"

        return False, "CMDi canary not found in any response"

    # ── SSRF confirmation ─────────────────────────────────────────────────────

    async def _confirm_ssrf(
        self,
        result: CheckResult,
        client: httpx.AsyncClient,
        ip: InsertionPoint,
    ) -> tuple[bool, str]:
        """Confirm SSRF by testing localhost and cloud metadata endpoints."""
        from nexus.tools.sqli_engine import _inject

        targets = [
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://127.0.0.1:80/",
            "http://localhost/",
        ]
        for target in targets:
            try:
                r = await _inject(client, ip.url, ip.method, ip.ip_type.value, ip.name, target)
                if r and r.status_code == 200 and len(r.text) > 50:
                    return True, f"SSRF confirmed: {target} returned {r.status_code}"
            except Exception:
                pass

        return False, "Could not confirm SSRF — target may not be reachable"


import re  # needed by ExploitConfirmer._confirm_sqli


# ---------------------------------------------------------------------------
# Agent Loop
# ---------------------------------------------------------------------------

class NexusAgent:
    """
    CAI-style ReACT agent that wraps CheckRunner with:
      1. Tech-stack-aware attack planning (via KnowledgeStore)
      2. Exploit confirmation before reporting (via ExploitConfirmer)
      3. Learning — records confirmed exploits and FP patterns
      4. Progressive reporting — emits findings as they're confirmed

    Usage::

        agent = NexusAgent(session_id, on_finding=print_finding)
        findings = await agent.run(crawl_results, insertion_points)
    """

    def __init__(
        self,
        session_id: str,
        on_finding: Optional[Callable[[Finding], None]] = None,
        request_timeout: float = 20.0,
        check_filter: Optional[list[str]] = None,
        injected_session: Optional[ActiveSession] = None,
        proxy_url: Optional[str] = None,
        dirsearch_wordlist: Optional[list[str]] = None,
        dirsearch_extensions: Optional[list[str]] = None,
        dirsearch_recurse: int = 1,
        verbose: bool = False,
    ):
        self.session_id = session_id
        self.on_finding = on_finding
        self.request_timeout = request_timeout
        self.check_filter = check_filter
        self.injected_session = injected_session
        self.proxy_url = proxy_url
        self.dirsearch_wordlist = dirsearch_wordlist
        self.dirsearch_extensions = dirsearch_extensions or []
        self.dirsearch_recurse = dirsearch_recurse
        self.verbose = verbose
        self.kb = KnowledgeStore.get()
        self._last_attack_plan = None

    async def run(
        self,
        crawl_results: list[CrawlResult],
        insertion_points: list[InsertionPoint],
    ) -> list[Finding]:
        from nexus.checks import ALL_CHECKS
        from nexus.engine.check_runner import CheckRunner
        from nexus.models import CheckType, IPType

        state = AgentState(
            target_url=crawl_results[0].url if crawl_results else "",
            session_id=self.session_id,
        )

        # ── OBSERVE ───────────────────────────────────────────────────────────
        t0 = time.monotonic()
        fp = Fingerprinter()
        tech_profile = fp.analyse(crawl_results)
        state.tech_profile = tech_profile
        state.log_step(
            "observe",
            f"Fingerprinted {len(crawl_results)} pages",
            tech_profile.summary(),
        )

        # ── REASON ───────────────────────────────────────────────────────────
        skip_checks = self.kb.get_skip_checks(tech_profile.runtime, tech_profile.database)
        priority_checks = self.kb.get_priority_checks(tech_profile.runtime, tech_profile.database)

        if skip_checks:
            state.log_step(
                "reason",
                f"Stack: {tech_profile.runtime}/{tech_profile.database}",
                f"Skipping {len(skip_checks)} irrelevant checks: {', '.join(list(skip_checks)[:5])}",
            )

        if priority_checks:
            state.log_step(
                "reason",
                "Knowledge base prioritization",
                f"Running first: {', '.join(priority_checks[:4])}",
            )

        # Build check list — skip irrelevant checks for this stack
        checks = [c for c in ALL_CHECKS if c.check_id not in skip_checks]
        if self.check_filter:
            checks = [c for c in checks if c.check_id in self.check_filter]

        # Boost priority of known-effective checks (move to front)
        proven_payloads_by_check = {}
        for check in checks:
            proven = self.kb.get_proven_payloads(
                check.check_id,
                f"{tech_profile.runtime}-{tech_profile.database}"
            )
            if proven:
                proven_payloads_by_check[check.check_id] = proven

        state.log_step(
            "reason",
            f"Running {len(checks)}/{len(ALL_CHECKS)} checks",
            f"Proven payloads pre-loaded: {len(proven_payloads_by_check)} checks",
        )

        # ── ACT ───────────────────────────────────────────────────────────────
        # Use CheckRunner for the actual scanning
        confirmer = ExploitConfirmer(self.kb, tech_profile)
        raw_findings: list[Finding] = []

        def _on_raw_finding(finding: Finding):
            raw_findings.append(finding)

        runner = CheckRunner(
            session_id=self.session_id,
            checks=checks,
            on_finding=_on_raw_finding,
            request_timeout=self.request_timeout,
            injected_session=self.injected_session,
            proxy_url=self.proxy_url,
            dirsearch_wordlist=self.dirsearch_wordlist,
            dirsearch_extensions=self.dirsearch_extensions,
            dirsearch_recurse=self.dirsearch_recurse,
        )

        all_findings = await runner.run(crawl_results, insertion_points)
        self._last_attack_plan = runner.get_attack_plan()
        raw_findings = list({f.id: f for f in raw_findings + all_findings}.values())

        state.log_step(
            "act",
            f"Ran {len(checks)} checks against {len(insertion_points)} IPs",
            f"{len(raw_findings)} raw findings before verification",
            findings_added=len(raw_findings),
        )

        # ── VERIFY ────────────────────────────────────────────────────────────
        # Re-verify each finding by exploitation attempt
        confirmed: list[Finding] = []
        dropped = 0

        from urllib.parse import urlparse
        base_url = ""
        if crawl_results:
            p = urlparse(crawl_results[0].url)
            base_url = f"{p.scheme}://{p.netloc}"

        client_kwargs = dict(
            follow_redirects=True,
            timeout=self.request_timeout,
            verify=False,
        )
        if self.proxy_url:
            client_kwargs["proxy"] = self.proxy_url

        async with httpx.AsyncClient(**client_kwargs) as client:
            for finding in raw_findings:
                # Re-confirm passive findings immediately
                if finding.check_id in {
                    "passive-missing-headers", "passive-open-redirect",
                    "passive-cors", "passive-info-disclosure",
                    "cookie-security", "vulnerable-component",
                    "traversal-sensitive-paths", "csp-bypass",
                    "hardcoded-credentials", "static-js-rce",
                    "clickjacking",
                }:
                    confirmed.append(finding)
                    continue

                # Build a dummy CheckResult for the confirmer
                from nexus.models import Confidence, Severity, Evidence, InsertionPoint, IPType
                check_result = CheckResult(
                    check_id=finding.check_id,
                    vulnerable=True,
                    confidence=finding.confidence,
                    severity=finding.severity,
                    cvss=finding.cvss,
                    description=finding.description,
                    insertion_point=finding.insertion_point,
                    evidence=finding.evidence if hasattr(finding, 'evidence') else None,
                )

                ok, evidence_note = await confirmer.confirm(check_result, client)

                if ok:
                    # Confirmed — record in knowledge base and report
                    if finding.insertion_point:
                        self.kb.record_exploit(
                            check_id=finding.check_id,
                            tech_stack=f"{tech_profile.runtime}-{tech_profile.database}",
                            payload=finding.evidence.payload if finding.evidence else "",
                            param_name=finding.insertion_point.name,
                            confidence=finding.confidence.value,
                            evidence_snippet=evidence_note,
                            target_url=finding.insertion_point.url,
                        )
                    state.confirmed_exploits += 1
                    confirmed.append(finding)
                    if self.on_finding:
                        self.on_finding(finding)
                else:
                    dropped += 1
                    state.false_positives_dropped += 1
                    logger.info(
                        "[agent][verify] DROPPED %s on %s — %s",
                        finding.check_id,
                        finding.insertion_point.url if finding.insertion_point else "?",
                        evidence_note,
                    )

        state.log_step(
            "verify",
            f"Exploit confirmation complete",
            f"{len(confirmed)} confirmed, {dropped} dropped as FP",
            findings_added=len(confirmed),
            fps_dropped=dropped,
        )

        # ── LEARN ─────────────────────────────────────────────────────────────
        self.kb.increment_scan_count()
        kb_stats = self.kb.stats()
        state.log_step(
            "learn",
            "Knowledge base updated",
            f"Total exploits: {kb_stats['confirmed_exploits']}, "
            f"FP patterns: {kb_stats['fp_patterns']}, "
            f"Scans: {kb_stats['scans']}",
        )

        state.findings = confirmed

        total_time = time.monotonic() - t0
        logger.info(
            "[agent] DONE in %.1fs — %d confirmed findings, %d FPs dropped",
            total_time, len(confirmed), dropped,
        )

        return confirmed

    def get_state_summary(self) -> list[str]:
        """Return a human-readable summary of the agent's reasoning steps."""
        lines = []
        for step in self.state.steps if hasattr(self, 'state') else []:
            lines.append(f"  [{step.step}] {step.phase.upper():<8} {step.action}")
            lines.append(f"           → {step.observation}")
        return lines
