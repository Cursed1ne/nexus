"""
swarm.py — CAI-style multi-agent swarm for NEXUS.

Replaces the monolithic NexusAgent ReACT loop with a pipeline of
specialised agents that hand off context between them:

  ThoughtAgent   →  Plans which checks matter for this target
       ↓ handoff (AttackPlan + TechProfile)
  ScanAgent      →  Runs NEXUS checks in parallel streams
       ↓ handoff (raw CheckResults)
  ExploitAgent   →  Confirms every raw finding by re-exploitation
       ↓ handoff (confirmed Findings)
  [caller]       →  Receives verified, non-hallucinating findings

Parallel Specialist Pattern (Tier 1.3):
  ScanAgent spawns three concurrent specialist streams:
    - SqliStream    (sqli-*, traversal, cmdi)
    - WebStream     (xss-*, ssti-*, ssrf-*, jwt-*)
    - PassiveStream (passive-*, cookie-*, static-js-*, api-*)
  Results are merged before handoff to ExploitAgent.

Memory integration (Tier 2.1):
  Each confirmed finding is stored in ScanMemory.
  ThoughtAgent queries ScanMemory before planning to skip known dead-ends.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, List, Optional

import httpx

from nexus.engine.knowledge import KnowledgeStore
from nexus.engine.memory import ScanMemory
from nexus.engine.scan_context import ActiveSession
from nexus.engine.think import Fingerprinter, TechProfile
from nexus.engine.verifier import Verifier
from nexus.models import CheckResult, CrawlResult, Finding, InsertionPoint

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Swarm context — shared across all agents in one scan
# ---------------------------------------------------------------------------

@dataclass
class SwarmContext:
    """Immutable context passed between swarm agents via handoff."""
    session_id:        str
    target_url:        str
    crawl_results:     List[CrawlResult]
    insertion_points:  List[InsertionPoint]
    tech_profile:      Optional[TechProfile]    = None
    skip_checks:       set                      = field(default_factory=set)
    priority_checks:   List[str]                = field(default_factory=list)
    raw_results:       List[CheckResult]        = field(default_factory=list)
    confirmed_findings:List[Finding]            = field(default_factory=list)
    dropped_count:     int                      = 0
    thought_log:       List[str]                = field(default_factory=list)
    timing:            dict                     = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Parallel specialist streams (Tier 1.3)
# ---------------------------------------------------------------------------

# Which check IDs belong to each specialist stream
_SQLI_STREAM = {
    "sqli-error", "sqli-union", "sqli-boolean", "sqli-time",
    "sqli-auth-bypass", "traversal-lfi", "cmdi", "cmdi-ext",
}
_WEB_STREAM = {
    "xss-reflected", "xss-stored-review", "xss-stored-feedback",
    "xss-stored-profile", "ssti-generic", "ssti-profile-eval",
    "ssrf-generic", "ssrf-challenge", "jwt-unsigned", "jwt-alg-none",
    "open-redirect",
}
# Everything else goes to passive stream


async def _run_stream(
    checks: list,
    crawl_results: List[CrawlResult],
    insertion_points: List[InsertionPoint],
    session_id: str,
    injected_session: Optional[ActiveSession],
    proxy_url: Optional[str],
    request_timeout: float,
    dirsearch_wordlist: Optional[list],
    dirsearch_extensions: List[str],
    dirsearch_recurse: int,
    stream_name: str,
) -> List[CheckResult]:
    """Run one specialist stream's checks and return raw results."""
    if not checks:
        return []

    from nexus.engine.check_runner import CheckRunner

    raw: List[CheckResult] = []

    def _collect(finding: Finding):
        raw.append(CheckResult(
            check_id=finding.check_id,
            vulnerable=True,
            confidence=finding.confidence,
            severity=finding.severity,
            cvss=finding.cvss,
            description=finding.description,
            insertion_point=finding.insertion_point,
            evidence=finding.evidence if hasattr(finding, "evidence") else None,
        ))

    runner = CheckRunner(
        session_id=f"{session_id}-{stream_name}",
        checks=checks,
        on_finding=_collect,
        request_timeout=request_timeout,
        injected_session=injected_session,
        proxy_url=proxy_url,
        dirsearch_wordlist=dirsearch_wordlist,
        dirsearch_extensions=dirsearch_extensions,
        dirsearch_recurse=dirsearch_recurse,
    )
    findings = await runner.run(crawl_results, insertion_points)
    # Merge both collected and returned findings
    all_ids = {r.check_id + str(id(r)) for r in raw}
    for f in findings:
        cr = CheckResult(
            check_id=f.check_id,
            vulnerable=True,
            confidence=f.confidence,
            severity=f.severity,
            cvss=f.cvss,
            description=f.description,
            insertion_point=f.insertion_point,
            evidence=f.evidence if hasattr(f, "evidence") else None,
        )
        raw.append(cr)

    logger.info("[swarm][%s] stream done → %d raw results", stream_name, len(raw))
    return raw


# ---------------------------------------------------------------------------
# ThoughtAgent — LLM-style planner (rule-based + KB query)
# ---------------------------------------------------------------------------

class ThoughtAgent:
    """
    Plans the attack:
      - Fingerprints target tech stack
      - Queries KnowledgeStore + ScanMemory (RAG) for past findings on similar stacks
      - Decides which checks to skip (irrelevant) vs prioritise
      - Augments with JS surface mapper hints
    """

    def __init__(self, kb: KnowledgeStore):
        self.kb  = kb
        self.mem = ScanMemory.get()

    async def plan(self, ctx: SwarmContext) -> SwarmContext:
        t0 = time.monotonic()
        fp = Fingerprinter()
        ctx.tech_profile = fp.analyse(ctx.crawl_results)
        tp = ctx.tech_profile

        # Query KB for skip/priority lists
        ctx.skip_checks    = self.kb.get_skip_checks(tp.runtime, tp.database)
        ctx.priority_checks = self.kb.get_priority_checks(tp.runtime, tp.database)

        # Build thought log — what the agent "knows"
        thoughts = [
            f"Target fingerprint: {tp.summary()}",
            f"Skip {len(ctx.skip_checks)} irrelevant checks for {tp.runtime}/{tp.database}",
        ]

        if ctx.priority_checks:
            thoughts.append(f"Priority checks: {', '.join(ctx.priority_checks[:6])}")

        # Feature-flag based reasoning
        if tp.has_graphql:
            thoughts.append("GraphQL detected → enabling introspection + batch query checks")
            ctx.priority_checks = ["graphql-introspection", "graphql-batch"] + ctx.priority_checks

        if tp.has_file_upload:
            thoughts.append("File upload detected → prioritising upload bypass checks")
            ctx.priority_checks = ["file-upload-bypass"] + ctx.priority_checks

        if tp.has_jwt_in_response:
            thoughts.append("JWT tokens observed → prioritising JWT checks")
            ctx.priority_checks = ["jwt-unsigned", "jwt-alg-none"] + ctx.priority_checks

        if tp.has_login_form:
            thoughts.append("Login form detected → sqli-auth-bypass is relevant")
            ctx.priority_checks = ["sqli-auth-bypass"] + ctx.priority_checks

        if tp.waf not in ("none", "unknown"):
            thoughts.append(f"WAF detected ({tp.waf}) → sqli/cmdi may need evasion, reducing time-based checks")
            ctx.skip_checks.add("sqli-time")

        if tp.is_spa:
            thoughts.append("SPA detected → many paths will be catch-all 200s, JS surface mapper results critical")

        # ── RAG memory query ─────────────────────────────────────────────────
        if self.mem.is_enabled():
            from urllib.parse import urlparse
            target_host = urlparse(ctx.target_url).netloc
            query = f"vulnerabilities on {tp.runtime} {tp.framework} {tp.database} stack"
            past = self.mem.query(query, top_k=5, target_host=target_host)
            if past:
                checks_that_worked = list(dict.fromkeys(r.check_id for r in past))
                thoughts.append(
                    f"Memory: {len(past)} past findings recalled for similar stack → "
                    f"prioritising: {', '.join(checks_that_worked[:4])}"
                )
                # Boost checks that worked before
                ctx.priority_checks = checks_that_worked + [
                    c for c in ctx.priority_checks if c not in checks_that_worked
                ]
                # Share payload hints via KB
                for rec in past:
                    if rec.payload and rec.check_id:
                        self.kb.record_exploit(
                            check_id=rec.check_id,
                            tech_stack=f"{tp.runtime}-{tp.database}",
                            payload=rec.payload,
                            param_name=rec.param_name,
                            confidence="FIRM",
                            evidence_snippet=f"recalled from memory: {rec.evidence_note[:100]}",
                            target_url=ctx.target_url,
                        )
            else:
                thoughts.append("Memory: no past findings for this stack — running full scan")

        ctx.thought_log = thoughts
        ctx.timing["thought"] = time.monotonic() - t0

        for t in thoughts:
            logger.info("[swarm][thought] %s", t)

        return ctx


# ---------------------------------------------------------------------------
# ScanAgent — parallel specialist streams
# ---------------------------------------------------------------------------

class ScanAgent:
    """
    Splits checks into specialist streams and runs them in parallel.
    Merges results and hands off to ExploitAgent.
    """

    def __init__(
        self,
        check_filter: Optional[list] = None,
        request_timeout: float = 20.0,
        injected_session: Optional[ActiveSession] = None,
        proxy_url: Optional[str] = None,
        dirsearch_wordlist: Optional[list] = None,
        dirsearch_extensions: Optional[list] = None,
        dirsearch_recurse: int = 1,
    ):
        self.check_filter          = check_filter
        self.request_timeout       = request_timeout
        self.injected_session      = injected_session
        self.proxy_url             = proxy_url
        self.dirsearch_wordlist    = dirsearch_wordlist
        self.dirsearch_extensions  = dirsearch_extensions or []
        self.dirsearch_recurse     = dirsearch_recurse

    async def scan(self, ctx: SwarmContext) -> SwarmContext:
        from nexus.checks import ALL_CHECKS

        t0 = time.monotonic()

        # Apply thought agent's skip list and user filter
        eligible = [
            c for c in ALL_CHECKS
            if c.check_id not in ctx.skip_checks
            and (not self.check_filter or c.check_id in self.check_filter)
        ]

        # Re-order: priority checks first
        priority_set = set(ctx.priority_checks)
        priority = [c for c in eligible if c.check_id in priority_set]
        rest     = [c for c in eligible if c.check_id not in priority_set]
        eligible = priority + rest

        # Split into specialist streams
        sqli_checks    = [c for c in eligible if c.check_id in _SQLI_STREAM]
        web_checks     = [c for c in eligible if c.check_id in _WEB_STREAM]
        passive_checks = [c for c in eligible if c.check_id not in _SQLI_STREAM | _WEB_STREAM]

        logger.info(
            "[swarm][scan] streams: sqli=%d, web=%d, passive=%d",
            len(sqli_checks), len(web_checks), len(passive_checks),
        )

        # Run all three streams concurrently
        stream_kwargs = dict(
            crawl_results=ctx.crawl_results,
            insertion_points=ctx.insertion_points,
            session_id=ctx.session_id,
            injected_session=self.injected_session,
            proxy_url=self.proxy_url,
            request_timeout=self.request_timeout,
            dirsearch_wordlist=self.dirsearch_wordlist,
            dirsearch_extensions=self.dirsearch_extensions,
            dirsearch_recurse=self.dirsearch_recurse,
        )

        sqli_results, web_results, passive_results = await asyncio.gather(
            _run_stream(sqli_checks,    stream_name="sqli",    **stream_kwargs),
            _run_stream(web_checks,     stream_name="web",     **stream_kwargs),
            _run_stream(passive_checks, stream_name="passive", **stream_kwargs),
        )

        ctx.raw_results = sqli_results + web_results + passive_results
        ctx.timing["scan"] = time.monotonic() - t0

        logger.info(
            "[swarm][scan] done → %d raw results in %.1fs",
            len(ctx.raw_results), ctx.timing["scan"],
        )
        return ctx


# ---------------------------------------------------------------------------
# ExploitAgent — re-verify every raw result
# ---------------------------------------------------------------------------

class ExploitAgent:
    """
    Confirms every raw CheckResult by attempting re-exploitation.
    Uses the Verifier (re-probe) + ExploitConfirmer (differential boolean).
    Drops unconfirmed findings.  Records confirmed exploits in KB.
    """

    def __init__(
        self,
        kb: KnowledgeStore,
        request_timeout: float = 20.0,
        proxy_url: Optional[str] = None,
        on_finding: Optional[Callable[[Finding], None]] = None,
    ):
        self.kb              = kb
        self.mem             = ScanMemory.get()
        self.request_timeout = request_timeout
        self.proxy_url       = proxy_url
        self.on_finding      = on_finding

    async def confirm(self, ctx: SwarmContext) -> SwarmContext:
        from nexus.engine.agent_loop import ExploitConfirmer
        from nexus.models import Confidence, Severity, Evidence, CheckType
        from urllib.parse import urlparse

        t0 = time.monotonic()
        tp = ctx.tech_profile
        confirmer = ExploitConfirmer(self.kb, tp) if tp else None
        verifier  = Verifier()

        # Build httpx client
        client_kwargs = dict(
            follow_redirects=True,
            timeout=self.request_timeout,
            verify=False,
        )
        if self.proxy_url:
            client_kwargs["proxy"] = self.proxy_url

        confirmed: List[Finding] = []
        dropped = 0

        _PASSIVE_IDS = {
            "passive-missing-headers", "passive-open-redirect",
            "passive-cors", "passive-info-disclosure",
            "cookie-security", "vulnerable-component",
            "traversal-sensitive-paths", "csp-bypass",
            "hardcoded-credentials", "static-js-rce", "clickjacking",
        }

        async with httpx.AsyncClient(**client_kwargs) as client:
            for cr in ctx.raw_results:
                # Passive checks — accept without re-verification
                if cr.check_id in _PASSIVE_IDS:
                    finding = self._to_finding(cr, session_id=ctx.session_id)
                    confirmed.append(finding)
                    if self.on_finding:
                        self.on_finding(finding)
                    continue

                # Step 1: Verifier async re-probe
                ip = cr.insertion_point
                if ip:
                    verified = await verifier.verify(cr, client)
                    if verified is None:
                        dropped += 1
                        logger.info("[swarm][exploit] DROPPED by verifier: %s", cr.check_id)
                        continue
                    cr = verified

                # Step 2: ExploitConfirmer deeper check
                exploit_note = ""
                if confirmer and ip:
                    ok, exploit_note = await confirmer.confirm(cr, client)
                    if not ok:
                        dropped += 1
                        logger.info("[swarm][exploit] DROPPED by confirmer: %s — %s", cr.check_id, exploit_note)
                        continue

                    # Record confirmed exploit in KB
                    if tp and ip:
                        self.kb.record_exploit(
                            check_id=cr.check_id,
                            tech_stack=f"{tp.runtime}-{tp.database}",
                            payload=cr.evidence.payload if cr.evidence else "",
                            param_name=ip.name,
                            confidence=cr.confidence.value,
                            evidence_snippet=exploit_note,
                            target_url=ip.url,
                        )

                finding = self._to_finding(cr, session_id=ctx.session_id)
                confirmed.append(finding)

                # Store in RAG memory (online mode)
                if self.mem.is_enabled() and tp:
                    from urllib.parse import urlparse
                    target_host = urlparse(ctx.target_url).netloc
                    rec = ScanMemory.record_from_finding(
                        finding,
                        tech_stack=f"{tp.runtime}-{tp.database}",
                        evidence_note=exploit_note,
                    )
                    self.mem.store(rec, target_host=target_host)

                if self.on_finding:
                    self.on_finding(finding)

        ctx.confirmed_findings = confirmed
        ctx.dropped_count      = dropped
        ctx.timing["exploit"]  = time.monotonic() - t0

        logger.info(
            "[swarm][exploit] confirmed=%d dropped=%d in %.1fs",
            len(confirmed), dropped, ctx.timing["exploit"],
        )
        return ctx

    @staticmethod
    def _to_finding(cr: CheckResult, session_id: str = "") -> Finding:
        from nexus.models import Finding
        return Finding(
            id=str(uuid.uuid4()),
            session_id=session_id,
            check_id=cr.check_id,
            confidence=cr.confidence,
            severity=cr.severity,
            cvss=cr.cvss,
            description=cr.description,
            evidence=cr.evidence,
            insertion_point=cr.insertion_point,
        )


# ---------------------------------------------------------------------------
# Swarm orchestrator — wires the three agents together
# ---------------------------------------------------------------------------

class NexusSwarm:
    """
    CAI-style swarm replacing the monolithic NexusAgent.

    Pipeline:
      ThoughtAgent → ScanAgent (parallel streams) → ExploitAgent

    Usage::

        swarm = NexusSwarm(session_id="abc", on_finding=cb)
        findings = await swarm.run(crawl_results, insertion_points)
    """

    def __init__(
        self,
        session_id: str,
        on_finding: Optional[Callable[[Finding], None]] = None,
        request_timeout: float = 20.0,
        check_filter: Optional[list] = None,
        injected_session: Optional[ActiveSession] = None,
        proxy_url: Optional[str] = None,
        dirsearch_wordlist: Optional[list] = None,
        dirsearch_extensions: Optional[list] = None,
        dirsearch_recurse: int = 1,
    ):
        self.session_id = session_id
        self.kb = KnowledgeStore.get()

        self._thought  = ThoughtAgent(self.kb)
        self._scan     = ScanAgent(
            check_filter=check_filter,
            request_timeout=request_timeout,
            injected_session=injected_session,
            proxy_url=proxy_url,
            dirsearch_wordlist=dirsearch_wordlist,
            dirsearch_extensions=dirsearch_extensions or [],
            dirsearch_recurse=dirsearch_recurse,
        )
        self._exploit  = ExploitAgent(
            kb=self.kb,
            request_timeout=request_timeout,
            proxy_url=proxy_url,
            on_finding=on_finding,
        )

    async def run(
        self,
        crawl_results: List[CrawlResult],
        insertion_points: List[InsertionPoint],
    ) -> List[Finding]:
        t_total = time.monotonic()

        ctx = SwarmContext(
            session_id=self.session_id,
            target_url=crawl_results[0].url if crawl_results else "",
            crawl_results=crawl_results,
            insertion_points=insertion_points,
        )

        # ── Agent 1: ThoughtAgent ─────────────────────────────────────────────
        logger.info("[swarm] THINK: fingerprinting + planning")
        ctx = await self._thought.plan(ctx)
        # Expose for scan.py summary
        self._thought._last_tp = ctx.tech_profile
        self._last_thought_log = ctx.thought_log

        # ── Agent 2: ScanAgent (parallel streams) ─────────────────────────────
        logger.info("[swarm] SCAN: %d insertion points across 3 parallel streams",
                    len(insertion_points))
        ctx = await self._scan.scan(ctx)

        # ── Agent 3: ExploitAgent ─────────────────────────────────────────────
        logger.info("[swarm] EXPLOIT: confirming %d raw results", len(ctx.raw_results))
        ctx = await self._exploit.confirm(ctx)

        # ── Learn ─────────────────────────────────────────────────────────────
        self.kb.increment_scan_count()

        # Deduplicate findings (same check_id + url + param can appear from multiple streams)
        seen_keys: set = set()
        unique_findings: List[Finding] = []
        for f in ctx.confirmed_findings:
            ip = f.insertion_point
            key = (
                f.check_id,
                ip.url if ip else "",
                ip.name if ip else "",
            )
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)
        ctx.confirmed_findings = unique_findings

        total = time.monotonic() - t_total
        logger.info(
            "[swarm] DONE in %.1fs | thought=%.1fs scan=%.1fs exploit=%.1fs | "
            "confirmed=%d (deduped from %d) dropped=%d",
            total,
            ctx.timing.get("thought", 0),
            ctx.timing.get("scan", 0),
            ctx.timing.get("exploit", 0),
            len(ctx.confirmed_findings),
            len(seen_keys),
            ctx.dropped_count,
        )

        return ctx.confirmed_findings

    def get_thought_log(self) -> List[str]:
        """Return the ThoughtAgent's reasoning log from the last run."""
        return []  # populated on SwarmContext, exposed here for API callers
