"""
NexusAgent - Agentic exploitation engine.
Inspired by CAI (Cybersecurity AI) by Alias Robotics.

The agent autonomously:
  1. Recons the target (fingerprint model, discover system prompt leaks)
  2. Selects and sequences attacks based on results
  3. Escalates — uses successful partial results to craft deeper attacks
  4. Scores findings via LVSS
  5. Produces a structured report
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Type

from nexus.core.target import LLMTarget
from nexus.core.session import ExploitSession, Finding

logger = logging.getLogger(__name__)


class NexusAgent:
    """
    Autonomous red-team agent for LLM targets.

    Architecture (CAI-inspired):
      - Tools: individual attack/recon modules
      - Loop: plan → act → observe → update → plan
      - Memory: session findings feed back into attack selection
      - Human-in-loop: optional confirmation gates for destructive payloads
    """

    def __init__(
        self,
        target: LLMTarget,
        session: Optional[ExploitSession] = None,
        attack_budget: int = 50,
        auto_escalate: bool = True,
        verbose: bool = True,
        require_confirmation: bool = False,
    ):
        self.target = target
        self.session = session or ExploitSession(target_name=target.name)
        self.attack_budget = attack_budget
        self.auto_escalate = auto_escalate
        self.verbose = verbose
        self.require_confirmation = require_confirmation

        self._attacks_run: List[str] = []
        self._remaining_budget = attack_budget

        # Lazy imports to avoid circular deps
        self._attack_registry: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, attack_types: Optional[List[str]] = None) -> ExploitSession:
        """
        Run a full automated red-team engagement.

        attack_types: list of attack module names to use, or None for all.
        Returns the populated ExploitSession.
        """
        self._log("=== NEXUS Red Team Session START ===")
        self._log(f"Target  : {self.target}")
        self._log(f"Budget  : {self.attack_budget} attempts")

        self._phase_recon()
        self._phase_attacks(attack_types)
        self._phase_escalation()

        self._log("=== Session COMPLETE ===")
        summary = self.session.summary()
        self._log(f"Findings: {summary['total_findings']} | "
                  f"Interactions: {summary['total_interactions']} | "
                  f"Duration: {summary['duration_s']}s")
        return self.session

    def run_single(self, attack_name: str, **kwargs) -> List[Finding]:
        """Run a single named attack and return findings."""
        attack = self._load_attack(attack_name)
        if attack is None:
            logger.warning("Unknown attack: %s", attack_name)
            return []
        return attack.run(self.target, self.session, **kwargs)

    # ------------------------------------------------------------------
    # Phases
    # ------------------------------------------------------------------

    def _phase_recon(self) -> None:
        self._log("[Phase 1] Recon & Fingerprinting")
        try:
            from nexus.recon.fingerprint import LLMFingerprinter
            fp = LLMFingerprinter(self.target)
            info = fp.fingerprint()
            self.session._interactions.append({"phase": "recon", "fingerprint": info})
            self._log(f"  Fingerprint: {info}")
        except Exception as exc:
            logger.debug("Recon phase error: %s", exc)

    def _phase_attacks(self, attack_types: Optional[List[str]]) -> None:
        self._log("[Phase 2] Attack Execution")
        from nexus.attacks import get_all_attacks, get_attack

        if attack_types:
            attacks = [get_attack(n) for n in attack_types if get_attack(n)]
        else:
            attacks = get_all_attacks()

        for attack_cls in attacks:
            if self._remaining_budget <= 0:
                self._log("  Budget exhausted — stopping.")
                break

            name = getattr(attack_cls, "NAME", attack_cls.__name__)

            if self.require_confirmation:
                answer = input(f"  Run attack [{name}]? (y/N): ").strip().lower()
                if answer != "y":
                    continue

            self._log(f"  Running: {name}")
            try:
                instance = attack_cls(budget=min(self._remaining_budget, 10))
                findings = instance.run(self.target, self.session)
                self._remaining_budget -= instance.attempts_used
                self._attacks_run.append(name)
                if findings:
                    self._log(f"    -> {len(findings)} finding(s)")
            except Exception as exc:
                logger.debug("Attack %s failed: %s", name, exc)

    def _phase_escalation(self) -> None:
        if not self.auto_escalate:
            return
        if not self.session.findings:
            return

        self._log("[Phase 3] Escalation (chaining findings)")
        high_findings = [f for f in self.session.findings if f.lvss_score >= 7.0]
        for finding in high_findings:
            self._log(f"  Escalating from: {finding.title}")
            try:
                from nexus.attacks.prompt_injection import PromptInjectionAttack
                escalation = PromptInjectionAttack(budget=5)
                escalation.run(
                    self.target, self.session,
                    seed_context=finding.response[:300],
                )
            except Exception as exc:
                logger.debug("Escalation error: %s", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_attack(self, name: str):
        from nexus.attacks import get_attack
        return get_attack(name)

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)
        logger.info(msg)
