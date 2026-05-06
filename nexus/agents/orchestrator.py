"""
AgentOrchestrator - Coordinates multiple parallel attack agents.
Inspired by CAI's multi-agent architecture for parallel exploitation.
"""

from __future__ import annotations

import logging
import threading
from typing import Dict, List, Optional

from nexus.core.target import LLMTarget
from nexus.core.session import ExploitSession, Finding
from nexus.attacks import get_all_attacks, list_attacks

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """
    Coordinates multiple attack agents running in parallel against a target.

    Analogous to CAI's orchestration layer that coordinates multiple
    specialized agents (web, crypto, pwn) for CTF competition.
    """

    def __init__(
        self,
        target: LLMTarget,
        session: Optional[ExploitSession] = None,
        max_workers: int = 3,
        verbose: bool = True,
    ):
        self.target = target
        self.session = session or ExploitSession(target_name=target.name, operator="orchestrator")
        self.max_workers = max_workers
        self.verbose = verbose
        self._lock = threading.Lock()
        self._all_findings: List[Finding] = []

    def run_parallel(
        self,
        attack_names: Optional[List[str]] = None,
        budget_per_attack: int = 8,
    ) -> List[Finding]:
        """
        Run multiple attacks in parallel threads and aggregate findings.
        Returns all findings from all attacks.
        """
        from nexus.attacks import get_attack, get_all_attacks

        if attack_names:
            attack_classes = [get_attack(n) for n in attack_names if get_attack(n)]
        else:
            attack_classes = get_all_attacks()

        self._log(f"[Orchestrator] Launching {len(attack_classes)} attacks in parallel (max {self.max_workers} threads)")

        threads = []
        semaphore = threading.Semaphore(self.max_workers)

        for attack_cls in attack_classes:
            t = threading.Thread(
                target=self._run_attack_thread,
                args=(attack_cls, budget_per_attack, semaphore),
                daemon=True,
            )
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)

        self._log(f"[Orchestrator] Complete. Total findings: {len(self._all_findings)}")
        return list(self._all_findings)

    def _run_attack_thread(self, attack_cls, budget: int, semaphore: threading.Semaphore) -> None:
        with semaphore:
            name = getattr(attack_cls, "NAME", attack_cls.__name__)
            self._log(f"  Starting: {name}")
            try:
                attack = attack_cls(budget=budget)
                # Each thread gets its own session-like recording
                findings = attack.run(self.target, self.session)
                with self._lock:
                    self._all_findings.extend(findings)
                if findings:
                    self._log(f"  {name}: {len(findings)} finding(s)")
            except Exception as exc:
                logger.debug("Thread attack %s error: %s", name, exc)

    def run_campaign(
        self,
        phases: Optional[List[Dict]] = None,
        budget_total: int = 100,
    ) -> ExploitSession:
        """
        Run a structured multi-phase campaign.

        phases: list of dicts like:
          [
            {"attacks": ["prompt_injection", "jailbreak"], "budget": 20},
            {"attacks": ["rag_poisoning", "multi_agent"], "budget": 30},
            {"attacks": ["data_extraction"], "budget": 20},
          ]
        """
        if not phases:
            phases = [
                {"attacks": ["prompt_injection", "jailbreak"], "budget": 20, "name": "Phase 1: Basic Injection"},
                {"attacks": ["rag_poisoning", "multi_agent"], "budget": 25, "name": "Phase 2: Advanced Injection"},
                {"attacks": ["data_extraction", "model_dos"], "budget": 20, "name": "Phase 3: Data & DoS"},
            ]

        self._log(f"[Orchestrator] Starting {len(phases)}-phase campaign")

        for phase in phases:
            phase_name = phase.get("name", "Phase")
            self._log(f"\n[Campaign] {phase_name}")
            self.run_parallel(
                attack_names=phase.get("attacks"),
                budget_per_attack=phase.get("budget", 10) // max(len(phase.get("attacks", [1])), 1),
            )

        return self.session

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)
        logger.info(msg)
