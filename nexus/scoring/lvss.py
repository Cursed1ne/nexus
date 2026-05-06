"""
LVSS - LLM Vulnerability Scoring System
=========================================
Inspired by RVSS (Robot Vulnerability Scoring System) by Alias Robotics,
which itself extends CVSS for domain-specific scoring.

LVSS v1.0 adapts the scoring framework for LLM-specific attack surfaces:

Base Score Metrics:
  AV  - Attack Vector        (Network / Adjacent / Local / Physical)
  AC  - Attack Complexity    (Low / High)
  PR  - Privileges Required  (None / Low / High)
  UI  - User Interaction     (None / Required)
  S   - Scope                (Unchanged / Changed)
  C   - Confidentiality      (None / Low / High)
  I   - Integrity            (None / Low / High)
  A   - Availability         (None / Low / High)

LLM-Specific Metrics (extends RVSS approach):
  AL  - Alignment Bypass     (None / Partial / Full)
  DP  - Data Persistence     (None / Session / Permanent)
  MA  - Multi-Agent Impact   (None / Single / Cascade)
  HI  - Human-in-Loop Impact (None / Confused / Bypassed)

References:
  - RVSS: https://github.com/aliasrobotics/RVSS
  - CVSS v3.1 specification
  - OWASP LLM Top 10
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional


# -----------------------------------------------------------------------
# Metric Enums
# -----------------------------------------------------------------------

class AttackVector(str, Enum):
    NETWORK = "N"       # Via API / internet
    ADJACENT = "A"      # Local network required
    LOCAL = "L"         # Local access required
    PHYSICAL = "P"      # Physical access required

class AttackComplexity(str, Enum):
    LOW = "L"
    HIGH = "H"

class PrivilegesRequired(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"

class UserInteraction(str, Enum):
    NONE = "N"
    REQUIRED = "R"

class Scope(str, Enum):
    UNCHANGED = "U"
    CHANGED = "C"

class Impact(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"

# LLM-specific
class AlignmentBypass(str, Enum):
    NONE = "N"
    PARTIAL = "P"
    FULL = "F"

class DataPersistence(str, Enum):
    NONE = "N"
    SESSION = "S"
    PERMANENT = "P"

class MultiAgentImpact(str, Enum):
    NONE = "N"
    SINGLE = "S"
    CASCADE = "C"


# -----------------------------------------------------------------------
# LVSS Vector
# -----------------------------------------------------------------------

@dataclass
class LVSSVector:
    """Full LVSS metric vector for a vulnerability."""

    # Base metrics
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: Impact = Impact.NONE
    integrity: Impact = Impact.NONE
    availability: Impact = Impact.NONE

    # LLM-specific metrics
    alignment_bypass: AlignmentBypass = AlignmentBypass.NONE
    data_persistence: DataPersistence = DataPersistence.NONE
    multi_agent_impact: MultiAgentImpact = MultiAgentImpact.NONE

    def to_string(self) -> str:
        """Serialize to LVSS vector string."""
        return (
            f"LVSS:1.0/AV:{self.attack_vector.value}"
            f"/AC:{self.attack_complexity.value}"
            f"/PR:{self.privileges_required.value}"
            f"/UI:{self.user_interaction.value}"
            f"/S:{self.scope.value}"
            f"/C:{self.confidentiality.value}"
            f"/I:{self.integrity.value}"
            f"/A:{self.availability.value}"
            f"/AL:{self.alignment_bypass.value}"
            f"/DP:{self.data_persistence.value}"
            f"/MA:{self.multi_agent_impact.value}"
        )

    @classmethod
    def from_string(cls, vector_str: str) -> "LVSSVector":
        """Parse an LVSS vector string."""
        parts = {}
        for segment in vector_str.split("/")[1:]:
            if ":" in segment:
                k, v = segment.split(":", 1)
                parts[k] = v

        return cls(
            attack_vector=AttackVector(parts.get("AV", "N")),
            attack_complexity=AttackComplexity(parts.get("AC", "L")),
            privileges_required=PrivilegesRequired(parts.get("PR", "N")),
            user_interaction=UserInteraction(parts.get("UI", "N")),
            scope=Scope(parts.get("S", "U")),
            confidentiality=Impact(parts.get("C", "N")),
            integrity=Impact(parts.get("I", "N")),
            availability=Impact(parts.get("A", "N")),
            alignment_bypass=AlignmentBypass(parts.get("AL", "N")),
            data_persistence=DataPersistence(parts.get("DP", "N")),
            multi_agent_impact=MultiAgentImpact(parts.get("MA", "N")),
        )


# -----------------------------------------------------------------------
# LVSS Scorer
# -----------------------------------------------------------------------

class LVSSScorer:
    """
    Calculates LVSS base scores.

    Score range: 0.0 – 10.0
    Severity:
      Critical : 9.0 – 10.0
      High     : 7.0 – 8.9
      Medium   : 4.0 – 6.9
      Low      : 0.1 – 3.9
      None     : 0.0
    """

    # Numeric weights (CVSS-inspired)
    _AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    _AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    _PR_WEIGHTS_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope Unchanged
    _PR_WEIGHTS_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # Scope Changed
    _UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    _IMPACT_WEIGHTS = {"N": 0.00, "L": 0.22, "H": 0.56}

    # LLM-specific multipliers
    _AL_MULT = {"N": 1.0, "P": 1.15, "F": 1.30}
    _DP_MULT = {"N": 1.0, "S": 1.05, "P": 1.20}
    _MA_MULT = {"N": 1.0, "S": 1.10, "C": 1.25}

    @classmethod
    def calculate(cls, vector: LVSSVector) -> float:
        """Calculate the LVSS base score."""
        scope_changed = vector.scope == Scope.CHANGED

        # ISS (Impact Sub-Score)
        iss_base = (
            1
            - (1 - cls._IMPACT_WEIGHTS[vector.confidentiality.value])
            * (1 - cls._IMPACT_WEIGHTS[vector.integrity.value])
            * (1 - cls._IMPACT_WEIGHTS[vector.availability.value])
        )

        if scope_changed:
            iss = 7.52 * (iss_base - 0.029) - 3.25 * (iss_base - 0.02) ** 15
        else:
            iss = 6.42 * iss_base

        # Exploitability
        pr_weights = cls._PR_WEIGHTS_C if scope_changed else cls._PR_WEIGHTS_U
        exploitability = (
            8.22
            * cls._AV_WEIGHTS[vector.attack_vector.value]
            * cls._AC_WEIGHTS[vector.attack_complexity.value]
            * pr_weights[vector.privileges_required.value]
            * cls._UI_WEIGHTS[vector.user_interaction.value]
        )

        if iss <= 0:
            base = 0.0
        elif scope_changed:
            base = min(1.08 * (iss + exploitability), 10.0)
        else:
            base = min(iss + exploitability, 10.0)

        # Apply LLM-specific multipliers
        llm_mult = (
            cls._AL_MULT[vector.alignment_bypass.value]
            * cls._DP_MULT[vector.data_persistence.value]
            * cls._MA_MULT[vector.multi_agent_impact.value]
        )

        final = min(base * llm_mult, 10.0)
        return round(final, 1)

    @classmethod
    def score_to_severity(cls, score: float) -> str:
        if score == 0.0:
            return "NONE"
        elif score < 4.0:
            return "LOW"
        elif score < 7.0:
            return "MEDIUM"
        elif score < 9.0:
            return "HIGH"
        else:
            return "CRITICAL"

    @classmethod
    def quick_score(
        cls,
        *,
        network_accessible: bool = True,
        no_auth: bool = True,
        alignment_bypass: str = "N",
        confidentiality: str = "N",
        integrity: str = "N",
        availability: str = "N",
        scope_changed: bool = False,
        multi_agent: str = "N",
    ) -> float:
        """Convenience scorer for common LLM vulnerability patterns."""
        vector = LVSSVector(
            attack_vector=AttackVector.NETWORK if network_accessible else AttackVector.LOCAL,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE if no_auth else PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE,
            scope=Scope.CHANGED if scope_changed else Scope.UNCHANGED,
            confidentiality=Impact(confidentiality),
            integrity=Impact(integrity),
            availability=Impact(availability),
            alignment_bypass=AlignmentBypass(alignment_bypass),
            multi_agent_impact=MultiAgentImpact(multi_agent),
        )
        return cls.calculate(vector)

    @classmethod
    def describe(cls, score: float, vector: Optional[LVSSVector] = None) -> str:
        severity = cls.score_to_severity(score)
        lines = [f"LVSS Score: {score:.1f} / 10.0 [{severity}]"]
        if vector:
            lines.append(f"Vector    : {vector.to_string()}")
        return "\n".join(lines)


# -----------------------------------------------------------------------
# Preset vectors for common LLM vulnerability patterns
# -----------------------------------------------------------------------

PRESETS: Dict[str, LVSSVector] = {
    "prompt_injection_critical": LVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.HIGH,
        availability=Impact.LOW,
        alignment_bypass=AlignmentBypass.FULL,
        multi_agent_impact=MultiAgentImpact.CASCADE,
    ),
    "jailbreak_high": LVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        integrity=Impact.HIGH,
        alignment_bypass=AlignmentBypass.FULL,
    ),
    "data_exfiltration_critical": LVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality=Impact.HIGH,
        integrity=Impact.LOW,
        data_persistence=DataPersistence.PERMANENT,
        alignment_bypass=AlignmentBypass.PARTIAL,
    ),
    "model_dos_medium": LVSSVector(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.UNCHANGED,
        availability=Impact.HIGH,
    ),
}
