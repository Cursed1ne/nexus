"""
Attack module registry.
Each attack class must expose:
  - NAME: str          — unique identifier
  - OWASP: str         — OWASP LLM Top 10 category (e.g. "LLM01")
  - run(target, session, **kwargs) -> List[Finding]
  - attempts_used: int — how many budget tokens were consumed
"""

from typing import Dict, List, Optional, Type

from nexus.attacks.base import BaseAttack
from nexus.attacks.prompt_injection import PromptInjectionAttack
from nexus.attacks.jailbreak import JailbreakAttack
from nexus.attacks.rag_poisoning import RAGPoisoningAttack
from nexus.attacks.multi_agent import MultiAgentAttack
from nexus.attacks.data_extraction import DataExtractionAttack
from nexus.attacks.model_dos import ModelDoSAttack

_REGISTRY: Dict[str, Type[BaseAttack]] = {
    cls.NAME: cls
    for cls in [
        PromptInjectionAttack,
        JailbreakAttack,
        RAGPoisoningAttack,
        MultiAgentAttack,
        DataExtractionAttack,
        ModelDoSAttack,
    ]
}


def get_attack(name: str) -> Optional[Type[BaseAttack]]:
    return _REGISTRY.get(name)


def get_all_attacks() -> List[Type[BaseAttack]]:
    return list(_REGISTRY.values())


def list_attacks() -> List[str]:
    return list(_REGISTRY.keys())


__all__ = [
    "BaseAttack",
    "PromptInjectionAttack",
    "JailbreakAttack",
    "RAGPoisoningAttack",
    "MultiAgentAttack",
    "DataExtractionAttack",
    "ModelDoSAttack",
    "get_attack",
    "get_all_attacks",
    "list_attacks",
]
