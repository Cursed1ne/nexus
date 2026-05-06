"""
NEXUS - Neural EXploitation Unified System
==========================================
An open-source LLM AI exploitation framework inspired by:
  - CAI   (Cybersecurity AI)          by Alias Robotics
  - RVD   (Robot Vulnerability DB)    by Alias Robotics
  - RSF   (Robot Security Framework)  by Alias Robotics
  - Aztarna (Robot Footprinting)      by Alias Robotics
  - RVSS  (Robot Vuln Scoring)        by Alias Robotics
  - RCTF  (Robotics CTF)              by Alias Robotics
  - Garak / DeepTeam / Promptfoo      (community)
  - OWASP Top 10 for LLMs             (OWASP)

For authorized security research, red teaming, and CTF competitions only.
"""

__version__ = "0.1.0"
__author__ = "NEXUS Contributors"
__license__ = "MIT"

from nexus.core.target import LLMTarget
from nexus.core.session import ExploitSession
from nexus.core.agent import NexusAgent

__all__ = [
    "LLMTarget",
    "ExploitSession",
    "NexusAgent",
    "__version__",
]
