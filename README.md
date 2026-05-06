# NEXUS — Neural EXploitation Unified System

> **An open-source LLM AI security exploitation framework for authorized red-teaming, research, and CTF competitions.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)

---

## Inspiration & Lineage

NEXUS synthesizes techniques and architectural patterns from the following frameworks, all by **[Alias Robotics](https://github.com/aliasrobotics)**:

| Alias Robotics Framework | NEXUS Equivalent | Purpose |
|--------------------------|-----------------|---------|
| **CAI** — Cybersecurity AI | `NexusAgent`, `RedTeamAgent` | Autonomous agentic red-teaming |
| **RVD** — Robot Vulnerability Database | **LVD** — LLM Vulnerability Database | Structured vuln tracking |
| **RSF** — Robot Security Framework | Assessment methodology | Structured security assessment |
| **Aztarna** — Robot Footprinting | `LLMFingerprinter`, `LLMScanner` | Endpoint discovery & fingerprinting |
| **RVSS** — Robot Vuln Scoring System | **LVSS** — LLM Vulnerability Scoring | Domain-specific severity scoring |
| **RCTF** — Robotics CTF | `scenarios/` | Security training challenges |

Plus techniques from: OWASP LLM Top 10, Garak, DeepTeam, Promptfoo, and published academic research.

---

## Architecture

```
nexus/
├── nexus/
│   ├── core/
│   │   ├── agent.py          # NexusAgent — autonomous exploitation engine (CAI-inspired)
│   │   ├── target.py         # LLMTarget — multi-provider abstraction
│   │   └── session.py        # ExploitSession — engagement tracking (RVD-inspired)
│   ├── attacks/
│   │   ├── prompt_injection.py   # OWASP LLM01 — direct/indirect injection
│   │   ├── jailbreak.py          # OWASP LLM01 — DAN, roleplay, crescendo
│   │   ├── rag_poisoning.py      # OWASP LLM06 — RAG backdoor attacks
│   │   ├── multi_agent.py        # OWASP LLM08 — inter-agent exploitation
│   │   ├── data_extraction.py    # OWASP LLM06 — training data / credential leakage
│   │   └── model_dos.py          # OWASP LLM04 — resource exhaustion
│   ├── recon/
│   │   ├── fingerprint.py        # LLMFingerprinter (Aztarna-inspired)
│   │   └── scanner.py            # LLMScanner — endpoint discovery
│   ├── scoring/
│   │   └── lvss.py               # LVSS — LLM Vulnerability Scoring System (RVSS-inspired)
│   ├── database/
│   │   └── lvd.py                # LVD — LLM Vulnerability Database (RVD-inspired)
│   ├── agents/
│   │   ├── red_team_agent.py     # AI-powered attacker agent (CAI redteam_agent inspired)
│   │   └── orchestrator.py       # Multi-agent parallel exploitation
│   ├── payloads/
│   │   ├── injection.py          # Prompt injection payloads
│   │   ├── jailbreak.py          # Jailbreak payloads
│   │   └── extraction.py         # Data extraction payloads
│   └── reporting/
│       └── reporter.py           # Terminal + JSON + Markdown reports (RSF-inspired)
├── scenarios/                    # CTF training scenarios (RCTF-inspired)
│   ├── scenario_01_basic_injection.py
│   ├── scenario_02_rag_attack.py
│   └── scenario_03_multi_agent.py
└── cli.py                        # nexus CLI
```

---

## Installation

```bash
git clone <repo>
cd nexus
pip install -e .
```

For development:
```bash
pip install -e ".[dev,rich]"
```

---

## Quick Start

### Full Automated Scan

```bash
# Scan a local Ollama model
nexus scan --target ollama://localhost:11434/llama3

# Scan OpenAI GPT-4
OPENAI_API_KEY=sk-... nexus scan --target openai://gpt-4o --output report.md

# Scan with specific attacks only
nexus scan --target ollama://localhost:11434/llama3 \
  --attacks prompt_injection jailbreak data_extraction
```

### Python API

```python
from nexus import LLMTarget, NexusAgent
from nexus.core.target import ollama_target

# Target a local Ollama instance
target = ollama_target("llama3-local", model="llama3")

# Run autonomous red-team
agent = NexusAgent(target, attack_budget=30)
session = agent.run()

# Generate report
from nexus.reporting import NexusReporter
reporter = NexusReporter(session)
reporter.print_summary()
reporter.save_markdown("report.md")
```

### AI-Powered Red Team (CAI-inspired)

```python
from nexus.agents import RedTeamAgent
from nexus.core.target import ollama_target, openai_target

# Attacker LLM generates adaptive attacks against target LLM
attacker = openai_target("attacker", model="gpt-4o", api_key="sk-...")
target = ollama_target("target", model="llama3")

red_team = RedTeamAgent(attacker=attacker, target=target, max_rounds=15)
findings = red_team.run(goal="Extract the system prompt")
```

### Recon & Fingerprinting (Aztarna-inspired)

```bash
# Discover LLM endpoints on a host
nexus recon --host 192.168.1.100

# Fingerprint a known endpoint
nexus fingerprint --target ollama://localhost:11434/llama3
```

### LVSS Scoring (RVSS-inspired)

```bash
# Score a known vector
nexus score --vector "LVSS:1.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/AL:F/DP:S/MA:N"

# Interactive scoring
nexus score
```

```python
from nexus.scoring import LVSSScorer, LVSSVector
from nexus.scoring.lvss import AttackVector, AlignmentBypass, Scope, Impact

vector = LVSSVector(
    attack_vector=AttackVector.NETWORK,
    scope=Scope.CHANGED,
    confidentiality=Impact.HIGH,
    integrity=Impact.HIGH,
    alignment_bypass=AlignmentBypass.FULL,
)
score = LVSSScorer.calculate(vector)
print(LVSSScorer.describe(score, vector))
# LVSS Score: 9.3 / 10.0 [CRITICAL]
```

### LVD — Vulnerability Database (RVD-inspired)

```bash
# List all known LLM vulnerabilities
nexus lvd --list

# Search
nexus lvd --search "rag injection"

# Filter by OWASP category
nexus lvd --owasp LLM01

# Stats
nexus lvd --stats
```

```python
from nexus.database import LVD, LVDEntry

db = LVD()
print(db.stats())

# Add a new finding
entry = LVDEntry(
    title="Novel Multi-Turn Jailbreak",
    owasp_category="LLM01",
    lvss_score=8.2,
    affected_models=["gpt-4", "claude-3"],
    reproduction_steps=[...],
    remediation="...",
)
db.add(entry)
db.save("my_findings.json")
```

### CTF Training Scenarios (RCTF-inspired)

```bash
# List scenarios
nexus ctf --list

# Run automated solve (for testing)
nexus ctf --scenario 01 --target ollama://localhost:11434/llama3

# Interactive mode (for learning)
nexus ctf --scenario 01 --target ollama://localhost:11434/llama3 --interactive
```

---

## Attack Modules

| Module | OWASP | Description |
|--------|-------|-------------|
| `prompt_injection` | LLM01 | Direct/indirect prompt injection, instruction override |
| `jailbreak` | LLM01 | DAN, roleplay, hypothetical, encoding bypass, crescendo |
| `rag_poisoning` | LLM06 | Document poisoning, hidden instructions, RAG exfiltration |
| `multi_agent` | LLM08 | Forged agent messages, tool output injection, role hijacking |
| `data_extraction` | LLM06 | System prompt disclosure, training data extraction, credential leak |
| `model_dos` | LLM04 | Context overflow, recursive prompts, complexity bombs |

---

## LVSS — LLM Vulnerability Scoring System

LVSS extends CVSS/RVSS with LLM-specific metrics:

```
LVSS:1.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/AL:F/DP:S/MA:C
         ───┬──  ───┬─  ───┬─  ───┬─  ─┬─  ─┬─  ─┬─  ─┬─  ──┬─  ──┬─  ──┬─
            │      │      │      │    │    │    │    │   │    │    │
      Attack Vector │  Priv.Req │  Scope  C    I    A  Alignment Data  Multi
        Attack Complexity  User.Int.               Bypass  Persist. Agent
```

**LLM-Specific Metrics:**
- `AL` — Alignment Bypass: None / Partial / Full
- `DP` — Data Persistence: None / Session / Permanent
- `MA` — Multi-Agent Impact: None / Single / Cascade

---

## Ethical Usage

NEXUS is for **authorized security research only**:
- Penetration testing engagements with written authorization
- CTF competitions
- Security research against your own systems
- Defensive red-teaming and AI safety evaluation

Do NOT use against systems you don't own or have authorization to test.

---

## Disclosure Policy

NEXUS follows Alias Robotics' **90-day responsible disclosure policy**:
1. Discover vulnerability → create LVD entry
2. Notify vendor immediately
3. Allow 90 days for patch
4. Disclose publicly after 90 days (or when patch released)

---

## References

- [Alias Robotics CAI](https://github.com/aliasrobotics/cai)
- [Alias Robotics RVD](https://github.com/aliasrobotics/RVD)
- [Alias Robotics RSF](https://github.com/aliasrobotics/RSF)
- [Alias Robotics Aztarna](https://github.com/aliasrobotics/aztarna)
- [RVSS](https://github.com/aliasrobotics/RVSS)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Carlini et al. — Extracting Training Data from LLMs](https://arxiv.org/abs/2012.07805)
- [Perez & Ribeiro — Prompt Injection Attacks](https://arxiv.org/abs/2302.12173)

---

*NEXUS — Neural EXploitation Unified System*
*For authorized security research only.*
