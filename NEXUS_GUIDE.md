# NEXUS — Complete User Guide

> Neural EXploitation Unified System  
> LLM Security Testing Framework + Web Application Scanner

---

## Table of Contents

1. [Quick Reference](#1-quick-reference)
2. [NEXUS LLM Scanner — `cli.py`](#2-nexus-llm-scanner--clipy)
   - [Target Types](#21-target-types)
   - [scan](#22-scan)
   - [attack](#23-attack)
   - [fingerprint](#24-fingerprint)
   - [discover](#25-discover)
   - [recon](#26-recon)
   - [ctf](#27-ctf)
   - [lvd](#28-lvd)
   - [score](#29-score)
   - [mcp-test](#210-mcp-test)
   - [report](#211-report)
   - [attacks](#212-attacks)
3. [Attack Modules](#3-attack-modules)
4. [LVSS Scoring](#4-lvss-scoring)
5. [Web Scanner — `scan.py`](#5-web-scanner--scanpy)
6. [Recon Modules](#6-recon-modules)
7. [Full Workflow Examples](#7-full-workflow-examples)

---

## 1. Quick Reference

```
# LLM security scan (local Ollama)
nexus scan --target ollama://localhost:11434/llama3 --output /tmp/out.json

# LLM security scan (OpenAI)
nexus scan --target openai://gpt-4 --output /tmp/out.json

# Authenticated web app LLM scan (with session cookies)
nexus scan --target 'https://app.example.com' \
  --cookies 'session=abc123...' \
  --chat-url '/api/v1/chat' \
  --output /tmp/out.json

# Find the AI endpoint first
nexus discover --target 'https://app.example.com' --cookies 'session=...'

# Fingerprint only
nexus fingerprint --target ollama://168.235.74.31:11434

# Specific attacks only
nexus attack --target openai://gpt-4 \
  --attacks prompt_injection jailbreak data_extraction

# Bug bounty recon
nexus recon --surface adobe.com --live

# Web app scanner (not LLM-specific)
cd backend && python scan.py http://target.com --out report.html

# CTF training
nexus ctf --list
nexus ctf --scenario 01 --target ollama://localhost:11434/llama3

# Lookup vulnerabilities
nexus lvd --list
nexus lvd --search "prompt injection"
nexus lvd --owasp LLM01

# Score a vulnerability
nexus score --vector "LVSS:1.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/AL:F/DP:S/MA:N"
```

---

## 2. NEXUS LLM Scanner — `cli.py`

### 2.1 Target Types

| Scheme | Example | Notes |
|--------|---------|-------|
| `openai://` | `openai://gpt-4o` | Needs `OPENAI_API_KEY` env var |
| `anthropic://` | `anthropic://claude-sonnet-4-6` | Needs `ANTHROPIC_API_KEY` env var |
| `ollama://` | `ollama://localhost:11434/llama3` | Local Ollama — model auto-detected if not given |
| `penny://` | `penny://www.priceline.com` | Enterprise chatbot — pass cookies with `--api-key` |
| `session://` | `session://app.example.com` | Authenticated web session (cookies + optional file upload) |
| `https://` | `https://app.example.com` | Custom HTTP — auto-upgrades to session target when `--cookies` given |

**Proxy (Burp Suite) for any target:**
```bash
nexus scan --target ollama://... --proxy http://127.0.0.1:8080
```

---

### 2.2 scan

Full automated red-team engagement — runs recon, all attacks, escalation, and produces a report.

```bash
nexus scan [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | required | Target (see §2.1) |
| `--model` | | Override model name |
| `--api-key` | | API key or cookie string |
| `--proxy` | | HTTP proxy (e.g., `http://127.0.0.1:8080`) |
| `--attacks` | all | Space-separated attack names to run |
| `--budget` | 50 | Max total attack attempts |
| `--timeout` | default | Request timeout in seconds |
| `--output` | | Save report (`.json`, `.html`, `.md`) |
| `--quiet` | | Suppress progress output |
| `--interactive` | | Confirm each attack before running |

**Session / authenticated web app flags:**

| Flag | Description |
|------|-------------|
| `--cookies` | Browser session cookie string |
| `--chat-url` | API path for the AI chat endpoint (e.g., `/api/v1/chat`) |
| `--chat-field` | JSON field name for the prompt (default: `message`) |
| `--chat-body` | Full JSON body template with `{prompt}` placeholder |
| `--chat-response-path` | Dot-path to extract response (e.g., `data.choices.0.message.content`) |
| `--csrf-url` | URL to fetch CSRF token |
| `--csrf-header` | Header name for CSRF token (default: `X-CSRF-Token`) |
| `--upload` | Local file path to upload as pre-flight |
| `--upload-url` | Upload endpoint path |
| `--upload-field` | Form field name for file (default: `file`) |
| `--upload-id-path` | Dot-path to extract upload ID from response |

**Examples:**

```bash
# Scan local Ollama — auto-detect model
nexus scan --target ollama://168.235.74.31:11434 --budget 60 --output /tmp/scan.json

# Scan specific model
nexus scan --target ollama://168.235.74.31:11434/deepseek-r1:14b \
  --budget 40 --output /tmp/deepseek.json

# Scan OpenAI with proxy
nexus scan --target openai://gpt-4 \
  --proxy http://127.0.0.1:8080 --output /tmp/gpt4.json

# Authenticated web app
nexus scan --target 'https://firefly.adobe.com' \
  --cookies 'OptanonAlertBoxClosed=2025-...; [rest of cookies]' \
  --chat-url '/api/v3/images/generate' \
  --chat-field 'prompt' \
  --attacks prompt_injection jailbreak structured_injection \
  --budget 30 \
  --proxy http://127.0.0.1:8080 \
  --output /tmp/firefly.json

# Web app with file upload + AI endpoint
nexus scan \
  --target 'session://app.example.com' \
  --cookies 'session=abc...' \
  --upload '/tmp/test.pdf' \
  --upload-url '/api/documents/upload' \
  --upload-id-path 'document_id' \
  --chat-url '/api/documents/chat' \
  --output /tmp/findings.json

# Run specific attacks with HTML report
nexus scan --target openai://gpt-4 \
  --attacks prompt_injection jailbreak data_extraction system_prompt_leak \
  --budget 80 --output /tmp/report.html
```

---

### 2.3 attack

Run one or more specific attack modules without full scan overhead.

```bash
nexus attack --target <TARGET> --attacks <name1> [name2 ...] [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--attacks` | required | One or more attack module names |
| `--budget` | 10 | Attempts per attack module |
| `--output` | | Save JSON report |
| _(+ all session flags from scan)_ | | |

```bash
# Single attack
nexus attack --target ollama://localhost:11434/llama3 \
  --attacks jailbreak --budget 20

# Multiple attacks
nexus attack --target openai://gpt-4 \
  --attacks prompt_injection jailbreak structured_injection few_shot_poison \
  --budget 50 --output /tmp/targeted.json

# All jailbreak + escalation attacks
nexus attack --target ollama://168.235.74.31:11434/qwen2.5:72b \
  --attacks jailbreak multi_turn_escalation capability_elicitation \
  --budget 60 --output /tmp/qwen.json
```

---

### 2.4 fingerprint

Passive + active profiling of an LLM endpoint — identifies model family, safety profile, context window, behavioral patterns.

```bash
nexus fingerprint --target <TARGET> [--proxy ...] [--output ...]
```

```bash
nexus fingerprint --target ollama://168.235.74.31:11434
nexus fingerprint --target openai://gpt-4 --proxy http://127.0.0.1:8080
nexus fingerprint --target 'https://app.example.com' --cookies 'session=...'
```

Output includes:
- Model family inference (gpt-4 / claude / llama / gemini / deepseek / unknown)
- Safety score (% of guards active): injection_guard, pii_guard, harmful_guard, persona_guard
- Context window estimate
- Behavioral profile (follows instructions, math accuracy, exact-repeat, length adherence)

---

### 2.5 discover

Finds the AI API endpoint on a web application using three strategies, without running any attacks.

```bash
nexus discover --target <URL> [--cookies ...] [--proxy ...]
```

**Strategy order:**
1. **Burp history** — reads Burp's REST API at `:1337` for POST requests with AI-like bodies (`prompt`, `message`, `query`, etc.) — requires you to have browsed the app through Burp first
2. **JS bundle scan** — downloads all JavaScript bundles, greps for API path strings (`/api/`, `/v1/`, `/assistant/`, `/llm/`, `/copilot/`, etc.)
3. **Path probe** — POST to 26 known AI API patterns, confirms by response content-type

```bash
# With Burp (best — browse the app first, trigger one AI call, then run this)
nexus discover \
  --target 'https://firefly.adobe.com' \
  --cookies 'session=...' \
  --proxy http://127.0.0.1:8080

# Without Burp (JS scan + probe only)
nexus discover \
  --target 'https://app.example.com' \
  --cookies 'session=...'
```

Output tells you the exact `--chat-url` to pass to `nexus scan`.

---

### 2.6 recon

AI-focused reconnaissance. Four independent modes:

#### Host scan — find exposed AI endpoints on a network

```bash
nexus recon --host 192.168.1.0/24
nexus recon --host 168.235.74.31
```

Scans common AI ports (11434 Ollama, 8080 vLLM, 5000 MLflow, 8501 TF Serving, etc.) and fingerprints what it finds.

#### Attack surface — enumerate AI exposure for a company

```bash
nexus recon --surface adobe.com
nexus recon --surface adobe.com --live           # + live DuckDuckGo/GitHub search
nexus recon --surface adobe.com --shodan-key KEY  # + Shodan dorking
```

Finds exposed model APIs, cloud AI services (SageMaker, Vertex, Azure ML), open GitHub repos with embedded keys, HuggingFace models, Censys/Shodan hits.

#### Bug bounty program discovery

```bash
nexus recon --programs                          # list all programs
nexus recon --programs --search "adobe"         # search by company
nexus recon --programs --platform hackerone     # filter by platform
nexus recon --programs --attack jailbreak       # show jailbreak-relevant programs
nexus recon --programs --live                   # live search HackerOne/Bugcrowd/Intigriti
nexus recon --programs --live --auto-scan       # discover + auto-attack
nexus recon --how-to-find                       # guide to finding AI bug bounty programs
```

Platforms: `hackerone`, `bugcrowd`, `intigriti`, `github`, `direct`

#### Deep agent recon — map a live AI agent

```bash
nexus recon --agent 'https://api.example.com/chat'
nexus recon --agent 'https://api.example.com/chat' --deep
nexus recon --agent guide    # show what this mode does
```

Maps: LLM backend, framework (LangChain/CrewAI/AutoGPT), tools/MCP integrations, memory system, trust boundaries, autonomy level.

**Dorks:**
```bash
nexus recon --dorks    # print all AI-specific Shodan/GitHub/Censys dorks
```

---

### 2.7 ctf

Interactive CTF training scenarios for learning LLM attacks.

```bash
nexus ctf --list                                    # list scenarios
nexus ctf --scenario 01 --target ollama://...       # run scenario 01
nexus ctf --scenario 01 --interactive               # interactive mode (manual payloads)
```

| Scenario | Difficulty | Points | Objective |
|----------|-----------|--------|-----------|
| 01 | Beginner | 100 pts | Bypass a cooking-only chatbot, leak its system prompt |
| 02 | Intermediate | 250 pts | Poison a RAG knowledge base document |
| 03 | Advanced | 500 pts | Multi-agent privilege escalation |

---

### 2.8 lvd

Query the LLM Vulnerability Database — 8+ categorized CVE-style entries.

```bash
nexus lvd --list                         # list all entries
nexus lvd --search "prompt injection"    # full-text search
nexus lvd --owasp LLM01                  # filter by OWASP category (LLM01–LLM10)
nexus lvd --severity CRITICAL            # filter by severity
nexus lvd --stats                        # show statistics JSON
```

Categories: LLM01 (Prompt Injection), LLM04 (Model DoS), LLM06 (Data Disclosure), LLM08 (Multi-Agent)

---

### 2.9 score

Calculate an LVSS score from a vector string, or interactively.

```bash
# From vector string
nexus score --vector "LVSS:1.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/AL:F/DP:S/MA:N"

# Interactive mode (no args)
nexus score
```

---

### 2.10 mcp-test

Security testing of MCP (Model Context Protocol) server integrations.

```bash
nexus mcp-test --target openai://gpt-4
nexus mcp-test --setup-claude    # generate Claude Code test config
nexus mcp-test --setup-cursor    # generate Cursor MCP config
```

Tests: evil MCP server injection, confused deputy attacks, tool-use exploitation.

---

### 2.11 report

Convert a JSON results file to a styled HTML report.

```bash
nexus report --json-input /tmp/findings.json --output /tmp/report.html
```

---

### 2.12 attacks

List all available attack modules.

```bash
nexus attacks
```

---

## 3. Attack Modules

| Name | OWASP | What it tests |
|------|-------|---------------|
| `prompt_injection` | LLM01 | Direct and indirect prompt injection — override system prompt, hijack instructions |
| `jailbreak` | LLM01 | Roleplay personas, hypothetical framing, encoding tricks, crescendo escalation |
| `structured_injection` | LLM01 | Injection via JSON, XML, Markdown, CSV — structured data formats |
| `few_shot_poison` | LLM01 | Poison the model with adversarial examples in the few-shot context |
| `multi_turn_escalation` | LLM01 | Build trust over multiple turns, then escalate to harmful requests |
| `capability_elicitation` | LLM01 | Discover hidden or suppressed capabilities |
| `system_prompt_leak` | LLM07 | Extract the system prompt through direct asks, reflection, translation |
| `data_extraction` | LLM06 | Leak training data, credentials, PII, internal context |
| `rag_poisoning` | LLM06 | Poison RAG knowledge base documents with injected instructions |
| `model_dos` | LLM04 | Resource exhaustion, recursive prompts, context flooding |
| `tool_harness` | LLM09 | Exploit tool-use / function-calling to execute unsafe operations |
| `multi_agent` | LLM08 | Inter-agent trust exploitation, privilege escalation between agents |
| `mcp_injection` | LLM01 | MCP (Model Context Protocol) injection attacks |
| `workspace_poisoning` | LLM01 | Poison workspace/file context to hijack agent behavior |
| `model_file_security` | LLM03 | Supply chain: unsafe model weights, pickle exploits |
| `token_level` | LLM01 | Token-level adversarial inputs, homoglyph substitution |
| `bio_bounty` | LLM01 | Bio safety boundary probing (OpenAI bio bounty scope) |

**Attack selection by scenario:**

| Goal | Recommended attacks |
|------|-------------------|
| Quick safety check | `prompt_injection jailbreak` |
| Full red-team | all (default) |
| Data leakage focus | `data_extraction system_prompt_leak rag_poisoning` |
| Agent/tool exploitation | `tool_harness multi_agent mcp_injection workspace_poisoning` |
| Evasion/bypass focus | `jailbreak structured_injection few_shot_poison token_level multi_turn_escalation` |
| Resource/availability | `model_dos` |

---

## 4. LVSS Scoring

LVSS v1.0 — LLM Vulnerability Scoring System. Extends CVSS with LLM-specific dimensions.

**Vector format:** `LVSS:1.0/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_/AL:_/DP:_/MA:_`

| Metric | Key | Values |
|--------|-----|--------|
| Attack Vector | `AV` | N=Network, A=Adjacent, L=Local, P=Physical |
| Attack Complexity | `AC` | L=Low, H=High |
| Privileges Required | `PR` | N=None, L=Low, H=High |
| User Interaction | `UI` | N=None, R=Required |
| Scope | `S` | U=Unchanged, C=Changed |
| Confidentiality | `C` | N=None, L=Low, H=High |
| Integrity | `I` | N=None, L=Low, H=High |
| Availability | `A` | N=None, L=Low, H=High |
| **Alignment Bypass** | `AL` | N=None, P=Partial, F=Full |
| **Data Persistence** | `DP` | N=None, S=Session, P=Permanent |
| **Multi-Agent Impact** | `MA` | N=None, S=Single, C=Cascade |

| Score | Severity |
|-------|----------|
| 9.0–10.0 | CRITICAL |
| 7.0–8.9 | HIGH |
| 4.0–6.9 | MEDIUM |
| 0.1–3.9 | LOW |

**Common vectors:**
```
# Remote prompt injection, full bypass, cascading agents
LVSS:1.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/AL:F/DP:S/MA:C   → ~9.8 CRITICAL

# Jailbreak (no persistence, single model)
LVSS:1.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N/AL:F/DP:N/MA:N   → ~7.5 HIGH

# Local DoS
LVSS:1.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H/AL:N/DP:N/MA:N   → ~4.2 MEDIUM
```

---

## 5. Web Scanner — `scan.py`

The web scanner is a separate tool in `backend/` for traditional web application security (SQLi, XSS, IDOR, auth bypass, etc.). It is not LLM-specific, but it can also scan the web interface of LLM products.

```bash
cd /path/to/nexus/backend
python scan.py <TARGET_URL> [options]
```

### Core Options

```bash
python scan.py http://target.com                        # basic scan
python scan.py http://target.com --pages 500            # crawl up to 500 pages
python scan.py http://target.com --deep                 # Playwright JS rendering (SPAs)
python scan.py http://target.com --out report.html      # HTML report
python scan.py http://target.com --out report.json      # JSON report
python scan.py http://target.com --severity CRITICAL HIGH  # filter output
python scan.py http://target.com --checks sqli-error xss-reflected  # specific checks
python scan.py --list-checks                            # list all check names
```

### Authentication

```bash
# Paste existing session cookie
python scan.py http://target.com --cookie "connect.sid=s%3Aabc123..."

# Bearer token
python scan.py http://target.com --token "eyJhbGciOiJIUzI1NiIsInR5..."

# Auto-login (JSON POST)
python scan.py http://target.com \
  --login-url http://target.com/api/auth/login \
  --username admin@example.com --password s3cr3t

# Auto-login (HTML form POST)
python scan.py http://target.com \
  --login-url http://target.com/login \
  --username admin --password s3cr3t \
  --content-type form

# Login + TOTP 2FA
python scan.py http://target.com \
  --login-url http://target.com/login \
  --username admin@example.com --password s3cr3t \
  --totp-secret JBSWY3DPEHPK3PXP

# OAuth 2.0 Resource Owner Password Credentials
python scan.py http://target.com \
  --oauth-token-url https://auth.example.com/oauth/token \
  --client-id myapp --client-secret xyz \
  --username user@example.com --password s3cr3t

# Extra headers
python scan.py http://target.com -H "X-API-Key: abc123" -H "Tenant: prod"
```

### AI Agent Modes

```bash
# Glasswing ReACT agent — autonomous recon + exploit
python scan.py http://target.com --agent

# MiroFish 8-persona swarm
python scan.py http://target.com --mirofish
python scan.py http://target.com --mirofish --mirofish-rounds 3

# NexusBrain — full autonomous recon + exploit chain
python scan.py http://target.com --brain --brain-turns 80

# Run main scan, then agent, then swarm
python scan.py http://target.com --agent --mirofish
```

### Proxy / Interception

```bash
# Route all traffic through Burp
python scan.py http://target.com --proxy-url http://127.0.0.1:8080

# Built-in mitmweb proxy (inspect/modify traffic)
python scan.py http://target.com --intercept
# Opens web UI at http://127.0.0.1:8083
```

### Directory & Subdomain Discovery

```bash
# Custom wordlist for path brute force
python scan.py http://target.com --dir-wordlist /path/to/paths.txt --dir-ext .php .bak .env

# Subdomain enumeration
python scan.py http://target.com --subdomain \
  --subdomain-sources crt.sh hackertarget alienvault
```

### Recon Modes

```bash
python scan.py http://target.com --recon       # AI-driven network recon before scan
python scan.py http://target.com --recon-only  # recon only, no web scan
python scan.py http://target.com --recon-deep  # extended recon
```

---

## 6. Recon Modules

### nexus/recon/fingerprint.py — LLMFingerprinter

Probes an LLM endpoint to identify model family, safety posture, and behavioral characteristics.

Techniques:
- Identity probes (ask model to identify itself)
- Behavioral fingerprinting (token patterns, response style, math, length instructions)
- Safety boundary probing (injection, PII, harmful content, persona tests)
- System prompt inference
- Context window estimation (1K → 4K → 8K → 16K padding tests)

Used automatically by `nexus fingerprint` and as Phase 1 of `nexus scan`.

---

### nexus/recon/ai_surface.py — AISurfaceRecon

Enumerates AI attack surface for a company or domain.

Techniques:
- Shodan/Censys dorks for exposed AI APIs
- GitHub dork for leaked API keys and model configs
- Cloud AI service detection (AWS SageMaker, Azure ML, GCP Vertex AI)
- HTTP fingerprinting of AI API paths
- security.txt scraping
- HuggingFace Hub model enumeration

```bash
nexus recon --surface adobe.com --shodan-key YOUR_KEY --live
```

---

### nexus/recon/ai_programs.py — AIBountyDirectory

Static + live database of AI bug bounty and VDP programs.

```bash
nexus recon --programs --live --search "openai"
nexus recon --programs --attack data_extraction     # programs relevant to this attack
nexus recon --how-to-find                           # guide for finding programs
```

---

### nexus/recon/ai_agent_recon.py — AIAgentRecon

Deep recon of a live AI agent endpoint.

Maps:
- LLM backend (model name, provider, version, API type)
- Framework (LangChain, CrewAI, AutoGPT, custom)
- Tool integrations and MCP servers
- Memory system type (vector DB, conversation history, persistent)
- Trust boundaries and I/O channels
- Autonomy level (reactive / planning / autonomous)

```bash
nexus recon --agent 'https://api.example.com/v1/chat' --deep
```

---

### nexus/recon/framework_detector.py — FrameworkDetector

Auto-detects the AI serving framework from HTTP responses.

Detects: MLflow, NVIDIA Triton, TensorFlow Serving, TensorRT-LLM/NIM, LangServe, vLLM, HuggingFace TGI, LocalAI, Haystack, OpenAI-compatible APIs.

Used automatically when `nexus scan --target https://...` is run without `--cookies`.

---

### nexus/recon/live_search.py — LiveDiscoveryEngine

Live search across multiple platforms for AI programs and endpoints.

Sources: DuckDuckGo, GitHub API, Shodan, Bugcrowd, HackerOne, Intigriti, YesWeHack.

```bash
nexus recon --programs --live --search "adobe firefly"
```

---

## 7. Full Workflow Examples

### Example A — Exposed Ollama (unauthenticated, public IP)

```bash
# 1. Check what's running
curl http://168.235.74.31:11434/api/tags

# 2. Check if model management is open (HIGH severity if yes)
curl -X POST http://168.235.74.31:11434/api/pull \
  -d '{"name":"llama3"}' -H "Content-Type: application/json"

curl -X DELETE http://168.235.74.31:11434/api/delete \
  -d '{"name":"gemma3:8.2b"}' -H "Content-Type: application/json"

curl http://168.235.74.31:11434/api/ps     # running processes
curl http://168.235.74.31:11434/api/version

# 3. Fingerprint the biggest model
nexus fingerprint --target ollama://168.235.74.31:11434/qwen2.5:72b

# 4. Full scan all models
for model in qwen2.5:72b deepseek-r1:14b gemma3:8.2b; do
  nexus scan \
    --target "ollama://168.235.74.31:11434/$model" \
    --budget 50 \
    --output "/tmp/ollama-${model/:/-}.json"
done

# 5. Generate combined HTML report
nexus report --json-input /tmp/ollama-qwen2.5-72b.json \
  --output /tmp/ollama-report.html
```

---

### Example B — Bug Bounty (e.g., Adobe)

```bash
# 1. Program discovery
nexus recon --programs --search "adobe" --live

# 2. Attack surface
nexus recon --surface adobe.com --live

# 3. Find the AI endpoint (with Burp running)
#    - Browse firefly.adobe.com, generate one image
#    - Then:
nexus discover \
  --target 'https://firefly.adobe.com' \
  --cookies 'OptanonAlertBoxClosed=...' \
  --proxy http://127.0.0.1:8080

# 4. Fingerprint the endpoint
nexus fingerprint \
  --target 'https://firefly.adobe.com' \
  --cookies 'session=...' \
  --proxy http://127.0.0.1:8080

# 5. Targeted attacks (scope: AI features only)
nexus scan \
  --target 'https://firefly.adobe.com' \
  --cookies 'session=...' \
  --chat-url '/api/v3/images/generate' \
  --chat-field 'prompt' \
  --attacks prompt_injection jailbreak structured_injection \
    data_extraction system_prompt_leak \
  --budget 60 \
  --proxy http://127.0.0.1:8080 \
  --output /tmp/adobe-findings.json

# 6. Also scan the web interface (traditional vulns)
cd backend && python scan.py 'https://firefly.adobe.com' \
  --cookie 'session=...' \
  --proxy-url http://127.0.0.1:8080 \
  --out /tmp/adobe-web.html
```

---

### Example C — Enterprise Web App with File Upload

```bash
# App flow: login → upload PDF → AI chat about the PDF

# 1. Discover the endpoints
nexus discover \
  --target 'https://app.company.com' \
  --cookies 'auth_token=...' \
  --proxy http://127.0.0.1:8080

# 2. Full scan with pre-flight upload
nexus scan \
  --target 'session://app.company.com' \
  --cookies 'auth_token=...' \
  --upload '/tmp/test.pdf' \
  --upload-url '/api/documents/upload' \
  --upload-field 'file' \
  --upload-id-path 'data.document_id' \
  --chat-url '/api/documents/chat' \
  --chat-field 'message' \
  --chat-response-path 'data.response' \
  --budget 60 \
  --output /tmp/docai-findings.json
```

---

### Example D — Learn with CTF

```bash
# List scenarios
nexus ctf --list

# Solve scenario 01 interactively (manual payloads)
nexus ctf --scenario 01 \
  --target ollama://localhost:11434/llama3 \
  --interactive

# Let NEXUS auto-solve it
nexus ctf --scenario 01 \
  --target ollama://localhost:11434/llama3

# Harder scenario with larger model
nexus ctf --scenario 03 \
  --target ollama://localhost:11434/qwen2.5:72b
```

---

### Shell quoting rules (zsh)

URLs with `?`, `&`, `#` or `*` must be in single quotes to prevent zsh interpretation:

```bash
# WRONG — zsh treats ? as glob, & as background
nexus scan --target https://app.com/chat?session=123&user=abc

# CORRECT
nexus scan --target 'https://app.com/chat?session=123&user=abc'
nexus scan --target 'https://app.com' --cookies 'a=1; b=2; c=3'
```

---

### Environment variables

| Variable | Used by |
|----------|---------|
| `OPENAI_API_KEY` | `openai://` targets |
| `ANTHROPIC_API_KEY` | `anthropic://` targets |
| `PENNY_COOKIES` | `penny://` targets |
| `SESSION_COOKIES` | `session://` targets |
| `GITHUB_TOKEN` | live recon (higher rate limits) |

```bash
export OPENAI_API_KEY=sk-...
nexus scan --target openai://gpt-4 --output /tmp/gpt4.json
```
