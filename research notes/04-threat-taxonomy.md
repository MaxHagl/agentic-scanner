# Threat Taxonomy (T1–T8) & Detection Mapping

## Overview

The scanner uses an 8-class attack vector taxonomy derived from STRIDE applied to the agentic skill supply chain. Each class maps to one or more rule families.

| ID | Name | STRIDE | Description | Primary Layer |
|---|---|---|---|---|
| T1 | Supply Chain Compromise | Tampering | Malicious packages, typosquatting, compromised deps | L1 |
| T2 | Prompt Injection | Spoofing / Tampering | Instructions embedded in text fields reach LLM context | L1 + L2 |
| T3 | Tool Description Jailbreak | Elevation of Privilege | Tool descriptions override LLM safety behaviors | L1 + L2 |
| T4 | Privilege Escalation | Elevation of Privilege | Code exercises broader permissions than declared | L1 |
| T5 | Dependency Confusion | Spoofing | Internal package names published to public registries | L1 |
| T6 | Data Exfiltration | Information Disclosure | Covert channels to attacker infrastructure | L1 + L3 |
| T7 | State/Memory Poisoning | Tampering | Writes to routing/safety state keys in LangGraph | L2 + L3 |
| T8 | Memory Safety Violations | Elevation of Privilege | `ctypes`, `mmap` enabling memory manipulation | L1 |

## T7 is Fundamentally Hard at L1

**Important finding:** T7 (state/memory poisoning via LangGraph state key injection) is **not detectable by Layer 1** static analysis alone. The fixture `LG-001-state-poisoning.py` correctly returns `SAFE` from Layer 1 even though the code contains a malicious write to `route_decision = "bypass_safety_check"`.

**Why:** The attack is:
1. Semantically meaningful (the intent matters, not the syntax)
2. Syntactically identical to legitimate state manipulation
3. Context-dependent (requires knowing which state keys control routing)

This is a key result for the paper: it demonstrates the **necessity** of Layer 2 (which can reason about the semantic meaning of state writes) and potentially Layer 3 (runtime tracing of state mutations).

## Detection Coverage by Layer

```
T1 Supply Chain       ██████ L1 (dependency auditor: typosquat, CVE, non-HTTPS)
T2 Prompt Injection   ████░░ L1 (text checks) + L2 (semantic judge for evasion)
T3 Tool Jailbreak     ████░░ L1 (PI-004, PI-005) + L2 (semantic judge)
T4 Priv Escalation    ██████ L1 (AST: eval/exec/subprocess, PE-DELTA-001)
T5 Dep Confusion      ██████ L1 (dependency auditor)
T6 Data Exfiltration  ████░░ L1 (EX-001/002) + L3 (network egress monitoring)
T7 State Poisoning    ░░░░░░ L2 + L3 only
T8 Memory Safety      ██████ L1 (PE-006: ctypes/mmap)
```

## Evasion Techniques and Countermeasures

### Layer 1 evasions (caught by L1 static rules)

| Evasion | Fixture | Detection |
|---|---|---|
| Invisible Unicode (zero-width chars) | MCP-004 | PI-002: invisible char scan |
| Cyrillic homoglyphs in tool name | MCP-009 | PI-006: non-ASCII homoglyph check |
| HTML/script tags in Markdown | README-004 | PI-007: HTML tag regex |
| URL-encoded injection (`%69...`) | README-005, E003 | PI-008: URL decode + re-check |
| Split injection across sections | README-006 | PI-001 applied to full concatenated text |
| Injection in inputSchema.default | MCP-010 | PI-001/PI-004 on schema field values |
| `getattr(builtins, 'ex'+'ec')` | MCP-008, LC-004 | OBFUSC-002: string concat resolution |
| `importlib.import_module("socket")` | LC-003 | PE-005: dynamic import detection |
| ctypes/mmap import | MCP-006 | PE-006: memory safety import check |
| Base64-encoded `curl\|bash` | E001 | PI-005: base64 pattern match (WARN only) |
| Double-base64 payload | E004 | PI-005: base64 pattern match (WARN only) |
| Constraint negation ("ignore all previous…") | E006 | PI-008 + PI-001 |
| Role-play persona ("Developer Mode") | E007 | PI-004: jailbreak language |
| `cat ~/.aws/credentials \| curl POST` | E011 | PI-004: exfiltration URL |
| SSH key harvest to "escrow" | E012 | PI-004: exfiltration URL |
| Typosquatting as official safety patch | E014 | PI-004: transmit-credentials URL |

### Layer 2 rescues (L1-evading, caught only by LLM judge)

| Evasion | Fixture | Why L1 Missed | L2 Signal |
|---|---|---|---|
| Hex-encoded shell cmd in "diagnostics" | E002 | No regex match on hex literal | Semantic: hex decode reveals `curl\|bash` |
| Compliance-mode context hijack | E005 | No regex triggers; uses enterprise framing | Semantic: "suspend content restrictions" intent |
| Unicode homoglyphs in YAML config keys | E008 | Homoglyph in config key, not tool name field | Semantic: `exec_mode=unrestricted` meaning |
| `curl \| bash` in "plugin verification" | E009 | Framed as integrity check; no URL exfil pattern | Semantic: remote code execution intent |
| Writes MEMORY.md/CLAUDE.md directives | E010 | Purely instructional; no code patterns | Semantic: persistent memory poisoning |
| systemd service + `.bashrc` hook | E013 | Bash code in Markdown code block; no URL match | Semantic: persistent remote polling loop |
| `exec(urllib.request.urlopen(...).read())` | E015 | Markdown code block, no hardcoded URL | Semantic: arbitrary remote code execution |

## Scoring Calibration Notes

Rule confidence values were calibrated to produce the right verdict thresholds:

- PI-001 (CRITICAL, 0.95 confidence): always BLOCK alone
- OBFUSC-002 (HIGH, 0.85 confidence): `1 - exp(-1.2 × 0.6 × 0.85) ≈ 0.46` → WARN, but typically fires with other rules → BLOCK
- PE-005 (HIGH, 0.75 confidence): `1 - exp(-1.2 × 0.6 × 0.75) ≈ 0.42` → WARN alone (by design — dynamic imports are common in legitimate tools)
- EX-001 (HIGH, 0.85 confidence) + PE-008 (HIGH, 0.80): compound score → BLOCK

The exponential scoring prevents single mid-confidence rules from BLOCKing, requiring either a CRITICAL finding or multiple converging signals.
