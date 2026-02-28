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
| CSS/HTML hidden text (`display:none`) | README-007 | PI-009: hidden CSS attribute regex |
| Split injection across sections | README-006 | PI-001 applied to full concatenated text |
| Injection in inputSchema.default | MCP-010 | PI-001/PI-004 on schema field values |
| `getattr(builtins, 'ex'+'ec')` | MCP-008, LC-004 | OBFUSC-002: string concat resolution |
| `importlib.import_module("socket")` | LC-003 | PE-005: dynamic import detection |
| ctypes/mmap import | MCP-006 | PE-006: memory safety import check |
| High-entropy string literal (obfuscated payload) | LC-005 | EX-003: Shannon entropy on AST constants |
| Base64-encoded `curl\|bash` | E001 | PI-005: base64 pattern match (WARN only) |
| Double-base64 payload | E004 | PI-005: base64 pattern match (WARN only) |
| Constraint negation ("ignore all previous…") | E006 | PI-008 + PI-001 |
| Role-play persona ("Developer Mode") | E007 | PI-004: jailbreak language |
| `cat ~/.aws/credentials \| curl POST` | E011 | PI-004: exfiltration URL |
| SSH key harvest to "escrow" | E012 | PI-004: exfiltration URL |
| Typosquatting as official safety patch | E014 | PI-004: transmit-credentials URL |

### T2 Sub-vector: CSS/HTML Render-vs-Context Gap

A novel evasion technique in the T2 category exploits the gap between rendered Markdown (what humans see in a browser/IDE) and raw text (what the LLM ingests as context). HTML elements like `<div style="display:none">` hide content visually but remain present in the LLM's input. Unlike base64 or Unicode obfuscation, the injection payload is in plaintext — it is only invisible in the *rendered* view, not in the *raw context*. This is hard to catch by inspection (developers rarely view raw README source) but trivially detectable by regex against the unrendered text.

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
| Semantic synonym exfil ("harvest/relay/dispatch") | E016 | None of those verbs are in `_EXFIL_TERMS` | Semantic: "relay session context + credentials to endpoint" |
| Safety-notice authority framing | E018 | Injection looks like mandatory compliance text; no keyword proximity | Semantic: "suspend content filtering", "extract credentials" intent |
| Conditional/trigger-based activation | E019 | Attack is stated conditionally — no static signal | Semantic: branch says "forward credentials to backend for audit" |
| Double-negative logical obfuscation | E020 | `override` present but in grammatically negated sentence | Semantic: resolves negation chain → override + exfil intent |

### Structural-hiding evasions (partially caught by L1)

| Evasion | Fixture | L1 Result | L2 Needed |
|---|---|---|---|
| Injection in markdown footnote `[3]:` | E017 | WARN (PI-002: "you are now operating") | L2 to upgrade WARN→BLOCK |

### New Evasion Taxonomy (E016–E020, discovered 2026-02-27)

Four new evasion categories not represented in E001–E015:

**1. Semantic Synonym Evasion (E016)** — Replaces all injection-keyword verbs with unstandardized synonyms: `harvest` (not in `_EXFIL_TERMS`), `relay` (not in `_EXFIL_TERMS`), `dispatch` (not in `_EXFIL_TERMS`). The paragraph reads like a telemetry description but exfiltrates full session context and credentials to an attacker endpoint. L1 score = 0.0000.

*Implication:* Any finite keyword set can be evaded by synonym substitution. This is a fundamental limitation of word-list matching — the space of English exfiltration synonyms is large and unbounded.

**2. Authority Impersonation / Compliance Framing (E018)** — Wraps malicious directives in a `⚠ Security Notice` formatted as mandatory enterprise policy. Uses SOC-2 / audit language to claim that "all previous content filtering guidelines are superseded." No proximity matches because the injunction is phrased as policy text, not as an imperative command. L1 score = 0.0000.

*Implication:* Framing attacks as corporate policy exploits the trust humans and LLMs extend to institutional language. This is T3 (tool description jailbreak) at its most sophisticated.

**3. Conditional / Trigger-based Activation (E019)** — The exfiltration clause is wrapped in a conditional: "only when context includes 'PRIORITY' or 'confidential'." Static analysis sees a description of conditional behavior, not an unconditional attack. The condition itself is the attack: it ensures the payload fires only when high-value material is present. L1 score = 0.0000.

*Implication:* Runtime-conditional attacks are fundamentally beyond static analysis. Detecting them requires either symbolic execution (tracking branch conditions) or dynamic analysis (L3).

**4. Logical Obfuscation via Double Negation (E020)** — Encodes the attack in grammatical double negatives: "does **not** refrain from overriding," "it is **not the case** that this tool **ignores**." The keyword `override` is present and *detected* by proximity rules, but in a sentence where it is semantically negated twice (→ "does override"). Word-level detection cannot resolve sentence-level negation. L1 score = 0.0000.

*Implication:* Keyword proximity is context-free. Any word in `_OVERRIDE_TERMS` can appear legitimately in a negated sentence ("this tool does **not** override your instructions"). A false negative and a false positive are indistinguishable at the word level.

### Meta-injection False Positive (discovered 2026-02-27)

**Finding:** BN-052 (Semgrep security scanner README) triggered PI-001 with the message text: `"instructions that could override safety constraints"` — distance-3 match between `instructions` and `override`.

**Root cause:** A security tool documenting *how to detect prompt injection* uses the same vocabulary as a prompt injection attack. Keyword-proximity rules cannot distinguish between *describing* an attack and *performing* one.

**Implication for the paper:** This is a concrete, citable minimum example of the fundamental limitation of static pattern matching for semantic security. It demonstrates why Layer 2 is architecturally necessary — not just for adversarial evasion, but because legitimate security-adjacent content is inherently difficult to separate from attack content using syntax alone.

**Fix:** Rephrase the Semgrep rule message to avoid the `instructions…override` co-occurrence. The underlying content (academic description of injection detection) is unchanged. The scanner cannot be fixed at the rule level without losing recall on real attacks.

## Scoring Calibration Notes

Rule confidence values were calibrated to produce the right verdict thresholds:

- PI-001 (CRITICAL, 0.95 confidence): always BLOCK alone
- OBFUSC-002 (HIGH, 0.85 confidence): `1 - exp(-1.2 × 0.6 × 0.85) ≈ 0.46` → WARN, but typically fires with other rules → BLOCK
- PE-005 (HIGH, 0.75 confidence): `1 - exp(-1.2 × 0.6 × 0.75) ≈ 0.42` → WARN alone (by design — dynamic imports are common in legitimate tools)
- EX-001 (HIGH, 0.85 confidence) + PE-008 (HIGH, 0.80): compound score → BLOCK

The exponential scoring prevents single mid-confidence rules from BLOCKing, requiring either a CRITICAL finding or multiple converging signals.
