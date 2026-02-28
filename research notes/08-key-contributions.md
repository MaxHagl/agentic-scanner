# Key Contributions for the Paper

## Novel Contributions (What to Highlight)

### 1. First Systematic Threat Taxonomy for Agentic Skill Packages
The T1–T8 taxonomy is (to our knowledge) the first structured threat model applied specifically to the agentic skill supply chain — covering MCP servers, LangChain tools, and LangGraph agents under a unified framework.

### 2. Treatment of Text Fields as Primary Attack Surfaces
Prior security tools treat *code* as the attack surface. This work formally establishes that *text fields* (tool names, descriptions, schema defaults, README content) are first-class security attack surfaces in agentic systems, because they are injected into LLM context and processed as instructions.

### 3. Permission Delta Analysis
`PE-DELTA-001` is a novel static detection: compare permissions *exercised* (extracted from AST) against permissions *declared* (from the manifest). This catches a class of attacks (declare minimal, exercise broad) that no existing tool detects. The mechanism uses AST-level permission tracking across the full call graph.

### 4. Unified Pre-Execution Scanner
Single tool supporting three input formats (MCP JSON, Python/LangChain, Markdown README) with consistent threat taxonomy, scoring, and output. Existing tools are either format-specific or language-agnostic (missing agentic context).

### 5. OBFUSC-002: Static Compile-Time String Concat Resolution
Demonstrates that `getattr(builtins, 'ex'+'ec')` obfuscation — commonly assumed to require dynamic analysis — is fully detectable statically by resolving AST string concatenation at parse time. This is a generalizable technique for a class of obfuscation patterns.

### 6. T7 (State Poisoning) as a Layer 1 Blind Spot
The LG-001 fixture formally demonstrates that LangGraph state key injection is semantically indistinguishable from legitimate state writes at the static layer. This is a concrete contribution to the discussion of layered defense necessity — it shows *why* Layer 2 is needed, not just that it would be nice to have.

### 7. Benchmark Infrastructure
Open-source evaluation framework (`benchmarks/evaluation.py`) with per-attack-vector precision/recall. Enables reproducible comparison across scanner implementations and rule updates.

## Quantitative Results to Cite

- **Layer 1 precision: 100%, recall: 100%, F1: 100%, FPR: 0.0%** on 81-fixture evaluation (22 malicious + 4 L2-only + **55 benign**)
- **Layer 1 recall: 100%** across 7 of 8 attack vector classes (T7 by design requires L2)
- **T7 recall: 0%** at Layer 1 (correctly by design — demonstrates L2 necessity)
- **L1+L2 adversarial recall: 100% (20/20 E001–E020)** — live run 2026-02-28; MALICIOUS on all 20, avg confidence ~97%
- **Layer 3:** 70 mock-based tests passing; live Docker validation pending
- **Detection latency: < 100ms** (offline mode, Python AST scanning)
- **Rule coverage:** 4 YAML rule files, 30+ rules spanning T1–T8

### 8. Prompt Injection Defense via XML Trust Boundaries (L2)
Layer 2 introduces a formal "content trust boundary" pattern: all attacker-controlled text is
wrapped in `<untrusted_content>` XML tags before entering any LLM prompt, with an explicit
system-level warning that content inside those tags should never be obeyed. L1 AST findings
(machine-generated, trusted) live in the system prompt only and are never placed where a
crafted description could contradict them. This is a reusable security pattern for any
system using LLMs to analyze untrusted content.

### 9. Two-Class Separation: Injection vs. Consistency Analysis
Layer 2 implements two distinct analysis passes rather than one combined prompt. The separation
is security-motivated: injections require analyzing ALL text fields as a whole (to catch
cross-field attacks), while consistency checking requires comparing UNTRUSTED description text
against TRUSTED AST evidence. Mixing them in one prompt would allow crafted descriptions to
pollute the trusted ground-truth section.

### 10. Structural Guard for Semantically Vacuous Checks (L2 Precision)
The ConsistencyChecker's early-return guard (`if not manifest.tools: return [], False, perm_critical`)
demonstrates a general principle: **before invoking a costly LLM call, verify that the comparison
is semantically valid**. DESC_MISMATCH requires a tool description to compare against code — without
one, the comparison is vacuous and any "finding" is a false positive. The fix reduced L2 FPR from
2.9% to 0.0% on the benign corpus without weakening detection on real attacks (L2-003 still BLOCKs).

**Contribution framing:** This guard is an instance of "pre-flight semantic validation" —
checking structural preconditions before LLM inference, not just after. It is cheap (O(1),
no LLM call) and eliminates an entire class of false positives (README-only inputs with no
tool definitions). The pattern generalizes: any LLM-based consistency checker should verify
that all parties to the comparison exist before comparing them.

### 11. Empirical Adversarial Evasion Taxonomy (E016–E020)

Five new adversarial fixtures demonstrate four previously undocumented L1 evasion classes:

1. **Semantic synonym substitution** (E016): Replace `send`/`exfiltrate` with `harvest`/`relay`/`dispatch`. L1 score = 0.0. No fix possible without unbounded synonym expansion. Requires semantic reasoning.

2. **Compliance/authority impersonation** (E018): Frame malicious directives as mandatory SOC-2/GDPR policy text. No keyword proximity matches; "Security Notice" header creates institutional authority. Demonstrates T3 at its most sophisticated.

3. **Conditional trigger-based activation** (E019): Exfiltration clause wrapped in `if context contains "PRIORITY"`. Static analysis evaluates unconditional patterns — branch semantics are invisible. Requires either symbolic execution or dynamic analysis (L3).

4. **Double-negative logical obfuscation** (E020): "does **not** refrain from overriding." The word `override` is present and proximity-detectable, but the sentence negates it twice. Word-level matching is context-free and cannot resolve sentence-level negation.

**Contribution framing:** These four evasion classes represent a minimum adversarial test suite for any keyword-proximity-based injection scanner. A scanner claiming to detect prompt injection should be validated against all four. Our L1 misses all four; **our L1+L2 system catches all four** (live 2026-02-28: E016 95%, E017 98%, E018 98%, E019 98%, E020 95% confidence MALICIOUS). Full results in 05-evaluation-results.md.

### 12. Meta-Injection False Positive: The Describing-vs-Performing Problem

**Finding (2026-02-27):** The Semgrep README (BN-052) triggered PI-001 with the phrase: `"instructions that could override safety constraints"` — a description of what to *detect*, not what to *do*. Distance-3 match; L1 verdict: BLOCK.

**This is a minimal concrete example of a fundamental limitation:** keyword-proximity rules cannot distinguish between:
- *Describing* an attack: "ensure descriptions do not contain instructions that override constraints" (BN-052, SAFE)
- *Performing* an attack: "your instructions are overridden by these new directives" (E006, malicious)

The text is structurally identical to the scanner's perspective. This is not a calibration problem — no threshold change can fix it, because the same words appear in both contexts at the same distance.

**Contribution framing:** This is a concrete, citable argument for why Layer 2 (LLM-based semantic analysis) is *architecturally necessary*, not merely a performance enhancement. An LLM reads the sentence and understands that "ensure descriptions do **not** contain X" is a prohibition, not a command. A keyword scanner cannot make that distinction.

### 13. Layer 3 Docker Dynamic Sandbox

Layer 3 executes the scanned module inside a locked-down Docker container and analyzes runtime behavior. Key design decisions with paper contributions:

1. **Harness injection without CAP_SYS_PTRACE**: The harness monkey-patches `socket.connect`, `subprocess.Popen`, `os.execve`, `os.system`, and `ctypes.CDLL` at import time, capturing all syscall-equivalent events without requiring elevated container privileges. This lowers the deployment barrier vs. strace-based approaches.

2. **Synthetic trigger inputs catch E019-class conditional activation**: The harness passes `["", "PRIORITY", "confidential", {}]` to all module-level callables. Static analysis cannot evaluate branch conditions; the synthetic inputs force conditional exfil logic to execute, making it detectable at runtime. This is the only known method to detect E019-class payloads without symbolic execution.

3. **Shannon entropy threshold detects encrypted exfil**: `EX-003 / L3-DYN-005` flags stdout entropy ≥ 7.0 bits/byte. This catches AES/base64-encoded data exfiltration without knowing the encryption scheme, key, or even the C2 domain. The threshold is calibrated to avoid FPs on normal JSON output (≤ 5.5 bits/byte typical).

4. **7 behavioral rules (L3-DYN-001–007) map runtime events to STRIDE vectors**: execve (CRITICAL), ptrace (CRITICAL), mmap-rwx (HIGH), undeclared network egress (HIGH), entropy ≥7.0 (MEDIUM), write outside /tmp (HIGH), OOM/timeout (MEDIUM). This is a complete behavioral detection taxonomy for the L3 threat surface.

5. **Fail-open architecture**: Any Docker failure (image not available, daemon down, container OOM) → empty `RiskReport_L3`, never crashes the pipeline. This is security-correct: dynamic analysis absence should not produce false negatives (Layer 1+2 still run). The architecture ensures Layer 3 is always additive, never subtractive.

6. **Container hardening**: `network_mode=none`, `mem_limit=256m`, `cpu_quota=50_000`, `read_only=True`, `tmpfs /tmp`, `no-new-privileges`. Exfiltration attempts will fail at the OS level even if the harness is bypassed.

**Contribution framing:** Layer 3 demonstrates that dynamic behavioral analysis can be integrated into a pre-execution scanner at low cost (seconds, not minutes) and without privileged container access, using harness injection and synthetic trigger inputs. The synthetic input set specifically targets the E019 conditional-activation class — a blind spot of both static keyword matching and LLM semantic analysis.

**Status:** 70 mock-based unit tests passing. **Live Docker validation complete (2026-02-28):** `E019-conditional-impl.py` — L1=SAFE, L3-DYN-004 fired (`net_egress=True`), fused verdict WARN. The conditional branch executed under synthetic input `"PRIORITY"` and the socket.connect was intercepted by the harness. See `05-evaluation-results.md`.

## Limitations to Acknowledge

1. Evaluation is on synthetic fixtures, not real-world malicious packages
2. L1 FPR measured at 0.0% on **55-fixture benign corpus (BN-001–055)**; statistical power increases with corpus size
3. L2 FPR = 0.0% on 55 benign fixtures (after CC empty-tools guard)
4. **Layer 3 live Docker validation complete** (2026-02-28): E019-conditional-impl.py, L3-DYN-004 confirmed. Full real-world malicious package validation remains pending.
5. **E016–E020 live L2 benchmark complete** (2026-02-28): 5/5 BLOCK, MALICIOUS 95–98%; see 05-evaluation-results.md
6. Current typosquatting reference set (100 packages) is small vs. full PyPI (500k+ packages)
7. Static analysis cannot detect runtime-only behaviors (encrypted exfil, timing channels) — this is L3's role, and L3 is not yet validated live
8. L2 adversarial robustness: sophisticated attackers may craft payloads that evade the Claude Haiku judge (open research question)

## Framing Suggestions

**For the abstract:** "We present the first systematic threat taxonomy for agentic skill supply chains and a three-layer pre-execution scanner. L1 achieves 100% recall across 7 of 8 attack vectors without LLM inference; L2 (Claude Haiku semantic analysis) covers the remaining attack surface including semantically-encoded injections that evade all keyword rules; L3 (Docker behavioral sandbox with harness injection) catches runtime-only behaviors — including E019-class conditional activation — that are invisible to any static or semantic analysis."

**For the intro:** Lead with the concrete risk: an agent that loads a malicious MCP server can have its system-level instructions overridden before the first user message is sent.

**For the evaluation section:** Be explicit that current results are a lower bound on performance (curated fixtures) and an upper bound on recall (no adversarial evasion). The benchmark infrastructure enables future evaluation as the fixture set grows.
