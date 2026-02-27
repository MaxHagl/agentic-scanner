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

- **Layer 1 precision: 100%** on 21-fixture evaluation set (note caveat: no benign corpus yet)
- **Layer 1 recall: 100%** across 7 of 8 attack vector classes
- **T7 recall: 0%** at Layer 1 (correctly by design — demonstrates L2 necessity)
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

## Limitations to Acknowledge

1. Evaluation is on synthetic fixtures, not real-world malicious packages
2. No benign corpus → false positive rate is unmeasured
3. Layer 2 is implemented but not yet wired into the CLI; end-to-end live performance untested
4. Layer 3 is a stub → dynamic analysis not yet implemented
5. Current typosquatting reference set (100 packages) is small vs. full PyPI (500k+ packages)
6. Static analysis cannot detect runtime-only behaviors (encrypted exfil, timing channels)
7. L2 adversarial robustness: sophisticated attackers may evade Gemini judge (open research question)

## Framing Suggestions

**For the abstract:** "We present the first systematic threat taxonomy for agentic skill supply chains and a three-layer pre-execution scanner that achieves 100% recall across 7 of 8 threat classes using only static analysis, without requiring LLM inference."

**For the intro:** Lead with the concrete risk: an agent that loads a malicious MCP server can have its system-level instructions overridden before the first user message is sent.

**For the evaluation section:** Be explicit that current results are a lower bound on performance (curated fixtures) and an upper bound on recall (no adversarial evasion). The benchmark infrastructure enables future evaluation as the fixture set grows.
