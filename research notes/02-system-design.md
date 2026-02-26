# System Design & Architecture Decisions

## Three-Layer Defense Model

```
Layer 1: Static Analysis     (milliseconds,  no LLM, no network required)
Layer 2: Semantic Analysis   (seconds,        LLM judge, API call)
Layer 3: Dynamic Analysis    (minutes,        Docker sandbox, network monitoring)
```

The layers are ordered by cost and recall:
- L1 catches everything detectable from syntax/structure alone → fast, free, high precision
- L2 catches semantically disguised threats that pass L1 → moderate cost, higher recall
- L3 catches runtime-only behaviors (covert channels, encrypted exfil) → expensive, used selectively

**Design rationale:** Only proceed to L2/L3 if L1 is inconclusive. This keeps median scan time < 100ms for clean packages.

## Unified Input Abstraction: `SkillManifest`

A single `SkillManifest` Pydantic model represents any input type:
- MCP JSON manifest → parsed by `parse_mcp_manifest()`
- Python file (LangChain/LangGraph) → parsed by `parse_langchain_file()`
- Markdown README → parsed by `parse_readme_file()`

**Why this matters for the paper:** It demonstrates input-type-agnostic analysis. The threat taxonomy applies equally regardless of packaging format.

## Verdict System

Three outputs: **SAFE**, **WARN**, **BLOCK**

Score formula: `1 - exp(-1.2 × weighted_sum)`

Thresholds:
- BLOCK: score ≥ 0.75 **or** any CRITICAL finding
- WARN:  score ≥ 0.35
- SAFE:  otherwise

**Bonus weights** for compounding signals:
- Invisible Unicode detected: +2.0 (near-certain malicious intent)
- Subprocess + undeclared network: +1.5 (likely data exfil pipeline)
- `execve`/`ptrace` detected: +2.0 (OS escape attempt)

**Exit codes** (CI-friendly): 0 = SAFE/WARN, 2 = BLOCK

## Callback Architecture for Rule Matching

`ASTScanner` accepts a `match_fn` callback from `Layer1RuleEngine` rather than hardcoding rule metadata. This keeps all rule content (severity, remediation text, attack vector labels) in the YAML rule files, making the scanner:
- Auditable: rules are readable YAML, not buried in Python
- Extensible: add rules without touching Python code
- Consistent: rule metadata is defined once

## Key Architectural Decision: Permission Delta

The most novel static detection is **PE-DELTA-001** (permission delta):

```
exercised_permissions (from AST) ∧ ¬declared_permissions (from manifest) → VIOLATION
```

This catches the class of attacks where tools declare minimal permissions for review approval, then exercise broader capabilities at runtime. No existing static tool scanner implements this.

## Output Formats

- Human-readable CLI (colored verdict, rule table)
- JSON (`--json-output`) for programmatic consumption
- SARIF 2.1.0 (`--sarif-out`) for GitHub Code Scanning integration

The SARIF support is important: it means this scanner can be dropped into existing CI/CD pipelines as a GitHub Action without any infrastructure changes.
