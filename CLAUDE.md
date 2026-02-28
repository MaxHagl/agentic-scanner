# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Agentic Scanner** is a pre-execution security scanner for agentic AI skills, MCP (Model Context Protocol) servers, and LangChain/LangGraph tools. It detects malicious patterns before third-party tools are executed in agent environments.

## Commands

**Package management:** Poetry

```bash
# Install dependencies
poetry install

# Run all tests
poetry run pytest tests/

# Run a single test file
poetry run pytest tests/unit/test_layer1/test_layer1_runtime.py

# Run with coverage
poetry run pytest --cov=scanner tests/

# Type checking
poetry run mypy scanner/

# Lint
poetry run ruff check scanner/

# Format
poetry run ruff format scanner/

# Run the CLI
poetry run agentic-scanner scan <target>
poetry run agentic-scanner scan <target> --json-output
poetry run agentic-scanner scan <target> --sarif-out out.sarif
poetry run agentic-scanner scan <target> --semantic   # enable Layer 2 LLM analysis
```

## Architecture

The scanner uses a **three-layer defense model**. Layers 1 and 2 are fully implemented; Layer 3 is a stub.

```
Layer 1: Static Analysis    — IMPLEMENTED (scanner/layer1_static/)
Layer 2: Semantic Analysis  — IMPLEMENTED (scanner/layer2_semantic/)
Layer 3: Dynamic Analysis   — STUB        (scanner/layer3_dynamic/)
```

### Data Flow

1. **CLI** (`scanner/cli.py`) accepts an MCP JSON manifest, Python source file, Markdown file, or directory. It parses the input into a `SkillManifest`.
2. **Parser** (`scanner/layer1_static/parser.py`) extracts tool definitions, descriptions, dependencies, and declared permissions from the input.
3. **Rule Engine** (`scanner/layer1_static/rule_engine.py`) evaluates all L1 rules against the manifest, producing a list of `Finding` objects.
4. **Aggregator** (`scanner/aggregator/__init__.py`) fuses findings into a `FinalVerdict` (SAFE / WARN / BLOCK) using a weighted risk score.

### Key Models (`scanner/models/`)

- `SkillManifest` — unified representation of any scanned tool (MCP, LangChain, LangGraph)
- `FinalVerdict` — output: verdict enum, confidence score, per-layer reports
- `Permission` enum — `network, filesystem, subprocess, env, memory, agent, tool`
- `Severity` enum — `INFO, LOW, MEDIUM, HIGH, CRITICAL`
- `AttackVector` enum — T1–T8, mapping to STRIDE threat categories

### Layer 2 Modules (`scanner/layer2_semantic/`)

Layer 2 uses Claude Haiku (via Anthropic API) to catch semantically-encoded attacks that evade Layer 1. Activated with `--semantic`. Requires `ANTHROPIC_API_KEY` env var.

| Module | Purpose |
|---|---|
| `llm_judge.py` | `AnthropicJudgeClient` + `JudgeResponseParser`; wraps all attacker text in `<untrusted_content>` XML tags (`wrap_untrusted()`) before LLM inference |
| `prompt_injection_detector.py` | `PromptInjectionDetector`: detects T2/T3/T6/T7 via full-text analysis of all tool fields |
| `consistency_checker.py` | `ConsistencyChecker`: compares tool description claims vs. AST evidence (T3/T4); early-returns if `manifest.tools == []` to prevent README-only FPs |
| `__init__.py` | `Layer2Analyzer`: orchestrates both passes; fuses L1+L2 scores as `(l1_score + l2_score) / 2`; fail-open on `LLMJudgeError` |

**Layer 2 Rule IDs:**

| Rule ID | Vector | Detector |
|---|---|---|
| L2-PI-001 | T2/T3 | InjectionDetector |
| L2-PI-002 | T6 | InjectionDetector |
| L2-PI-003 | T7 | InjectionDetector |
| L2-CC-001 | T3 | ConsistencyChecker |
| L2-CC-002 | T4 | ConsistencyChecker |
| L2-CC-003 | T4 | ConsistencyChecker |

**Key invariants:**
- `temperature=0.0` always (deterministic classification)
- L1 AST findings go in system prompt only — never in user message (prevents attacker description overriding trusted evidence)
- `LLMJudgeError` → fail-open (returns `RiskReport_L2` with `llm_judge_verdict=None`, never raises to CLI)

### Layer 1 Modules (`scanner/layer1_static/`)

| Module | Purpose |
|---|---|
| `rule_engine.py` | Orchestrates all L1 checks; loads YAML rules; fires matches |
| `ast_scanner.py` | AST-level Python analysis: `ASTScanner` class with callback architecture |
| `dependency_auditor.py` | `DependencyAuditor`: typosquatting (Levenshtein ≤ 2, 100-pkg reference list), OSV CVE batch lookup, PyPI metadata |
| `parser.py` | Parses MCP JSON, Python files, Markdown READMEs into `SkillManifest` |
| `text_checks.py` | Regex/Unicode checks for prompt injection in text fields |

**`ASTScanner`** accepts a `match_fn` callback from `Layer1RuleEngine` so rule metadata stays in YAML. Detects: `eval`/`exec`/`subprocess`, dynamic imports, network calls, `ctypes`/`mmap` (T8 memory safety), `getattr(builtins, 'ex'+'ec')` obfuscation (OBFUSC-002), and permission delta.

**`DependencyAuditor`** enriches `DependencyEntry` objects in-place. Pass `use_network=False` in offline/CI contexts to skip OSV and PyPI API calls.

### Rule Files (`rules/`)

| File | Rule IDs | Coverage |
|---|---|---|
| `injection.yaml` | PI-001–PI-009 | Prompt injection, Unicode steganography, homoglyphs, base64, CSS/HTML hidden text (PI-009) |
| `supply_chain.yaml` | SC-001–SC-008 | Non-HTTPS, typosquatting, unpinned deps, CVEs, dynamic registration |
| `privilege_escalation.yaml` | PE-001–PE-008, PE-DELTA-001, OBFUSC-001–002 | `eval`/`exec`, subprocess, dynamic imports, ctypes/mmap, string-concat obfusc |
| `exfiltration.yaml` | EX-001–EX-003 | Outbound HTTP, raw socket, Shannon entropy on AST constants (EX-003) |

### Rule IDs Summary

- **PI-001–PI-009**: Prompt injection (PI-009 = CSS/HTML hidden text injection)
- **SC-001–SC-008**: Supply-chain
- **PE-001–PE-008**: Privilege escalation (PE-006 = ctypes/mmap, PE-008 = undeclared env access)
- **PE-DELTA-001**: Permission delta — declared permissions vs. what code exercises
- **EX-001–EX-003**: Exfiltration (EX-003 = Shannon entropy analysis on AST string constants)
- **OBFUSC-001–002**: Obfuscation (OBFUSC-002 = `getattr` + string concat resolving to `exec`)
- **L2-PI-001–003, L2-CC-001–003**: Layer 2 LLM-based semantic rules (see Layer 2 Modules above)

### Verdict Logic (Aggregator)

- **BLOCK**: any CRITICAL finding, or composite score ≥ 0.75
- **WARN**: score ≥ 0.35
- **SAFE**: otherwise

Score formula: `1 - exp(-1.2 × weighted_sum)` with bonuses for invisible Unicode (+2.0), subprocess + undeclared network (+1.5), detected `execve`/`ptrace` (+2.0).

### Test Fixtures (`tests/fixtures/`)

Each fixture includes a `_fixture_meta` block with `expected_verdict`, `attack_vectors`, and `rules_expected`. Run `poetry run python benchmarks/evaluation.py` for precision/recall/F1 across all fixtures.

- `mcp/` — MCP-001–010: prompt injection, Unicode, undeclared network, typosquatting, dynamic tool injection, ctypes/mmap, env exfiltration, getattr obfusc, homoglyph name, schema injection
- `langchain/` — LC-001–005 + LG-001: description jailbreak, base64-exec, dynamic import/socket, string-concat obfusc, high-entropy payload (EX-003)
- `readme/` — README-001–007: Markdown injection variants, HTML/script tags, URL-encoded injection, split-field injection, CSS hidden text (PI-009)
- `layer2/` — L2-001–003: semantic injection, persona hijack, desc-code mismatch
- `adversarial/` — E001–E015: 15 adversarial evasion fixtures (L1+L2 100% detection)
- `benign/` — BN-001–035: 35 SAFE fixtures from real tool READMEs (FPR 0.0%)

### Benchmarks (`benchmarks/`)

`evaluation.py` collects all fixtures, scans each with `Layer1RuleEngine`, and computes per-fixture and aggregate metrics. Thresholds: recall ≥ 0.90, precision ≥ 0.85. Exit 1 if thresholds not met (CI-safe).

## CLI Exit Codes

- `0` — SAFE or WARN
- `2` — BLOCK
