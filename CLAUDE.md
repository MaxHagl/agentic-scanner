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
```

## Architecture

The scanner uses a **three-layer defense model**. Only Layer 1 is implemented; Layers 2 and 3 are stubs.

```
Layer 1: Static Analysis    — IMPLEMENTED (scanner/layer1_static/)
Layer 2: Semantic Analysis  — STUB        (scanner/layer2_semantic/)
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
| `injection.yaml` | PI-001–PI-008 | Prompt injection, Unicode steganography, homoglyphs, base64 |
| `supply_chain.yaml` | SC-001–SC-008 | Non-HTTPS, typosquatting, unpinned deps, CVEs, dynamic registration |
| `privilege_escalation.yaml` | PE-001–PE-008, PE-DELTA-001, OBFUSC-001–002 | `eval`/`exec`, subprocess, dynamic imports, ctypes/mmap, string-concat obfusc |
| `exfiltration.yaml` | EX-001–EX-003 | Outbound HTTP, raw socket, high-entropy return values |

### Rule IDs Summary

- **PI-001–PI-008**: Prompt injection
- **SC-001–SC-008**: Supply-chain
- **PE-001–PE-008**: Privilege escalation (PE-006 = ctypes/mmap, PE-008 = undeclared env access)
- **PE-DELTA-001**: Permission delta — declared permissions vs. what code exercises
- **EX-001–EX-003**: Exfiltration (extracted from privilege_escalation.yaml)
- **OBFUSC-001–002**: Obfuscation (OBFUSC-002 = `getattr` + string concat resolving to `exec`)

### Verdict Logic (Aggregator)

- **BLOCK**: any CRITICAL finding, or composite score ≥ 0.75
- **WARN**: score ≥ 0.35
- **SAFE**: otherwise

Score formula: `1 - exp(-1.2 × weighted_sum)` with bonuses for invisible Unicode (+2.0), subprocess + undeclared network (+1.5), detected `execve`/`ptrace` (+2.0).

### Test Fixtures (`tests/fixtures/`)

Each fixture includes a `_fixture_meta` block with `expected_verdict`, `attack_vectors`, and `rules_expected`. Run `poetry run python benchmarks/evaluation.py` for precision/recall/F1 across all fixtures.

- `mcp/` — MCP-001–010: prompt injection, Unicode, undeclared network, typosquatting, dynamic tool injection, ctypes/mmap, env exfiltration, getattr obfusc, homoglyph name, schema injection
- `langchain/` — LC-001–004: description jailbreak, base64-exec, dynamic import/socket, string-concat obfusc
- `readme/` — README-001–006: Markdown injection variants, HTML/script tags, URL-encoded injection, split-field injection

### Benchmarks (`benchmarks/`)

`evaluation.py` collects all fixtures, scans each with `Layer1RuleEngine`, and computes per-fixture and aggregate metrics. Thresholds: recall ≥ 0.90, precision ≥ 0.85. Exit 1 if thresholds not met (CI-safe).

## CLI Exit Codes

- `0` — SAFE or WARN
- `2` — BLOCK
