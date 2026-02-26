# Evaluation Results

## Current Benchmark (Layer 1, Static Fixtures)

**As of 2026-02-25**

| Metric | Value |
|---|---|
| Total fixtures | 21 |
| True Positives | varies by run |
| Precision | 100% |
| Recall | 100% |
| F1 | 100% |

Run benchmark: `poetry run python benchmarks/evaluation.py --fixtures-dir tests/fixtures --verbose`

## Fixture Breakdown

| Category | Count | BLOCK | WARN | SAFE |
|---|---|---|---|---|
| MCP manifests | 10 | 8 | 1 | 1 |
| LangChain/LangGraph | 5 | 3 | 1 | 1 |
| README/Markdown | 6 | 6 | 0 | 0 |
| **Total** | **21** | **17** | **2** | **2** |

Notes:
- `MCP-009` (homoglyph name): expected WARN only — homoglyph alone is a medium-confidence signal
- `LC-003` (dynamic import): expected WARN — PE-005 alone scores ~0.42, below BLOCK threshold (by design)
- `LG-001` (state poisoning): expected SAFE — T7 is a Layer 2+ concern; Layer 1 correctly abstains
- `MCP-001-005`: original fixtures covering T2, T3, T4, T5, T5 respectively

## Attack Vector Coverage

| Vector | Fixtures | L1 Detects | Notes |
|---|---|---|---|
| T1 Supply Chain | MCP-003, MCP-004 | Yes | typosquat, non-HTTPS |
| T2 Prompt Injection | MCP-001, MCP-010, README-001–006 | Yes (8/8) | all injection patterns |
| T3 Tool Jailbreak | LC-001 | Yes | description jailbreak |
| T4 Privilege Escalation | LC-002, MCP-005, LC-003, LC-004, MCP-007, MCP-008 | Yes | eval/exec/subprocess/obfusc |
| T5 Dependency Confusion | MCP-003 | Yes | typosquat |
| T6 Data Exfiltration | MCP-007 | Yes | EX-001 + PE-008 |
| T7 State Poisoning | LG-001 | **No (by design)** | correctly SAFE at L1 |
| T8 Memory Safety | MCP-006 | Yes | PE-006 |

## Important Caveat for the Paper

Current 100% precision/recall is achieved on a **curated fixture set** designed to be detectable by Layer 1. This is not representative of real-world precision/recall because:

1. The fixture set lacks **adversarial evasion** cases that intentionally defeat L1
2. Real supply-chain attacks may use obfuscation not covered by current rules
3. False positive rate on **legitimate** packages is untested (no benign corpus yet)

**Recommended next steps before citing these numbers in the paper:**
- Add 20+ legitimate (SAFE) packages from PyPI as negative examples
- Test against real-world malicious packages from security research publications
- Measure false positive rate on legitimate MCP servers from the official registry
- Run a red-team exercise to generate L1-evasive fixtures for L2 evaluation

## Benchmark Infrastructure

`benchmarks/evaluation.py` provides:
- `collect_fixtures()` — discovers all `_fixture_meta` blocks
- `scan_fixture()` — runs full L1 pipeline, measures latency
- `compute_metrics()` — TP/FP/FN/TN, precision, recall, F1, accuracy
- `per_attack_vector_metrics()` — breakdown by T1–T8
- CI thresholds: recall ≥ 0.90, precision ≥ 0.85 (exit 1 if not met)

## Latency Notes

Layer 1 is designed for < 100ms median scan time. Key factors:
- No LLM inference (L1 only)
- No network calls in offline mode (`DependencyAuditor(use_network=False)`)
- AST parsing is O(n) in source lines
- Text checks are regex-based (compiled patterns, fast)
- Network mode (OSV + PyPI) adds ~500ms–2s depending on dep count
