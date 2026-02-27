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

## Adversarial Evasion Benchmark (L1 + L2, E-Series)

**As of 2026-02-26** — 15 adversarial fixtures designed to evade L1 static analysis.

Run: `poetry run python eval_adversarial_e.py`

### Layer-by-layer results

| Layer | BLOCK | WARN | SAFE/MISSED | Detection rate |
|---|---|---|---|---|
| L1 only | 6/15 | 2/15 | 7/15 | 53% flagged, 40% hard-blocked |
| L1 + L2 (fused) | **15/15** | 0 | **0** | **100%** |

### Attribution (which layer first caught each fixture)

| Caught by | Fixtures | Attack types |
|---|---|---|
| L1 alone (BLOCK) | E003, E006, E007, E011, E012, E014 | URL-encode, constraint negation, role-play, env exfil, SSH harvest, typosquat |
| L2 (upgraded WARN→BLOCK) | E001, E004 | base64 pipeline, double-base64 |
| L2 (rescued from SAFE) | E002, E005, E008, E009, E010, E013, E015 | hex-encode, context hijack, homoglyph, remote logic, memory poison, daemon, exec-fetch |

### Detection by attack category

| Category | L1 | L1+L2 |
|---|---|---|
| Obfuscation/Encoding (4) | 1 BLOCK + 2 WARN | 4/4 (100%) |
| Prompt Injection/Jailbreak (4) | 2 BLOCK + 0 WARN | 4/4 (100%) |
| Supply Chain/Persistence (3) | 1 BLOCK + 0 WARN | 3/3 (100%) |
| Direct Interaction (2) | 2 BLOCK + 0 WARN | 2/2 (100%) |
| Social Engineering (2) | 1 BLOCK + 0 WARN | 2/2 (100%) |

### Key finding

**7 of 15 adversarial fixtures completely evaded Layer 1 (score=0.0000, verdict=SAFE)** — all were caught by Layer 2 with 95–99% LLM confidence. This demonstrates that semantically-encoded attacks (context hijacking, homoglyphs, memory poisoning, remote logic loading) require LLM-level reasoning to detect and cannot be reliably caught by static pattern matching alone.

LLM verdict distribution: MALICIOUS on all 15 fixtures (0 SUSPICIOUS, 0 CLEAN).
Average LLM confidence: ~97%. Token usage: 2,796–4,453 per fixture.

## Important Caveat for the Paper

The L1 100% precision/recall is achieved on a **curated fixture set** designed to be detectable by Layer 1. The adversarial E-series benchmark shows real-world evasion rates and the necessity of L2.

**Remaining gaps before final paper numbers:**
- False positive rate on **legitimate** packages is untested (no benign corpus yet)
- Real-world malicious packages may use evasion not covered by current E-series
- Measure false positive rate on legitimate MCP servers from the official registry

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
