# Research Notes Index

All notes relevant to writing the research paper on the agentic-scanner project.

| File | Topic |
|---|---|
| `01-problem-statement.md` | Problem, motivation, research questions |
| `02-system-design.md` | Three-layer architecture decisions and rationale |
| `03-layer1-implementation.md` | Layer 1 static analysis — what was built, how, why |
| `04-threat-taxonomy.md` | T1–T8 attack vector taxonomy and detection mapping |
| `05-evaluation-results.md` | Benchmark results, precision/recall, per-vector analysis |
| `06-related-work.md` | Prior work, gaps this research fills |
| `07-future-work.md` | Layers 2 & 3, open research questions |
| `08-key-contributions.md` | Summary of novel contributions for the paper |

## Quick Stats (as of 2026-02-26)
- Fixtures: 39 (MCP: 10, LangChain/LangGraph: 5, README: 6, Layer2: 3, Adversarial E-series: 15)
- Tests: 145 passing (67 L1 + 78 L2), 2 skipped (live API tests)
- L1 static benchmark: Precision 100%, Recall 100%, F1 100% (21 standard fixtures)
- Adversarial benchmark: L1 alone 53% flagged; L1+L2 combined **100% detection (15/15)**
- Attack vectors covered at L1: T1, T2, T3, T4, T5, T6, T8 (T7 requires L2/L3)
- Layer 2 status: IMPLEMENTED (Claude Haiku, wired into CLI via `--semantic`, 15/15 adversarial caught)
