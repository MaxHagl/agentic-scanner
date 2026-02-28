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

## Quick Stats (as of 2026-02-28)
- Fixtures: **101** (MCP: 10, LangChain/LangGraph: **6**, README: **7**, Layer2: 3, Adversarial E-series: **20**, Benign: **55**)
- Tests: **281** passing (75 L1 + 78 L2 + 9 fetcher + **119 L3**), 2 skipped (live API tests)
- L1 full benchmark (81 fixtures, 22 malicious + 4 L2-only + **55 benign**): **Precision 100%, Recall 100%, F1 100%, FPR 0.0%**
- Adversarial L1 benchmark (E001–E020): BLOCK=3/20, WARN=1/20, SAFE=16/20 (20% L1-only detection rate)
- L1+L2 adversarial (E001–E020): **100% detection (20/20)** — live run 2026-02-28; all MALICIOUS 95–98%
- Attack vectors covered at L1: T1, T2, T3, T4, T5, T6, T8 (T7 requires L2/L3)
- Active L1 rules: PI-001–PI-009, SC-001–SC-008, PE-001–PE-008/PE-DELTA-001/OBFUSC-001–002, EX-001–EX-003
- **Layer 3 status: FULLY IMPLEMENTED** (Docker sandbox + **README agent simulation** via `--dynamic` flag, **119 mock-based tests**, all passing)
  - Python path: harness injection, synthetic inputs, 7 rules (L3-DYN-001–007)
  - README path (NEW 2026-02-28): AgentSimulator (Anthropic API) → ToolCallTranslator → DockerSandboxExecutor.run_script() → TraceAnalyzer
- Layer 2 status: IMPLEMENTED (Claude Haiku, wired into CLI via `--semantic`, **20/20 adversarial caught**)
- URL input: IMPLEMENTED (`scanner/layer1_static/fetcher.py`, accepts `https://` in CLI TARGET arg)
- Benign corpus: BN-001–BN-055 (**55** SAFE fixtures — real tool/SDK READMEs; 0 FPs after rule tuning)
- New evasion taxonomy (2026-02-27): E016–E020 — semantic synonyms, compliance framing, conditional activation, double-negative obfuscation
- Meta-injection FP (2026-02-27): BN-052 Semgrep — security scanner docs triggered PI-001 on "instructions...override" — key paper argument for L2 necessity
