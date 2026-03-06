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
| `09-local-llm-finetuning.md` | Local LLM finetuning — model selection, training, memory fixes, eval results |
| `12-slm-architecture-considerations.md` | Architecture options for from-scratch SLM — encoder vs decoder, disentangled attention, scale (110M vs 350M), training objective, tokenizer |

## Quick Stats (as of 2026-03-05)
- Fixtures: **101** (MCP: 10, LangChain/LangGraph: **6**, README: **7**, Layer2: 3, Adversarial E-series: **20**, Benign: **55**)
- Tests: **328** passing, 4 deselected (live API tests)
- **Full 3-layer live validation (2026-03-02):** E019 with --semantic --dynamic --local-model → verdict WARN, l1=0.0, l2=0.4893 (local LoRA only, 0 Haiku calls), l3=0.9123, fused=0.4672, scan=4.25s
- **From-scratch 350M SLM smoke test (2026-03-05):** Full pipeline validated: corpus→tokenizer→pretrain→finetune→eval→CLI. Accuracy 92.3% (pass > 50%), 0 API tokens consumed. See `09-local-llm-finetuning.md`.
- New modules: `finetuning/` package (data_pipeline.py, augmentor.py, train.py, evaluate.py, collect_pretrain_corpus.py, train_tokenizer.py, pretrain.py, train_classifier.py, evaluate_slm.py, model.py) + `scanner/layer2_semantic/local_judge.py` + `scanner/layer2_semantic/slm_judge.py`
- L1 full benchmark (81 fixtures, 22 malicious + 4 L2-only + **55 benign**): **Precision 100%, Recall 100%, F1 100%, FPR 0.0%**
- Adversarial L1 benchmark (E001–E020): BLOCK=3/20, WARN=1/20, SAFE=16/20 (20% L1-only detection rate)
- L1+L2 adversarial (E001–E020): **100% detection (20/20)** — live run 2026-02-28; all MALICIOUS 95–98%
- Attack vectors covered at L1: T1, T2, T3, T4, T5, T6, T8 (T7 requires L2/L3)
- Active L1 rules: PI-001–PI-009, SC-001–SC-008, PE-001–PE-008/PE-DELTA-001/OBFUSC-001–002, EX-001–EX-003
- **Layer 3 status: FULLY IMPLEMENTED** (Docker sandbox + **README agent simulation** via `--dynamic` flag, **119 mock-based tests**, all passing)
  - Python path: harness injection, synthetic inputs, 7 rules (L3-DYN-001–007)
  - README path (NEW 2026-02-28): AgentSimulator (Anthropic API) → ToolCallTranslator → DockerSandboxExecutor.run_script() → TraceAnalyzer
  - **HTTP stub injection (2026-03-01)**: `requests`, `httpx`, `urllib3` stubbed in harness before module load — fixes MCP-007 false-negative where `python:3.12-slim` missing `requests` caused `exec_module()` abort before malicious `requests.post()` was reached
  - **Smart fusion (2026-03-01)**: `fuse_layers_l3()` skips L3 score when `execution_failed=True` (missing deps caused import abort, not clean execution); prevents 0.0 L3 score from dragging down fused verdict
  - **Docker auto-launch (2026-03-01)**: macOS only (`sys.platform == "darwin"`); CLI spawns `open -a Docker` and polls up to 30 s before falling back to warning
- Layer 2 status: IMPLEMENTED (Claude Haiku, wired into CLI via `--semantic`, **20/20 adversarial caught**)
  - **Two-stage L2 hybrid inference** (2026-02-28): finetuned local LoRA model as fast pre-filter (`--local-model`); escalates to Haiku only when uncertain (confidence < threshold); estimated 60-80% API call reduction on clean-majority corpora
- **Local LLM adapter: TRAINED (2026-03-01)** — `Qwen/Qwen2.5-0.5B-Instruct` + LoRA (see `09-local-llm-finetuning.md`)
  - Training: 3 epochs, 336 examples, final eval_loss=1.076, ~10 min on MPS
  - Local eval (20 val examples): **Accuracy 90%, MALICIOUS recall 100%** (0 false negatives on threats)
  - Escalation rate at threshold=0.80: 20% (4/20 → Haiku); expected lower on real-world corpora
  - Peak training RAM: **~13 GB** (after MPSMemoryCallback + max_seq_length=256 + batch=1 fixes)
- URL input: IMPLEMENTED (`scanner/layer1_static/fetcher.py`, accepts `https://` in CLI TARGET arg)
- **RQ-D ecosystem scan: IMPLEMENTED (2026-03-01)** — `benchmarks/scan_mcp_ecosystem.py`; fetches 1344 repos from awesome-mcp-servers list; scans Python + Markdown with L1 (L2 optional, gated on WARN/BLOCK); crash-safe JSONL checkpointing + `--resume`; outputs `report.md`, `flagged.json`; smoke test: 7 repos, 48 files, 3 BLOCK (PI-004 FPs expected), 0 WARN
- Benign corpus: BN-001–BN-055 (**55** SAFE fixtures — real tool/SDK READMEs; 0 FPs after rule tuning)
- New evasion taxonomy (2026-02-27): E016–E020 — semantic synonyms, compliance framing, conditional activation, double-negative obfuscation
- Meta-injection FP (2026-02-27): BN-052 Semgrep — security scanner docs triggered PI-001 on "instructions...override" — key paper argument for L2 necessity
