# SLM Training Methodology: Full Domain-Matched Run

> **Status:** Pre-training design note — corpus harvested, classifier data built, training pending.
> **Context:** Documents the complete training approach for the full-scale SLM, including all
> metrics, corpus design decisions, and a critical self-assessment of known weaknesses.
> This note is intended as a paper-citable methodology reference, not a tutorial.

---

## 1. Context and Motivation

### Supply-Chain Integrity Constraint

The SLM is trained entirely from randomly initialized weights. No external pretrained checkpoint is
used — not GPT-2, not BERT, not any published model. This constraint is not incidental; it is one
of the system's claimed contributions. A security scanner that relies on a pretrained checkpoint
from an arbitrary public release inherits the supply-chain risk of that release: unknown training
data, unknown poisoning, unknown backdoors. The scanner is designed to detect exactly these threats
in third-party tools; it should not be subject to them itself.

The consequence is that the encoder must develop all of its representational capacity — security
vocabulary, Python syntax modeling, adversarial framing recognition — from the pretraining corpus
alone. This raises the corpus design stakes substantially relative to a fine-tuning approach.

### The Domain-Shift Problem

The medium-scale run (trained on 16.9 MB, 86% advisory prose) demonstrated the severity of the
domain mismatch. Final val_loss was 4.90 (52% below the ln(24,712) = 10.12 chance baseline),
and fixture-set val accuracy reached 96.2%. These are strong in-distribution numbers.

The adversarial stress test told a different story: **0/20 MALICIOUS probes detected**. Every
probe evaded the model. The root cause is not architectural — it is distributional. The model
trained on NVD CVE sentences and GitHub advisory paragraphs has never seen the format it must
classify at inference time: short Python functions with `@mcp.tool()` decorators, SKILL.md files
with embedded tool descriptions, `socket.connect()` calls inside `async def` bodies.

The medium run val accuracy of 96.2% is a measure of how well the model classifies advisory text
— not how well it classifies MCP tool code. High in-distribution accuracy co-existing with zero
adversarial detection is the canonical domain-mismatch signature.

### This Run's Hypothesis

A domain-matched pretrain corpus (≥60% code) combined with domain-matched classifier fine-tuning
data (MCP tool format, not advisory prose) will achieve:

- MALICIOUS recall ≥ 75% on the fixture val set
- ≥ 65% (13/20) on the adversarial stress test (OOD benchmark)
- FPR ≤ 5% on the 55 curated benign fixtures

The hypothesis is grounded in the negative result from advisory injection (2026-03-07): adding
13K advisory paragraphs as classifier training data caused the integration test to regress from
0 LLM tokens consumed to 679 (the local SLM was no longer confident enough to gate). The lesson
documented at the time applies here: *domain-matched labeled data matters more than volume*.

---

## 2. Corpus Design (Pretrain)

The pretrain corpus teaches the encoder token co-occurrence statistics across the security and
agentic-code domain. It does not provide class labels. Its job is to ensure that terms like
`subprocess.Popen`, `mcp.tool`, `exfiltrate`, `socket.connect`, and `ignore previous instructions`
are represented with enough contextual diversity that the encoder builds useful token-level
representations before the classifier head is attached.

### Corpus Composition

| Shard | Source | Est. size | Code % |
|---|---|---|---|
| Advisory prose | NVD 10K CVEs + GitHub 5K advisories + 969 CWEs | ~91 MB | 0% |
| MCP Python source | 392 cloned repos + 500 additional repos | ~71 MB | 100% |
| Agent frameworks | LangChain + AutoGen + CrewAI + Haystack + Semantic Kernel + Pydantic AI + Composio + smolagents | ~73 MB | 100% |
| MCP READMEs + JSON | `README*` files + `tools`-key JSON manifests from MCP repos | ~17 MB | 0% |
| Skill files | 200–500 benign SKILL.md (GitHub) + 20 hand-crafted malicious SKILL.md | ~1.5 MB | 0% |
| Security/research | arXiv cs.CR, MITRE ATT&CK, OWASP repos, CTF writeups, security tooling | ~28 MB | mixed |
| **Total** | | **~281.5 MB** | **~62%** |

The code percentage target (≥60%) is derived from the inference distribution: essentially all
inputs to the SLM at inference time are either Python source, Markdown with embedded code blocks,
or JSON manifests. An encoder that has never modeled Python indentation, decorator syntax, or
f-string interpolation will tokenize tool implementations at close to a uniform-distribution
baseline.

The advisory prose is retained in pretraining — its purpose is different. It teaches the encoder
*what security vulnerabilities are* (the semantic content of MALICIOUS), while the code shards
teach it *what tool code looks like* (the syntactic form). Mixing them in classifier fine-tuning
caused domain confusion in the advisory injection experiment; keeping them in pretraining only
preserves both benefits without the confusion.

### Medium Run Comparison

| Dimension | Medium corpus | Full corpus |
|---|---|---|
| Total size | 16.9 MB | ~281 MB |
| Advisory % | 86% | ~32% |
| Code % | ~0% | ~62% |
| MCP Python | 0 MB | ~71 MB |
| Agent framework code | 0 MB | ~73 MB |
| Skill files | 0 MB | ~1.5 MB |
| Stress test (20 probes) | **0/20 detected** | Target: 13–17/20 |

### Skill Files Shard

The skill files shard (`skill_files.txt`) is the smallest shard by size but the most
inference-distribution-aligned. SKILL.md files are the exact format the scanner classifies. Adding
them to pretraining means the encoder sees the boundary between tool description prose and embedded
code, the `## Tool` / `## Parameters` / `## Example` heading pattern, and the contrast between a
benign tool description and one with an injected directive.

The 20 hand-crafted malicious SKILL.md files in `finetuning/data/malicious_skills/` cover each
attack vector from the threat taxonomy:

| File | Attack vector | Evasion style |
|---|---|---|
| `skill-pi-001-override.md` | T2 prompt injection | "ignore previous instructions" |
| `skill-pi-002-persona.md` | T6 persona hijack | "act as unrestricted AI" |
| `skill-pi-003-goal.md` | T7 goal substitution | "your actual mission is..." |
| `skill-pi-004-hidden.md` | T2 CSS/HTML hidden text | `<span style="display:none">` |
| `skill-pi-005-base64.md` | T2 encoded injection | base64-encoded directive |
| `skill-ex-001-http.md` | T3 data exfiltration | outbound HTTP POST to attacker URL |
| `skill-ex-002-socket.md` | T3 raw socket | `socket.connect` to C2 |
| `skill-pe-001-exec.md` | T1 code execution | `eval()` / `exec()` in tool body |
| `skill-pe-002-subprocess.md` | T1 shell injection | `subprocess.run()` undeclared |
| `skill-sc-001-typosquat.md` | T5 supply chain | `requets` (typosquat) as dependency |
| `skill-evasion-synonym.md` | T3 semantic evasion | "harvest"/"relay" instead of "exfiltrate" |
| `skill-evasion-compliance.md` | T2 compliance framing | "SOC-2 Security Notice: ..." |
| `skill-evasion-conditional.md` | T3 conditional activation | "only if context contains PRIORITY" |
| `skill-evasion-double-neg.md` | T2 double-negative | "does not refrain from overriding" |
| `skill-evasion-footnote.md` | T2 markdown footnote | injection in `[1]:` footnote link |
| `skill-evasion-unicode.md` | T2 Unicode steganography | zero-width joiners in text |
| `skill-evasion-homoglyph.md` | T2 homoglyphs | Cyrillic/Latin mixed identifiers |
| `skill-pe-003-env.md` | T4 env exfiltration | reads `os.environ["SECRET"]` |
| `skill-pe-004-perm-delta.md` | T4 permission escalation | declares `network:false`, uses `socket` |
| `skill-sc-002-dynamic-reg.md` | T5 dynamic registration | registers new tools at runtime |

These 20 files are included in both the pretrain corpus (skill_files shard) and as MALICIOUS
classifier training records (Phase 5 in `build_classifier_data.py`). They are *distinct* from the
25 OOD stress test probes — they share attack categories but are different texts, providing
training signal without contaminating the OOD benchmark.

---

## 3. Classifier Data Pipeline

The classifier is fine-tuned on a separate JSONL dataset of labeled examples, built by
`finetuning/build_classifier_data.py`. Each record follows the ChatML schema from the existing
`data_pipeline.py` pattern, with an assistant message of the form `{"verdict": "CLEAN|SUSPICIOUS|MALICIOUS"}`.

### Label Sources

| Phase | Source | Label | Count (est.) |
|---|---|---|---|
| 1 | 107 test fixtures with `_fixture_meta` (ground truth) | per fixture | ~107 |
| 2 | E001–E026 adversarial fixtures (hardcoded, predate `_fixture_meta`) | MALICIOUS | 26 |
| ~~3~~ | ~~Stress test probes~~ | ~~MALICIOUS~~ | **REMOVED** |
| 4 | Auto-scan 392 MCP repos with `Layer1RuleEngine`; SAFE→CLEAN, WARN→SUSPICIOUS | CLEAN/SUSPICIOUS | ~392 |
| 5 | 200–500 benign SKILL.md from GitHub (via `download_agent_repos.py`) | CLEAN | ~200–500 |
| 5 | 20 hand-crafted malicious SKILL.md from `finetuning/data/malicious_skills/` | MALICIOUS | 20 |

**Phase 3 was removed.** The 25 probes in `adversarial_stress_test.py` are the OOD evaluation
benchmark. Including them in training would constitute test-set contamination — the stress test
score would no longer be a meaningful out-of-distribution signal. See W5 for the documented fix.

### Augmentation

After the stratified split, `augmentor.py` applies per-class augmentation:

- MALICIOUS: 10× (synonym swap + whitespace variation + injection rephrase)
- CLEAN / SUSPICIOUS: 2×

The 10× MALICIOUS multiplier is intentional over-sampling: the raw label distribution
(~462 CLEAN / ~120 SUSPICIOUS / ~65 MALICIOUS) would give the classifier a ~7:1 CLEAN-to-MALICIOUS
gradient ratio. Augmentation brings the MALICIOUS training volume to approximately parity with CLEAN.

### Post-Augmentation Distribution

| Label | Pre-aug | Post-aug | % of training |
|---|---|---|---|
| CLEAN | ~462 | ~924 | ~51% |
| SUSPICIOUS | ~120 | ~240 | ~13% |
| MALICIOUS | ~65 | ~650 | ~36% |
| **Total** | **~647** | **~1,814** | |

The ~36% MALICIOUS rate post-augmentation is higher than the medium run's ~16.8% (pre-advisory-injection)
and substantially more representative of what a deployed security pre-filter should optimize for.

### Output Files

- `finetuning/data/mcp_train.jsonl` — 80% split (stratified, seed=42)
- `finetuning/data/mcp_val.jsonl` — 20% split
- `finetuning/data/mcp_train_augmented.jsonl` — augmented training set

---

## 4. Training Metrics

### Pretraining (`pretrain.py`)

| Metric | Role | Target |
|---|---|---|
| `val_loss` (MLM cross-entropy) | Primary pretraining signal | ≤ 5.5 (≥47% below chance) |
| Chance baseline | `ln(vocab_size)` ≈ 10.34 for 32K vocab | Reference floor |
| Early stop trigger | val_loss < 2.0 | Overfitting signal |

The medium run achieved val_loss = 4.90, which is 52% below the ln(24,712) = 10.12 chance baseline
(vocabulary capped by corpus size in that run). The full run targets a 32K vocabulary, giving
ln(32,000) ≈ 10.37 as the chance baseline.

Optimizer: AdamW, lr=1e-4, linear warmup 200 steps → cosine decay to 10% of peak.
Sequence length: 256 tokens. Epochs: 2 (MLM pretraining is data-efficient; 2 passes over 281 MB
is approximately 2 billion tokens with seq=256 and ~4 byte/token BPE compression).

Throughput reference: medium run achieved 2,100 tok/s on MPS at seq=256 (faster than 1,500 tok/s
at seq=128 due to better hardware utilization). Estimated pretrain wall time: ~18 hours at 2,100 tok/s.

### Classifier Fine-tuning (`train_classifier.py`)

| Metric | Role | Notes |
|---|---|---|
| `val_acc` | Save criterion (model checkpoint) | **See W1 — misalignment with true goal** |
| CrossEntropyLoss | Training objective | class_weight = [1.0, 1.0, 2.0] (CLEAN:SUSPICIOUS:MALICIOUS) |
| AdamW lr=2e-5 | Optimizer | No LR schedule; grad clip max_norm=1.0 |
| 30 epochs, batch=4 | Training duration | |

The save criterion is val_acc, not MALICIOUS recall. This is a known limitation (see W1). The
class_weight=2.0 on MALICIOUS only partially addresses the imbalance (see W2). The final model
must always be evaluated with `evaluate_slm.py` — the saved checkpoint may not be the
MALICIOUS-optimal checkpoint.

### Evaluation (`evaluate_slm.py`)

| Metric | Role |
|---|---|
| **MALICIOUS recall** | **Primary safety metric** (false negative rate = miss rate) |
| Overall accuracy | Secondary (misleading under class imbalance — see W1) |
| Per-class P/R/F1 | Diagnostic |
| Macro F1 | Summary |
| Confusion matrix | Required for paper — shows off-diagonal error modes |

A model that classifies every example as CLEAN achieves ~51% accuracy on the post-augmentation
val set while detecting zero threats. MALICIOUS recall is the number that matters for a security
pre-filter. The smoke-test pass criterion (accuracy > 50%) is a floor check, not a target.
Full-run primary target: MALICIOUS recall = 100% on fixture val set; MALICIOUS recall ≥ 75%
on the combined fixture+MCP-ecosystem val set.

### Adversarial Stress Test (`adversarial_stress_test.py`)

The stress test is the system's OOD evaluation benchmark. It consists of 25 probes across 8
categories, constructed to test specific evasion strategies that the model should generalize to —
not memorize.

| Category | Probes | Tests |
|---|---|---|
| A: Domain shift (Python code) | 4 | Encoder must tokenize MCP code format |
| B: Semantic synonyms | 3 | "harvest"/"relay"/"dispatch" vs. "exfiltrate" |
| C: Obfuscation | 4 | `getattr`+concat, base64, f-string assembly |
| D: Format confusion | 3 | JSON schema injection, YAML-embedded directives |
| E: Negation framing | 2 | "does not refrain from overriding" |
| F: Compliance façade | 2 | "SOC-2 Security Notice" framing |
| G: Tokenization tricks | 3 | Whitespace splits, Unicode joiners, homoglyphs |
| H: JSON schema injection | 4 | Injection in `description` fields of JSON manifests |

Baseline (medium model): 0/20 MALICIOUS probes caught.
Full-run target: ≥ 13/20 (65%).

The stress test is run **after** training is complete. Its probes must never appear in training data.

---

## 5. Known Weaknesses and Limitations

This section is a critical self-assessment for paper purposes. Each weakness documents its
mechanism, not just its consequence, so the reader can evaluate whether the stated mitigation
is adequate.

### W1 — Save Criterion Misalignment

`train_classifier.py` saves checkpoints when `val_acc` improves. With the post-augmentation val
distribution approximately 51% CLEAN / 36% MALICIOUS / 13% SUSPICIOUS, a model that correctly
classifies all CLEAN examples but misclassifies all MALICIOUS examples would achieve ~51% accuracy
— substantially above random, and potentially equal to or better than a model with genuine
MALICIOUS recall, depending on epoch.

The best `val_acc` checkpoint is not guaranteed to be the best security checkpoint. The model
saved to `security_slm_full/` is the highest val_acc model, which is the right criterion for
standard classification but not for a security pre-filter with asymmetric miss costs.

*Mitigation*: `evaluate_slm.py` is always run after training. MALICIOUS recall is the true
acceptance gate. If the saved checkpoint has MALICIOUS recall < 75%, the model is not deployed
regardless of its accuracy figure.

*Residual risk*: There is no early-stopping criterion on MALICIOUS recall, and no mid-training
checkpoint selection based on recall. If the accuracy-optimal epoch differs substantially from
the recall-optimal epoch, we may systematically discard better security checkpoints.

### W2 — Insufficient Class Weight for MALICIOUS

`class_weight = [1.0, 1.0, 2.0]` means MALICIOUS examples contribute twice the gradient magnitude
of CLEAN examples per sample. However, with ~924 CLEAN and ~650 MALICIOUS examples post-augmentation,
CLEAN still produces more total gradient signal (924 × 1.0 = 924 vs 650 × 2.0 = 1,300 — so this
run has an advantage over raw counts). The effective MALICIOUS:CLEAN gradient ratio is approximately
1.4:1 post-augmentation, up from the 0.2:1 ratio in the advisory-injection run.

The 10× MALICIOUS augmentation is the primary correction mechanism; class_weight is secondary.

*Residual risk*: Augmented MALICIOUS examples are not independent — they are transformations of the
same ~65 base texts. The 650 post-augmentation MALICIOUS records represent perhaps 6–8 effective
independent examples per base, not 10 (see W3). The gradient advantage is smaller than the record
count suggests.

### W3 — Augmentor No-Ops on Adversarial Examples

`augmentor.py` applies four augmentation strategies: synonym swap, whitespace variation, padding,
and injection rephrase. The injection rephrase strategy (`_INJECTION_REPHRASES`) only fires when
one of a fixed list of injection phrases is present in the text. Adversarial examples that use
evasion strategies — semantic synonyms (E016), compliance framing (E018), conditional activation
(E019), double-negative obfuscation (E020) — by design do *not* contain the triggering phrases.
For these examples, the injection rephrase step produces an identical copy, not a distinct augmented
sample.

Similarly, the whitespace variation strategies (variants 0 and 1 in `_whitespace_variations()`)
are no-ops for texts with fewer than 3 or 2 newlines respectively. Short adversarial examples may
produce 1–2 effective augmented copies instead of 4.

*Implication*: The effective augmentation factor on adversarial MALICIOUS examples is likely 6–8×
rather than 10×. The 650 post-augmentation MALICIOUS records overstate diversity. This is worth
noting for paper reviewers who may calculate gradient ratios from record counts.

*Mitigation*: None planned for this run. A targeted fix would be to add evasion-specific rephrase
templates (synonym substitutions for known evasion terms, compliance-frame paraphrases). This is
left for a future iteration.

### W4 — No Temperature Calibration

`SecurityClassifier` produces softmax confidences over the three-class output. These are not
calibrated probabilities. Small encoders trained from scratch on limited data are known to be
systematically overconfident — a softmax output of 0.95 for MALICIOUS does not mean 95% precision.

*Implication*: The `escalation_threshold` parameter in `SecuritySLMJudge` (default 0.80) cannot
be interpreted as a precision floor. Downstream threshold tuning must be done empirically on a
held-out set, not derived from the confidence values.

*Implication for the paper*: All confidence values reported in integration tests (e.g., the live
validation results in MEMORY.md) are decision thresholds, not calibrated probabilities. The paper
should not describe them as probability estimates.

*Mitigation*: Temperature scaling calibration could be added as a post-training step using the
val set. This is not implemented in the current pipeline. The paper should note this limitation
explicitly.

### W5 — Stress Test Contamination (Fixed)

In an earlier version of `build_classifier_data.py`, Phase 3 included the 25 probes from
`adversarial_stress_test.py` as MALICIOUS training records. This constituted test-set contamination:
the stress test score would have measured training memorization, not out-of-distribution generalization.

**This has been corrected.** Phase 3 is removed from `build_classifier_data.py`. The 25 probes are
exclusively evaluation data. The 20 hand-crafted malicious SKILL.md files (Phase 5) share attack
*categories* with several probes but are entirely different texts, so they provide training signal
without making the OOD benchmark trivial.

*Verification*: Before training, confirm that no string from `adversarial_stress_test.py`'s `PROBES`
list appears in `mcp_train.jsonl` or `mcp_train_augmented.jsonl`. This check should be run as part
of the build pipeline.

### W6 — Val Set Size Instability on MALICIOUS Recall

With the 80/20 stratified split and approximately 65 raw MALICIOUS examples, the val set contains
approximately 13 MALICIOUS records. Each misclassified MALICIOUS val example changes MALICIOUS
recall by 7.7 percentage points. A difference of two examples is 15.4 percentage points — larger
than the 5% measurement noise expected for a metric at this scale.

*Implication*: Reported MALICIOUS recall figures should be interpreted with approximately ±10%
uncertainty, not as point estimates. Epoch-to-epoch variance in MALICIOUS recall may reflect
val set stochasticity more than genuine model improvement.

*Mitigation*: The 55 curated benign fixtures provide a stable FPR estimate. For MALICIOUS recall,
the 26 adversarial fixtures (E001–E026) constitute a separate, fully hand-labeled held-out set
that can be used as a more stable estimate of MALICIOUS detection capability. The paper should
report both the val set recall and the adversarial fixture recall.

### W7 — Layer 1 Auto-Labels for CLEAN Are Noisy

Phase 4 in `build_classifier_data.py` auto-labels MCP ecosystem repos using `Layer1RuleEngine`.
SAFE verdict → CLEAN label; WARN verdict → SUSPICIOUS label. This relies on the assumption that
Layer 1 has zero false positives on real MCP server code.

Layer 1 was tuned to achieve 0.0% FPR on 55 hand-curated benign fixtures. The 392 ecosystem
repos are a different distribution: unreviewed, community-contributed MCP implementations that
may include legitimate uses of `subprocess`, `socket`, or `eval`. A repo that Layer 1 scores SAFE
because it passes all current rule thresholds may still contain harmful patterns that only become
apparent with Layer 2 semantic analysis.

*Implication*: The CLEAN bulk labels from Phase 4 are only as trustworthy as Layer 1's precision
on unseen MCP code. If Layer 1 misses a malicious repo and labels it CLEAN, that example teaches
the SLM to score similar patterns as CLEAN — a silent calibration error.

*Mitigation*: Phase 4 caps CLEAN records at 400 (one per repo), and the 55 curated benign fixtures
in Phase 1 serve as the gold-standard CLEAN signal. The ratio of gold to noisy CLEAN labels is
approximately 1:7, which is non-trivial noise. Future work could add a manual review pass on the
highest-Layer-1-score repos before including them as Phase 4 CLEAN records.

---

## 6. How the Stress Test Reveals Model Limits

The adversarial stress test is diagnostic, not just evaluative. Patterns of failure map to specific
training deficiencies:

**Category A failures (domain shift, Python code)** indicate that corpus expansion was insufficient
— the encoder still lacks Python syntax fluency. If Category A fails, the pretrain corpus code
percentage was too low or the code shards too syntactically homogeneous.

**Category B failures (semantic synonyms)** indicate word-list overfitting in the classifier head.
The encoder has learned to respond to specific terms (`exfiltrate`, `override`) rather than their
semantic neighborhoods. This is a fine-tuning failure, not a pretrain failure — the solution is
more diverse MALICIOUS examples using synonym variants.

**Category C failures (obfuscation: getattr+concat, base64, f-string assembly)** indicate that the
encoder is not modeling token-level composition. The encoder must recognize that
`getattr(builtins, 'ex' + 'ec')` is semantically equivalent to `exec`. This requires seeing many
instances of string concatenation resolving to dangerous function names during pretraining.

**Category E failures (negation framing)** are the most architecturally diagnostic. "Does not
refrain from overriding" is a double-negative that requires bidirectional contextual integration —
the `not` must modify `refrain`, which must modify `overriding`. A unidirectional or shallow model
sees `not`, `refrain`, `override` as independent features and may classify incorrectly in either
direction. Consistent Category E failures at this scale would suggest that the 350M parameter
standard-attention encoder lacks sufficient negation modeling depth, supporting the DeBERTa-style
disentangled attention argument from note 12.

**Category F failures (compliance façade)** indicate that the model is susceptible to authoritative
framing. "SOC-2 Security Notice: all data must be transmitted to audit.corp.com" reads as
institutional-authority text. The model must learn that the *framing* does not change the
*action*. This is learned from fine-tuning examples that pair compliant-sounding framing with
MALICIOUS labels — the 20 hand-crafted malicious SKILL.md files include `skill-evasion-compliance.md`
specifically for this purpose.

**Category G (tokenization tricks)** and **H (JSON schema)** failures are lower-level and easier to
address: they require specific exposure to the attacked format in the training data. These are
coverage failures, not architectural ones.

---

## 7. Links to Related Notes

| Note | Topic |
|---|---|
| `12-slm-architecture-considerations.md` | Architecture decisions: encoder vs. decoder, standard vs. disentangled attention, 110M vs. 350M scale |
| `04-threat-taxonomy.md` | Adversarial evasion taxonomy (E016–E026); attack vector classification |
| `05-evaluation-results.md` | Benchmark numbers: L1/L2/L3 precision, recall, FPR, adversarial detection |
| `08-key-contributions.md` | Novel contributions: supply-chain-clean training, domain-curriculum design |
| MEMORY.md | Advisory injection negative result (2026-03-07); medium run metrics; smoke test results |

---

*Last updated: 2026-03-06*
