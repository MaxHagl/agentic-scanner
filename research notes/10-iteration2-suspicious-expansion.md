# Iteration 2 — SUSPICIOUS Class Expansion and 5-Epoch Retrain

**Date:** 2026-03-01  
**Status:** In progress

---

## What the First Evaluation Told Us

After training 3 epochs on 336 augmented examples, the model achieved 90% accuracy with
**100% MALICIOUS recall** (zero false negatives on genuine threats). The 2 errors were both
**over-escalations**: the model predicted MALICIOUS on one SUSPICIOUS example and one CLEAN example.

Confidence breakdown over the 20 val examples:
- MALICIOUS correct: 0.85–0.95 (high, correct)
- CLEAN correct: 0.80–0.90 (high, correct)
- SUSPICIOUS correct: **0.70** (low — the model is uncertain here, hence the `*` flag)
- SUSPICIOUS wrong (→ MALICIOUS): 0.95 (very confident but wrong)
- CLEAN wrong (→ MALICIOUS): 0.95 (very confident but wrong)

**Key diagnostic:** SUSPICIOUS confidence = 0.70 universally. The model learned a stereotyped
"I am unsure → 0.70 SUSPICIOUS" pattern rather than genuinely reasoning about what makes
something suspicious vs. malicious. This is a training data problem, not a capacity problem.

### Root Cause of Over-Escalations

The base training set has:
- **~25 SUSPICIOUS** (W001–W025)
- **~30 MALICIOUS** (E-series + malicious MCP/LC/README fixtures)
- **~30 CLEAN** (benign corpus subset)

At a ratio of ~29% SUSPICIOUS in the base set, augmented to ~27%, the model sees many more
jointly-confusable examples (MALICIOUS tools that look legitimate) than genuinely-ambiguous
SUSPICIOUS tools. The training signal for the SUSPICIOUS→MALICIOUS decision boundary is weak.

Additionally, the SUSPICIOUS examples in W001–W025 are all drawn from real W-fixture files.
These cover legitimate-but-risky patterns: env-var access, session logging, shell helpers,
dynamic plugin loading, etc. The descriptions are short and structurally similar. The augmentor
produces paraphrases of these same patterns, so the training set has low variety in *why*
something is suspicious.

---

## Why More Epochs Alone Won't Fix This

Simply increasing from 3 to 5 epochs on the same 336-example dataset would:
1. Further memorize the existing SUSPICIOUS examples without adding new decision boundary signals
2. Risk overfitting to the small 20-example validation set (the eval_loss at epoch 3 was still
   decreasing, which is promising, but pushing further on the same data yields diminishing returns)
3. Not address the structural gap: the model needs more *variety* in SUSPICIOUS examples, not
   more passes over the same 25 patterns

The analysis: **more data matters more than more epochs** when the class boundary is underspecified.

---

## The Plan: 30 New SUSPICIOUS Fixtures + 5-Epoch Retrain

### New Fixture Design Principles

A good SUSPICIOUS fixture must:
1. **Not clearly cross the line into MALICIOUS** — no explicit exfiltration, no override instructions,
   no hardcoded C2 endpoints
2. **Have a plausible legitimate use case** — the tool could exist in a well-intentioned codebase
3. **Have a specific risk vector** that an expert reviewer would flag for further investigation
4. **Cover diverse risk categories** — not all env-var access, not all shell helpers

### SUSPICIOUS Risk Categories to Add (covering gaps in W001–W025)

| Category | New Fixtures | Gap Being Filled |
|---|---|---|
| Broad filesystem access | W026–W028 | W009 covers this but needs more variety |
| LLM-augmented tools (meta-risk) | W029–W031 | New: tools that themselves call LLMs |
| Configuration mutation | W032–W034 | W010 covers remote config; these cover local mut |
| Supply chain (soft) | W035–W037 | Unmarked package installs without version pins |
| Credential adjacent | W038–W040 | Tools that handle auth tokens but don't exfil |
| Subprocess (non-exec) | W041–W043 | subprocess.run with user args but no shell=True |
| Agent self-modification | W044–W046 | Writes to its own config/memory files |
| Elevated API scope | W047–W049 | Declares broad OAuth scopes |
| Network enumeration | W050–W052 | Port scanning, DNS lookups, workspace mapping |
| Audit/logging bypass | W053–W055 | Disables logging, suppresses errors |

### Why These Categories

The existing W fixture set (W001–W025) is dominated by:
- Env-var readers (W001, W011, W015, W021)
- Shell helpers (W003, W007, W019)
- File managers (W009, W017, W025)
- Plugin/code loaders (W006, W012, W013, W014)

The new categories add tools that are suspicious *because of their architectural role* in an
agentic pipeline rather than their immediate code-level behavior. "LLM-augmented tools" and
"agent self-modification" are particularly important because these are real-world patterns
appearing in MCP toolkits that L1 static analysis cannot catch (no explicit attack code)
but that a semantic reviewer would flag.

---

## Expected Impact

With 30 new SUSPICIOUS fixtures, the augmented training set grows from ~336 to ~450+ examples.
The SUSPICIOUS class representation increases from ~90 to ~180+ augmented examples (2× increase).
At 5 epochs, the model should learn a more nuanced SUSPICIOUS decision boundary.

**Target results after retraining:**
- SUSPICIOUS confidence ≥ 0.80 (currently 0.70 — suggests the model will escalate these)
- MALICIOUS recall: stays at 100%
- Accuracy: ≥ 92% (up from 90%)
- Escalation rate: drops from 20% to ≤ 15%

---

## Training Config Changes

| Parameter | Before | After |
|---|---|---|
| Epochs | 3 | 5 |
| Train examples (augmented) | ~336 | ~450+ |
| SUSPICIOUS base fixtures | 25 | 55 |
| Everything else | unchanged | unchanged |

The extra 2 epochs at a higher SUSPICIOUS/MALICIOUS ratio should push the decision boundary
to be less aggressively MALICIOUS on borderline cases.

---

## Paper Implication

This iteration demonstrates the **iterative labeling and retraining loop** that is central to
finetuning small models for specialized classification tasks. The first evaluation wasn't just
a result — it was a diagnostic that directly informed the next data collection step. This
"evaluate → diagnose → add targeted fixtures → retrain" loop is itself a contribution:
it shows how to bootstrap a task-specific classifier with <500 human-labeled examples.
