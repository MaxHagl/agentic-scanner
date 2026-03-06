# Architecture Considerations for a Domain-Specific Security Classification SLM

> **Status:** Pre-implementation design note — options surveyed, no final decision made.
> **Context:** Evaluating architectural choices for a ~100–400M parameter SLM trained
> entirely from scratch as a supply-chain-clean L2 security judge.

---

## 1. Framing the Decision Space

The model has a narrow, well-defined task: given the text of an agentic AI tool manifest or README, produce a three-class verdict — clean, suspicious, or malicious. Three hard constraints shape every architectural choice:

1. **Supply-chain integrity** — training must proceed from randomly initialized weights on a controlled corpus. No pretrained checkpoint of external origin is permitted.
2. **Inference latency** — the model runs as a pre-filter in a latency-sensitive pipeline. Generation-based approaches carry a real cost; a single forward pass is strongly preferred.
3. **Bounded training corpus** — the corpus is domain-specific and capped at approximately 3 billion tokens.

Every option below should be evaluated against all three.

---

## 2. Encoder vs. Decoder

The fundamental architectural split is between encoder-only (BERT-style, bidirectional attention) and decoder (GPT-style, causal/autoregressive).

### Encoder — Bidirectional

An encoder sees the full token sequence before producing any representation. Bidirectional attention means a token's embedding reflects its complete sentential context — the word `override` is conditioned on everything before and after it, including negations and qualifications. Classification reduces to a single linear layer over the `[CLS]` token representation. Inference is one forward pass; latency is 5–15 ms for 100–400M parameter models on modern consumer hardware.

| | |
|---|---|
| **Advantages** | Full context per token; single forward pass; no output parsing required; directly maps to classification |
| **Disadvantages** | Not generative; no rationale output; requires MLM pretraining objective |
| **Constraints** | Requires implementing MLM masking pipeline; no generation capability for future extensibility |

### Decoder — Autoregressive

A decoder generates output token by token. Applied to classification, the model produces a text verdict (`MALICIOUS`, `CLEAN`) parsed downstream. Causal language modeling is the natural pretraining objective.

| | |
|---|---|
| **Advantages** | Future extensibility (rationale generation, few-shot prompting); single architecture for pretraining and inference |
| **Disadvantages** | Output parsing is fragile — hallucinated labels, hedged outputs, malformed JSON; inference latency scales with output length; causal LM objective is misaligned with classification |
| **Constraints** | Parsing layer adds brittleness; left-to-right attention disadvantaged for tasks requiring full context |

> **Note:** The parsing fragility concern is not theoretical. The existing Qwen+LoRA pre-filter already requires a `JudgeResponseParser` with a `PARSE_ERROR → escalate` fallback path, precisely because generative models occasionally produce malformed outputs on security inputs.

---

## 3. Attention Mechanism: Standard vs. Disentangled

Assuming an encoder architecture, the next choice is the attention formulation.

### Standard Self-Attention (BERT-style)

Content and positional embeddings are summed before computing attention scores. A token's positional information is baked into its representation prior to any inter-token interaction.

| | |
|---|---|
| **Advantages** | Simpler implementation; well-understood; extensive reference implementations available |
| **Disadvantages** | Position and content conflated in the representation; weaker negation handling |
| **Constraints** | None beyond the standard transformer architecture |

### Disentangled Attention (DeBERTa-style)

Attention is computed across four separate terms: content-to-content, content-to-position, position-to-content, and position-to-position. The net effect is that a token's *relative position* to another token contributes to the attention weight directly, rather than being absorbed into the token embedding before attention begins.

| | |
|---|---|
| **Advantages** | Meaningfully better at negation and relative-position reasoning; +18 percentage points over RoBERTa-large on ANLI Round 3; directly relevant to detecting double-negative obfuscation attacks |
| **Disadvantages** | ~15–20% additional FLOPS and memory overhead versus standard attention at equal parameter count; implementation complexity — bugs in relative position encoding are easy to introduce and hard to detect through training loss alone |
| **Constraints** | Requires a relative position encoding matrix in addition to the standard positional encoding; adds non-trivial implementation surface |

The ANLI benchmark is the empirically relevant comparison axis here. ANLI Round 3 was constructed specifically to fool models at each preceding scale — examples that stumped 110M-scale models were collected by human annotators to build the 350M-scale challenge set. Performance on ANLI-R3 therefore measures robustness to adversarial framing, not vocabulary coverage, which maps directly to the compliance-framing detection requirement (E018-class attacks).

---

## 4. Parameter Scale

Two scales warrant serious consideration.

### ~110M Parameters (BERT-base equivalent)

At 3 billion training tokens, this is approximately 27× Chinchilla-optimal — heavily over-trained on the domain, which tends to improve downstream task performance beyond what perplexity curves suggest.

| | |
|---|---|
| **Advantages** | Trains in 7–20 hours for 3 epochs on a single 4090; ample budget for re-runs and hyperparameter search; well within Chinchilla territory for the training corpus |
| **Disadvantages** | ANLI-R3 accuracy ~33–40%; frame-level disambiguation is unreliable; E018-class compliance-framing attacks will fail at roughly 60–70% |
| **Constraints** | VRAM: ~5 GB training footprint at batch=64, seq=512; no hardware constraint |

### ~350M Parameters (DeBERTa-large equivalent)

At 3 billion training tokens, approximately 8.6× Chinchilla-optimal.

| | |
|---|---|
| **Advantages** | ANLI-R3 accuracy ~65–75%; frame-level reasoning emerges more reliably; meaningfully better on compliance-framing attack detection |
| **Disadvantages** | ~3× training compute versus 110M; 20–60 hours for 3 epochs — fits within one week but leaves limited margin for failed runs |
| **Constraints** | VRAM: ~14–16 GB training footprint (weights + AdamW fp32 optimizer states + activations at batch=64); fits in 24 GB but batch size may need reduction |

The scale decision is not primarily about average accuracy — the two options perform comparably on standard, in-distribution classification. The difference is concentrated at the **adversarial framing** end of the distribution, specifically attacks that require recognizing a contradiction between an outer frame and embedded directives. This capability does not scale smoothly; it appears as a step change in the 300–400M range according to ANLI scaling data.

---

## 5. Training Objective and Tokenizer

### Pretraining Objective

| Objective | Applicable to | Notes |
|---|---|---|
| **Masked Language Modeling (MLM)** | Encoder | 15% of tokens masked per sequence; forces bidirectional contextual representations; directly transferable to classification |
| **Causal Language Modeling (CLM)** | Decoder | Predict next token left-to-right; natural for generation but misaligned with classification |
| **Classification-only (no pretraining)** | Either | Train only on labeled examples from random init; ~1,900 examples is insufficient at any scale — catastrophic overfitting guaranteed |

MLM is the correct objective for an encoder. The third option (no pretraining) is listed for completeness but is not viable.

### Tokenizer

| Option | Notes |
|---|---|
| **BPE trained from scratch on pretraining corpus** | Security-relevant sequences (`socket.connect`, `subprocess.Popen`, `os.execve`) become single tokens; eliminates the last external artifact; vocabulary tailored to domain |
| **External tokenizer (e.g., GPT-2, BERT WordPiece)** | Introduces external dependency, undermining supply-chain argument; domain vocabulary coverage may be poor for security-specific terms |
| **Character-level / byte-level** | Robust to out-of-vocabulary terms; sequences are much longer, increasing memory cost; slower convergence |

Training a BPE tokenizer from scratch on the pretraining corpus takes under an hour and eliminates the final external dependency from the training pipeline. The domain benefit — security API calls and system call names as atomic vocabulary units — is a small but genuine advantage for the classification task.

---

## 6. Summary of Options

| Dimension | Option A | Option B |
|---|---|---|
| **Architecture** | Encoder (BERT-style) | Decoder (GPT-style) |
| **Attention** | Standard self-attention | Disentangled (DeBERTa-style) |
| **Scale** | ~110M params | ~350M params |
| **Pretraining objective** | MLM | CLM |
| **Tokenizer** | BPE from scratch | External |
| **Training time (3B tokens, 3 epochs, 4090)** | 7–20 hours | 20–60 hours |
| **ANLI-R3 (adversarial framing)** | ~33–40% | ~65–75% |
| **E018-class recall estimate** | ~60–70% | ~80–90% |
| **VRAM footprint** | ~5 GB | ~14–16 GB |
| **Implementation complexity** | Low | Medium–High |

---

*Last updated: 2026-03-05*
