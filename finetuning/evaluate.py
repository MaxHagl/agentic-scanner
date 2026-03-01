"""
finetuning/evaluate.py
──────────────────────
Phase 4: Evaluate the finetuned local LoRA model against the validation set.

Computes:
  - Accuracy (overall)
  - Precision / Recall / F1 per verdict class (CLEAN / SUSPICIOUS / MALICIOUS)
  - Escalation rate (% of examples where confidence < threshold → would escalate to Haiku)
  - Confusion matrix (3×3)
  - Comparison table: local-only vs local+escalation (upper bound with perfect escalation)

The evaluation reuses JudgeResponseParser from the main scanner to ensure
the same JSON parsing logic applies at eval time as at runtime.

Usage:
    poetry run python finetuning/evaluate.py
    poetry run python finetuning/evaluate.py \\
        --adapter finetuning/adapter \\
        --val-file finetuning/data/val.jsonl \\
        --threshold 0.80

Requirements (same as train.py):
    pip install transformers>=4.44 peft>=0.12 torch>=2.3 datasets>=2.20
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scanner.layer2_semantic.llm_judge import JudgeResponseParser  # noqa: E402


# ── Label ordering ────────────────────────────────────────────────────────────

_LABELS = ["CLEAN", "SUSPICIOUS", "MALICIOUS"]


# ── Inference helper ──────────────────────────────────────────────────────────

def _load_model_and_tokenizer(adapter_path: Path) -> tuple[Any, Any, Any]:
    """Load base model + LoRA adapter. Returns (model, tokenizer, torch)."""
    try:
        import torch
    except ImportError:
        print("[ERROR] torch not installed.", file=sys.stderr)
        sys.exit(1)

    try:
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError:
        print("[ERROR] transformers not installed.", file=sys.stderr)
        sys.exit(1)

    try:
        from peft import PeftModel
    except ImportError:
        print("[ERROR] peft not installed.", file=sys.stderr)
        sys.exit(1)

    # Read base model from provenance file
    provenance_file = adapter_path / "training_provenance.json"
    if provenance_file.exists():
        provenance = json.loads(provenance_file.read_text(encoding="utf-8"))
        base_model = provenance["base_model"]
    else:
        # Fallback: try to infer from adapter config
        adapter_config = adapter_path / "adapter_config.json"
        if adapter_config.exists():
            cfg = json.loads(adapter_config.read_text(encoding="utf-8"))
            base_model = cfg.get("base_model_name_or_path", "microsoft/Phi-3.5-mini-instruct")
        else:
            base_model = "microsoft/Phi-3.5-mini-instruct"
        print(f"[WARN] No provenance file — inferring base model: {base_model}")

    print(f"[INFO] Base model: {base_model}")
    print(f"[INFO] Adapter:    {adapter_path}")

    if torch.backends.mps.is_available():
        device = torch.device("mps")
    elif torch.cuda.is_available():
        device = torch.device("cuda")
    else:
        device = torch.device("cpu")
    print(f"[INFO] Device: {device}")

    # Load tokenizer from the base model to avoid TokenizersBackend mismatch
    # (adapter tokenizer_config.json may reference a class not in the installed version)
    tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    base = AutoModelForCausalLM.from_pretrained(
        base_model,
        dtype=torch.float32,
        trust_remote_code=True,
        attn_implementation="eager",  # bypass Phi-3.5-mini sliding-window path that breaks DynamicCache
    ).to(device)

    model = PeftModel.from_pretrained(base, str(adapter_path))
    model.eval()

    return model, tokenizer, torch


def _run_inference(
    model: Any,
    tokenizer: Any,
    torch: Any,
    record: dict[str, Any],
    max_new_tokens: int = 256,
) -> str:
    """Run one inference pass and return the raw assistant text."""
    # Build prompt from messages (exclude the assistant turn)
    messages = [m for m in record["messages"] if m["role"] != "assistant"]
    prompt = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True,
    )

    device = next(model.parameters()).device
    inputs = tokenizer(prompt, return_tensors="pt").to(device)

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            temperature=1.0,  # deterministic (do_sample=False overrides)
            pad_token_id=tokenizer.eos_token_id,
            use_cache=False,  # avoids DynamicCache.seen_tokens AttributeError on transformers>=4.44
        )

    # Decode only the newly generated tokens
    generated = outputs[0][inputs["input_ids"].shape[1]:]
    return tokenizer.decode(generated, skip_special_tokens=True)


def _get_true_label(record: dict[str, Any]) -> str:
    """Extract the true verdict label from the assistant message."""
    for msg in record.get("messages", []):
        if msg.get("role") == "assistant":
            try:
                data = json.loads(msg["content"])
                return str(data.get("verdict", "CLEAN"))
            except (json.JSONDecodeError, AttributeError):
                pass
    return "CLEAN"


# ── Metrics ───────────────────────────────────────────────────────────────────

def compute_metrics(
    true_labels: list[str],
    pred_labels: list[str],
    confidences: list[float],
    threshold: float,
) -> dict[str, Any]:
    """Compute accuracy, per-class P/R/F1, escalation rate, confusion matrix."""
    n = len(true_labels)
    assert n == len(pred_labels) == len(confidences)

    # Accuracy
    correct = sum(t == p for t, p in zip(true_labels, pred_labels))
    accuracy = correct / n if n > 0 else 0.0

    # Escalation rate
    escalated = sum(1 for c in confidences if c < threshold)
    escalation_rate = escalated / n if n > 0 else 0.0

    # Per-class P/R/F1
    per_class: dict[str, dict[str, float]] = {}
    for label in _LABELS:
        tp = sum(1 for t, p in zip(true_labels, pred_labels) if t == label and p == label)
        fp = sum(1 for t, p in zip(true_labels, pred_labels) if t != label and p == label)
        fn = sum(1 for t, p in zip(true_labels, pred_labels) if t == label and p != label)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) > 0 else 0.0)
        per_class[label] = {"precision": precision, "recall": recall, "f1": f1, "support": tp + fn}

    # Confusion matrix: rows = true, cols = predicted
    matrix: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for t, p in zip(true_labels, pred_labels):
        matrix[t][p] += 1

    # Upper bound: accuracy if all escalated examples were correctly classified by Haiku
    # (assumes Haiku is perfect on escalated subset — optimistic bound)
    escaped_wrong = sum(
        1 for t, p, c in zip(true_labels, pred_labels, confidences)
        if t != p and c < threshold
    )
    upper_bound_correct = correct + escaped_wrong
    upper_bound_accuracy = upper_bound_correct / n if n > 0 else 0.0

    return {
        "n": n,
        "accuracy": accuracy,
        "escalation_rate": escalation_rate,
        "escalated_count": escalated,
        "per_class": per_class,
        "confusion_matrix": {t: dict(preds) for t, preds in matrix.items()},
        "upper_bound_accuracy": upper_bound_accuracy,
    }


def print_report(metrics: dict[str, Any], threshold: float) -> None:
    """Print a human-readable evaluation report."""
    print(f"\nLocal model evaluation (threshold={threshold:.2f})")
    print(f"  Examples:        {metrics['n']}")
    print(f"  Accuracy:        {metrics['accuracy']:.1%}")
    print(f"  Escalation rate: {metrics['escalation_rate']:.1%}  "
          f"({metrics['escalated_count']}/{metrics['n']} → would escalate to Haiku)")
    print(f"  Upper bound acc: {metrics['upper_bound_accuracy']:.1%}  "
          f"(if Haiku perfect on escalated subset)")

    print(f"\n  {'Label':<12} {'Precision':>9} {'Recall':>8} {'F1':>6} {'Support':>8}")
    print(f"  {'-'*48}")
    for label in _LABELS:
        pc = metrics["per_class"].get(label, {})
        print(
            f"  {label:<12} "
            f"{pc.get('precision', 0):.3f}    "
            f"{pc.get('recall', 0):.3f}   "
            f"{pc.get('f1', 0):.3f}   "
            f"{pc.get('support', 0):>6}"
        )

    print(f"\n  Confusion matrix (rows=true, cols=predicted):")
    cm = metrics["confusion_matrix"]
    header = "  {:>12}".format("") + "".join(f"  {l:>12}" for l in _LABELS)
    print(header)
    for true_label in _LABELS:
        row = f"  {true_label:>12}"
        for pred_label in _LABELS:
            row += f"  {cm.get(true_label, {}).get(pred_label, 0):>12}"
        print(row)


# ── Main evaluation loop ──────────────────────────────────────────────────────

def evaluate(
    adapter_path: Path,
    val_file: Path,
    threshold: float = 0.80,
    max_examples: int | None = None,
    output_json: Path | None = None,
) -> dict[str, Any]:
    """Run evaluation and return metrics dict."""
    # Load val data
    records: list[dict[str, Any]] = []
    with val_file.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    if max_examples is not None:
        records = records[:max_examples]

    print(f"[INFO] Evaluating {len(records)} examples from {val_file}")

    model, tokenizer, torch = _load_model_and_tokenizer(adapter_path)

    true_labels: list[str] = []
    pred_labels: list[str] = []
    confidences: list[float] = []

    for i, record in enumerate(records, 1):
        true_label = _get_true_label(record)
        raw_output = _run_inference(model, tokenizer, torch, record)
        response = JudgeResponseParser.parse(raw_output)

        pred_label = response.verdict if response.verdict != "PARSE_ERROR" else "CLEAN"
        confidence = response.confidence

        true_labels.append(true_label)
        pred_labels.append(pred_label)
        confidences.append(confidence)

        status = "✓" if true_label == pred_label else "✗"
        escalated = "*" if confidence < threshold else " "
        print(
            f"  [{i:3d}/{len(records)}] {status}{escalated} "
            f"true={true_label:<12} pred={pred_label:<12} conf={confidence:.2f}"
        )

    metrics = compute_metrics(true_labels, pred_labels, confidences, threshold)
    print_report(metrics, threshold)

    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        print(f"\n[INFO] Metrics saved to: {output_json}")

    return metrics


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate the finetuned local LoRA model on the validation set."
    )
    parser.add_argument(
        "--adapter",
        type=Path,
        default=_HERE / "adapter",
        help="Path to the saved LoRA adapter directory.",
    )
    parser.add_argument(
        "--val-file",
        type=Path,
        default=_HERE / "data" / "val.jsonl",
        help="Validation JSONL file.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.80,
        help="Confidence threshold below which examples would escalate to Haiku.",
    )
    parser.add_argument(
        "--max-examples",
        type=int,
        default=None,
        help="Limit evaluation to first N examples (useful for quick testing).",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Write evaluation metrics JSON to this path.",
    )
    args = parser.parse_args()

    if not args.adapter.exists():
        print(
            f"[ERROR] Adapter not found: {args.adapter}\n"
            "Run train.py first.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.val_file.exists():
        print(
            f"[ERROR] Val file not found: {args.val_file}\n"
            "Run data_pipeline.py first.",
            file=sys.stderr,
        )
        sys.exit(1)

    evaluate(
        adapter_path=args.adapter,
        val_file=args.val_file,
        threshold=args.threshold,
        max_examples=args.max_examples,
        output_json=args.output_json,
    )


if __name__ == "__main__":
    main()
