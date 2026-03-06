"""
finetuning/evaluate_slm.py
──────────────────────────
Phase 5: Evaluate the trained SecurityClassifier on the validation set.

Metrics reported:
  Overall accuracy
  Per-class precision / recall / F1 (CLEAN / SUSPICIOUS / MALICIOUS)
  Confusion matrix (3×3)
  MALICIOUS recall — critical: missing a MALICIOUS is a security failure

Smoke test success criterion:
  Accuracy > 50% (chance = 33.3%)
  → confirms classification head learned something from pretrained encoder

Full run success criterion:
  MALICIOUS recall = 100% (no false negatives on critical class)
  Overall accuracy ≥ 88%

Usage:
    python finetuning/evaluate_slm.py \
        --model finetuning/security_slm_smoke/ \
        --tokenizer finetuning/tokenizer_smoke/ \
        [--val-data finetuning/data/val.jsonl]

Requirements:
    pip install torch>=2.3 tokenizers>=0.19
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from finetuning.model import (  # noqa: E402
    SecurityClassifier,
    _LABEL_MAP,
    _ID_TO_LABEL,
)

_LABELS = ["CLEAN", "SUSPICIOUS", "MALICIOUS"]
_UNTRUSTED_RE = re.compile(
    r"<untrusted_content>\s*(.*?)\s*</untrusted_content>", re.DOTALL
)


def _load_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _extract_example(record: dict) -> tuple[str, str] | None:
    """Extract (text, verdict_str) from a ChatML record."""
    messages = record.get("messages", [])
    user_text = assistant_verdict = ""
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if role == "user":
            m = _UNTRUSTED_RE.search(content)
            user_text = m.group(1).strip() if m else content.strip()
        elif role == "assistant":
            try:
                parsed = json.loads(content)
                assistant_verdict = parsed.get("verdict", "").upper()
            except (json.JSONDecodeError, AttributeError):
                pass
    if not user_text or not assistant_verdict:
        return None
    if assistant_verdict not in _LABEL_MAP:
        return None
    return user_text, assistant_verdict


def evaluate(
    model_dir: Path,
    tokenizer_dir: Path,
    val_data: Path,
    batch_size: int = 8,
    use_flash_attn: bool = False,
) -> dict[str, Any]:
    try:
        import torch
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError:
        print("[ERROR] torch not installed.", file=sys.stderr)
        sys.exit(1)

    try:
        from tokenizers import Tokenizer
    except ImportError:
        print("[ERROR] tokenizers not installed.", file=sys.stderr)
        sys.exit(1)

    # ── Device ────────────────────────────────────────────────────────────────
    if torch.backends.mps.is_available():
        device = torch.device("mps")
    elif torch.cuda.is_available():
        device = torch.device("cuda")
    else:
        device = torch.device("cpu")
    print(f"[INFO] Device: {device}", flush=True)

    # ── Load model ────────────────────────────────────────────────────────────
    # Try the tokenizer from model dir first (train_classifier.py copies it there)
    tok_path = model_dir / "tokenizer.json"
    if not tok_path.exists():
        tok_path = tokenizer_dir / "tokenizer.json"
    tokenizer = Tokenizer.from_file(str(tok_path))

    tok_cfg = {}
    for cfg_path in (model_dir / "tokenizer_config.json", tokenizer_dir / "tokenizer_config.json"):
        if cfg_path.exists():
            tok_cfg = json.loads(cfg_path.read_text())
            break
    sp = tok_cfg.get("special_tokens", {})
    pad_id = sp.get("[PAD]", 0)
    cls_id = sp.get("[CLS]", 1)
    sep_id = sp.get("[SEP]", 2)

    print(f"[INFO] Loading model from: {model_dir}", flush=True)
    model = SecurityClassifier.load(model_dir, use_flash_attn=use_flash_attn)
    model = model.to(device)
    model.eval()

    max_seq_len = model.config.max_seq_len
    tokenizer.enable_padding(pad_id=pad_id, pad_token="[PAD]", length=max_seq_len)
    tokenizer.enable_truncation(max_length=max_seq_len)

    # ── Load data ─────────────────────────────────────────────────────────────
    records = _load_jsonl(val_data)
    examples: list[tuple[list[int], list[int], int]] = []
    for rec in records:
        result = _extract_example(rec)
        if result is None:
            continue
        text, verdict = result
        enc = tokenizer.encode(text)
        label_id = _LABEL_MAP[verdict]
        examples.append((enc.ids, enc.attention_mask, label_id))

    if not examples:
        print("[ERROR] No valid examples found in val data.", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Evaluating on {len(examples)} examples", flush=True)

    # Build tensors
    all_ids   = torch.tensor([e[0] for e in examples], dtype=torch.long)
    all_masks = torch.tensor([e[1] for e in examples], dtype=torch.long)
    all_labels = torch.tensor([e[2] for e in examples], dtype=torch.long)

    dataset = TensorDataset(all_ids, all_masks, all_labels)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=False)

    # ── Run inference ─────────────────────────────────────────────────────────
    all_preds: list[int] = []
    all_confs: list[float] = []

    import torch.nn.functional as F

    with torch.no_grad():
        for batch in loader:
            ids, masks, _ = [t.to(device) for t in batch]
            verdict_logits, _type_logits = model(ids, masks)
            probs = F.softmax(verdict_logits, dim=-1)
            confs, preds = probs.max(dim=-1)
            all_preds.extend(preds.cpu().tolist())
            all_confs.extend(confs.cpu().tolist())

    labels = all_labels.tolist()

    # ── Metrics ───────────────────────────────────────────────────────────────
    # Confusion matrix: conf[true][pred]
    conf_matrix: dict[int, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for true, pred in zip(labels, all_preds):
        conf_matrix[true][pred] += 1

    results: dict[str, Any] = {}

    # Overall accuracy
    correct = sum(t == p for t, p in zip(labels, all_preds))
    accuracy = correct / max(1, len(labels))
    results["accuracy"] = accuracy
    print(f"\n── Results ─────────────────────────────────────────────────")
    print(f"  Overall accuracy: {accuracy:.1%} ({correct}/{len(labels)})")

    # Per-class metrics
    per_class: dict[str, dict[str, float]] = {}
    for class_id, class_name in enumerate(_LABELS):
        tp = conf_matrix[class_id][class_id]
        fp = sum(conf_matrix[other][class_id] for other in range(3) if other != class_id)
        fn = sum(conf_matrix[class_id][other] for other in range(3) if other != class_id)
        precision = tp / max(1, tp + fp)
        recall    = tp / max(1, tp + fn)
        f1        = 2 * precision * recall / max(1e-9, precision + recall)
        support   = sum(conf_matrix[class_id].values())
        per_class[class_name] = {"precision": precision, "recall": recall, "f1": f1, "support": support}
        print(f"  {class_name:12s}  P={precision:.1%}  R={recall:.1%}  F1={f1:.1%}  support={support}")

    results["per_class"] = per_class

    # Macro F1
    macro_f1 = sum(per_class[c]["f1"] for c in _LABELS) / len(_LABELS)
    results["macro_f1"] = macro_f1
    print(f"  Macro F1: {macro_f1:.1%}")

    # MALICIOUS recall — primary safety metric
    mal_recall = per_class["MALICIOUS"]["recall"]
    results["malicious_recall"] = mal_recall
    status = "PASS" if mal_recall == 1.0 else "FAIL"
    print(f"  MALICIOUS recall: {mal_recall:.1%}  [{status}]")

    # Confusion matrix
    print(f"\n── Confusion matrix (rows=true, cols=predicted) ────────────")
    header = f"{'':12s}" + "".join(f"{l:12s}" for l in _LABELS)
    print(f"  {header}")
    for true_id, true_name in enumerate(_LABELS):
        row = "".join(f"{conf_matrix[true_id][pred_id]:12d}" for pred_id in range(3))
        print(f"  {true_name:12s}{row}")

    # Smoke test check
    print(f"\n── Smoke test criteria ─────────────────────────────────────")
    acc_pass = accuracy > 0.50
    print(f"  Accuracy > 50%: {'PASS' if acc_pass else 'FAIL'} ({accuracy:.1%})")
    print(f"  (Chance baseline: 33.3%)")

    results["smoke_pass"] = acc_pass
    return results


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate the trained SecurityClassifier on the validation set."
    )
    parser.add_argument("--model",      type=Path, default=_HERE / "security_slm_smoke")
    parser.add_argument("--tokenizer",  type=Path, default=_HERE / "tokenizer_smoke")
    parser.add_argument("--val-data",   type=Path, default=_HERE / "data" / "val.jsonl")
    parser.add_argument(
        "--val-file", type=Path, default=None,
        help="Override path to validation JSONL (takes precedence over --val-data).",
    )
    parser.add_argument("--batch-size", type=int,  default=8)
    parser.add_argument("--no-flash-attn", action="store_true")
    args = parser.parse_args()

    # --val-file overrides --val-data when specified
    if args.val_file is not None:
        args.val_data = args.val_file

    for req in (args.model, args.tokenizer):
        if not req.exists():
            print(f"[ERROR] Required path not found: {req}", file=sys.stderr)
            sys.exit(1)

    if not args.val_data.exists():
        print(f"[ERROR] Val data not found: {args.val_data}", file=sys.stderr)
        sys.exit(1)

    results = evaluate(
        model_dir=args.model,
        tokenizer_dir=args.tokenizer,
        val_data=args.val_data,
        batch_size=args.batch_size,
        use_flash_attn=not args.no_flash_attn,
    )

    if not results.get("smoke_pass", False):
        print("\n[WARN] Accuracy ≤ 50% — model may not have learned effectively.", file=sys.stderr)
        print("       This is expected if pretraining ran for < 1 epoch on a tiny corpus.", file=sys.stderr)
        print("       Run full pretraining on 4090 for production-quality results.", file=sys.stderr)


if __name__ == "__main__":
    main()
