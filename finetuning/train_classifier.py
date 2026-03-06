"""
finetuning/train_classifier.py
──────────────────────────────
Phase 4: Classification fine-tuning on top of the pretrained RoPE encoder.

Loads the encoder from Phase 3 (pretrained_smoke/ or pretrained_slm/).
Adds a randomly-initialized linear classification head: Linear(1024, 3).
Fine-tunes the ENTIRE model (encoder + head) on the labeled security dataset.

Label space (3 classes):
  CLEAN      = 0   (from SAFE fixtures / benign examples)
  SUSPICIOUS = 1   (from WARN fixtures / borderline cases)
  MALICIOUS  = 2   (from BLOCK fixtures / clear attacks)

Class weighting:
  MALICIOUS is upweighted (×2.0) because:
  - False negative cost (missing MALICIOUS) >> False positive cost (flagging CLEAN)
  - CLEAN class typically has more examples → natural imbalance correction

Training data:
  Reads finetuning/data/train.jsonl and val.jsonl (from data_pipeline.py).
  Each record: {"messages": [{"role": "user", "content": "<untrusted_content>..."}, ...]}
  Extracts the text from <untrusted_content> tags + the verdict from assistant JSON.

Usage:
    python finetuning/train_classifier.py \
        --model finetuning/pretrained_smoke/ \
        --tokenizer finetuning/tokenizer_smoke/ \
        --output finetuning/security_slm_smoke/ \
        --epochs 20 --batch-size 4

    python finetuning/train_classifier.py \
        --model finetuning/pretrained_slm/ \
        --tokenizer finetuning/tokenizer/ \
        --output finetuning/security_slm/ \
        --epochs 40 --batch-size 32 --bfloat16

Requirements:
    pip install torch>=2.3 tokenizers>=0.19
"""

from __future__ import annotations

import argparse
import gc
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from finetuning.model import (  # noqa: E402
    SecurityClassifier,
    SecurityEncoderConfig,
    _LABEL_MAP,
    _ID_TO_LABEL,
    count_parameters,
)


# ── Dataset ───────────────────────────────────────────────────────────────────

_UNTRUSTED_RE = re.compile(
    r"<untrusted_content>\s*(.*?)\s*</untrusted_content>", re.DOTALL
)

# Map from data_pipeline.py labels to class IDs
_VERDICT_TO_ID = {
    "CLEAN":      _LABEL_MAP["CLEAN"],
    "SUSPICIOUS": _LABEL_MAP["SUSPICIOUS"],
    "MALICIOUS":  _LABEL_MAP["MALICIOUS"],
}


def _load_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _extract_example(record: dict) -> tuple[str, int] | None:
    """Extract (text, label_id) from a ChatML record."""
    messages = record.get("messages", [])
    user_text = ""
    assistant_text = ""

    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if role == "user":
            m = _UNTRUSTED_RE.search(content)
            user_text = m.group(1).strip() if m else content.strip()
        elif role == "assistant":
            assistant_text = content

    if not user_text:
        return None

    # Parse verdict from assistant JSON
    try:
        parsed = json.loads(assistant_text)
        verdict = parsed.get("verdict", "").upper()
    except (json.JSONDecodeError, AttributeError):
        return None

    label_id = _VERDICT_TO_ID.get(verdict)
    if label_id is None:
        return None

    return user_text, label_id


class SecurityClassificationDataset:
    """Dataset of (tokenized_input, label) pairs for security classification."""

    def __init__(
        self,
        jsonl_path: Path,
        tokenizer: Any,
        max_seq_len: int = 512,
        cls_id: int = 1,
        sep_id: int = 2,
        pad_id: int = 0,
    ) -> None:
        self.max_seq_len = max_seq_len
        self.cls_id = cls_id
        self.sep_id = sep_id
        self.pad_id = pad_id
        self.tokenizer = tokenizer

        # Configure tokenizer for classification (truncation + padding)
        tokenizer.enable_padding(
            pad_id=pad_id, pad_token="[PAD]", length=max_seq_len
        )
        tokenizer.enable_truncation(max_length=max_seq_len)

        records = _load_jsonl(jsonl_path)
        self.examples: list[tuple[list[int], list[int], int]] = []  # ids, mask, label

        skipped = 0
        for rec in records:
            result = _extract_example(rec)
            if result is None:
                skipped += 1
                continue
            text, label_id = result
            enc = tokenizer.encode(text)
            self.examples.append((enc.ids, enc.attention_mask, label_id))

        if skipped:
            print(f"  [Dataset] Skipped {skipped} unparseable records", flush=True)
        print(
            f"  [Dataset] {jsonl_path.name}: {len(self.examples)} examples "
            f"({self._class_dist()})",
            flush=True,
        )

    def _class_dist(self) -> str:
        from collections import Counter
        c = Counter(e[2] for e in self.examples)
        return " | ".join(f"{_ID_TO_LABEL[k]}: {v}" for k, v in sorted(c.items()))

    def __len__(self) -> int:
        return len(self.examples)

    def __getitem__(self, idx: int) -> tuple[list[int], list[int], int]:
        return self.examples[idx]


def _clf_collate(batch: list[tuple[list[int], list[int], int]]) -> dict:
    import torch
    ids = [b[0] for b in batch]
    masks = [b[1] for b in batch]
    labels = [b[2] for b in batch]
    return {
        "input_ids":      torch.tensor(ids,    dtype=torch.long),
        "attention_mask": torch.tensor(masks,  dtype=torch.long),
        "labels":         torch.tensor(labels, dtype=torch.long),
    }


# ── Training loop ─────────────────────────────────────────────────────────────

def train_classifier(
    model_dir: Path,
    tokenizer_dir: Path,
    train_data: Path,
    val_data: Path,
    output_dir: Path,
    epochs: int = 20,
    batch_size: int = 4,
    lr: float = 2e-5,
    weight_decay: float = 0.01,
    use_flash_attn: bool = True,
    use_bfloat16: bool = False,
    log_every: int = 10,
) -> None:
    try:
        import torch
        from torch.utils.data import DataLoader
    except ImportError:
        print("[ERROR] torch not installed. Run: pip install torch>=2.3", file=sys.stderr)
        sys.exit(1)

    try:
        from tokenizers import Tokenizer
    except ImportError:
        print("[ERROR] tokenizers not installed. Run: pip install tokenizers>=0.19", file=sys.stderr)
        sys.exit(1)

    # ── Device ────────────────────────────────────────────────────────────────
    if torch.backends.mps.is_available():
        device = torch.device("mps")
        print("[INFO] Device: Apple MPS", flush=True)
        if use_bfloat16:
            print("[WARN] bfloat16 not supported on MPS — using float32", flush=True)
            use_bfloat16 = False
    elif torch.cuda.is_available():
        device = torch.device("cuda")
        print(f"[INFO] Device: CUDA ({torch.cuda.get_device_name(0)})", flush=True)
    else:
        device = torch.device("cpu")
        print("[WARN] CPU only — training will be slow", flush=True)

    # ── Tokenizer ─────────────────────────────────────────────────────────────
    tok_path = tokenizer_dir / "tokenizer.json"
    tokenizer = Tokenizer.from_file(str(tok_path))

    tok_cfg = {}
    tok_cfg_path = tokenizer_dir / "tokenizer_config.json"
    if tok_cfg_path.exists():
        tok_cfg = json.loads(tok_cfg_path.read_text())
    sp = tok_cfg.get("special_tokens", {})
    pad_id  = sp.get("[PAD]", 0)
    cls_id  = sp.get("[CLS]", 1)
    sep_id  = sp.get("[SEP]", 2)

    # ── Load pretrained encoder → build classifier ────────────────────────────
    config = SecurityEncoderConfig.load(model_dir / "config.json")
    max_seq_len = config.max_seq_len
    print(f"[INFO] Loading pretrained encoder from: {model_dir}", flush=True)
    model = SecurityClassifier.from_pretrained_encoder(model_dir, use_flash_attn=use_flash_attn)

    dtype = torch.bfloat16 if use_bfloat16 else torch.float32
    model = model.to(device=device, dtype=dtype)
    counts = count_parameters(model)
    print(f"[INFO] Classifier params: {counts['total']:,} ({counts['total']/1e6:.1f}M)", flush=True)

    # ── Datasets ──────────────────────────────────────────────────────────────
    train_ds = SecurityClassificationDataset(
        train_data, tokenizer, max_seq_len=max_seq_len, cls_id=cls_id, sep_id=sep_id, pad_id=pad_id
    )
    val_ds = SecurityClassificationDataset(
        val_data, tokenizer, max_seq_len=max_seq_len, cls_id=cls_id, sep_id=sep_id, pad_id=pad_id
    )

    if len(train_ds) == 0:
        print(
            "[ERROR] Training dataset is empty.\n"
            "Run: python finetuning/data_pipeline.py && python finetuning/augmentor.py",
            file=sys.stderr,
        )
        sys.exit(1)

    train_loader = DataLoader(
        train_ds, batch_size=batch_size, shuffle=True,
        collate_fn=_clf_collate, num_workers=0,
    )
    val_loader = DataLoader(
        val_ds, batch_size=batch_size, shuffle=False,
        collate_fn=_clf_collate, num_workers=0,
    )

    # ── Loss with class weighting (upweight MALICIOUS) ────────────────────────
    class_weights = torch.tensor([1.0, 1.0, 2.0], dtype=dtype, device=device)
    criterion = torch.nn.CrossEntropyLoss(weight=class_weights)

    # ── Optimiser ─────────────────────────────────────────────────────────────
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=lr, betas=(0.9, 0.999), weight_decay=weight_decay,
    )

    # ── Training ──────────────────────────────────────────────────────────────
    output_dir.mkdir(parents=True, exist_ok=True)
    best_val_acc = 0.0
    log_path = output_dir / "training_log.jsonl"

    print(
        f"\n[INFO] Fine-tuning: {epochs} epochs, batch={batch_size}, lr={lr}",
        flush=True,
    )

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        correct = 0
        total = 0
        t0 = time.perf_counter()

        for batch in train_loader:
            input_ids = batch["input_ids"].to(device)
            attn_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            optimizer.zero_grad()
            if use_bfloat16:
                with torch.autocast(device_type="cuda", dtype=torch.bfloat16):
                    verdict_logits, _type_logits = model(input_ids, attn_mask)
                    loss = criterion(verdict_logits, labels)
            else:
                verdict_logits, _type_logits = model(input_ids, attn_mask)
                loss = criterion(verdict_logits, labels)

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            total_loss += loss.item()
            preds = verdict_logits.argmax(dim=-1)
            correct += (preds == labels).sum().item()
            total += labels.size(0)

            # MPS memory management
            gc.collect()
            if device.type == "mps":
                torch.mps.empty_cache()

        train_acc = correct / max(1, total)
        avg_loss = total_loss / max(1, len(train_loader))
        elapsed = time.perf_counter() - t0

        # Validation
        val_acc, val_loss = _validate_clf(model, val_loader, criterion, device, use_bfloat16)

        print(
            f"  Epoch {epoch:3d}/{epochs} | "
            f"train_loss={avg_loss:.4f} train_acc={train_acc:.1%} | "
            f"val_loss={val_loss:.4f} val_acc={val_acc:.1%} | "
            f"{elapsed:.1f}s",
            flush=True,
        )
        _log_clf(log_path, epoch, avg_loss, train_acc, val_loss, val_acc)

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            model.save(output_dir)
            # Also copy tokenizer for convenience
            import shutil
            if (tokenizer_dir / "tokenizer.json").exists():
                shutil.copy2(tokenizer_dir / "tokenizer.json", output_dir / "tokenizer.json")
            if tok_cfg_path.exists():
                shutil.copy2(tok_cfg_path, output_dir / "tokenizer_config.json")
            print(f"  ✓ Best val_acc {best_val_acc:.1%} → saved to {output_dir}", flush=True)

    print(f"\n[INFO] Best val accuracy: {best_val_acc:.1%}", flush=True)
    print(f"[INFO] Model saved to: {output_dir}", flush=True)


def _validate_clf(
    model: Any, loader: Any, criterion: Any, device: Any, use_bfloat16: bool
) -> tuple[float, float]:
    import torch
    model.eval()
    correct = 0
    total = 0
    total_loss = 0.0
    with torch.no_grad():
        for batch in loader:
            input_ids = batch["input_ids"].to(device)
            attn_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)
            if use_bfloat16:
                with torch.autocast(device_type="cuda", dtype=torch.bfloat16):
                    verdict_logits, _type_logits = model(input_ids, attn_mask)
                    loss = criterion(verdict_logits, labels)
            else:
                verdict_logits, _type_logits = model(input_ids, attn_mask)
                loss = criterion(verdict_logits, labels)
            total_loss += loss.item()
            preds = verdict_logits.argmax(dim=-1)
            correct += (preds == labels).sum().item()
            total += labels.size(0)
    model.train()
    acc = correct / max(1, total)
    avg_loss = total_loss / max(1, len(loader))
    return acc, avg_loss


def _log_clf(path: Path, epoch: int, train_loss: float, train_acc: float, val_loss: float, val_acc: float) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "epoch": epoch, "train_loss": train_loss, "train_acc": train_acc,
            "val_loss": val_loss, "val_acc": val_acc,
        }) + "\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fine-tune the pretrained RoPE encoder for 3-class security classification."
    )
    parser.add_argument("--model",      type=Path, default=_HERE / "pretrained_smoke",
                        help="Pretrained encoder directory (from pretrain.py).")
    parser.add_argument("--tokenizer",  type=Path, default=_HERE / "tokenizer_smoke")
    parser.add_argument("--train-data", type=Path, default=_HERE / "data" / "train_augmented.jsonl")
    parser.add_argument("--val-data",   type=Path, default=_HERE / "data" / "val.jsonl")
    parser.add_argument(
        "--train-file", type=Path, default=None,
        help="Override path to training JSONL (takes precedence over --train-data).",
    )
    parser.add_argument(
        "--val-file", type=Path, default=None,
        help="Override path to validation JSONL (takes precedence over --val-data).",
    )
    parser.add_argument("--output",     type=Path, default=_HERE / "security_slm_smoke")
    parser.add_argument("--epochs",     type=int,   default=20)
    parser.add_argument("--batch-size", type=int,   default=4)
    parser.add_argument("--lr",         type=float, default=2e-5)
    parser.add_argument("--no-flash-attn", action="store_true")
    parser.add_argument("--bfloat16",   action="store_true")
    args = parser.parse_args()

    # --train-file / --val-file override --train-data / --val-data when specified
    if args.train_file is not None:
        args.train_data = args.train_file
    if args.val_file is not None:
        args.val_data = args.val_file

    for req in (args.model, args.tokenizer):
        if not req.exists():
            print(f"[ERROR] Required path not found: {req}", file=sys.stderr)
            sys.exit(1)

    if not args.train_data.exists():
        print(
            f"[ERROR] Training data not found: {args.train_data}\n"
            "Run: python finetuning/data_pipeline.py && python finetuning/augmentor.py",
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.val_data.exists():
        print(f"[ERROR] Val data not found: {args.val_data}", file=sys.stderr)
        sys.exit(1)

    train_classifier(
        model_dir=args.model,
        tokenizer_dir=args.tokenizer,
        train_data=args.train_data,
        val_data=args.val_data,
        output_dir=args.output,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        use_flash_attn=not args.no_flash_attn,
        use_bfloat16=args.bfloat16,
    )


if __name__ == "__main__":
    main()
