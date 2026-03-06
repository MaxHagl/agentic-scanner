"""
finetuning/pretrain.py
──────────────────────
Phase 3: MLM pretraining of the 350M RoPE encoder from random weights.

The model architecture is IDENTICAL between smoke and full runs.
What changes is the data, batch size, precision, and epoch count.

MacBook MPS (smoke test):
  --batch-size 4 --seq-len 128 --epochs 1 --warmup-steps 200 --no-flash-attn
  Precision: float32 (MPS constraint — no bfloat16 backward pass)
  Flash Attention: disabled (standard SDPA still used)
  Memory: ~6 GB peak for 350M float32 + AdamW at batch=4, seq=128

4090 full run:
  --batch-size 64 --seq-len 512 --epochs 3 --warmup-steps 10000
  Precision: bfloat16 (PyTorch autocast)
  Flash Attention: enabled via F.scaled_dot_product_attention
  Memory: ~8–10 GB in 24 GB VRAM

MLM masking (standard BERT-style):
  15% of tokens are chosen for masking:
    80% → [MASK] token
    10% → random token from vocab
    10% → unchanged (the model must still predict them)
  [CLS], [SEP], [PAD] tokens are never masked.

Convergence target:
  Smoke: val loss < 7.5 after 1 epoch (sanity check; chance = ln(4000) ≈ 8.3)
  Full:  val loss < 2.0 after 3 epochs (genuine language understanding)

Usage:
    python finetuning/pretrain.py \
        --corpus-dir finetuning/pretrain_corpus_smoke/ \
        --tokenizer finetuning/tokenizer_smoke/ \
        --output finetuning/pretrained_smoke/ \
        --batch-size 4 --seq-len 128 --epochs 1 --warmup-steps 200 \
        --no-flash-attn

Requirements:
    pip install torch>=2.3 tokenizers>=0.19
"""

from __future__ import annotations

import argparse
import gc
import json
import math
import random
import sys
import time
from pathlib import Path
from typing import Any, Iterator

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from finetuning.model import (  # noqa: E402
    SecurityEncoderConfig,
    SecurityMLMModel,
    count_parameters,
)


# ── MLM Dataset ───────────────────────────────────────────────────────────────

class MLMDataset:
    """
    Tokenise corpus text and chunk into fixed-length sequences for MLM training.

    Strategy:
      1. Read all .txt shards, concatenate text with a separator between documents.
      2. Tokenise the full concatenation as one stream.
      3. Chunk into overlapping windows of seq_len tokens.
         Each window starts with [CLS] and ends with [SEP].
      4. Apply 15% MLM masking at getitem time (stochastic — different mask each epoch).
    """

    _NEVER_MASK = {0, 1, 2}  # PAD, CLS, SEP token IDs

    def __init__(
        self,
        corpus_dir: Path,
        tokenizer: Any,          # tokenizers.Tokenizer (with post_processor set)
        seq_len: int,
        cls_id: int = 1,
        sep_id: int = 2,
        pad_id: int = 0,
        mask_id: int = 4,
        vocab_size: int = 4000,
        val_fraction: float = 0.05,
        seed: int = 42,
        is_val: bool = False,
    ) -> None:
        self.seq_len = seq_len
        self.cls_id = cls_id
        self.sep_id = sep_id
        self.pad_id = pad_id
        self.mask_id = mask_id
        self.vocab_size = vocab_size
        self.rng = random.Random(seed + int(is_val))

        # Collect all token IDs from corpus
        all_ids = self._tokenise_corpus(corpus_dir, tokenizer)

        # Split into train / val
        split = max(1, int(len(all_ids) * val_fraction))
        if is_val:
            all_ids = all_ids[:split]
        else:
            all_ids = all_ids[split:]

        # Chunk into sequences of (seq_len - 2) content tokens
        # Each chunk becomes: [CLS] + content + [SEP]
        content_len = seq_len - 2
        self.chunks: list[list[int]] = []
        for start in range(0, len(all_ids) - content_len + 1, content_len):
            chunk = all_ids[start : start + content_len]
            if len(chunk) < content_len:
                continue  # skip incomplete final chunk
            sequence = [cls_id] + chunk + [sep_id]
            self.chunks.append(sequence)

        print(
            f"  {'Val' if is_val else 'Train'} set: "
            f"{len(all_ids):,} tokens → {len(self.chunks):,} sequences "
            f"of length {seq_len}",
            flush=True,
        )

    def _tokenise_corpus(self, corpus_dir: Path, tokenizer: Any) -> list[int]:
        """Tokenise all shard files and return flat list of token IDs.

        The tokenizer may have a post_processor that adds [CLS] and [SEP] per
        encode() call.  We filter those out here so the corpus is a flat stream
        of content tokens, which we then chunk into fixed-length sequences with
        our own [CLS] + content + [SEP] framing.
        """
        shards_dir = corpus_dir / "shards"
        if not shards_dir.exists():
            shards_dir = corpus_dir
        files = sorted(shards_dir.glob("*.txt"))
        if not files:
            print(f"[ERROR] No shards found in {shards_dir}", file=sys.stderr)
            sys.exit(1)

        all_ids: list[int] = []
        NEVER_SPECIAL = {self.cls_id, self.sep_id}

        for shard_path in files:
            text = shard_path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                enc = tokenizer.encode(line)
                # Filter out [CLS] and [SEP] added by the TemplateProcessing post_processor
                ids = [i for i in enc.ids if i not in NEVER_SPECIAL]
                all_ids.extend(ids)

        return all_ids

    def __len__(self) -> int:
        return len(self.chunks)

    def __getitem__(self, idx: int) -> dict[str, list[int]]:
        """Return a masked sequence with labels.

        Returns dict with:
          input_ids:      masked token IDs
          attention_mask: 1 for real tokens (all 1s — no padding in fixed-length chunks)
          labels:         original token IDs for masked positions, -100 elsewhere
        """
        original = self.chunks[idx][:]
        seq_len = len(original)
        input_ids = original[:]
        labels = [-100] * seq_len

        for i in range(seq_len):
            if original[i] in self._NEVER_MASK:
                continue
            if self.rng.random() < 0.15:
                labels[i] = original[i]
                r = self.rng.random()
                if r < 0.80:
                    input_ids[i] = self.mask_id
                elif r < 0.90:
                    input_ids[i] = self.rng.randint(5, self.vocab_size - 1)
                # else: keep original (10%)

        attention_mask = [1] * seq_len
        return {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "labels": labels,
        }


def _collate(batch: list[dict[str, list[int]]]) -> dict[str, Any]:
    """Simple collate: stack lists of equal-length sequences into tensors."""
    import torch
    return {
        "input_ids": torch.tensor([b["input_ids"] for b in batch], dtype=torch.long),
        "attention_mask": torch.tensor([b["attention_mask"] for b in batch], dtype=torch.long),
        "labels": torch.tensor([b["labels"] for b in batch], dtype=torch.long),
    }


# ── LR scheduler ─────────────────────────────────────────────────────────────

def _get_lr(step: int, warmup_steps: int, lr: float, min_lr_ratio: float = 0.1) -> float:
    """Linear warmup + cosine decay."""
    if step < warmup_steps:
        return lr * step / max(1, warmup_steps)
    # Cosine decay after warmup (simplified: decay from step=warmup to never below min_lr)
    progress = (step - warmup_steps) / max(1, warmup_steps * 10)
    cos = 0.5 * (1 + math.cos(math.pi * min(progress, 1.0)))
    return lr * (min_lr_ratio + (1 - min_lr_ratio) * cos)


# ── MPS memory callback ───────────────────────────────────────────────────────

def _free_mps_memory(device_type: str) -> None:
    """Release cached MPS/CUDA memory after each step."""
    gc.collect()
    if device_type == "mps":
        import torch
        torch.mps.empty_cache()
    elif device_type == "cuda":
        import torch
        torch.cuda.empty_cache()


# ── Training loop ─────────────────────────────────────────────────────────────

def pretrain(
    corpus_dir: Path,
    tokenizer_dir: Path,
    output_dir: Path,
    checkpoint_dir: Path,
    batch_size: int = 4,
    seq_len: int = 128,
    epochs: int = 1,
    warmup_steps: int = 200,
    lr: float = 1e-4,
    weight_decay: float = 0.01,
    grad_accum: int = 1,
    use_flash_attn: bool = True,
    use_bfloat16: bool = False,
    checkpoint_every: int = 2000,
    log_every: int = 50,
    val_fraction: float = 0.05,
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
        print("[INFO] Device: Apple MPS (float32 only)", flush=True)
        if use_bfloat16:
            print("[WARN] bfloat16 not supported on MPS — using float32", flush=True)
            use_bfloat16 = False
    elif torch.cuda.is_available():
        device = torch.device("cuda")
        print(f"[INFO] Device: CUDA ({torch.cuda.get_device_name(0)})", flush=True)
    else:
        device = torch.device("cpu")
        print("[WARN] No GPU/MPS — training on CPU (very slow)", flush=True)

    # ── Load tokenizer ────────────────────────────────────────────────────────
    tok_path = tokenizer_dir / "tokenizer.json"
    if not tok_path.exists():
        print(f"[ERROR] Tokenizer not found: {tok_path}", file=sys.stderr)
        sys.exit(1)
    tokenizer = Tokenizer.from_file(str(tok_path))
    vocab_size = tokenizer.get_vocab_size()

    tok_cfg_path = tokenizer_dir / "tokenizer_config.json"
    if tok_cfg_path.exists():
        tok_cfg = json.loads(tok_cfg_path.read_text())
        sp = tok_cfg.get("special_tokens", {})
        pad_id   = sp.get("[PAD]",  0)
        cls_id   = sp.get("[CLS]",  1)
        sep_id   = sp.get("[SEP]",  2)
        unk_id   = sp.get("[UNK]",  3)
        mask_id  = sp.get("[MASK]", 4)
    else:
        pad_id, cls_id, sep_id, unk_id, mask_id = 0, 1, 2, 3, 4

    print(f"[INFO] Vocab size: {vocab_size}", flush=True)

    # ── Model config ──────────────────────────────────────────────────────────
    config = SecurityEncoderConfig(
        vocab_size=vocab_size,
        max_seq_len=seq_len,
        pad_token_id=pad_id,
        cls_token_id=cls_id,
        sep_token_id=sep_id,
        unk_token_id=unk_id,
        mask_token_id=mask_id,
    )
    print(
        f"[INFO] Model: 24L × 1024H × 16A × 4096FFN | "
        f"vocab={vocab_size} | max_seq={seq_len}",
        flush=True,
    )

    # ── Build model ───────────────────────────────────────────────────────────
    dtype = torch.bfloat16 if use_bfloat16 else torch.float32
    model = SecurityMLMModel(config, use_flash_attn=use_flash_attn).to(device=device, dtype=dtype)
    counts = count_parameters(model)
    print(f"[INFO] Parameters: {counts['total']:,} ({counts['total']/1e6:.1f}M)", flush=True)

    # ── Dataset ───────────────────────────────────────────────────────────────
    print("[INFO] Building dataset ...", flush=True)
    train_ds = MLMDataset(
        corpus_dir, tokenizer, seq_len,
        cls_id=cls_id, sep_id=sep_id, pad_id=pad_id, mask_id=mask_id,
        vocab_size=vocab_size, val_fraction=val_fraction, is_val=False,
    )
    val_ds = MLMDataset(
        corpus_dir, tokenizer, seq_len,
        cls_id=cls_id, sep_id=sep_id, pad_id=pad_id, mask_id=mask_id,
        vocab_size=vocab_size, val_fraction=val_fraction, is_val=True,
    )
    if len(train_ds) == 0:
        print("[ERROR] Training dataset is empty. Check corpus collection.", file=sys.stderr)
        sys.exit(1)

    train_loader = DataLoader(
        train_ds, batch_size=batch_size, shuffle=True,
        collate_fn=_collate, num_workers=0, pin_memory=False,
    )
    val_loader = DataLoader(
        val_ds, batch_size=batch_size, shuffle=False,
        collate_fn=_collate, num_workers=0, pin_memory=False,
    )

    # ── Optimiser ─────────────────────────────────────────────────────────────
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=lr, betas=(0.9, 0.999), weight_decay=weight_decay,
    )

    # ── Training ──────────────────────────────────────────────────────────────
    output_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / "training_log.jsonl"

    global_step = 0
    total_tokens = 0
    optimizer.zero_grad()

    print(
        f"\n[INFO] Starting pretraining: {epochs} epoch(s), "
        f"batch={batch_size}, seq_len={seq_len}, "
        f"grad_accum={grad_accum}, lr={lr}, warmup={warmup_steps}",
        flush=True,
    )

    # Initial val loss (sanity check — should be close to ln(vocab_size))
    expected_chance_loss = math.log(vocab_size)
    print(f"[INFO] Expected initial MLM loss (chance): {expected_chance_loss:.3f}", flush=True)
    _validate(model, val_loader, device, dtype, 0, log_path, use_bfloat16)

    for epoch in range(1, epochs + 1):
        model.train()
        epoch_start = time.perf_counter()
        accum_loss = 0.0
        accum_steps = 0

        for batch_idx, batch in enumerate(train_loader):
            # Update LR
            current_lr = _get_lr(global_step, warmup_steps, lr)
            for pg in optimizer.param_groups:
                pg["lr"] = current_lr

            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            # Forward pass
            if use_bfloat16:
                with torch.autocast(device_type="cuda", dtype=torch.bfloat16):
                    logits = model(input_ids, attention_mask)
                    loss = _mlm_loss(logits, labels, vocab_size)
            else:
                logits = model(input_ids, attention_mask)
                loss = _mlm_loss(logits, labels, vocab_size)

            loss = loss / grad_accum
            loss.backward()

            accum_loss += loss.item() * grad_accum
            accum_steps += 1
            total_tokens += input_ids.numel()

            if accum_steps % grad_accum == 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()
                optimizer.zero_grad()
                global_step += 1
                _free_mps_memory(device.type)

                if global_step % log_every == 0:
                    avg_loss = accum_loss / accum_steps
                    elapsed = time.perf_counter() - epoch_start
                    tps = total_tokens / elapsed if elapsed > 0 else 0
                    print(
                        f"  Epoch {epoch} | step {global_step:6d} | "
                        f"loss {avg_loss:.4f} | lr {current_lr:.2e} | "
                        f"{tps/1000:.1f}K tok/s",
                        flush=True,
                    )
                    _log(log_path, {"step": global_step, "epoch": epoch, "loss": avg_loss, "lr": current_lr})
                    accum_loss = 0.0
                    accum_steps = 0

                if global_step % checkpoint_every == 0:
                    ckpt = checkpoint_dir / f"step_{global_step:06d}"
                    model.save_pretrained(ckpt)
                    print(f"  Checkpoint → {ckpt}", flush=True)

        # End of epoch: run validation
        val_loss = _validate(model, val_loader, device, dtype, epoch, log_path, use_bfloat16)

        epoch_time = time.perf_counter() - epoch_start
        print(
            f"Epoch {epoch} done in {epoch_time/60:.1f} min | "
            f"val_loss={val_loss:.4f}",
            flush=True,
        )

        # Early stopping
        if val_loss < 2.0:
            print(f"[INFO] Val loss {val_loss:.4f} < 2.0 — stopping early", flush=True)
            break

    # ── Save final model ──────────────────────────────────────────────────────
    model.save_pretrained(output_dir)
    print(f"\n[INFO] Pretrained encoder saved to: {output_dir}", flush=True)
    print(f"  Total tokens processed: {total_tokens:,}", flush=True)


def _mlm_loss(logits: Any, labels: Any, vocab_size: int) -> Any:
    """Cross-entropy loss on masked positions only (labels=-100 are ignored)."""
    import torch.nn.functional as F
    B, L, V = logits.shape
    return F.cross_entropy(logits.view(B * L, V), labels.view(B * L), ignore_index=-100)


def _validate(model: Any, loader: Any, device: Any, dtype: Any, epoch: int, log_path: Path, use_bfloat16: bool) -> float:
    import torch
    import torch.nn.functional as F
    model.eval()
    total_loss = 0.0
    total_batches = 0
    with torch.no_grad():
        for batch in loader:
            input_ids = batch["input_ids"].to(device)
            attn_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)
            if use_bfloat16:
                with torch.autocast(device_type="cuda", dtype=torch.bfloat16):
                    logits = model(input_ids, attn_mask)
            else:
                logits = model(input_ids, attn_mask)
            loss = _mlm_loss(logits, labels, model.config.vocab_size)
            total_loss += loss.item()
            total_batches += 1
    model.train()
    avg_loss = total_loss / max(1, total_batches)
    _log(log_path, {"epoch": epoch, "val_loss": avg_loss})
    print(f"  [Val] epoch={epoch} val_loss={avg_loss:.4f}", flush=True)
    return avg_loss


def _log(path: Path, entry: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="MLM pretraining of the 350M RoPE encoder from random weights."
    )
    parser.add_argument("--corpus-dir",    type=Path, default=_HERE / "pretrain_corpus_smoke")
    parser.add_argument("--tokenizer",     type=Path, default=_HERE / "tokenizer_smoke")
    parser.add_argument("--output",        type=Path, default=_HERE / "pretrained_smoke")
    parser.add_argument("--checkpoint-dir", type=Path, default=None)
    parser.add_argument("--batch-size",    type=int,   default=4)
    parser.add_argument("--seq-len",       type=int,   default=128)
    parser.add_argument("--epochs",        type=int,   default=1)
    parser.add_argument("--warmup-steps",  type=int,   default=200)
    parser.add_argument("--lr",            type=float, default=1e-4)
    parser.add_argument("--weight-decay",  type=float, default=0.01)
    parser.add_argument("--grad-accum",    type=int,   default=1,
                        help="Gradient accumulation steps. Effective batch = batch-size × grad-accum.")
    parser.add_argument("--no-flash-attn", action="store_true",
                        help="Disable memory-efficient SDPA hints (recommended on MPS).")
    parser.add_argument("--bfloat16",      action="store_true",
                        help="Use bfloat16 precision (CUDA only, ignored on MPS).")
    parser.add_argument("--checkpoint-every", type=int, default=2000)
    parser.add_argument("--log-every",     type=int,   default=50)
    args = parser.parse_args()

    if args.checkpoint_dir is None:
        args.checkpoint_dir = args.output.parent / (args.output.name + "_checkpoints")

    for req in (args.corpus_dir, args.tokenizer):
        if not req.exists():
            print(f"[ERROR] Required path not found: {req}", file=sys.stderr)
            sys.exit(1)

    pretrain(
        corpus_dir=args.corpus_dir,
        tokenizer_dir=args.tokenizer,
        output_dir=args.output,
        checkpoint_dir=args.checkpoint_dir,
        batch_size=args.batch_size,
        seq_len=args.seq_len,
        epochs=args.epochs,
        warmup_steps=args.warmup_steps,
        lr=args.lr,
        weight_decay=args.weight_decay,
        grad_accum=args.grad_accum,
        use_flash_attn=not args.no_flash_attn,
        use_bfloat16=args.bfloat16,
        checkpoint_every=args.checkpoint_every,
        log_every=args.log_every,
    )


if __name__ == "__main__":
    main()
