"""
finetuning/train_tokenizer.py
─────────────────────────────
Phase 2: Train a BPE tokenizer from scratch on our security corpus.

Zero external vocab — every token merges from the corpus itself.
Domain benefit: security primitives like `socket.connect`, `subprocess.Popen`,
`os.execve`, `base64.decode` become single or 2-token sequences rather than
being split across 6–8 subword pieces by a general-purpose tokenizer.

Special tokens (fixed IDs 0–4, in order):
  [PAD]  = 0   padding token
  [CLS]  = 1   start-of-sequence / classification token
  [SEP]  = 2   end-of-sequence / separator
  [UNK]  = 3   out-of-vocabulary token
  [MASK] = 4   masked token for MLM training

Post-processor: automatically prepends [CLS] and appends [SEP] on encode().
Padding + truncation: configured at encode time, not saved in the tokenizer.

Output:
  <output-dir>/tokenizer.json   — fully serialised tokenizer (load with
                                  tokenizers.Tokenizer.from_file())
  <output-dir>/tokenizer_config.json  — vocab_size + special token IDs

Usage:
    # Smoke (vocab=4000):
    python finetuning/train_tokenizer.py \
        --corpus-dir finetuning/pretrain_corpus_smoke/ \
        --vocab-size 4000 \
        --output finetuning/tokenizer_smoke/

    # Full run (vocab=32000):
    python finetuning/train_tokenizer.py \
        --corpus-dir finetuning/pretrain_corpus/ \
        --vocab-size 32000 \
        --output finetuning/tokenizer/

Requirements:
    pip install tokenizers>=0.19
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterator

_HERE = Path(__file__).resolve().parent


# ── Shard iterator ────────────────────────────────────────────────────────────

def _shard_files(corpus_dir: Path) -> list[str]:
    """Return paths to all .txt shard files as strings (for tokenizers API)."""
    shards_dir = corpus_dir / "shards"
    if not shards_dir.exists():
        # Fallback: treat the corpus dir itself as containing .txt files
        shards_dir = corpus_dir
    files = sorted(shards_dir.glob("*.txt"))
    if not files:
        print(f"[ERROR] No .txt files found in {shards_dir}", file=sys.stderr)
        sys.exit(1)
    return [str(f) for f in files]


# ── Tokenizer training ────────────────────────────────────────────────────────

_SPECIAL_TOKENS = ["[PAD]", "[CLS]", "[SEP]", "[UNK]", "[MASK]"]
_PAD_ID, _CLS_ID, _SEP_ID, _UNK_ID, _MASK_ID = 0, 1, 2, 3, 4


def train_tokenizer(
    corpus_dir: Path,
    vocab_size: int,
    output_dir: Path,
) -> None:
    try:
        from tokenizers import Tokenizer
        from tokenizers.models import BPE
        from tokenizers.trainers import BpeTrainer
        from tokenizers.pre_tokenizers import ByteLevel
        from tokenizers.normalizers import NFKC, Lowercase, Sequence as NormSeq
        from tokenizers.processors import TemplateProcessing
        from tokenizers.decoders import ByteLevel as ByteLevelDecoder
    except ImportError:
        print(
            "[ERROR] tokenizers not installed. Run:\n"
            "  pip install tokenizers>=0.19",
            file=sys.stderr,
        )
        sys.exit(1)

    shard_files = _shard_files(corpus_dir)
    total_size = sum(Path(f).stat().st_size for f in shard_files)
    print(f"Training on {len(shard_files)} shard(s), {total_size/1024/1024:.1f} MB total")
    print(f"Vocab size: {vocab_size}")

    # ── Build tokenizer ────────────────────────────────────────────────────────
    # ByteLevel BPE: operates on UTF-8 bytes → avoids any OOV characters.
    # The unknown token is only used as a fallback for the Byte-level model
    # (in practice, ByteLevel BPE never produces UNK since every byte is covered).
    tokenizer = Tokenizer(BPE(unk_token="[UNK]"))

    # Normaliser: NFKC + lowercase — improves merging of security terms
    # (e.g., "Socket.Connect" and "socket.connect" merge identically)
    tokenizer.normalizer = NormSeq([NFKC(), Lowercase()])

    # Pre-tokeniser: ByteLevel — splits on whitespace and encodes chars as bytes
    tokenizer.pre_tokenizer = ByteLevel(add_prefix_space=False)

    # Decoder: reverses ByteLevel encoding for display
    tokenizer.decoder = ByteLevelDecoder()

    # ── Train ──────────────────────────────────────────────────────────────────
    trainer = BpeTrainer(
        vocab_size=vocab_size,
        special_tokens=_SPECIAL_TOKENS,
        min_frequency=2,        # ignore tokens seen < 2 times (noise reduction)
        show_progress=True,
        initial_alphabet=ByteLevel.alphabet(),
    )

    print("Training BPE ...", flush=True)
    tokenizer.train(files=shard_files, trainer=trainer)

    # Verify special token IDs match our expected order
    for expected_id, tok in enumerate(_SPECIAL_TOKENS):
        actual_id = tokenizer.token_to_id(tok)
        if actual_id != expected_id:
            print(
                f"[WARN] Special token {tok!r} got ID {actual_id}, expected {expected_id}. "
                "This may cause issues in pretrain.py. Check BpeTrainer special_tokens order.",
                file=sys.stderr,
            )

    # ── Post-processor: auto-add [CLS] and [SEP] ──────────────────────────────
    # After this, tokenizer.encode(text) → [CLS] tokens... [SEP]
    tokenizer.post_processor = TemplateProcessing(
        single="[CLS] $A [SEP]",
        pair="[CLS] $A [SEP] $B:1 [SEP]:1",
        special_tokens=[
            ("[CLS]", tokenizer.token_to_id("[CLS]")),
            ("[SEP]", tokenizer.token_to_id("[SEP]")),
        ],
    )

    # ── Save ───────────────────────────────────────────────────────────────────
    output_dir.mkdir(parents=True, exist_ok=True)
    tokenizer_path = output_dir / "tokenizer.json"
    tokenizer.save(str(tokenizer_path))
    print(f"\nTokenizer saved to: {tokenizer_path}")

    # Save config for model construction
    config = {
        "vocab_size": tokenizer.get_vocab_size(),
        "special_tokens": {tok: tokenizer.token_to_id(tok) for tok in _SPECIAL_TOKENS},
    }
    (output_dir / "tokenizer_config.json").write_text(
        json.dumps(config, indent=2), encoding="utf-8"
    )
    print(f"Config saved to: {output_dir / 'tokenizer_config.json'}")

    # ── Verification ───────────────────────────────────────────────────────────
    print("\n── Tokenization verification ──────────────────────────────────")
    test_phrases = [
        "socket.connect",
        "subprocess.Popen",
        "os.execve",
        "base64.decode",
        "eval(base64.b64decode",
        "ignore all previous instructions and",
        "prompt injection attack",
    ]
    for phrase in test_phrases:
        enc = tokenizer.encode(phrase)
        # Remove [CLS] and [SEP] tokens for the count
        content_tokens = [t for t in enc.tokens if t not in ("[CLS]", "[SEP]")]
        print(f"  {phrase!r:45s} → {len(content_tokens):2d} tokens: {content_tokens}")

    print(f"\nFinal vocab size: {tokenizer.get_vocab_size():,}")
    print("Special token IDs:", {tok: tokenizer.token_to_id(tok) for tok in _SPECIAL_TOKENS})


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train a BPE tokenizer from scratch on the security pretraining corpus."
    )
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=_HERE / "pretrain_corpus_smoke",
        help="Directory containing corpus shards/ subdirectory.",
    )
    parser.add_argument(
        "--vocab-size",
        type=int,
        default=4000,
        help="BPE vocabulary size. Smoke: 4000. Full run: 32000.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=_HERE / "tokenizer_smoke",
        help="Output directory for tokenizer files.",
    )
    args = parser.parse_args()

    if not args.corpus_dir.exists():
        print(
            f"[ERROR] Corpus directory not found: {args.corpus_dir}\n"
            "Run collect_pretrain_corpus.py first.",
            file=sys.stderr,
        )
        sys.exit(1)

    train_tokenizer(args.corpus_dir, args.vocab_size, args.output)


if __name__ == "__main__":
    main()
