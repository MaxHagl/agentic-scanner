"""
finetuning/train.py
───────────────────
Phase 3: LoRA finetuning of a local LLM for Layer 2 pre-filtering.

Hardware: Apple Silicon (MPS) — no QLoRA/4-bit (bitsandbytes not supported on MPS).
Strategy: float32 + LoRA adapter (PEFT) via TRL SFTTrainer.

Recommended base model: Qwen/Qwen2.5-0.5B-Instruct (1.5B params)
  - Excellent JSON adherence
  - Fits in ~14 GB unified memory (float32 + LoRA overhead)
  - ~200ms inference on MPS vs ~1-2s Haiku API roundtrip
Fallback: meta-llama/Llama-3.2-3B-Instruct

LoRA config:
  r=16, alpha=32, target_modules=[q_proj, v_proj], dropout=0.05

Training:
  3 epochs, lr=2e-4, effective batch=8 (batch=2 × grad_accum=4)
  float32 training (MPS constraint)

Output: LoRA adapter saved to finetuning/adapter/
  (base model weights NOT saved — only the adapter diff)

Usage:
    poetry run python finetuning/train.py
    poetry run python finetuning/train.py \\
        --base-model Qwen/Qwen2.5-0.5B-Instruct \\
        --train-file finetuning/data/train_augmented.jsonl \\
        --val-file   finetuning/data/val.jsonl \\
        --output-dir finetuning/adapter \\
        --epochs 3

Requirements (not in base pyproject.toml — install separately):
    pip install transformers>=4.44 peft>=0.12 trl>=0.10 torch>=2.3 datasets>=2.20
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _require_imports() -> tuple[Any, Any, Any, Any, Any]:
    """Import ML libraries lazily with a helpful error message."""
    try:
        import torch
    except ImportError:
        print(
            "[ERROR] torch not installed. Run:\n"
            "  pip install torch>=2.3",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        import transformers
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError:
        print(
            "[ERROR] transformers not installed. Run:\n"
            "  pip install transformers>=4.44",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        from peft import LoraConfig, get_peft_model, TaskType
    except ImportError:
        print(
            "[ERROR] peft not installed. Run:\n"
            "  pip install peft>=0.12",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        from trl import SFTConfig, SFTTrainer
    except ImportError:
        print(
            "[ERROR] trl not installed. Run:\n"
            "  pip install trl>=0.10",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        from datasets import Dataset
    except ImportError:
        print(
            "[ERROR] datasets not installed. Run:\n"
            "  pip install datasets>=2.20",
            file=sys.stderr,
        )
        sys.exit(1)

    return torch, (AutoModelForCausalLM, AutoTokenizer), (LoraConfig, get_peft_model, TaskType), (SFTConfig, SFTTrainer), Dataset


def _select_device(torch: Any) -> Any:
    """Select best available device: MPS → CUDA → CPU."""
    if torch.backends.mps.is_available():
        device = torch.device("mps")
        print(f"[INFO] Using Apple MPS backend")
    elif torch.cuda.is_available():
        device = torch.device("cuda")
        print(f"[INFO] Using CUDA: {torch.cuda.get_device_name(0)}")
    else:
        device = torch.device("cpu")
        print("[WARN] Neither MPS nor CUDA available — training on CPU (slow)")
    return device


def train(
    base_model: str,
    train_file: Path,
    val_file: Path,
    output_dir: Path,
    epochs: int = 3,
    learning_rate: float = 2e-4,
    per_device_batch: int = 1,   # batch=2 doubles per-step MPS allocation; keep at 1
    grad_accum: int = 8,         # compensate: effective batch = 8 (was 2×4=8)
    lora_r: int = 16,
    lora_alpha: int = 32,
    lora_dropout: float = 0.05,
    max_seq_length: int = 256,  # skill descriptions are short; 2048 causes ~2GB/step MPS leak
) -> None:
    torch, (AutoModelForCausalLM, AutoTokenizer), (LoraConfig, get_peft_model, TaskType), (SFTConfig, SFTTrainer), Dataset = _require_imports()

    device = _select_device(torch)
    print(f"[INFO] Base model: {base_model}")
    print(f"[INFO] Train file: {train_file} ({_count_lines(train_file)} examples)")
    print(f"[INFO] Val file:   {val_file} ({_count_lines(val_file)} examples)")
    print(f"[INFO] Output dir: {output_dir}")

    # ── Load tokenizer ────────────────────────────────────────────────────────
    print("[INFO] Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # ── Load base model in float32 (MPS constraint — no fp16/bf16 for backward) ─
    print("[INFO] Loading base model (float32)...")
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype=torch.float32,    # torch_dtype= is correct for transformers 4.46.x
        trust_remote_code=True,
    )
    model = model.to(device)

    # ── Apply LoRA adapter ────────────────────────────────────────────────────
    # Auto-detect correct attention projection names for the loaded model.
    # Qwen2.5 / LLaMA / Mistral: "q_proj" + "v_proj"  (separate projections)
    # Phi-3.x: "qkv_proj" + "o_proj"  (combined QKV — no longer default)
    # Fallback: target all linear layers automatically.
    named_modules = {name for name, _ in model.named_modules()}
    if any("qkv_proj" in n for n in named_modules):
        detected_target = ["qkv_proj", "o_proj"]   # Phi-3.x family
    elif any("q_proj" in n for n in named_modules):
        detected_target = ["q_proj", "v_proj"]      # Qwen2.5 / LLaMA / Mistral
    else:
        detected_target = "all-linear"              # safe fallback
    print(f"[INFO] LoRA target modules: {detected_target}")

    lora_config = LoraConfig(
        r=lora_r,
        lora_alpha=lora_alpha,
        target_modules=detected_target,
        lora_dropout=lora_dropout,
        task_type=TaskType.CAUSAL_LM,
        bias="none",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # ── Build HuggingFace datasets ────────────────────────────────────────────
    train_records = _load_jsonl(train_file)
    val_records = _load_jsonl(val_file)

    def _format_record(record: dict[str, Any]) -> dict[str, str]:
        """Convert ChatML messages list into a single formatted string."""
        text = tokenizer.apply_chat_template(
            record["messages"],
            tokenize=False,
            add_generation_prompt=False,
        )
        return {"text": text}

    train_dataset = Dataset.from_list(train_records).map(_format_record)
    val_dataset = Dataset.from_list(val_records).map(_format_record)

    print(f"[INFO] Dataset sizes — train: {len(train_dataset)}, val: {len(val_dataset)}")

    # ── Training config ───────────────────────────────────────────────────────
    output_dir.mkdir(parents=True, exist_ok=True)

    sft_config = SFTConfig(
        output_dir=str(output_dir),
        num_train_epochs=epochs,
        per_device_train_batch_size=per_device_batch,
        per_device_eval_batch_size=per_device_batch,
        gradient_accumulation_steps=grad_accum,
        learning_rate=learning_rate,
        # MPS does not support fp16 or bf16 training — use float32
        fp16=False,
        bf16=False,
        save_strategy="epoch",
        eval_strategy="epoch",
        logging_steps=10,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        max_seq_length=max_seq_length,  # trl 0.14.x uses max_seq_length (renamed to max_length in ≥0.15)
        dataset_text_field="text",
        packing=False,
        report_to="none",  # disable wandb/tensorboard
    )

    # ── MPS memory callback ───────────────────────────────────────────────────
    # MPS allocator expands its pool ~2GB/step but never shrinks between steps.
    # Calling empty_cache() after every step keeps memory stable.
    from transformers import TrainerCallback
    import gc

    class MPSMemoryCallback(TrainerCallback):
        def on_step_end(self, args, state, control, **kwargs):
            if hasattr(torch, "mps") and torch.backends.mps.is_available():
                torch.mps.empty_cache()
            gc.collect()

        def on_evaluate(self, args, state, control, **kwargs):
            if hasattr(torch, "mps") and torch.backends.mps.is_available():
                torch.mps.empty_cache()
            gc.collect()

    trainer = SFTTrainer(
        model=model,
        args=sft_config,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        tokenizer=tokenizer,
        callbacks=[MPSMemoryCallback()],
    )

    # ── Train ─────────────────────────────────────────────────────────────────
    print(f"[INFO] Starting training ({epochs} epochs)...")
    trainer.train()

    # ── Save adapter only (not base model weights) ────────────────────────────
    print(f"[INFO] Saving LoRA adapter to {output_dir} ...")
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)

    # Save training provenance
    provenance = {
        "base_model": base_model,
        "train_file": str(train_file),
        "val_file": str(val_file),
        "epochs": epochs,
        "lora_r": lora_r,
        "lora_alpha": lora_alpha,
        "learning_rate": learning_rate,
        "per_device_batch": per_device_batch,
        "grad_accum": grad_accum,
    }
    (output_dir / "training_provenance.json").write_text(
        json.dumps(provenance, indent=2), encoding="utf-8"
    )

    print(f"[INFO] Done. Adapter saved to: {output_dir}")


def _count_lines(path: Path) -> int:
    try:
        return sum(1 for _ in path.open(encoding="utf-8"))
    except FileNotFoundError:
        return 0


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Finetune a local LoRA model for Layer 2 security pre-filtering."
    )
    parser.add_argument(
        "--base-model",
        default="Qwen/Qwen2.5-0.5B-Instruct",
        help="HuggingFace model ID or local path (default: Qwen2.5-1.5B-Instruct).",
    )
    parser.add_argument(
        "--train-file",
        type=Path,
        default=_HERE / "data" / "train_augmented.jsonl",
        help="Augmented training JSONL (from augmentor.py).",
    )
    parser.add_argument(
        "--val-file",
        type=Path,
        default=_HERE / "data" / "val.jsonl",
        help="Validation JSONL (from data_pipeline.py).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_HERE / "adapter",
        help="Directory to save the LoRA adapter.",
    )
    parser.add_argument("--epochs",      type=int,   default=3)
    parser.add_argument("--lr",          type=float, default=2e-4)
    parser.add_argument("--batch-size",  type=int,   default=2)
    parser.add_argument("--grad-accum",  type=int,   default=4)
    parser.add_argument("--lora-r",      type=int,   default=16)
    parser.add_argument("--lora-alpha",  type=int,   default=32)
    parser.add_argument("--max-seq-len", type=int,   default=1024)
    args = parser.parse_args()

    for required_file in (args.train_file, args.val_file):
        if not required_file.exists():
            print(
                f"[ERROR] Required file not found: {required_file}\n"
                "Run data_pipeline.py and augmentor.py first.",
                file=sys.stderr,
            )
            sys.exit(1)

    train(
        base_model=args.base_model,
        train_file=args.train_file,
        val_file=args.val_file,
        output_dir=args.output_dir,
        epochs=args.epochs,
        learning_rate=args.lr,
        per_device_batch=args.batch_size,
        grad_accum=args.grad_accum,
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,
        max_seq_length=args.max_seq_len,
    )


if __name__ == "__main__":
    main()
