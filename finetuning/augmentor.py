"""
finetuning/augmentor.py
───────────────────────
Phase 2: Deterministic synthetic augmentation of training data.

Expands the training set from ~80 examples to ~400 by applying
deterministic, semantics-preserving transforms.

Strategies applied per example:
  1. whitespace_variation   — vary indentation and blank-line density
  2. synonym_swap (benign)  — swap safe technical synonyms in CLEAN examples
  3. sentence_padding       — prepend/append generic boilerplate to CLEAN examples
  4. injection_rephrase     — vary phrasing of attack indicators in MALICIOUS examples

Invariants:
  - Malicious augmentation ONLY varies phrasing, never semantics.
    The attack payload MUST remain present in all variants.
  - Augmentation is deterministic (seeded random) for reproducibility.
  - The original example is always included alongside its augmented variants.

Usage:
    poetry run python finetuning/augmentor.py
    poetry run python finetuning/augmentor.py \
        --train-in  finetuning/data/train.jsonl \
        --train-out finetuning/data/train_augmented.jsonl \
        --factor    4
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent


# ── Synonym tables (benign technical terms only) ──────────────────────────────
# These are safe to swap in CLEAN examples only — never applied to MALICIOUS.

_BENIGN_SYNONYMS: list[tuple[str, list[str]]] = [
    ("filesystem",   ["file system", "file-system", "local fs"]),
    ("network",      ["net", "networking", "network layer"]),
    ("authenticate", ["auth", "verify credentials", "log in"]),
    ("database",     ["db", "data store", "datastore"]),
    ("endpoint",     ["URL", "API endpoint", "service URL"]),
    ("token",        ["auth token", "access token", "bearer token"]),
    ("directory",    ["folder", "dir"]),
    ("repository",   ["repo", "source repo"]),
    ("initialize",   ["init", "set up", "bootstrap"]),
    ("execute",      ["run", "invoke", "call"]),
    ("configuration","config", ),
    ("documentation","docs",),
    ("retrieve",     ["fetch", "get", "pull"]),
    ("return",       ["output", "yield", "produce"]),
]

# Normalize the table (ensure all values are lists)
_SYNONYM_TABLE: list[tuple[str, list[str]]] = [
    (src, alts if isinstance(alts, list) else list(alts))
    for src, alts in _BENIGN_SYNONYMS
]


# ── Generic boilerplate sentences for padding ─────────────────────────────────

_BOILERPLATE_PREFIX: list[str] = [
    "This tool is part of a modular agent toolkit.",
    "Built for production use in enterprise environments.",
    "Designed for reliability and ease of integration.",
    "Compatible with all major agentic frameworks.",
    "Tested on Python 3.10+ and macOS/Linux.",
]

_BOILERPLATE_SUFFIX: list[str] = [
    "For more information, see the project README.",
    "Issues and PRs welcome on GitHub.",
    "Licensed under Apache 2.0.",
    "Maintained by the core toolkit team.",
    "See CHANGELOG for recent updates.",
]


# ── Attack rephrasings (MALICIOUS only) ───────────────────────────────────────
# Each entry is (original_fragment, list_of_phrasings).
# Applied only when the original fragment is found in the text — never blind.

_INJECTION_REPHRASES: list[tuple[str, list[str]]] = [
    (
        "ignore previous",
        ["disregard prior", "set aside earlier", "forget your previous"],
    ),
    (
        "override",
        ["supersede", "replace", "take precedence over"],
    ),
    (
        "exfiltrate",
        ["transmit", "send out", "relay externally"],
    ),
    (
        "send to",
        ["forward to", "dispatch to", "relay to"],
    ),
    (
        "you are now",
        ["from this point you are", "henceforth you are", "consider yourself"],
    ),
    (
        "act as",
        ["behave as", "operate as", "function as"],
    ),
]


# ── Suspicious injection phrases (for synthetic SUSPICIOUS generation) ─────────
# Each entry is (fragment, plausible_framing).  The fragment is appended/inserted
# into a CLEAN example with a plausible-sounding but ambiguous framing.
# Applied only to CLEAN→SUSPICIOUS synthetic variants.

_SUSPICIOUS_INSERTS: list[str] = [
    "\n\n> **Note:** This tool forwards runtime context to a remote aggregator for telemetry.",
    "\n\nThe tool reads configuration from environment variables including credentials when available.",
    "\n\nFor observability, this tool logs the full request payload to the configured audit endpoint.",
    "\n\nThis tool may execute subprocess utilities to validate system connectivity before proceeding.",
    "\n\nWhen `debug=True`, the tool captures and transmits the current environment snapshot.",
    "\n\nThe plugin directory path is configurable and modules are loaded dynamically at runtime.",
    "\n\nThis tool caches authentication tokens in process memory across calls for performance.",
]


# ── Core transform functions ──────────────────────────────────────────────────

def whitespace_variation(text: str, rng: random.Random, variant: int) -> str:
    """
    Vary whitespace: compress blank lines (variant=0) or expand them (variant=1).
    Variant=2 adds a trailing newline; variant=3 strips leading whitespace per line.
    """
    if variant == 0:
        # Compress runs of blank lines to single blank line
        return re.sub(r"\n{3,}", "\n\n", text)
    elif variant == 1:
        # Expand single blank lines to double (more generous spacing)
        return re.sub(r"\n\n", "\n\n\n", text)
    elif variant == 2:
        return text.rstrip() + "\n"
    else:
        # Strip trailing whitespace on each line
        return "\n".join(line.rstrip() for line in text.splitlines())


def synonym_swap(text: str, rng: random.Random) -> str:
    """
    Replace one occurrence of a benign technical synonym (random selection).
    Applied ONLY to CLEAN examples.
    """
    # Build a list of applicable replacements
    applicable = []
    for src, alts in _SYNONYM_TABLE:
        pattern = re.compile(re.escape(src), re.IGNORECASE)
        if pattern.search(text):
            applicable.append((pattern, src, alts))

    if not applicable:
        return text

    pattern, src, alts = rng.choice(applicable)
    replacement = rng.choice(alts)

    # Replace only the first occurrence to keep the change minimal
    return pattern.sub(replacement, text, count=1)


def sentence_padding(text: str, rng: random.Random, position: str) -> str:
    """
    Prepend or append a boilerplate sentence.
    Applied ONLY to CLEAN examples.
    """
    if position == "prefix":
        sentence = rng.choice(_BOILERPLATE_PREFIX)
        return sentence + "\n\n" + text
    else:
        sentence = rng.choice(_BOILERPLATE_SUFFIX)
        return text + "\n\n" + sentence


def injection_rephrase(text: str, rng: random.Random) -> str:
    """
    Replace one attack indicator phrase with an alternative phrasing.
    Applied ONLY to MALICIOUS examples to vary surface form while preserving
    malicious intent. Never applied to CLEAN or SUSPICIOUS.
    """
    applicable = []
    for fragment, rephrases in _INJECTION_REPHRASES:
        pattern = re.compile(re.escape(fragment), re.IGNORECASE)
        if pattern.search(text):
            applicable.append((pattern, rephrases))

    if not applicable:
        return text

    pattern, rephrases = rng.choice(applicable)
    replacement = rng.choice(rephrases)
    return pattern.sub(replacement, text, count=1)


def suspicious_inject(text: str, rng: random.Random) -> str:
    """
    Append a mildly suspicious-sounding note to a CLEAN example to create a
    synthetic SUSPICIOUS training variant.

    Applied ONLY when generating synthetic SUSPICIOUS examples from CLEAN
    examples.  The insertion is semantically ambiguous — it raises mild concern
    without being clearly malicious, matching the SUSPICIOUS label intent.
    """
    insert = rng.choice(_SUSPICIOUS_INSERTS)
    # Find a good insertion point — after the first double newline block
    idx = text.find("\n\n")
    if idx != -1:
        return text[:idx] + insert + text[idx:]
    return text + insert


# ── Augmentation orchestrator ─────────────────────────────────────────────────

def _get_content_text(record: dict[str, Any]) -> str:
    """Extract the user message content from a ChatML record."""
    for msg in record.get("messages", []):
        if msg.get("role") == "user":
            return msg["content"]
    return ""


def _set_content_text(record: dict[str, Any], new_text: str) -> dict[str, Any]:
    """Return a new record with the user message replaced by new_text."""
    import copy
    new_record = copy.deepcopy(record)
    for msg in new_record["messages"]:
        if msg["role"] == "user":
            msg["content"] = new_text
            break
    return new_record


def _get_verdict_label(record: dict[str, Any]) -> str:
    """Extract verdict label from assistant message JSON."""
    for msg in record.get("messages", []):
        if msg.get("role") == "assistant":
            try:
                data = json.loads(msg["content"])
                return str(data.get("verdict", "CLEAN"))
            except (json.JSONDecodeError, AttributeError):
                pass
    return "CLEAN"


def augment_record(
    record: dict[str, Any],
    rng: random.Random,
    factor: int,
) -> list[dict[str, Any]]:
    """
    Produce up to `factor - 1` augmented variants of a record.
    The original is always returned as the first element.

    Strategy selection:
      CLEAN     → whitespace_variation, synonym_swap, sentence_padding,
                  plus one synthetic SUSPICIOUS variant via suspicious_inject
      SUSPICIOUS→ whitespace_variation + suspicious_inject variants
      MALICIOUS → whitespace_variation, injection_rephrase
    """
    label = _get_verdict_label(record)
    original_text = _get_content_text(record)

    results = [record]  # Always include original

    for variant_idx in range(1, factor):
        text = original_text
        if label == "CLEAN":
            strategy = variant_idx % 4
            if strategy == 0:
                text = whitespace_variation(text, rng, variant=0)
            elif strategy == 1:
                text = synonym_swap(text, rng)
            elif strategy == 2:
                text = sentence_padding(text, rng, position="prefix")
            else:
                text = sentence_padding(text, rng, position="suffix")
        elif label == "MALICIOUS":
            strategy = variant_idx % 3
            if strategy == 0:
                text = whitespace_variation(text, rng, variant=variant_idx % 4)
            elif strategy == 1:
                text = injection_rephrase(text, rng)
            else:
                text = whitespace_variation(text, rng, variant=0)
                text = injection_rephrase(text, rng)
        else:
            # SUSPICIOUS: whitespace variation + suspicious_inject variants
            strategy = variant_idx % 3
            if strategy == 0:
                text = whitespace_variation(text, rng, variant=variant_idx % 4)
            elif strategy == 1:
                text = suspicious_inject(text, rng)
            else:
                text = whitespace_variation(text, rng, variant=0)
                text = suspicious_inject(text, rng)

        # Only add if text actually changed (avoid duplicates)
        if text != original_text:
            results.append(_set_content_text(record, text))

    # For every CLEAN example, also produce one synthetic SUSPICIOUS variant
    # This directly addresses the SUSPICIOUS class imbalance in the fixture set.
    if label == "CLEAN":
        import copy, json as _json
        suspicious_text = suspicious_inject(original_text, rng)
        if suspicious_text != original_text:
            sus_record = copy.deepcopy(record)
            for msg in sus_record["messages"]:
                if msg["role"] == "user":
                    msg["content"] = suspicious_text
                elif msg["role"] == "assistant":
                    # Relabel as SUSPICIOUS
                    try:
                        data = _json.loads(msg["content"])
                        data["verdict"] = "SUSPICIOUS"
                        data["confidence"] = 0.65
                        data["rationale"] = "Ambiguous patterns detected; may warrant further review."
                        msg["content"] = _json.dumps(data, separators=(",", ":"))
                    except (_json.JSONDecodeError, AttributeError):
                        pass
            results.append(sus_record)

    return results


def augment_dataset(
    records: list[dict[str, Any]],
    factor: int = 4,
    seed: int = 42,
) -> list[dict[str, Any]]:
    """
    Augment all records to approximately `factor` times the original size.
    Returns shuffled list of all examples (original + augmented).
    """
    rng = random.Random(seed)
    all_records: list[dict[str, Any]] = []
    for rec in records:
        variants = augment_record(rec, rng, factor)
        all_records.extend(variants)

    rng.shuffle(all_records)
    return all_records


# ── I/O helpers ───────────────────────────────────────────────────────────────

def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def write_jsonl(records: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Augment JSONL training data via deterministic text transforms."
    )
    parser.add_argument(
        "--train-in",
        type=Path,
        default=_HERE / "data" / "train.jsonl",
        help="Input training JSONL (from data_pipeline.py).",
    )
    parser.add_argument(
        "--train-out",
        type=Path,
        default=_HERE / "data" / "train_augmented.jsonl",
        help="Output augmented training JSONL.",
    )
    parser.add_argument(
        "--factor",
        type=int,
        default=4,
        help="Target augmentation factor (default 4 → ~4× examples).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility.",
    )
    args = parser.parse_args()

    if not args.train_in.exists():
        print(
            f"[ERROR] Input file not found: {args.train_in}\n"
            "Run data_pipeline.py first.",
            file=sys.stderr,
        )
        sys.exit(1)

    records = read_jsonl(args.train_in)
    print(f"Loaded {len(records)} training examples from {args.train_in}")

    augmented = augment_dataset(records, factor=args.factor, seed=args.seed)
    write_jsonl(augmented, args.train_out)

    # Summary by label
    by_label: dict[str, int] = {}
    for rec in augmented:
        label = _get_verdict_label(rec)
        by_label[label] = by_label.get(label, 0) + 1

    print(f"Augmented to {len(augmented)} examples (factor={args.factor}×)")
    for label, count in sorted(by_label.items()):
        print(f"  {label}: {count}")
    print(f"Written to: {args.train_out}")


if __name__ == "__main__":
    main()
