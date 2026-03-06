#!/usr/bin/env python3
"""
finetuning/inject_advisory_labels.py
─────────────────────────────────────
Read the already-downloaded GitHub advisory shard, assign labels from severity tags,
merge with existing fixture-derived JSONL, and write merged train/val sets.

Severity mapping:
  CRITICAL / HIGH   → MALICIOUS  (0.95 confidence)
  MODERATE          → SUSPICIOUS (0.70 confidence)
  LOW / no tag      → skipped

Output:
  finetuning/data/advisory_train.jsonl   (80% of advisories)
  finetuning/data/advisory_val.jsonl     (20% of advisories)
  finetuning/data/train_merged.jsonl     (fixture_train + advisory_train)
  finetuning/data/val_merged.jsonl       (fixture_val + advisory_val)
"""
import argparse, json, random, re, sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SYSTEM_PROMPT = (
    "You are a security scanner for agentic AI tools. Analyze the provided tool "
    "content and classify it as CLEAN, SUSPICIOUS, or MALICIOUS. Return JSON with "
    "fields: verdict, confidence, attack_types, findings, rationale."
)
_SEVERITY_RE = re.compile(r"\[([A-Z]+)\]")
# Strip "GHSA-xxxx-xxxx-xxxx [SEVERITY] " prefix so the label is not visible in the input text.
_PREFIX_RE = re.compile(r"^[A-Za-z0-9\-]+\s*\[[A-Z]+\]\s*")
_SEVERITY_MAP = {
    "CRITICAL": ("MALICIOUS",  0.95),
    "HIGH":     ("MALICIOUS",  0.95),
    "MODERATE": ("SUSPICIOUS", 0.70),  # kept for forward-compat
    "MEDIUM":   ("SUSPICIOUS", 0.70),  # actual tag used in GHSA shard
}


def _make_record(text: str, label: str, confidence: float, source: str) -> dict:
    assistant_content = json.dumps({
        "verdict":    label,
        "confidence": confidence,
        "attack_types": [],
        "findings":   [],
        "rationale":  f"Advisory-labeled training example ({source}).",
    })
    return {
        "messages": [
            {"role": "system",    "content": _SYSTEM_PROMPT},
            {"role": "user",      "content": f"<untrusted_content>\n{text}\n</untrusted_content>"},
            {"role": "assistant", "content": assistant_content},
        ],
        "_meta": {"source": source, "label": label},
    }


def load_advisory_shard(shard_path: Path) -> list[dict]:
    """Parse advisory shard lines → list of {label, confidence, text} dicts."""
    records = []
    for line in shard_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        m = _SEVERITY_RE.search(line)
        if not m:
            continue
        severity = m.group(1)
        if severity not in _SEVERITY_MAP:
            continue
        label, confidence = _SEVERITY_MAP[severity]
        # Strip the "GHSA-xxx [SEVERITY] " prefix so the label is not visible to the classifier
        text = _PREFIX_RE.sub("", line).strip()
        if not text:
            continue
        records.append({"text": text, "label": label, "confidence": confidence})
    return records


def stratified_split(records: list[dict], val_frac: float = 0.20, seed: int = 42) -> tuple:
    rng = random.Random(seed)
    by_label: dict[str, list] = {}
    for r in records:
        by_label.setdefault(r["label"], []).append(r)
    train, val = [], []
    for label, group in by_label.items():
        rng.shuffle(group)
        n_val = max(1, int(len(group) * val_frac))
        val.extend(group[:n_val])
        train.extend(group[n_val:])
    rng.shuffle(train)
    rng.shuffle(val)
    return train, val


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Label GitHub advisory shard and merge with fixture JSONL."
    )
    parser.add_argument(
        "--shard", type=Path,
        default=_HERE / "pretrain_corpus_medium/shards/github_advisories.txt",
        help="Path to the downloaded advisory shard (one advisory per line with [SEVERITY] tags).",
    )
    parser.add_argument(
        "--data-dir", type=Path, default=_HERE / "data",
        help="Directory containing train_augmented.jsonl and val.jsonl (and where output is written).",
    )
    parser.add_argument("--val-frac", type=float, default=0.20)
    args = parser.parse_args()

    if not args.shard.exists():
        print(f"[ERROR] Advisory shard not found: {args.shard}", file=sys.stderr)
        print("       Run: poetry run python finetuning/collect_pretrain_corpus.py --medium", file=sys.stderr)
        sys.exit(1)

    print(f"[1/4] Loading advisory shard: {args.shard}", flush=True)
    raw = load_advisory_shard(args.shard)
    label_counts: dict[str, int] = {}
    for r in raw:
        label_counts[r["label"]] = label_counts.get(r["label"], 0) + 1
    print(f"  → {len(raw)} labeled advisories: {label_counts}", flush=True)

    if not raw:
        print("[ERROR] No labeled advisories found — check shard format (expected [CRITICAL]/[HIGH]/[MODERATE] tags).", file=sys.stderr)
        sys.exit(1)

    print("[2/4] Stratified 80/20 split ...", flush=True)
    adv_train, adv_val = stratified_split(raw, val_frac=args.val_frac)
    adv_train_recs = [_make_record(r["text"], r["label"], r["confidence"], "ghsa") for r in adv_train]
    adv_val_recs   = [_make_record(r["text"], r["label"], r["confidence"], "ghsa") for r in adv_val]
    print(f"  → train={len(adv_train_recs)}, val={len(adv_val_recs)}", flush=True)

    write_jsonl(args.data_dir / "advisory_train.jsonl", adv_train_recs)
    write_jsonl(args.data_dir / "advisory_val.jsonl",   adv_val_recs)
    print("  → Wrote advisory_train.jsonl, advisory_val.jsonl", flush=True)

    print("[3/4] Merging with fixture JSONL ...", flush=True)
    fixture_train_path = args.data_dir / "train_augmented.jsonl"
    fixture_val_path   = args.data_dir / "val.jsonl"

    if not fixture_train_path.exists():
        print(f"[ERROR] Fixture train not found: {fixture_train_path}", file=sys.stderr)
        print("       Run: poetry run python finetuning/data_pipeline.py && poetry run python finetuning/augmentor.py", file=sys.stderr)
        sys.exit(1)
    if not fixture_val_path.exists():
        print(f"[ERROR] Fixture val not found: {fixture_val_path}", file=sys.stderr)
        sys.exit(1)

    fixture_train = fixture_train_path.read_text(encoding="utf-8").splitlines(keepends=True)
    fixture_val   = fixture_val_path.read_text(encoding="utf-8").splitlines(keepends=True)
    # Strip blank lines
    fixture_train = [l for l in fixture_train if l.strip()]
    fixture_val   = [l for l in fixture_val   if l.strip()]
    print(f"  Fixture train={len(fixture_train)}, val={len(fixture_val)}", flush=True)

    adv_train_lines = [json.dumps(r) + "\n" for r in adv_train_recs]
    adv_val_lines   = [json.dumps(r) + "\n" for r in adv_val_recs]

    merged_train = fixture_train + adv_train_lines
    merged_val   = fixture_val   + adv_val_lines

    rng = random.Random(42)
    rng.shuffle(merged_train)
    rng.shuffle(merged_val)

    (args.data_dir / "train_merged.jsonl").write_text("".join(merged_train), encoding="utf-8")
    (args.data_dir / "val_merged.jsonl").write_text("".join(merged_val), encoding="utf-8")

    print("[4/4] Done.", flush=True)
    print(f"  train_merged.jsonl: {len(merged_train)} examples", flush=True)
    print(f"  val_merged.jsonl:   {len(merged_val)} examples", flush=True)

    # Summarise label distribution in merged train
    mal = sum(1 for l in adv_train_lines if '"MALICIOUS"' in l)
    sus = sum(1 for l in adv_train_lines if '"SUSPICIOUS"' in l)
    print(f"  Advisory contribution: MALICIOUS={mal}, SUSPICIOUS={sus}", flush=True)


if __name__ == "__main__":
    main()
