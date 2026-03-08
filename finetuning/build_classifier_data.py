"""
finetuning/build_classifier_data.py
─────────────────────────────────────
Build domain-matched classifier JSONL from five sources:

  Phase 1 — Fixture ground truth with _fixture_meta:
      SAFE  → CLEAN      (55 benign BN-series fixtures)
      WARN  → SUSPICIOUS (W-series borderline tools + E021, some E-series)
      BLOCK → MALICIOUS  (E022-E026, MCP-series, README-series, LC-series)

  Phase 2 — E001-E020 adversarial fixtures (no _fixture_meta, hardcoded MALICIOUS):
      These predate the _fixture_meta convention and are silently dropped by
      collect_fixtures(). All 20 are ground-truth MALICIOUS attacks —
      prompt injection, base64-exec, env exfiltration, credential harvesting.

  Phase 3 — REMOVED (train/test contamination).
      The adversarial stress test probes (adversarial_stress_test.py PROBES)
      are the OOD evaluation benchmark and must never appear in training data.
      Including them would make the stress test score measure memorisation,
      not out-of-distribution generalisation.

  Phase 4 — MCP ecosystem auto-labels (CLEAN bulk, L1 speed pass):
      Parse each repo README with Layer1RuleEngine.
      SAFE  → CLEAN record (capped at clean_cap)
      WARN  → SUSPICIOUS record
      BLOCK → skip (too noisy for auto-MALICIOUS)
      Applies to original clones-dir AND extra-clones-dir if provided.

  Phase 5 — Skill file records (NEW — inference-distribution-aligned):
      benign_skills_dir  → CLEAN records (benign SKILL.md from GitHub)
      malicious_skills_dir → MALICIOUS records (hand-crafted attack fixtures)
      These share attack *categories* with the stress test PROBES but are
      different texts — training signal without contaminating the OOD benchmark.

Target distribution after all phases (approximate):
    CLEAN:      ~55 fixture + ~350 auto-MCP + ~200+ benign skill = ~462
    SUSPICIOUS: ~15 fixture + ~25 auto-MCP                       = ~120
    MALICIOUS:  ~25 fixture + 20 E001-E020 + 20 skill files      = ~65

Augmentation (per-class, to address class imbalance):
    CLEAN      → 2× (augmentor also creates synthetic SUSPICIOUS variants)
    SUSPICIOUS → 2×
    MALICIOUS  → 10× (critical: must be well-represented for security recall)

Output:
    finetuning/data/mcp_train.jsonl           — 80% stratified train split
    finetuning/data/mcp_val.jsonl             — 20% stratified val split
    finetuning/data/mcp_train_augmented.jsonl — per-class augmented train set

Usage:
    poetry run python finetuning/build_classifier_data.py

    # With additional repos and skill files:
    poetry run python finetuning/build_classifier_data.py \\
        --fixtures-dir        tests/fixtures \\
        --clones-dir          benchmarks/ecosystem_local_400/clones \\
        --extra-clones-dir    benchmarks/ecosystem_local_400/additional_clones \\
        --benign-skills-dir   finetuning/data/benign_skills \\
        --malicious-skills-dir finetuning/data/malicious_skills \\
        --output-dir          finetuning/data \\
        --malicious-factor    10
"""

from __future__ import annotations

import argparse
import collections
import json
import random
import re
import sys
from pathlib import Path
from typing import Any

# ── sys.path so imports work from any cwd ─────────────────────────────────────
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ── Re-use existing pipeline helpers ─────────────────────────────────────────
from finetuning.data_pipeline import (  # noqa: E402
    _LABEL_DEFAULT_CONFIDENCE,
    _SYSTEM_PROMPT,
    _VERDICT_TO_LABEL,
    collect_fixtures,
    stratified_split,
    write_jsonl,
    _build_record as _build_fixture_record,
)
from finetuning.augmentor import augment_record  # noqa: E402
from scanner.layer1_static.parser import parse_target  # noqa: E402
from scanner.layer1_static.rule_engine import Layer1RuleEngine  # noqa: E402
from scanner.aggregator import fuse_layer1  # noqa: E402


# ── E001-E020 path pattern (files without _fixture_meta, hardcoded MALICIOUS) ─
# Matches: E001-…  through  E020-…  (the 20 adversarial fixtures that predate
# the _fixture_meta convention and are silently dropped by collect_fixtures()).
_E001_E020_RE = re.compile(r"^E0(0[1-9]|1[0-9]|20)-", re.IGNORECASE)


# ── JSONL record builder ───────────────────────────────────────────────────────

_RATIONALE_MAP: dict[str, str] = {
    "CLEAN":      "No injection, exfiltration, or privilege escalation indicators detected.",
    "SUSPICIOUS": "Ambiguous patterns detected; may warrant further review.",
    "MALICIOUS":  "Malicious intent detected: prompt injection, exfiltration, or escalation.",
}


def _make_record(text: str, label: str, source: str = "auto") -> dict[str, Any]:
    """
    Build one ChatML training record from raw text + label.
    Uses the same message format as data_pipeline.py.
    """
    confidence = _LABEL_DEFAULT_CONFIDENCE[label]
    assistant_json = json.dumps(
        {
            "verdict": label,
            "confidence": confidence,
            "attack_types": [],
            "findings": [],
            "rationale": _RATIONALE_MAP[label],
        },
        separators=(",", ":"),
    )
    return {
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": f"<untrusted_content>\n{text}\n</untrusted_content>"},
            {"role": "assistant", "content": assistant_json},
        ],
        "_meta": {
            "fixture": source,
            "expected_verdict": {"CLEAN": "SAFE", "SUSPICIOUS": "WARN", "MALICIOUS": "BLOCK"}.get(label, label),
            "label": label,
        },
    }


# ── Phase 1: Fixture ground truth (has _fixture_meta) ────────────────────────

def phase1_fixtures(fixtures_dir: Path) -> list[dict[str, Any]]:
    """
    Parse all fixtures that have a _fixture_meta block with expected_verdict.
    E001-E020 are excluded here (no metadata); handled separately in Phase 2.
    """
    print(f"\n[Phase 1] Fixture ground truth from: {fixtures_dir}")
    fixtures = collect_fixtures(fixtures_dir)
    print(f"          Found {len(fixtures)} fixtures with metadata")

    records: list[dict[str, Any]] = []
    failed = 0
    for fx in fixtures:
        rec = _build_fixture_record(fx)
        if rec is not None:
            records.append(rec)
        else:
            failed += 1

    by_label = collections.Counter(r["_meta"]["label"] for r in records)
    print(f"          Parsed {len(records)} examples  ({failed} skipped/failed)")
    for label, count in sorted(by_label.items()):
        print(f"            {label}: {count}")
    return records


# ── Phase 2: E001-E020 adversarial fixtures (no metadata) ────────────────────

def phase2_e001_e020(fixtures_dir: Path) -> list[dict[str, Any]]:
    """
    Collect E001-E020 adversarial fixtures and label them MALICIOUS.

    These predate the _fixture_meta convention so collect_fixtures() silently
    drops them. All 20 are ground-truth attacks (prompt injection, base64 exec,
    credential harvesting, env exfiltration) verified by L1+L2 evaluation.

    We parse with parse_target() to get manifest.all_untrusted_text — the exact
    field the runtime and classifier both receive.
    """
    adversarial_dir = fixtures_dir / "adversarial"
    if not adversarial_dir.exists():
        print(f"\n[Phase 2] Adversarial dir not found: {adversarial_dir} — skipping")
        return []

    print(f"\n[Phase 2] E001-E020 fixtures (hardcoded MALICIOUS) from: {adversarial_dir}")
    records: list[dict[str, Any]] = []
    skipped = 0

    for path in sorted(adversarial_dir.iterdir()):
        if not path.is_file():
            continue
        if not _E001_E020_RE.match(path.name):
            continue

        try:
            manifest = parse_target(path)
            text = manifest.all_untrusted_text
        except Exception as exc:
            print(f"  [WARN] parse_target failed for {path.name}: {exc}", file=sys.stderr)
            skipped += 1
            continue

        if not text.strip():
            skipped += 1
            continue

        records.append(_make_record(text, "MALICIOUS", source=path.name))

    print(f"          Collected {len(records)} MALICIOUS examples  ({skipped} skipped)")
    return records


# ── Phase 3: REMOVED — train/test contamination ───────────────────────────────
#
# The adversarial stress test probes (adversarial_stress_test.py PROBES) are the
# OOD evaluation benchmark. Including them as training data would mean the stress
# test score measures memorisation, not generalisation. Phase 3 is gone.
#
# The 20 hand-crafted malicious SKILL.md files in Phase 5 cover the same attack
# categories but use different texts — training signal without contamination.


# ── Phase 4: MCP ecosystem auto-labels ───────────────────────────────────────


# ── Phase 4: MCP ecosystem auto-labels ───────────────────────────────────────

def _find_repo_readme(repo_dir: Path) -> Path | None:
    for candidate in ("README.md", "README.rst", "README.txt", "README"):
        p = repo_dir / candidate
        if p.is_file() and p.stat().st_size > 100:
            return p
    return None


def phase4_mcp_autolabel(
    *clones_dirs: Path,
    clean_cap: int = 400,
) -> list[dict[str, Any]]:
    """
    Auto-label MCP ecosystem repos with Layer1RuleEngine (no network calls).

    Accepts one or more clone directories (original + additional_clones).
    The clean_cap is shared across all directories combined.

    SAFE  → CLEAN (capped at clean_cap)
    WARN  → SUSPICIOUS
    BLOCK → skip  (auto-MALICIOUS is too noisy; only hand-verified MALICIOUS used)

    README-only parse → empty dependency list → DependencyAuditor makes no
    network calls → fast, offline-safe.
    """
    active_dirs = [d for d in clones_dirs if d.exists()]
    if not active_dirs:
        print(f"\n[Phase 4] No clones dirs found — skipping", file=sys.stderr)
        return []

    print(f"\n[Phase 4] MCP ecosystem auto-labels")
    for d in active_dirs:
        print(f"          from: {d}")
    engine = Layer1RuleEngine()

    records: list[dict[str, Any]] = []
    n_clean = n_suspicious = n_block_skip = n_no_readme = n_err = 0

    for clones_dir in active_dirs:
        repo_dirs = sorted(p for p in clones_dir.iterdir() if p.is_dir())
        print(f"          {clones_dir.name}: {len(repo_dirs)} repo directories")

        for repo_dir in repo_dirs:
            if n_clean >= clean_cap:
                break  # Global cap reached

            readme = _find_repo_readme(repo_dir)
            if readme is None:
                n_no_readme += 1
                continue

            try:
                manifest = parse_target(readme)
            except Exception as exc:
                print(f"  [WARN] parse_target failed for {repo_dir.name}: {exc}", file=sys.stderr)
                n_err += 1
                continue

            text = manifest.all_untrusted_text
            if not text.strip():
                n_no_readme += 1
                continue

            try:
                report = engine.evaluate(manifest)
            except Exception as exc:
                print(f"  [WARN] L1 evaluate failed for {repo_dir.name}: {exc}", file=sys.stderr)
                n_err += 1
                continue

            verdict = fuse_layer1(manifest, report).verdict

            if verdict == "SAFE":
                if n_clean >= clean_cap:
                    continue
                records.append(_make_record(text, "CLEAN", source=repo_dir.name))
                n_clean += 1
            elif verdict == "WARN":
                records.append(_make_record(text, "SUSPICIOUS", source=repo_dir.name))
                n_suspicious += 1
            else:
                n_block_skip += 1

    print(
        f"          Auto-labeled: CLEAN={n_clean}, SUSPICIOUS={n_suspicious}, "
        f"BLOCK_skipped={n_block_skip}, no_readme={n_no_readme}, err={n_err}"
    )
    return records


# ── Phase 5: Skill file records ───────────────────────────────────────────────

_MIN_SKILL_CHARS = 100


def phase5_skill_files(
    benign_skills_dir: Path | None,
    malicious_skills_dir: Path | None,
) -> list[dict[str, Any]]:
    """
    Build classifier records from SKILL.md files.

    benign_skills_dir:   Benign SKILL.md files downloaded from GitHub → CLEAN
    malicious_skills_dir: Hand-crafted attack SKILL.md files          → MALICIOUS

    These are different texts from the stress test PROBES — they share attack
    categories but are not identical, so the OOD benchmark remains uncontaminated.
    """
    records: list[dict[str, Any]] = []
    n_clean = n_malicious = n_skip = 0

    print(f"\n[Phase 5] Skill file records")

    if benign_skills_dir and benign_skills_dir.exists():
        benign_files = sorted(benign_skills_dir.glob("*.md"))
        print(f"          benign SKILL.md: {len(benign_files)} files in {benign_skills_dir}")
        for path in benign_files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                n_skip += 1
                continue
            if len(text.strip()) < _MIN_SKILL_CHARS:
                n_skip += 1
                continue
            records.append(_make_record(text, "CLEAN", source=f"benign_skill:{path.name}"))
            n_clean += 1
    elif benign_skills_dir:
        print(f"          [WARN] benign skills dir not found: {benign_skills_dir}")

    if malicious_skills_dir and malicious_skills_dir.exists():
        mal_files = sorted(malicious_skills_dir.glob("*.md"))
        print(f"          malicious SKILL.md: {len(mal_files)} files in {malicious_skills_dir}")
        for path in mal_files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                n_skip += 1
                continue
            if len(text.strip()) < _MIN_SKILL_CHARS:
                n_skip += 1
                continue
            records.append(_make_record(text, "MALICIOUS", source=f"malicious_skill:{path.name}"))
            n_malicious += 1
    elif malicious_skills_dir:
        print(f"          [WARN] malicious skills dir not found: {malicious_skills_dir}")

    print(
        f"          Phase 5 collected: CLEAN={n_clean}, MALICIOUS={n_malicious}, "
        f"skipped={n_skip}"
    )
    return records


# ── Per-class augmentation ────────────────────────────────────────────────────

def _get_label(record: dict[str, Any]) -> str:
    return record.get("_meta", {}).get("label", "CLEAN")


def augment_per_class(
    records: list[dict[str, Any]],
    default_factor: int,
    malicious_factor: int,
    seed: int,
) -> list[dict[str, Any]]:
    """
    Augment each class with a different factor to address class imbalance.

    MALICIOUS uses malicious_factor (default 10) because it is severely
    underrepresented.  CLEAN and SUSPICIOUS use default_factor (default 2).

    This runs augment_record() per-record (same logic as augment_dataset())
    but with a class-dependent factor — avoiding the uniform factor that left
    MALICIOUS at 2.8% of the training set.
    """
    rng = random.Random(seed)

    by_class: dict[str, list[dict[str, Any]]] = {"CLEAN": [], "SUSPICIOUS": [], "MALICIOUS": []}
    for rec in records:
        by_class.setdefault(_get_label(rec), []).append(rec)

    all_augmented: list[dict[str, Any]] = []
    for label, class_records in by_class.items():
        factor = malicious_factor if label == "MALICIOUS" else default_factor
        for rec in class_records:
            all_augmented.extend(augment_record(rec, rng, factor))

    rng.shuffle(all_augmented)
    return all_augmented


# ── Reporting ─────────────────────────────────────────────────────────────────

def _print_distribution(header: str, records: list[dict[str, Any]]) -> None:
    by_label = collections.Counter(_get_label(r) for r in records)
    total = len(records)
    print(f"  {header} ({total} examples):")
    for lbl in ["CLEAN", "SUSPICIOUS", "MALICIOUS"]:
        n = by_label.get(lbl, 0)
        pct = n / total * 100 if total else 0
        print(f"    {lbl:12s}: {n:4d}  ({pct:.1f}%)")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build domain-matched classifier JSONL from fixture ground truth, "
            "E001-E020 adversarial fixtures, MCP ecosystem auto-labels, and "
            "SKILL.md files. Phase 3 (stress test probes) removed — OOD benchmark only."
        )
    )
    parser.add_argument("--fixtures-dir",  type=Path,
                        default=_ROOT / "tests" / "fixtures")
    parser.add_argument("--clones-dir",    type=Path,
                        default=_ROOT / "benchmarks" / "ecosystem_local_400" / "clones")
    parser.add_argument("--extra-clones-dir", type=Path, default=None,
                        help="Additional MCP repo clones (from download_agent_repos.py). Optional.")
    parser.add_argument("--benign-skills-dir", type=Path, default=None,
                        help="Benign SKILL.md files from GitHub (Phase 5 CLEAN). Optional.")
    parser.add_argument("--malicious-skills-dir", type=Path,
                        default=_HERE / "data" / "malicious_skills",
                        help="Hand-crafted malicious SKILL.md files (Phase 5 MALICIOUS).")
    parser.add_argument("--output-dir",    type=Path, default=_HERE / "data")
    parser.add_argument("--clean-cap",     type=int,  default=400,
                        help="Max auto-labeled CLEAN records from MCP repos.")
    parser.add_argument("--augment-factor",    type=int, default=2,
                        help="Augmentation factor for CLEAN and SUSPICIOUS (default: 2).")
    parser.add_argument("--malicious-factor",  type=int, default=10,
                        help="Augmentation factor for MALICIOUS class (default: 10).")
    parser.add_argument("--val-ratio", type=float, default=0.20)
    parser.add_argument("--seed",      type=int,   default=42)
    args = parser.parse_args()

    # ── Collect from all five phases (Phase 3 removed) ────────────────────────
    p1 = phase1_fixtures(args.fixtures_dir)
    p2 = phase2_e001_e020(args.fixtures_dir)
    # Phase 3 is removed — stress test probes are OOD benchmark only.
    extra_clones = [args.extra_clones_dir] if args.extra_clones_dir else []
    p4 = phase4_mcp_autolabel(args.clones_dir, *extra_clones, clean_cap=args.clean_cap)
    p5 = phase5_skill_files(args.benign_skills_dir, args.malicious_skills_dir)

    all_records = p1 + p2 + p4 + p5
    print(f"\n[Combined] {len(all_records)} total records (phases 1, 2, 4, 5)")
    _print_distribution("Combined", all_records)

    if not all_records:
        print("[ERROR] No records collected.", file=sys.stderr)
        sys.exit(1)

    # ── Stratified split ──────────────────────────────────────────────────────
    train_records, val_records = stratified_split(
        all_records, val_ratio=args.val_ratio, seed=args.seed
    )
    print(f"\n[Split]")
    _print_distribution("Train", train_records)
    _print_distribution("Val  ", val_records)

    # ── Per-class augmentation ────────────────────────────────────────────────
    mal_base = sum(1 for r in train_records if _get_label(r) == "MALICIOUS")
    print(
        f"\n[Augment] MALICIOUS {args.malicious_factor}×  |  "
        f"CLEAN/SUSPICIOUS {args.augment_factor}×  |  seed={args.seed}"
    )
    print(f"          MALICIOUS base: {mal_base}  →  ~{mal_base * args.malicious_factor} after augment")
    augmented_records = augment_per_class(
        train_records,
        default_factor=args.augment_factor,
        malicious_factor=args.malicious_factor,
        seed=args.seed,
    )
    _print_distribution("Train (augmented)", augmented_records)

    # ── Write outputs ─────────────────────────────────────────────────────────
    args.output_dir.mkdir(parents=True, exist_ok=True)
    train_path = args.output_dir / "mcp_train.jsonl"
    val_path   = args.output_dir / "mcp_val.jsonl"
    aug_path   = args.output_dir / "mcp_train_augmented.jsonl"

    write_jsonl(train_records, train_path)
    write_jsonl(val_records,   val_path)
    write_jsonl(augmented_records, aug_path)

    print(f"\n[Output]")
    print(f"  Train (raw):       {len(train_records):>5} → {train_path}")
    print(f"  Val:               {len(val_records):>5} → {val_path}")
    print(f"  Train (augmented): {len(augmented_records):>5} → {aug_path}")

    # ── Sanity checks ─────────────────────────────────────────────────────────
    val_counts = collections.Counter(_get_label(r) for r in val_records)
    aug_counts = collections.Counter(_get_label(r) for r in augmented_records)
    total_aug  = len(augmented_records)

    for label in ["CLEAN", "SUSPICIOUS", "MALICIOUS"]:
        val_n = val_counts.get(label, 0)
        aug_n = aug_counts.get(label, 0)
        aug_pct = aug_n / total_aug * 100 if total_aug else 0
        if val_n < 5:
            print(
                f"\n[WARN] Val set has only {val_n} {label} examples — "
                "metrics for this class will be noisy.",
                file=sys.stderr,
            )
        if label == "MALICIOUS" and aug_pct < 10:
            print(
                f"\n[WARN] MALICIOUS is only {aug_pct:.1f}% of augmented train set — "
                "consider increasing --malicious-factor.",
                file=sys.stderr,
            )

    print("\nDone.")


if __name__ == "__main__":
    main()
