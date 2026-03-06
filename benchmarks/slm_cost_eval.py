"""
benchmarks/slm_cost_eval.py
────────────────────────────
SLM Cost Evaluation Benchmark.

Measures how many Haiku API calls the SLM pre-filter eliminates while
preserving verdict consistency with the baseline (Haiku-only) system.

Key question:
  Across all 101 fixtures, what % of Haiku API calls does the SLM
  pre-filter eliminate while keeping verdict consistency at 100%?

Design: pre-load all expensive components once at startup (Layer1RuleEngine,
both Layer2Analyzer variants), then loop over fixtures reusing them.

Usage:
    # Quick run — adversarial fixtures only (~10 min)
    poetry run python benchmarks/slm_cost_eval.py --subset adversarial

    # Full run — all 101 fixtures (~45-60 min due to rate limiting)
    poetry run python benchmarks/slm_cost_eval.py

    # Custom model path
    poetry run python benchmarks/slm_cost_eval.py \\
        --slm-model finetuning/security_slm_medium/

    # Skip sleeps (high-tier API plan only)
    poetry run python benchmarks/slm_cost_eval.py --no-rate-limit
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# ── Project root on sys.path ──────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.evaluation import collect_fixtures, FixtureMeta
from scanner.aggregator import fuse_layer1, fuse_layers
from scanner.layer1_static.parser import parse_target
from scanner.layer1_static.rule_engine import Layer1RuleEngine
from scanner.layer2_semantic import Layer2Analyzer


# ── Constants ─────────────────────────────────────────────────────────────────

# 5 req/min → min gap 12 s; add 1 s buffer.
RATE_LIMIT_SLEEP = 13  # seconds


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class CostRecord:
    fixture_id: str
    category: str           # "benign" | "adversarial" | "layer2" | "standard"
    expected_verdict: str
    baseline_verdict: str   # fused verdict with Haiku-only L2
    slm_verdict: str        # fused verdict with SLM pre-filter L2
    baseline_tokens: int    # llm_tokens_used for baseline
    slm_tokens: int         # llm_tokens_used for SLM mode
    slm_escalated: bool     # True when SLM was uncertain → called Haiku
    baseline_time_ms: float
    slm_time_ms: float
    error: str | None = None

    @property
    def verdict_match(self) -> bool:
        return self.baseline_verdict == self.slm_verdict

    @property
    def tokens_saved(self) -> int:
        return max(0, self.baseline_tokens - self.slm_tokens)


# ── Category detection ────────────────────────────────────────────────────────

def _category(fixture: FixtureMeta) -> str:
    """Classify a fixture into one of four cost-eval categories."""
    parts = {p.lower() for p in fixture.path.parts}
    if "adversarial" in parts:
        return "adversarial"
    if "benign" in parts:
        return "benign"
    if "layer2" in parts:
        return "layer2"
    return "standard"


# ── Per-fixture scan ──────────────────────────────────────────────────────────

def _scan_fixture(
    fixture: FixtureMeta,
    engine: Layer1RuleEngine,
    l2_baseline: Layer2Analyzer,
    l2_slm: Layer2Analyzer,
    rate_limit: bool,
) -> CostRecord:
    """Run baseline and SLM scans for one fixture; return a CostRecord."""
    category = _category(fixture)

    try:
        manifest = parse_target(fixture.path)
        report_l1 = engine.evaluate(manifest)

        # ── Baseline: always uses Haiku for L2 ───────────────────────────────
        t0 = time.perf_counter()
        r_base = l2_baseline.analyze(manifest, report_l1)
        v_base = fuse_layers(manifest, report_l1, r_base)
        baseline_ms = (time.perf_counter() - t0) * 1000

        if rate_limit and r_base.llm_tokens_used > 0:
            time.sleep(RATE_LIMIT_SLEEP)

        # ── SLM mode: SLM pre-filter → Haiku only on escalation ──────────────
        t0 = time.perf_counter()
        r_slm = l2_slm.analyze(manifest, report_l1)
        v_slm = fuse_layers(manifest, report_l1, r_slm)
        slm_ms = (time.perf_counter() - t0) * 1000

        if rate_limit and r_slm.llm_tokens_used > 0:
            time.sleep(RATE_LIMIT_SLEEP)

        return CostRecord(
            fixture_id=fixture.fixture_id,
            category=category,
            expected_verdict=fixture.expected_verdict,
            baseline_verdict=v_base.verdict,
            slm_verdict=v_slm.verdict,
            baseline_tokens=r_base.llm_tokens_used,
            slm_tokens=r_slm.llm_tokens_used,
            slm_escalated=r_slm.llm_tokens_used > 0,
            baseline_time_ms=baseline_ms,
            slm_time_ms=slm_ms,
        )

    except Exception as exc:
        return CostRecord(
            fixture_id=fixture.fixture_id,
            category=category,
            expected_verdict=fixture.expected_verdict,
            baseline_verdict="ERROR",
            slm_verdict="ERROR",
            baseline_tokens=0,
            slm_tokens=0,
            slm_escalated=False,
            baseline_time_ms=0.0,
            slm_time_ms=0.0,
            error=str(exc),
        )


# ── Reporting ─────────────────────────────────────────────────────────────────

_CATEGORY_LABELS = {
    "benign":      "Benign (BN)",
    "adversarial": "Adversarial (E)",
    "standard":    "Standard",
    "layer2":      "Layer2-specific",
}

_CATEGORY_ORDER = ["benign", "adversarial", "standard", "layer2"]


def _pct(num: int, den: int) -> str:
    if den == 0:
        return "  N/A "
    return f"{num / den * 100:5.1f}%"


def _print_table(records: list[CostRecord], slm_path: str) -> None:
    print()
    print("═" * 70)
    print("  SLM Cost Evaluation")
    print(f"  SLM: {slm_path}")
    print("═" * 70)

    # Group by category
    by_cat: dict[str, list[CostRecord]] = {c: [] for c in _CATEGORY_ORDER}
    for rec in records:
        by_cat.setdefault(rec.category, []).append(rec)

    # Header
    print()
    print(
        f"{'Category':<22} {'n':>4}  {'Baseline':>9}  {'SLM':>9}  "
        f"{'Reduction':>9}  {'Verdict match':>13}"
    )
    print(
        f"{'':22} {'':>4}  {'tokens':>9}  {'tokens':>9}  "
        f"{'':>9}  {'':>13}"
    )
    print("─" * 70)

    total_n = 0
    total_base = 0
    total_slm = 0
    total_match = 0
    total_errors = 0

    for cat in _CATEGORY_ORDER:
        recs = by_cat.get(cat, [])
        if not recs:
            continue
        n = len(recs)
        errors = sum(1 for r in recs if r.error)
        base_tok = sum(r.baseline_tokens for r in recs)
        slm_tok = sum(r.slm_tokens for r in recs)
        match = sum(1 for r in recs if r.verdict_match and not r.error)
        label = _CATEGORY_LABELS.get(cat, cat)

        reduction = _pct(base_tok - slm_tok, base_tok)
        match_str = f"{match}/{n - errors}"

        print(
            f"{label:<22} {n:>4}  {base_tok:>9,}  {slm_tok:>9,}  "
            f"{reduction:>9}  {match_str:>13}"
        )

        total_n += n
        total_base += base_tok
        total_slm += slm_tok
        total_match += match
        total_errors += errors

    print("─" * 70)
    overall_reduction = _pct(total_base - total_slm, total_base)
    match_str = f"{total_match}/{total_n - total_errors}"
    print(
        f"{'TOTAL':<22} {total_n:>4}  {total_base:>9,}  {total_slm:>9,}  "
        f"{overall_reduction:>9}  {match_str:>13}"
    )

    # Summary stats
    n_escalated = sum(1 for r in records if r.slm_escalated and not r.error)
    n_api_calls_saved = sum(
        1 for r in records if not r.error and r.baseline_tokens > 0 and r.slm_tokens == 0
    )
    n_base_api_calls = sum(1 for r in records if not r.error and r.baseline_tokens > 0)

    base_times = [r.baseline_time_ms for r in records if not r.error]
    slm_times = [r.slm_time_ms for r in records if not r.error]
    avg_base_ms = sum(base_times) / len(base_times) if base_times else 0.0
    avg_slm_ms = sum(slm_times) / len(slm_times) if slm_times else 0.0

    print()
    print(f"  API calls in baseline:   {n_base_api_calls} of {total_n - total_errors} fixtures")
    print(f"  API calls saved by SLM:  {n_api_calls_saved} of {n_base_api_calls} baseline calls")
    print(f"  SLM escalations:         {n_escalated}")
    if n_base_api_calls > 0:
        print(f"  API call reduction:      {_pct(n_api_calls_saved, n_base_api_calls).strip()}")
    print(f"  Avg latency:  baseline={avg_base_ms:.0f}ms  slm={avg_slm_ms:.0f}ms")

    if total_errors > 0:
        print(f"\n  Errors: {total_errors} (see --verbose for details)")

    # Verdict consistency
    n_valid = total_n - total_errors
    print()
    if total_match == n_valid:
        print(f"  Verdict consistency: {total_match}/{n_valid} — PASS (100% consistent)")
    else:
        mismatches = [r for r in records if not r.verdict_match and not r.error]
        print(f"  Verdict consistency: {total_match}/{n_valid} — FAIL ({len(mismatches)} mismatches)")

    print("═" * 70)


def _print_verbose(records: list[CostRecord]) -> None:
    print()
    print(
        f"{'Fixture':<35} {'Cat':<12} {'Exp':<6} {'Base':<6} {'SLM':<6} "
        f"{'BseTok':>7} {'SlmTok':>7} {'Esc':>4} {'Match':>5}"
    )
    print("─" * 100)
    for r in sorted(records, key=lambda x: x.fixture_id):
        match_sym = "✓" if r.verdict_match else "✗"
        esc_sym = "Y" if r.slm_escalated else "N"
        err = f" ERR: {r.error[:30]}" if r.error else ""
        print(
            f"{r.fixture_id:<35} {r.category:<12} {r.expected_verdict:<6} "
            f"{r.baseline_verdict:<6} {r.slm_verdict:<6} "
            f"{r.baseline_tokens:>7,} {r.slm_tokens:>7,} {esc_sym:>4} {match_sym:>5}"
            + err
        )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure API cost reduction from the SLM pre-filter across all fixtures."
    )
    parser.add_argument(
        "--fixtures-dir",
        default=str(_ROOT / "tests" / "fixtures"),
        help="Path to fixtures directory (default: tests/fixtures)",
    )
    parser.add_argument(
        "--slm-model",
        default=str(_ROOT / "finetuning" / "security_slm_medium"),
        help="Path to SecurityClassifier model dir (default: finetuning/security_slm_medium/)",
    )
    parser.add_argument(
        "--escalation-threshold",
        type=float,
        default=0.80,
        help="SLM confidence threshold for Haiku escalation (default: 0.80)",
    )
    parser.add_argument(
        "--subset",
        choices=["adversarial", "benign", "standard", "layer2"],
        default=None,
        help="Run only a subset of fixtures for quick evaluation",
    )
    parser.add_argument(
        "--no-rate-limit",
        action="store_true",
        help="Skip sleep between API calls (use only with high-tier API plan)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write JSON results to this file path",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print per-fixture results",
    )
    args = parser.parse_args()

    fixtures_dir = Path(args.fixtures_dir).expanduser().resolve()
    if not fixtures_dir.is_dir():
        print(f"Error: fixtures directory not found: {fixtures_dir}", file=sys.stderr)
        return 1

    slm_path = Path(args.slm_model).expanduser().resolve()
    if not slm_path.is_dir():
        print(f"Error: SLM model directory not found: {slm_path}", file=sys.stderr)
        print("Hint: run the finetuning pipeline first:", file=sys.stderr)
        print("  poetry run python finetuning/train_classifier.py", file=sys.stderr)
        return 1

    # Collect and optionally filter fixtures
    all_fixtures = collect_fixtures(fixtures_dir)
    if not all_fixtures:
        print(f"No fixtures with _fixture_meta found in {fixtures_dir}", file=sys.stderr)
        return 1

    if args.subset:
        fixtures = [f for f in all_fixtures if _category(f) == args.subset]
        if not fixtures:
            print(f"No fixtures found for subset '{args.subset}'", file=sys.stderr)
            return 1
    else:
        fixtures = all_fixtures

    n = len(fixtures)
    rate_limit = not args.no_rate_limit

    print(f"Found {len(all_fixtures)} total fixtures; evaluating {n}.")
    if args.subset:
        print(f"Subset: {args.subset}")
    print(f"SLM model: {slm_path}")
    print(f"Escalation threshold: {args.escalation_threshold}")
    print(f"Rate limiting: {'enabled (13s sleep when API called)' if rate_limit else 'DISABLED'}")
    print()
    print("Pre-loading components (Layer1RuleEngine + 2× Layer2Analyzer)...")

    engine = Layer1RuleEngine()
    l2_baseline = Layer2Analyzer()  # Haiku only; no SLM
    l2_slm = Layer2Analyzer(
        slm_model_path=str(slm_path),
        escalation_threshold=args.escalation_threshold,
    )

    print(f"Components loaded. Running {n} fixtures × 2 modes...\n")

    records: list[CostRecord] = []
    for i, fixture in enumerate(fixtures, 1):
        print(f"  [{i:3d}/{n}] {fixture.fixture_id:<40}", end="", flush=True)
        rec = _scan_fixture(fixture, engine, l2_baseline, l2_slm, rate_limit)
        records.append(rec)

        if rec.error:
            print(f"ERROR: {rec.error[:50]}")
        else:
            match_sym = "✓" if rec.verdict_match else "✗"
            esc_str = f"escalated({rec.slm_tokens:,}tok)" if rec.slm_escalated else "SLM-only"
            saved = rec.tokens_saved
            print(
                f"base={rec.baseline_tokens:,}tok  slm={esc_str}  "
                f"saved={saved:,}  {match_sym}"
            )

    if args.verbose:
        _print_verbose(records)

    _print_table(records, str(slm_path))

    if args.output:
        out = {
            "slm_model": str(slm_path),
            "escalation_threshold": args.escalation_threshold,
            "subset": args.subset,
            "total_fixtures": n,
            "records": [
                {
                    "fixture_id": r.fixture_id,
                    "category": r.category,
                    "expected_verdict": r.expected_verdict,
                    "baseline_verdict": r.baseline_verdict,
                    "slm_verdict": r.slm_verdict,
                    "baseline_tokens": r.baseline_tokens,
                    "slm_tokens": r.slm_tokens,
                    "slm_escalated": r.slm_escalated,
                    "tokens_saved": r.tokens_saved,
                    "verdict_match": r.verdict_match,
                    "baseline_time_ms": round(r.baseline_time_ms, 1),
                    "slm_time_ms": round(r.slm_time_ms, 1),
                    "error": r.error,
                }
                for r in sorted(records, key=lambda x: x.fixture_id)
            ],
        }
        Path(args.output).write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"\nJSON results written to: {args.output}")

    # Exit 0 only if verdict consistency is 100%
    n_valid = sum(1 for r in records if not r.error)
    n_match = sum(1 for r in records if r.verdict_match and not r.error)
    return 0 if n_match == n_valid else 1


if __name__ == "__main__":
    sys.exit(main())
