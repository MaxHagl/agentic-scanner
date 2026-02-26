"""
benchmarks/evaluation.py
────────────────────────
Automated evaluation script for the agentic-scanner.

Runs Layer 1 (and optionally Layer 2) against all fixtures in tests/fixtures/
and computes precision, recall, and F1 per layer and per attack vector.

Usage:
    poetry run python benchmarks/evaluation.py
    poetry run python benchmarks/evaluation.py --fixtures-dir tests/fixtures --verbose
    poetry run python benchmarks/evaluation.py --output report.json

Exit codes:
    0 — All target thresholds met (recall ≥ 0.90, precision ≥ 0.85)
    1 — One or more thresholds not met
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Project root on sys.path so we can import scanner without installing
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scanner.aggregator import fuse_layer1
from scanner.layer1_static.parser import parse_target
from scanner.layer1_static.rule_engine import Layer1RuleEngine
from scanner.models import FinalVerdict


# ── Thresholds (from gameplan) ────────────────────────────────────────────────

RECALL_THRESHOLD = 0.90
PRECISION_THRESHOLD = 0.85


# ── Fixture loading ───────────────────────────────────────────────────────────

_META_RE = re.compile(
    r"_fixture_meta\s*[:\{].*?(?=\n\s*[\w#\[{]|\Z)",
    re.DOTALL,
)

# YAML-style key: value or key: [list]
_KV_RE = re.compile(r"^\s{2,}(\w+):\s*(.+)$", re.MULTILINE)
_LIST_RE = re.compile(r'^\s{4,}-\s+"?([^"\n]+)"?\s*$', re.MULTILINE)


@dataclass
class FixtureMeta:
    fixture_id: str
    path: Path
    expected_verdict: str          # SAFE | WARN | BLOCK
    attack_vectors: list[str]
    rules_expected: list[str]
    description: str = ""


def _parse_inline_list(text: str, key: str) -> list[str]:
    """Extract items from 'key: [item1, item2]' or 'key: item1, item2' patterns."""
    m = re.search(rf"{key}\s*:\s*\[([^\]]*)\]", text)
    if m:
        return [s.strip().strip('"').strip("'") for s in m.group(1).split(",") if s.strip()]
    m2 = re.search(rf"{key}\s*:\s*(.+)", text)
    if m2:
        raw = m2.group(1).strip()
        if not raw or raw.startswith("#"):
            return []
        return [s.strip().strip('"').strip("'") for s in raw.split(",") if s.strip()]
    return []


def _extract_meta_from_text(text: str, path: Path) -> FixtureMeta | None:
    """Extract _fixture_meta from JSON, Python, or Markdown fixture files."""
    # JSON: look for "_fixture_meta" key
    if path.suffix == ".json":
        try:
            data = json.loads(text)
            meta = data.get("_fixture_meta")
            if isinstance(meta, dict):
                return FixtureMeta(
                    fixture_id=str(meta.get("id", path.stem)),
                    path=path,
                    expected_verdict=str(meta.get("expected_verdict", "BLOCK")).upper(),
                    attack_vectors=list(meta.get("attack_vectors", [])),
                    rules_expected=list(meta.get("rules_expected", [])),
                    description=str(meta.get("description", "")),
                )
        except json.JSONDecodeError:
            return None

    # Python / Markdown: look for _fixture_meta: block in docstring/comments
    match = re.search(
        r"_fixture_meta\s*:\s*\n((?:[ \t]+\S[^\n]*\n)+)",
        text,
        re.MULTILINE,
    )
    if match:
        block = match.group(1)
        kv: dict[str, Any] = {}
        for line in block.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                kv[key.strip()] = val.strip()

        for list_key in ("attack_vectors", "rules_expected"):
            items = _parse_inline_list(match.group(0), list_key)
            if items:
                kv[list_key] = items

        return FixtureMeta(
            fixture_id=str(kv.get("id", path.stem)),
            path=path,
            expected_verdict=str(kv.get("expected_verdict", "BLOCK")).upper(),
            attack_vectors=kv.get("attack_vectors", []) if isinstance(kv.get("attack_vectors"), list) else [],
            rules_expected=kv.get("rules_expected", []) if isinstance(kv.get("rules_expected"), list) else [],
            description=str(kv.get("description", "")),
        )

    # Fallback: legacy docstring format used by pre-evaluator fixtures
    # Looks for: "Expected verdict: BLOCK" and "Attack vectors: T1, T2"
    verdict_m = re.search(r"Expected verdict:\s*(\w+)", text, re.IGNORECASE)
    av_m = re.search(r"Attack vectors?:\s*(.+)", text, re.IGNORECASE)
    if verdict_m:
        avs = [s.strip() for s in av_m.group(1).split(",") if s.strip()] if av_m else []
        return FixtureMeta(
            fixture_id=path.stem,
            path=path,
            expected_verdict=verdict_m.group(1).upper(),
            attack_vectors=avs,
            rules_expected=[],
            description="",
        )

    return None


def collect_fixtures(fixtures_dir: Path) -> list[FixtureMeta]:
    """Walk fixtures_dir and return all scannable fixtures with metadata."""
    scannable_extensions = {".json", ".py", ".md", ".markdown"}
    # Impl files (MCP-xxx-impl.py) are not standalone fixtures — skip them
    _impl_re = re.compile(r"-impl\.py$", re.IGNORECASE)

    fixtures: list[FixtureMeta] = []
    for path in sorted(fixtures_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in scannable_extensions:
            continue
        if path.name == "__init__.py":
            continue
        if _impl_re.search(path.name):
            continue  # implementation file, not a primary fixture

        text = path.read_text(encoding="utf-8", errors="ignore")
        meta = _extract_meta_from_text(text, path)
        if meta is None:
            continue
        fixtures.append(meta)

    return fixtures


# ── Scanning ──────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    fixture: FixtureMeta
    actual_verdict: str
    scan_time_ms: float
    rule_ids_fired: list[str]
    error: str | None = None

    @property
    def correct(self) -> bool:
        return self.actual_verdict == self.fixture.expected_verdict

    @property
    def true_positive(self) -> bool:
        """Malicious fixture correctly identified as WARN or BLOCK."""
        return (
            self.fixture.expected_verdict in {"WARN", "BLOCK"}
            and self.actual_verdict in {"WARN", "BLOCK"}
        )

    @property
    def false_negative(self) -> bool:
        """Malicious fixture incorrectly classified as SAFE."""
        return (
            self.fixture.expected_verdict in {"WARN", "BLOCK"}
            and self.actual_verdict == "SAFE"
        )

    @property
    def false_positive(self) -> bool:
        """Safe fixture incorrectly flagged as WARN or BLOCK."""
        return (
            self.fixture.expected_verdict == "SAFE"
            and self.actual_verdict in {"WARN", "BLOCK"}
        )

    @property
    def true_negative(self) -> bool:
        """Safe fixture correctly classified as SAFE."""
        return self.fixture.expected_verdict == "SAFE" and self.actual_verdict == "SAFE"


def scan_fixture(meta: FixtureMeta, engine: Layer1RuleEngine) -> ScanResult:
    t0 = time.perf_counter()
    try:
        manifest = parse_target(meta.path)
        report_l1 = engine.evaluate(manifest)
        verdict = fuse_layer1(manifest, report_l1)
        elapsed = (time.perf_counter() - t0) * 1000
        return ScanResult(
            fixture=meta,
            actual_verdict=verdict.verdict,
            scan_time_ms=elapsed,
            rule_ids_fired=[m.rule_id for m in verdict.all_findings],
        )
    except Exception as exc:
        elapsed = (time.perf_counter() - t0) * 1000
        return ScanResult(
            fixture=meta,
            actual_verdict="ERROR",
            scan_time_ms=elapsed,
            rule_ids_fired=[],
            error=str(exc),
        )


# ── Metrics ───────────────────────────────────────────────────────────────────

@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.fn + self.tn
        return (self.tp + self.tn) / total if total > 0 else 0.0


def compute_metrics(results: list[ScanResult]) -> Metrics:
    m = Metrics()
    for r in results:
        if r.error:
            continue
        if r.true_positive:
            m.tp += 1
        elif r.false_positive:
            m.fp += 1
        elif r.false_negative:
            m.fn += 1
        elif r.true_negative:
            m.tn += 1
    return m


def per_attack_vector_metrics(results: list[ScanResult]) -> dict[str, Metrics]:
    vectors: dict[str, Metrics] = {}
    for r in results:
        if r.error:
            continue
        for av in r.fixture.attack_vectors:
            if av not in vectors:
                vectors[av] = Metrics()
            m = vectors[av]
            if r.true_positive:
                m.tp += 1
            elif r.false_negative:
                m.fn += 1
            elif r.false_positive:
                m.fp += 1
    return vectors


# ── Reporting ─────────────────────────────────────────────────────────────────

def _pct(v: float) -> str:
    return f"{v * 100:.1f}%"


def print_report(results: list[ScanResult], metrics: Metrics, verbose: bool = False) -> None:
    print("\n" + "=" * 72)
    print("  AGENTIC SCANNER — Layer 1 Benchmark Results")
    print("=" * 72)

    if verbose:
        print(f"\n{'Fixture':<40} {'Expected':<10} {'Actual':<10} {'Time (ms)':<10} {'OK'}")
        print("-" * 72)
        for r in sorted(results, key=lambda x: x.fixture.fixture_id):
            status = "✓" if r.correct else ("ERR" if r.error else "✗")
            actual = r.actual_verdict if not r.error else f"ERROR: {r.error[:20]}"
            print(
                f"{r.fixture.fixture_id:<40} {r.fixture.expected_verdict:<10} "
                f"{actual:<10} {r.scan_time_ms:<10.1f} {status}"
            )

    print(f"\n  Total fixtures: {len(results)}")
    print(f"  Errors:         {sum(1 for r in results if r.error)}")
    print(f"\n  True Positives:  {metrics.tp}")
    print(f"  False Positives: {metrics.fp}")
    print(f"  False Negatives: {metrics.fn}")
    print(f"  True Negatives:  {metrics.tn}")
    print(f"\n  Precision: {_pct(metrics.precision)}  (threshold: {_pct(PRECISION_THRESHOLD)})")
    print(f"  Recall:    {_pct(metrics.recall)}  (threshold: {_pct(RECALL_THRESHOLD)})")
    print(f"  F1 Score:  {_pct(metrics.f1)}")
    print(f"  Accuracy:  {_pct(metrics.accuracy)}")

    # Latency
    times = [r.scan_time_ms for r in results if not r.error]
    if times:
        times_sorted = sorted(times)
        p50 = times_sorted[len(times_sorted) // 2]
        p95 = times_sorted[int(len(times_sorted) * 0.95)]
        p99 = times_sorted[min(int(len(times_sorted) * 0.99), len(times_sorted) - 1)]
        print(f"\n  Latency — P50: {p50:.0f}ms  P95: {p95:.0f}ms  P99: {p99:.0f}ms")

    av_metrics = per_attack_vector_metrics(results)
    if av_metrics:
        print("\n  Per Attack Vector:")
        for av, m in sorted(av_metrics.items()):
            print(
                f"    {av:<40} P={_pct(m.precision)}  R={_pct(m.recall)}  "
                f"F1={_pct(m.f1)}  (TP={m.tp} FN={m.fn})"
            )

    # Threshold check
    precision_ok = metrics.precision >= PRECISION_THRESHOLD
    recall_ok = metrics.recall >= RECALL_THRESHOLD
    print(f"\n  Precision threshold ({_pct(PRECISION_THRESHOLD)}): {'PASS ✓' if precision_ok else 'FAIL ✗'}")
    print(f"  Recall threshold    ({_pct(RECALL_THRESHOLD)}): {'PASS ✓' if recall_ok else 'FAIL ✗'}")
    print("=" * 72)

    if not precision_ok or not recall_ok:
        fns = [r for r in results if r.false_negative]
        if fns:
            print(f"\n  False negatives ({len(fns)}) — missed malicious fixtures:")
            for r in fns:
                print(f"    [{r.fixture.fixture_id}] {r.fixture.description[:60]}")
                print(f"      Expected rules: {r.fixture.rules_expected}")
                print(f"      Fired rules:    {r.rule_ids_fired}")


def build_json_report(results: list[ScanResult], metrics: Metrics) -> dict:
    av_metrics = per_attack_vector_metrics(results)
    return {
        "summary": {
            "total_fixtures": len(results),
            "errors": sum(1 for r in results if r.error),
            "tp": metrics.tp,
            "fp": metrics.fp,
            "fn": metrics.fn,
            "tn": metrics.tn,
            "precision": round(metrics.precision, 4),
            "recall": round(metrics.recall, 4),
            "f1": round(metrics.f1, 4),
            "accuracy": round(metrics.accuracy, 4),
            "thresholds_met": {
                "precision": metrics.precision >= PRECISION_THRESHOLD,
                "recall": metrics.recall >= RECALL_THRESHOLD,
            },
        },
        "per_attack_vector": {
            av: {
                "precision": round(m.precision, 4),
                "recall": round(m.recall, 4),
                "f1": round(m.f1, 4),
                "tp": m.tp,
                "fn": m.fn,
            }
            for av, m in sorted(av_metrics.items())
        },
        "fixtures": [
            {
                "id": r.fixture.fixture_id,
                "path": str(r.fixture.path),
                "expected": r.fixture.expected_verdict,
                "actual": r.actual_verdict,
                "correct": r.correct,
                "scan_time_ms": round(r.scan_time_ms, 2),
                "rules_fired": r.rule_ids_fired,
                "error": r.error,
            }
            for r in sorted(results, key=lambda x: x.fixture.fixture_id)
        ],
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark agentic-scanner Layer 1 against the fixture corpus."
    )
    parser.add_argument(
        "--fixtures-dir",
        default=str(_ROOT / "tests" / "fixtures"),
        help="Path to fixtures directory (default: tests/fixtures)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write JSON report to this file path",
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

    fixtures = collect_fixtures(fixtures_dir)
    if not fixtures:
        print(f"No fixtures with _fixture_meta found in {fixtures_dir}", file=sys.stderr)
        return 1

    print(f"Found {len(fixtures)} fixtures. Running Layer 1 scan...")
    engine = Layer1RuleEngine()
    results = [scan_fixture(meta, engine) for meta in fixtures]

    metrics = compute_metrics(results)
    print_report(results, metrics, verbose=args.verbose)

    if args.output:
        report = build_json_report(results, metrics)
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nJSON report written to: {args.output}")

    thresholds_met = (
        metrics.precision >= PRECISION_THRESHOLD
        and metrics.recall >= RECALL_THRESHOLD
    )
    return 0 if thresholds_met else 1


if __name__ == "__main__":
    sys.exit(main())
