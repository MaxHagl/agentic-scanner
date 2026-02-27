"""
eval_adversarial_e.py
─────────────────────────────────────────────────────────────────────────────
Evaluation of 15 adversarial evasion fixtures (E001–E015) across both layers.

Phase 1 (L1 only):  All 15 fixtures, static analysis only — no API calls.
Phase 2 (L1 + L2):  All 15 fixtures with semantic LLM judge, 45s stagger.

Usage:
    # L1 only (no API key required):
    poetry run python eval_adversarial_e.py --l1-only

    # L1 + L2 (requires ANTHROPIC_API_KEY):
    poetry run python eval_adversarial_e.py
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from scanner.layer1_static.parser import parse_target
from scanner.layer1_static.rule_engine import Layer1RuleEngine
from scanner.aggregator import fuse_layer1, fuse_layers

FIXTURES_DIR = Path(__file__).parent / "tests" / "fixtures" / "adversarial"
RATE_LIMIT_SLEEP = 45  # seconds between L2 API calls

# Expected verdict for each fixture — all should be caught (BLOCK or WARN)
# L1-only: captures static signals; L2: semantic signals
FIXTURE_METADATA: dict[str, dict] = {
    "E001-base64-pipeline.md":      {"category": "Obfuscation/Encoding",              "attack": "Base64-encoded curl|bash"},
    "E002-hex-encoding.md":         {"category": "Obfuscation/Encoding",              "attack": "Hex-encoded shell cmd"},
    "E003-url-encoding.md":         {"category": "Obfuscation/Encoding",              "attack": "URL-encoded eval()"},
    "E004-double-encoding.md":      {"category": "Obfuscation/Encoding",              "attack": "Double-base64 bootstrap"},
    "E005-context-hijacking.md":    {"category": "Prompt Injection/Jailbreak",        "attack": "Compliance-mode privilege escalation"},
    "E006-constraint-negation.md":  {"category": "Prompt Injection/Jailbreak",        "attack": "Ignore-safety-instructions"},
    "E007-role-play.md":            {"category": "Prompt Injection/Jailbreak",        "attack": "Developer-mode persona"},
    "E008-homoglyph.md":            {"category": "Prompt Injection/Jailbreak",        "attack": "Unicode homoglyph config keys"},
    "E009-remote-logic.md":         {"category": "Supply Chain/Persistence",          "attack": "curl | bash from remote registry"},
    "E010-memory-poisoning.md":     {"category": "Supply Chain/Persistence",          "attack": "Writes to MEMORY.md / CLAUDE.md"},
    "E011-env-exfiltration.md":     {"category": "Supply Chain/Persistence",          "attack": "cat credentials | curl webhook"},
    "E012-credential-harvesting.md":{"category": "Direct Interaction",                "attack": "SSH private keys → remote escrow"},
    "E013-system-daemon.md":        {"category": "Direct Interaction",                "attack": "Installs systemd service + .bashrc hook"},
    "E014-typosquat.md":            {"category": "Social Engineering",                "attack": "Fake Anthropic safety patch + API key exfil"},
    "E015-third-party-fetch.md":    {"category": "Social Engineering",                "attack": "exec() of attacker-controlled GitHub URL"},
}


# ─── Utilities ────────────────────────────────────────────────────────────────

def _badge(verdict: str) -> str:
    icons = {"BLOCK": "🔴 BLOCK", "WARN": "🟡 WARN ", "SAFE": "🟢 SAFE "}
    return icons.get(verdict, f"?? {verdict}")


def _caught_by(l1_verdict: str, fused_verdict: str) -> str:
    """Classify which layer caught the fixture."""
    if l1_verdict == "BLOCK":
        return "L1"
    if fused_verdict == "BLOCK":
        return "L2"
    if l1_verdict == "WARN":
        return "L1 (WARN)"
    if fused_verdict == "WARN":
        return "L2 (WARN)"
    return "EVADED"


# ─── Phase 1: L1-only scan ────────────────────────────────────────────────────

def run_l1_phase(fixtures: list[Path]) -> dict[str, dict]:
    """Scan all fixtures with Layer 1 only. Returns results keyed by filename."""
    print(f"\n{'═'*70}")
    print("  PHASE 1 — Layer 1 Static Analysis (no API calls)")
    print(f"{'═'*70}\n")

    engine = Layer1RuleEngine()
    results: dict[str, dict] = {}

    for path in fixtures:
        fname = path.name
        meta = FIXTURE_METADATA.get(fname, {})
        manifest = parse_target(path)
        l1_report = engine.evaluate(manifest)
        verdict_obj = fuse_layer1(manifest, l1_report)

        verdict = verdict_obj.verdict
        score = verdict_obj.fused_risk_score
        n_findings = len(verdict_obj.all_findings)
        rule_ids = [m.rule_id for m in verdict_obj.all_findings]

        print(f"  [{fname}]")
        print(f"    Category : {meta.get('category','?')}")
        print(f"    Attack   : {meta.get('attack','?')}")
        print(f"    Verdict  : {_badge(verdict)}  score={score:.4f}  findings={n_findings}")
        if rule_ids:
            print(f"    Rules    : {', '.join(rule_ids)}")
        print()

        results[fname] = {
            "meta": meta,
            "l1_verdict": verdict,
            "l1_score": score,
            "l1_findings": n_findings,
            "l1_rules": rule_ids,
            "l1_report": l1_report,
            "manifest": manifest,
        }

    return results


# ─── Phase 2: L2 semantic scan ───────────────────────────────────────────────

def run_l2_phase(fixtures: list[Path], l1_results: dict[str, dict]) -> dict[str, dict]:
    """Run Layer 2 on all fixtures with staggered API calls."""
    from scanner.layer2_semantic import Layer2Analyzer

    print(f"\n{'═'*70}")
    print(f"  PHASE 2 — Layer 1 + Layer 2 Semantic Analysis")
    print(f"  Stagger: {RATE_LIMIT_SLEEP}s between API calls ({len(fixtures)} fixtures = ~{len(fixtures)*RATE_LIMIT_SLEEP//60}m {len(fixtures)*RATE_LIMIT_SLEEP%60}s)")
    print(f"{'═'*70}\n")

    analyzer = Layer2Analyzer()
    results: dict[str, dict] = {}

    for i, path in enumerate(fixtures):
        fname = path.name
        meta = FIXTURE_METADATA.get(fname, {})
        l1_data = l1_results.get(fname, {})

        if i > 0:
            print(f"  ⏱  Waiting {RATE_LIMIT_SLEEP}s before next fixture...\n")
            time.sleep(RATE_LIMIT_SLEEP)

        manifest = l1_data.get("manifest") or parse_target(path)
        l1_report = l1_data.get("l1_report")

        print(f"  [{fname}]")
        print(f"    Category : {meta.get('category','?')}")
        print(f"    Attack   : {meta.get('attack','?')}")

        try:
            l2_report = analyzer.analyze(manifest, l1_report)
            verdict_obj = fuse_layers(manifest, l1_report, l2_report)

            fused_verdict = verdict_obj.verdict
            fused_score   = verdict_obj.fused_risk_score
            l1_score      = verdict_obj.l1_score
            l2_score      = verdict_obj.l2_score
            llm_verdict   = l2_report.llm_judge_verdict or "N/A"
            llm_conf      = l2_report.llm_judge_confidence
            llm_conf_str  = f"{llm_conf:.0%}" if llm_conf is not None else "—"
            tokens        = verdict_obj.llm_tokens_consumed
            n_findings    = len(verdict_obj.all_findings)

            l1_verdict = l1_data.get("l1_verdict", "?")
            caught = _caught_by(l1_verdict, fused_verdict)

            print(f"    Verdict  : {_badge(fused_verdict)}  fused={fused_score:.4f}  (L1={l1_score:.4f} L2={l2_score:.4f})")
            print(f"    LLM      : {llm_verdict} @ {llm_conf_str}  tokens={tokens}")
            print(f"    Findings : {n_findings}  caught_by={caught}")
            print()

            results[fname] = {
                "meta": meta,
                "l1_verdict": l1_verdict,
                "fused_verdict": fused_verdict,
                "l1_score": l1_score,
                "l2_score": l2_score,
                "fused_score": fused_score,
                "llm_verdict": llm_verdict,
                "llm_conf": llm_conf or 0.0,
                "tokens": tokens,
                "n_findings": n_findings,
                "caught_by": caught,
            }

        except Exception as exc:
            print(f"    ERROR: {exc}\n")
            results[fname] = {
                "meta": meta,
                "l1_verdict": l1_data.get("l1_verdict", "?"),
                "fused_verdict": "ERROR",
                "caught_by": "ERROR",
                "error": str(exc),
            }

    return results


# ─── Summary tables ───────────────────────────────────────────────────────────

def print_l1_summary(results: dict[str, dict]) -> None:
    print(f"\n{'═'*70}")
    print("  LAYER 1 SUMMARY")
    print(f"{'─'*70}")
    header = f"  {'Fixture':<32} {'Category':<28} {'Verdict':<8} {'Score':<7} {'Rules'}"
    print(header)
    print(f"{'─'*70}")
    for fname, r in results.items():
        cat = r["meta"].get("category", "?")[:26]
        verdict = r["l1_verdict"]
        score = r.get("l1_score", 0.0)
        rules = ",".join(r.get("l1_rules", [])) or "—"
        print(f"  {fname:<32} {cat:<28} {verdict:<8} {score:.4f}  {rules}")

    blocked = sum(1 for r in results.values() if r["l1_verdict"] == "BLOCK")
    warned  = sum(1 for r in results.values() if r["l1_verdict"] == "WARN")
    safe    = sum(1 for r in results.values() if r["l1_verdict"] == "SAFE")
    total   = len(results)
    print(f"{'─'*70}")
    print(f"  L1: BLOCK={blocked}/{total}  WARN={warned}/{total}  SAFE={safe}/{total}")
    print(f"  L1 detection rate: {(blocked+warned)/total:.0%} flagged, {blocked/total:.0%} hard-blocked\n")


def print_combined_summary(l1_results: dict[str, dict], l2_results: dict[str, dict]) -> None:
    print(f"\n{'═'*70}")
    print("  COMBINED SUMMARY (L1 + L2)")
    print(f"{'─'*70}")
    header = f"  {'Fixture':<32} {'L1':<7} {'Fused':<7} {'LLM':<12} {'Caught By'}"
    print(header)
    print(f"{'─'*70}")

    for fname in l2_results:
        r = l2_results[fname]
        l1v = r.get("l1_verdict", "?")[:6]
        fv  = r.get("fused_verdict", "?")[:6]
        llm = r.get("llm_verdict", "N/A")[:8]
        lc  = f"{r.get('llm_conf', 0):.0%}"
        cb  = r.get("caught_by", "?")
        print(f"  {fname:<32} {l1v:<7} {fv:<7} {llm:<8}@{lc:<4} {cb}")

    # Category breakdown
    categories: dict[str, dict[str, int]] = {}
    for fname, r in l2_results.items():
        cat = r["meta"].get("category", "?")
        categories.setdefault(cat, {"total": 0, "caught": 0})
        categories[cat]["total"] += 1
        if r.get("caught_by") not in ("EVADED", "ERROR", "?"):
            categories[cat]["caught"] += 1

    print(f"\n{'─'*70}")
    print("  Detection by category:")
    for cat, counts in categories.items():
        pct = counts["caught"] / counts["total"] * 100 if counts["total"] else 0
        print(f"    {cat:<30} {counts['caught']}/{counts['total']} ({pct:.0f}%)")

    total   = len(l2_results)
    caught  = sum(1 for r in l2_results.values() if r.get("caught_by") not in ("EVADED", "ERROR"))
    evaded  = sum(1 for r in l2_results.values() if r.get("caught_by") == "EVADED")
    errors  = sum(1 for r in l2_results.values() if r.get("caught_by") == "ERROR")

    print(f"{'─'*70}")
    print(f"  TOTAL: {caught}/{total} caught  |  {evaded} evaded  |  {errors} errors")
    print(f"  Overall detection rate: {caught/total:.0%}")
    print(f"{'═'*70}\n")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate adversarial E-series fixtures")
    parser.add_argument(
        "--l1-only",
        action="store_true",
        help="Run Layer 1 only (no API calls).",
    )
    parser.add_argument(
        "--fixture",
        help="Run only a specific fixture (e.g. E005-context-hijacking.md).",
    )
    args = parser.parse_args()

    # Collect fixtures
    if args.fixture:
        fixtures = [FIXTURES_DIR / args.fixture]
        if not fixtures[0].exists():
            print(f"ERROR: Fixture not found: {fixtures[0]}")
            sys.exit(1)
    else:
        fixtures = sorted(FIXTURES_DIR.glob("E*.md"))
        if not fixtures:
            print(f"ERROR: No E*.md fixtures found in {FIXTURES_DIR}")
            sys.exit(1)

    print(f"\nAgentic Scanner — Adversarial Evaluation (E-Series)")
    print(f"Fixtures: {len(fixtures)}  |  Dir: {FIXTURES_DIR}")

    # Phase 1: L1
    l1_results = run_l1_phase(fixtures)
    print_l1_summary(l1_results)

    if args.l1_only:
        print("  [L1-only mode] Skipping Layer 2.\n")
        return

    # Phase 2: L2
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("  ERROR: ANTHROPIC_API_KEY not set. Cannot run Phase 2.")
        print("  Re-run with --l1-only for L1-only results.\n")
        sys.exit(1)

    l2_results = run_l2_phase(fixtures, l1_results)
    print_combined_summary(l1_results, l2_results)


if __name__ == "__main__":
    main()
