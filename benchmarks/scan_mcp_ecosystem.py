#!/usr/bin/env python3
"""
benchmarks/scan_mcp_ecosystem.py
─────────────────────────────────
Large-scale in-the-wild scan of MCP community servers sourced from the
awesome-mcp-servers curated list (RQ-D study).

Usage:
  poetry run python benchmarks/scan_mcp_ecosystem.py [OPTIONS]

Options:
  --semantic          Run L2 on WARN/BLOCK items (requires ANTHROPIC_API_KEY)
  --out-dir PATH      Output directory [default: benchmarks/mcp_scan_results/]
  --max-repos N       Stop after N repos [default: 500]
  --resume            Skip repos already in checkpoint.jsonl
  --source-url URL    Override the awesome-mcp-servers list URL
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import re
import shutil
import subprocess
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from scanner.aggregator import fuse_layer1, fuse_layers
from scanner.layer1_static.parser import parse_target
from scanner.layer1_static.rule_engine import Layer1RuleEngine
from scanner.layer2_semantic import Layer2Analyzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Source URL and filtering ──────────────────────────────────────────────────

_DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md"
)
_GITHUB_URL_RE = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
)
# Owners / patterns that are not actual MCP server repos
_EXCLUDE_OWNERS = {"punkpeye"}
_EXCLUDE_PATTERNS = {
    "/orgs/",
    "/search?",
    "/topics/",
    "/explore",
    "github.com/features",
    "github.com/marketplace",
}

# ── Verdict severity ordering ─────────────────────────────────────────────────

_SEVERITY_ORDER: dict[str, int] = {"SAFE": 0, "WARN": 1, "BLOCK": 2}


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class FileResult:
    filepath: str
    file_type: str          # "python" | "markdown"
    verdict: str            # "SAFE" | "WARN" | "BLOCK"
    l1_score: float
    l2_score: float | None
    rules_fired: list[str]  # rule IDs that fired
    evidence: str           # top match snippet, truncated to 120 chars
    tools_found: int        # number of tool definitions in this file


@dataclass
class RepoResult:
    repo_url: str
    repo_name: str
    status: str             # "ok" | "clone_failed" | "no_files"
    file_results: list[FileResult]
    worst_verdict: str      # "SAFE" | "WARN" | "BLOCK"
    python_files_scanned: int
    markdown_files_scanned: int
    total_tools_found: int
    l2_run: bool
    l2_tokens_used: int
    error: str | None


# ── Data source ───────────────────────────────────────────────────────────────

def fetch_mcp_server_list(source_url: str = _DEFAULT_SOURCE_URL) -> list[str]:
    """Fetch the awesome-mcp-servers README and return unique GitHub repo URLs."""
    logger.info(f"Fetching MCP server list from {source_url}")
    with urllib.request.urlopen(source_url, timeout=30) as resp:
        content = resp.read().decode("utf-8", errors="replace")

    raw_urls = _GITHUB_URL_RE.findall(content)
    seen: set[str] = set()
    repos: list[str] = []
    for url in raw_urls:
        # Normalise: strip .git suffix and trailing slashes
        url = url.rstrip("/").removesuffix(".git")
        if url in seen:
            continue
        seen.add(url)

        # Must be exactly https://github.com/<owner>/<repo> (5 slash-parts)
        parts = url.split("/")
        if len(parts) != 5:
            continue

        owner = parts[3]
        if owner in _EXCLUDE_OWNERS:
            continue
        if any(pat in url for pat in _EXCLUDE_PATTERNS):
            continue

        repos.append(url)

    logger.info(f"Found {len(repos)} unique MCP repos")
    return repos


# ── Cloning ───────────────────────────────────────────────────────────────────

def clone_repo(github_url: str, dest_dir: Path, timeout: int = 120) -> bool:
    """Shallow-clone a repo. Returns True on success. Skips if already cloned."""
    if dest_dir.exists():
        logger.debug(f"Reusing existing clone: {dest_dir}")
        return True
    logger.info(f"Cloning {github_url} → {dest_dir.name}")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", github_url, str(dest_dir)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            logger.warning(
                f"Clone failed ({github_url}): {result.stderr.strip()[:200]}"
            )
            return False
        return True
    except subprocess.TimeoutExpired:
        logger.warning(f"Clone timed out after {timeout}s: {github_url}")
        shutil.rmtree(dest_dir, ignore_errors=True)
        return False
    except Exception as exc:
        logger.warning(f"Clone error ({github_url}): {exc}")
        return False


# ── Per-file scanning ─────────────────────────────────────────────────────────

def scan_file(filepath: Path, l1_engine: Layer1RuleEngine) -> FileResult | None:
    """
    Parse and L1-scan a single file.
    Returns None if the file cannot be parsed (unsupported extension, etc.).
    Also returns the SkillManifest and RiskReport_L1 via the internal tuple
    so scan_repo can reuse them for optional L2 without re-parsing.
    """
    file_type = "python" if filepath.suffix == ".py" else "markdown"
    try:
        manifest = parse_target(str(filepath))
    except ValueError:
        return None  # Unsupported extension — skip silently
    except Exception as exc:
        logger.debug(f"parse_target failed ({filepath.name}): {exc}")
        return None

    try:
        l1_report = l1_engine.evaluate(manifest)
        verdict_obj = fuse_layer1(manifest, l1_report)
    except Exception as exc:
        logger.debug(f"L1 evaluation failed ({filepath.name}): {exc}")
        return None

    # Extract top evidence snippet
    evidence = ""
    if verdict_obj.all_findings:
        top_match = verdict_obj.all_findings[0]
        if top_match.evidence:
            raw = top_match.evidence[0].snippet or ""
            evidence = raw[:120].replace("\n", " ")

    return FileResult(
        filepath=str(filepath),
        file_type=file_type,
        verdict=verdict_obj.verdict,
        l1_score=round(verdict_obj.fused_risk_score, 4),
        l2_score=None,
        rules_fired=[m.rule_id for m in verdict_obj.all_findings],
        evidence=evidence,
        tools_found=len(manifest.tools),
    )


# ── Internal helper: parse + evaluate (for L2 worst-file tracking) ─────────

def _parse_and_evaluate(
    filepath: Path, l1_engine: Layer1RuleEngine
) -> tuple[Any, Any] | None:
    """Return (manifest, l1_report) or None on any failure."""
    try:
        manifest = parse_target(str(filepath))
        l1_report = l1_engine.evaluate(manifest)
        return manifest, l1_report
    except Exception:
        return None


# ── Per-repo scanning ─────────────────────────────────────────────────────────

def scan_repo(
    repo_dir: Path,
    repo_url: str,
    l1_engine: Layer1RuleEngine,
    l2_analyzer: Layer2Analyzer | None,
) -> RepoResult:
    """
    Scan all Python + Markdown files in a cloned repo.
    Optionally runs L2 once on the worst-verdict file.
    """
    _MARKDOWN_CAP = 10  # Prevent docs-heavy repos from dominating

    file_results: list[FileResult] = []
    # Track (manifest, l1_report, idx) for the worst-scoring file (L2 needs it)
    worst_state: tuple[Any, Any, int] | None = None
    worst_so_far = "SAFE"
    py_count = md_count = 0

    # ── Markdown files ──
    md_files = sorted(repo_dir.rglob("*.md"))[:_MARKDOWN_CAP]
    for md_path in md_files:
        if not md_path.is_file():
            continue
        result = scan_file(md_path, l1_engine)
        if result is None:
            continue
        md_count += 1
        idx = len(file_results)
        file_results.append(result)
        if _SEVERITY_ORDER[result.verdict] > _SEVERITY_ORDER[worst_so_far]:
            worst_so_far = result.verdict
            if l2_analyzer is not None:
                state = _parse_and_evaluate(md_path, l1_engine)
                worst_state = (state[0], state[1], idx) if state else None

    # ── Python source files ──
    _PYTHON_CAP = 100
    py_files = sorted(repo_dir.rglob("*.py"))
    py_files.sort(key=lambda p: len(p.parts))
    for py_path in py_files[:_PYTHON_CAP]:
        if not py_path.is_file():
            continue
        # Skip test files as specified in the plan
        stem = py_path.stem.lower()
        if stem.startswith("test_") or stem.endswith("_test") or py_path.name == "conftest.py":
            continue
        result = scan_file(py_path, l1_engine)
        if result is None:
            continue
        py_count += 1
        idx = len(file_results)
        file_results.append(result)
        if _SEVERITY_ORDER[result.verdict] > _SEVERITY_ORDER[worst_so_far]:
            worst_so_far = result.verdict
            if l2_analyzer is not None:
                state = _parse_and_evaluate(py_path, l1_engine)
                worst_state = (state[0], state[1], idx) if state else None

    if not file_results:
        return RepoResult(
            repo_url=repo_url,
            repo_name=repo_dir.name,
            status="no_files",
            file_results=[],
            worst_verdict="SAFE",
            python_files_scanned=0,
            markdown_files_scanned=0,
            total_tools_found=0,
            l2_run=False,
            l2_tokens_used=0,
            error=None,
        )

    # ── Optional L2 pass on worst file ──
    l2_run = False
    l2_tokens_used = 0
    if l2_analyzer is not None and worst_so_far != "SAFE" and worst_state is not None:
        manifest, l1_report, worst_idx = worst_state
        try:
            l2_report = l2_analyzer.analyze(manifest, l1_report)
            l2_run = True
            l2_tokens_used = l2_report.llm_tokens_used
            fused = fuse_layers(manifest, l1_report, l2_report)
            file_results[worst_idx].l2_score = round(l2_report.composite_score, 4)
            file_results[worst_idx].verdict = fused.verdict
            # Recompute repo-level worst verdict after fusion
            worst_so_far = max(
                (f.verdict for f in file_results),
                key=lambda v: _SEVERITY_ORDER[v],
            )
        except Exception as exc:
            logger.warning(f"L2 failed for {repo_dir.name}: {exc}")

    total_tools = sum(f.tools_found for f in file_results)

    return RepoResult(
        repo_url=repo_url,
        repo_name=repo_dir.name,
        status="ok",
        file_results=file_results,
        worst_verdict=worst_so_far,
        python_files_scanned=py_count,
        markdown_files_scanned=md_count,
        total_tools_found=total_tools,
        l2_run=l2_run,
        l2_tokens_used=l2_tokens_used,
        error=None,
    )


# ── Checkpoint I/O ────────────────────────────────────────────────────────────

def save_checkpoint(result: RepoResult, checkpoint_path: Path) -> None:
    """Append one JSON line for this repo (crash-safe JSONL format)."""
    line = json.dumps(dataclasses.asdict(result), ensure_ascii=False)
    with checkpoint_path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
        fh.flush()


def load_checkpoint(checkpoint_path: Path) -> set[str]:
    """Return set of repo_url strings already fully processed."""
    if not checkpoint_path.exists():
        return set()
    done: set[str] = set()
    with checkpoint_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                done.add(obj["repo_url"])
            except (json.JSONDecodeError, KeyError):
                pass
    return done


def _load_checkpoint_results(checkpoint_path: Path) -> list[RepoResult]:
    """Reconstruct RepoResult objects from a checkpoint file."""
    if not checkpoint_path.exists():
        return []
    results: list[RepoResult] = []
    with checkpoint_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                file_results = [
                    FileResult(**fr) for fr in obj.get("file_results", [])
                ]
                obj["file_results"] = file_results
                results.append(RepoResult(**obj))
            except Exception:
                pass
    return results


# ── Report generation ─────────────────────────────────────────────────────────

def generate_report(
    all_results: list[RepoResult],
    output_path: Path,
    l2_enabled: bool,
) -> None:
    """Write a Markdown report summarising all scan results."""
    today = date.today().isoformat()

    ok_repos = [r for r in all_results if r.status == "ok"]
    failed = [r for r in all_results if r.status == "clone_failed"]
    no_files = [r for r in all_results if r.status == "no_files"]

    all_files: list[FileResult] = [f for r in ok_repos for f in r.file_results]
    total_files = len(all_files)
    py_files = sum(1 for f in all_files if f.file_type == "python")
    md_files_count = sum(1 for f in all_files if f.file_type == "markdown")
    total_tools = sum(r.total_tools_found for r in ok_repos)
    total_l2_tokens = sum(r.l2_tokens_used for r in ok_repos)

    verdict_counts: Counter[str] = Counter(f.verdict for f in all_files)
    repo_verdict_counts: Counter[str] = Counter(r.worst_verdict for r in ok_repos)

    # Rules frequency: hit count per rule_id + distinct repos affected
    rule_hits: Counter[str] = Counter(
        rule for f in all_files for rule in f.rules_fired
    )
    rule_repos: dict[str, set[str]] = defaultdict(set)
    for r in ok_repos:
        for f in r.file_results:
            for rule in f.rules_fired:
                rule_repos[rule].add(r.repo_name)

    warn_block_repos = [
        r for r in ok_repos if r.worst_verdict in ("WARN", "BLOCK")
    ]
    repo_ok_count = len(ok_repos)

    lines: list[str] = []

    # ── Section 1: Header ──
    lines += [
        "# MCP Ecosystem Security Scan Report",
        "",
        f"**Date:** {today}  ",
        f"**Source:** awesome-mcp-servers curated list  ",
        f"**Repos attempted:** {len(all_results)}  ",
        f"**Repos successfully scanned:** {repo_ok_count}  ",
        f"**L2 semantic analysis:** {'enabled (WARN/BLOCK only)' if l2_enabled else 'disabled (L1 only)'}  ",
        f"**Total L2 tokens consumed:** {total_l2_tokens:,}  ",
        "",
    ]

    # ── Section 2: Verdict distribution ──
    lines += [
        "## Overall Verdict Distribution",
        "",
        "### By File",
        "",
        "| Verdict | Count | Percentage |",
        "|---------|-------|------------|",
    ]
    for v in ("BLOCK", "WARN", "SAFE"):
        cnt = verdict_counts.get(v, 0)
        pct = f"{cnt / total_files * 100:.1f}%" if total_files else "0.0%"
        lines.append(f"| {v} | {cnt} | {pct} |")

    lines += ["", "### By Repository", ""]
    lines += [
        "| Verdict | Repos | Percentage |",
        "|---------|-------|------------|",
    ]
    for v in ("BLOCK", "WARN", "SAFE"):
        cnt = repo_verdict_counts.get(v, 0)
        pct = f"{cnt / repo_ok_count * 100:.1f}%" if repo_ok_count else "0.0%"
        lines.append(f"| {v} | {cnt} | {pct} |")

    lines += [
        "",
        f"**Files scanned:** {total_files} ({py_files} Python + {md_files_count} Markdown)  ",
        f"**Tool endpoints found:** {total_tools}  ",
        "",
    ]

    # ── Section 3: Most frequently triggered rules ──
    lines += [
        "## Most Frequently Triggered Rules",
        "",
        "| Rule ID | Hit Count | Repos Affected |",
        "|---------|-----------|----------------|",
    ]
    for rule_id, count in rule_hits.most_common(20):
        n_repos = len(rule_repos[rule_id])
        lines.append(f"| `{rule_id}` | {count} | {n_repos} |")
    if not rule_hits:
        lines.append("| — | 0 | 0 |")
    lines.append("")

    # ── Section 4: WARN/BLOCK repos ──
    lines += [
        "## Flagged Repositories (WARN / BLOCK)",
        "",
        f"*{len(warn_block_repos)} of {repo_ok_count} repos had at least one WARN or BLOCK finding.*",
        "",
    ]
    if warn_block_repos:
        for repo in sorted(
            warn_block_repos,
            key=lambda r: _SEVERITY_ORDER[r.worst_verdict],
            reverse=True,
        ):
            badge = "🔴 BLOCK" if repo.worst_verdict == "BLOCK" else "🟡 WARN"
            lines += [
                f"### {badge} — [{repo.repo_name}]({repo.repo_url})",
                "",
                (
                    f"Python files: {repo.python_files_scanned} | "
                    f"Markdown files: {repo.markdown_files_scanned} | "
                    f"Tools: {repo.total_tools_found}  "
                ),
            ]
            if repo.l2_run:
                lines.append(f"L2 tokens: {repo.l2_tokens_used:,}  ")
            lines.append("")

            flagged = [
                f for f in repo.file_results if f.verdict in ("WARN", "BLOCK")
            ]
            if flagged:
                lines += [
                    "| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |",
                    "|------|------|---------|----------|----------|-------|----------|",
                ]
                for f in sorted(
                    flagged,
                    key=lambda x: _SEVERITY_ORDER[x.verdict],
                    reverse=True,
                ):
                    fname = Path(f.filepath).name
                    rules_str = (
                        ", ".join(f"`{r}`" for r in f.rules_fired)
                        if f.rules_fired
                        else "—"
                    )
                    ev = f.evidence.replace("|", "\\|")[:80] if f.evidence else "—"
                    l2_str = f"{f.l2_score:.3f}" if f.l2_score is not None else "—"
                    lines.append(
                        f"| `{fname}` | {f.file_type} | **{f.verdict}** "
                        f"| {f.l1_score:.3f} | {l2_str} | {rules_str} | {ev} |"
                    )
                lines.append("")
    else:
        lines += ["*No repositories flagged.*", ""]

    # ── Section 5: Scanning notes ──
    lines += [
        "## Scanning Notes",
        "",
        f"- Repos attempted: **{len(all_results)}**",
        f"- Successfully scanned: **{repo_ok_count}**",
        f"- Clone failures: **{len(failed)}**",
        f"- Empty repos (no parseable files): **{len(no_files)}**",
        "",
    ]
    if failed:
        lines.append("### Clone Failures (first 20)")
        lines.append("")
        for r in failed[:20]:
            lines.append(f"- `{r.repo_url}` — {r.error or 'unknown error'}")
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info(f"Report written to {output_path}")


# ── Flagged JSON export ───────────────────────────────────────────────────────

def save_flagged_json(all_results: list[RepoResult], output_path: Path) -> None:
    """Save only WARN/BLOCK repos as structured JSON for downstream analysis."""
    flagged = [
        dataclasses.asdict(r)
        for r in all_results
        if r.worst_verdict in ("WARN", "BLOCK")
    ]
    output_path.write_text(
        json.dumps(flagged, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    logger.info(f"Flagged JSON saved to {output_path} ({len(flagged)} repos)")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Large-scale MCP ecosystem scanner (RQ-D study)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--semantic",
        action="store_true",
        help="Run L2 on WARN/BLOCK items (requires ANTHROPIC_API_KEY)",
    )
    parser.add_argument(
        "--out-dir",
        type=str,
        default="benchmarks/mcp_scan_results",
        help="Output directory",
    )
    parser.add_argument(
        "--max-repos",
        type=int,
        default=500,
        help="Stop after N repos",
    )
    parser.add_argument(
        "--local-model",
        type=str,
        default=None,
        help="Path to local LoRA adapter to use for L2 classification",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip repos already recorded in checkpoint.jsonl",
    )
    parser.add_argument(
        "--high-security",
        action="store_true",
        help="Force LLM analysis (Layer 2) to escalate to Haiku regardless of local model confidence",
    )
    parser.add_argument(
        "--source-url",
        type=str,
        default=_DEFAULT_SOURCE_URL,
        help="Override the awesome-mcp-servers list URL",
    )
    args = parser.parse_args()

    # ── Output directory setup ──
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = out_dir / "checkpoint.jsonl"
    report_path = out_dir / "report.md"
    flagged_path = out_dir / "flagged.json"
    clone_dir = out_dir / "clones"
    clone_dir.mkdir(exist_ok=True)

    # ── L2 setup ──
    l2_analyzer: Layer2Analyzer | None = None
    if args.semantic:
        if not os.environ.get("ANTHROPIC_API_KEY") and not args.local_model:
            logger.error("--semantic requires ANTHROPIC_API_KEY or --local-model")
            return
        logger.info("L2 semantic analysis enabled (runs only on WARN/BLOCK repos)")
        model_path = Path(args.local_model) if args.local_model else None
        applied_threshold = 1.01 if args.high_security else 0.80
        l2_analyzer = Layer2Analyzer(
            local_model_path=model_path,
            escalation_threshold=applied_threshold,
        )

    # ── Fetch repo list ──
    try:
        repos = fetch_mcp_server_list(args.source_url)
    except Exception as exc:
        logger.error(f"Failed to fetch MCP server list: {exc}")
        return

    repos = repos[: args.max_repos]
    logger.info(f"Will scan up to {len(repos)} repos")

    # ── Resume support ──
    all_results: list[RepoResult] = []
    done_urls: set[str] = set()
    if args.resume:
        all_results = _load_checkpoint_results(checkpoint_path)
        done_urls = {r.repo_url for r in all_results}
        logger.info(f"Resuming — {len(done_urls)} repos already done")

    # ── Initialise L1 engine (once, reused for all repos) ──
    logger.info("Initialising Layer 1 rule engine …")
    l1_engine = Layer1RuleEngine()

    # ── Main scan loop ──
    total = len(repos)
    for repo_url in repos:
        if repo_url in done_urls:
            continue

        repo_name = repo_url.rstrip("/").split("/")[-1]
        owner = repo_url.split("/")[-2]
        # Use owner__name to avoid collisions between repos with the same base name
        dest_dir = clone_dir / f"{owner}__{repo_name}"

        # ── Clone ──
        cloned = clone_repo(repo_url, dest_dir)
        if not cloned:
            result = RepoResult(
                repo_url=repo_url,
                repo_name=repo_name,
                status="clone_failed",
                file_results=[],
                worst_verdict="SAFE",
                python_files_scanned=0,
                markdown_files_scanned=0,
                total_tools_found=0,
                l2_run=False,
                l2_tokens_used=0,
                error="clone_failed",
            )
            all_results.append(result)
            save_checkpoint(result, checkpoint_path)
            continue

        # ── Scan ──
        try:
            result = scan_repo(dest_dir, repo_url, l1_engine, l2_analyzer)
        except Exception as exc:
            logger.warning(f"scan_repo raised for {repo_name}: {exc}")
            result = RepoResult(
                repo_url=repo_url,
                repo_name=repo_name,
                status="clone_failed",
                file_results=[],
                worst_verdict="SAFE",
                python_files_scanned=0,
                markdown_files_scanned=0,
                total_tools_found=0,
                l2_run=False,
                l2_tokens_used=0,
                error=str(exc)[:200],
            )

        all_results.append(result)
        save_checkpoint(result, checkpoint_path)

        # Progress log
        v = result.worst_verdict
        tag = "  " if v == "SAFE" else ("⚠ " if v == "WARN" else "🔴")
        progress = len(all_results)
        logger.info(
            f"[{progress}/{total}] {tag}{repo_name}: "
            f"{result.python_files_scanned}py + {result.markdown_files_scanned}md "
            f"→ {v}"
        )

    # ── Final report ──
    logger.info(f"Generating report for {len(all_results)} repos …")
    generate_report(all_results, report_path, l2_enabled=args.semantic)
    save_flagged_json(all_results, flagged_path)

    ok = sum(1 for r in all_results if r.status == "ok")
    flagged_n = sum(1 for r in all_results if r.worst_verdict in ("WARN", "BLOCK"))
    block_n = sum(1 for r in all_results if r.worst_verdict == "BLOCK")
    logger.info(
        "\n" + "─" * 60 + "\n"
        f"Scan complete:  {ok} repos scanned  |  "
        f"{flagged_n} flagged ({block_n} BLOCK)  |  "
        f"{len(all_results) - ok} failed/empty\n"
        f"Report:         {report_path}\n"
        f"Flagged JSON:   {flagged_path}\n"
        f"Checkpoint:     {checkpoint_path}\n"
        + "─" * 60
    )


if __name__ == "__main__":
    main()
