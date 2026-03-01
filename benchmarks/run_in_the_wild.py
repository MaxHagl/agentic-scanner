#!/usr/bin/env python3
"""
benchmarks/run_in_the_wild.py
─────────────────────────────
Runs the Agentic Scanner across real-world LLM tool repositories (e.g. MCP servers)
to evaluate the local LLM pre-filter in a realistic setting.

Usage:
  poetry run python benchmarks/run_in_the_wild.py --repos-file benchmarks/repos.txt --local-model finetuning/adapter
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from scanner.aggregator import fuse_layer1, fuse_layers
from scanner.layer1_static.parser import parse_target
from scanner.layer1_static.rule_engine import Layer1RuleEngine
from scanner.layer2_semantic import Layer2Analyzer

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)
console = Console()

def clone_repo(repo_url: str, dest_dir: Path) -> bool:
    if dest_dir.exists():
        logger.info(f"Using existing repo at {dest_dir}")
        return True
    logger.info(f"Cloning {repo_url} -> {dest_dir} ...")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(dest_dir)],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        logger.error(f"Failed to clone {repo_url}: {result.stderr}")
        return False
    return True

def scan_repo(repo_dir: Path, l1_engine: Layer1RuleEngine, l2_analyzer: Layer2Analyzer | None) -> dict[str, Any]:
    # 1. Parse all tools in the repo
    manifests = []
    logger.info(f"  Parsing tools in {repo_dir.name} ...")
    for filepath in repo_dir.rglob("*.py"):
        if filepath.is_symlink() or not filepath.is_file():
            continue
        try:
            m = parse_target(str(filepath))
            if m.tools:
                manifests.append(m)
        except Exception as e:
            logger.debug(f"Failed to parse {filepath}: {e}")
            
    if not manifests:
        logger.warning(f"  No tools found in {repo_dir.name}")
        return {"repo": repo_dir.name, "tools_found": 0, "results": []}

    results = []
    # 2. Run layers
    for m in manifests:
        tool_count = len(m.tools)
        # Layer 1
        l1_report = l1_engine.evaluate(m, source_directory=str(repo_dir))
        l1_verdict = fuse_layer1(m, l1_report)
        
        # Layer 2 (Semantic)
        l2_report = None
        final_verdict = l1_verdict
        escalated = False
        
        if l2_analyzer and l1_verdict != "MALICIOUS":
            l2_report = l2_analyzer.analyze(m, l1_report)
            final_verdict = fuse_layers(m, l1_report, l2_report)
            # If the local model flagged it as SUSPICIOUS, it escalated to Haiku
            escalated = l2_report.local_model_escalated
            
        manifest_path = m.raw_manifest_json.get("_manifest_path", "unknown")
        file_name = Path(manifest_path).name if manifest_path != "unknown" else "unknown"
            
        results.append({
            "file": file_name,
            "tool_count": tool_count,
            "l1_verdict": l1_verdict,
            "local_llm_verdict": l2_report.llm_judge_verdict if l2_report else None,
            "local_llm_confidence": l2_report.llm_judge_confidence if l2_report else None,
            "final_verdict": final_verdict,
            "l2_escalated": escalated,
            "l2_rationale": (l2_report.llm_judge_evidence_summary or "") if l2_report else ""
        })
        
    return {
        "repo": repo_dir.name,
        "tools_found": len(manifests),
        "total_endpoints": sum(r["tool_count"] for r in results),
        "results": results
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repos", type=str, required=True, help="Comma-separated list of GitHub clone URLs")
    parser.add_argument("--local-model", type=str, required=True, help="Path to local LoRA adapter")
    parser.add_argument("--out-markdown", type=str, default="benchmarks/in_the_wild_report.md")
    args = parser.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        console.print("[bold red]Error: ANTHROPIC_API_KEY environment variable is required to run Layer 2.[/bold red]")
        return

    model_path = Path(args.local_model)
    if not model_path.exists():
        console.print(f"[bold red]Error: Local model path {model_path} does not exist.[/bold red]")
        return

    work_dir = Path("benchmarks/repos")
    work_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize engines
    logger.info("Initializing Layer 1 engine...")
    l1_engine = Layer1RuleEngine()
    
    logger.info(f"Initializing Layer 2 analyzer with {model_path} ...")
    l2_analyzer = Layer2Analyzer(local_model_path=model_path, escalation_threshold=0.80)
    
    repos = [r.strip() for r in args.repos.split(",") if r.strip()]
    all_repo_results = []
    
    for repo_url in repos:
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        dest_dir = work_dir / repo_name
        
        if clone_repo(repo_url, dest_dir):
            res = scan_repo(dest_dir, l1_engine, l2_analyzer)
            all_repo_results.append(res)
            
    # Generate Markdown Report
    report_lines = [
        "# In-the-Wild Benchmark Report",
        "",
        f"**Date:** {time.strftime('%Y-%m-%d')}",
        f"**Local Model:** `{model_path.name}`",
        "",
        "## Summary",
        "",
        "| Repository | Files with Tools | Total Endpoints | Escalatations to L3 | Final MALICIOUS | Final WARN |",
        "|---|---|---|---|---|---|"
    ]
    
    total_files = 0
    total_tools = 0
    total_escalated = 0
    
    for r in all_repo_results:
        files = r["tools_found"]
        tools = r["total_endpoints"]
        escalated = sum(1 for x in r["results"] if x["l2_escalated"])
        malicious = sum(1 for x in r["results"] if x["final_verdict"] == "MALICIOUS")
        warn = sum(1 for x in r["results"] if x["final_verdict"] == "WARN")
        
        total_files += files
        total_tools += tools
        total_escalated += escalated
        
        report_lines.append(f"| {r['repo']} | {files} | {tools} | {escalated} | {malicious} | {warn} |")
        
    report_lines.extend(["", "## Detailed Findings", ""])
    
    for r in all_repo_results:
        if r["tools_found"] == 0:
            continue
        report_lines.append(f"### {r['repo']}")
        report_lines.append("")
        report_lines.append("| File | Tools | L1 Verdict | Local LLM | Esc. | Final Verdict | Rationale |")
        report_lines.append("|---|---|---|---|---|---|---|")
        
        for res in r["results"]:
            esc_str = "Yes" if res["l2_escalated"] else "No"
            loc_str = f"{res['local_llm_verdict']} ({res['local_llm_confidence']:.2f})" if res["local_llm_verdict"] else "-"
            # Truncate rationale for table
            rat = res["l2_rationale"][:60] + "..." if len(res["l2_rationale"]) > 60 else res["l2_rationale"]
            rat = rat.replace("\n", " ")
            report_lines.append(
                f"| `{res['file']}` | {res['tool_count']} | {res['l1_verdict']} | {loc_str} | {esc_str} | **{res['final_verdict']}** | {rat} |"
            )
        report_lines.append("")

    report_path = Path(args.out_markdown)
    report_path.write_text("\n".join(report_lines))
    
    console.print(f"\n[bold green]Success![/bold green] Benchmark complete. "
                  f"Scanned {total_files} files ({total_tools} tools). "
                  f"Escalated {total_escalated} files. "
                  f"Report saved to {report_path}")

if __name__ == "__main__":
    main()
