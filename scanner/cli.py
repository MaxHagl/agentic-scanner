from __future__ import annotations

import json
import os
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from scanner.aggregator import fuse_layer1, fuse_layers, fuse_layers_l3
from scanner.layer1_static.parser import parse_target
from scanner.layer1_static.rule_engine import Layer1RuleEngine


def _verdict_style(verdict: str) -> str:
    if verdict == "BLOCK":
        return "bold red"
    if verdict == "WARN":
        return "bold yellow"
    return "bold green"


@click.group()
def main() -> None:
    """Agentic scanner CLI."""


@main.command("scan")
@click.argument("target", type=str)
@click.option(
    "--source-file",
    "source_files",
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Explicit Python source files to analyze for AST findings.",
)
@click.option(
    "--source-directory",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Directory to recursively scan for Python source files.",
)
@click.option(
    "--semantic",
    is_flag=True,
    default=False,
    help="Run Layer 2 semantic analysis via LLM judge (requires ANTHROPIC_API_KEY).",
)
@click.option(
    "--dynamic",
    is_flag=True,
    default=False,
    help="Run Layer 3 dynamic analysis in Docker sandbox (requires Docker daemon).",
)
@click.option(
    "--json-output",
    is_flag=True,
    default=False,
    help="Print FinalVerdict JSON instead of human-readable output.",
)
@click.option(
    "--sarif-out",
    type=click.Path(path_type=Path),
    default=None,
    help="Write SARIF 2.1.0 output to the given file path.",
)
def scan_command(
    target: str,
    source_files: tuple[Path, ...],
    source_directory: Path | None,
    semantic: bool,
    dynamic: bool,
    json_output: bool,
    sarif_out: Path | None,
) -> None:
    console = Console()
    started = time.perf_counter()

    tmp_path: Path | None = None
    try:
        if target.startswith(("http://", "https://")):
            from scanner.layer1_static.fetcher import fetch_to_tempfile
            console.print(f"[dim]Fetching: {target}[/dim]")
            tmp_path = fetch_to_tempfile(target)
            scan_path = tmp_path
        else:
            scan_path = Path(target)
            if not scan_path.exists():
                raise click.BadParameter(
                    f"Path does not exist: {target}", param_hint="TARGET"
                )

        manifest = parse_target(scan_path)
        engine = Layer1RuleEngine()
        l1_report = engine.evaluate(
            manifest,
            source_files=[str(p.resolve()) for p in source_files] if source_files else None,
            source_directory=str(source_directory.resolve()) if source_directory else None,
        )

        l2_report = None
        if semantic:
            if not os.environ.get("ANTHROPIC_API_KEY"):
                console.print(
                    "[bold yellow]Warning:[/bold yellow] --semantic requires ANTHROPIC_API_KEY "
                    "to be set. Skipping Layer 2."
                )
            else:
                from scanner.layer2_semantic import Layer2Analyzer
                analyzer = Layer2Analyzer()
                l2_report = analyzer.analyze(manifest, l1_report)

        l3_report = None
        if dynamic:
            try:
                import docker as _docker
                _docker.from_env().ping()
            except Exception:
                console.print(
                    "[bold yellow]Warning:[/bold yellow] --dynamic requires a running Docker "
                    "daemon. Skipping Layer 3."
                )
            else:
                from scanner.layer3_dynamic import Layer3DynamicAnalyzer
                analyzer3 = Layer3DynamicAnalyzer()
                l3_report = analyzer3.analyze(manifest, l1_report, source_path=scan_path)

        if l3_report is not None:
            verdict = fuse_layers_l3(manifest, l1_report, l2_report, l3_report)
        elif l2_report is not None:
            verdict = fuse_layers(manifest, l1_report, l2_report)
        else:
            verdict = fuse_layer1(manifest, l1_report)

        verdict.total_scan_time_ms = int((time.perf_counter() - started) * 1000)

    except Exception as exc:
        console.print(f"[bold red]Scan failed:[/bold red] {exc}")
        raise SystemExit(1) from exc
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)

    if sarif_out is not None:
        sarif_out.parent.mkdir(parents=True, exist_ok=True)
        sarif_out.write_text(json.dumps(verdict.to_sarif(), indent=2), encoding="utf-8")

    if json_output:
        console.print(json.dumps(verdict.model_dump(mode="json"), indent=2))
    else:
        style = _verdict_style(verdict.verdict)
        console.print(
            f"[{style}]{verdict.verdict}[/{style}] "
            f"{verdict.skill_name} ({verdict.framework})"
        )
        layers_str = " + ".join(verdict.layers_executed)
        console.print(
            f"Risk score: {verdict.fused_risk_score:.4f} | "
            f"Confidence: {verdict.confidence:.2f} | "
            f"Findings: {len(verdict.all_findings)} | "
            f"Layers: {layers_str}"
        )

        # L1 / L2 / L3 score breakdown when multiple layers ran
        if l2_report is not None:
            l2_verdict = l2_report.llm_judge_verdict or "N/A"
            l2_conf = l2_report.llm_judge_confidence
            l2_conf_str = f"{l2_conf:.0%}" if l2_conf is not None else "—"
            console.print(
                f"  L1 score: {verdict.l1_score:.4f} | "
                f"L2 score: {verdict.l2_score:.4f} | "
                f"LLM verdict: {l2_verdict} ({l2_conf_str}) | "
                f"Tokens: {verdict.llm_tokens_consumed}"
            )
        if l3_report is not None:
            l3_score_val = verdict.l3_score if verdict.l3_score is not None else 0.0
            console.print(
                f"  L3 score: {l3_score_val:.4f} | "
                f"execve: {l3_report.execve_detected} | "
                f"net_egress: {l3_report.undeclared_network_egress} | "
                f"entropy: {l3_report.trace.output_entropy:.2f}"
            )

        if verdict.all_findings:
            table = Table(show_header=True, header_style="bold")
            table.add_column("Layer")
            table.add_column("Rule")
            table.add_column("Severity")
            table.add_column("Vector")
            table.add_column("Evidence")
            l1_ids = {id(m) for m in l1_report.matches}
            l3_ids = {id(m) for m in l3_report.matches} if l3_report is not None else set()
            for finding in verdict.all_findings:
                if id(finding) in l1_ids:
                    layer_label = "L1"
                elif id(finding) in l3_ids:
                    layer_label = "L3"
                else:
                    layer_label = "L2"
                evidence = finding.evidence[0] if finding.evidence else None
                if evidence is None:
                    evidence_text = "-"
                elif evidence.file_path and evidence.line_number:
                    evidence_text = f"{Path(evidence.file_path).name}:{evidence.line_number}"
                elif evidence.field_name:
                    evidence_text = evidence.field_name
                else:
                    evidence_text = (evidence.snippet or "-")[:60]
                table.add_row(
                    layer_label,
                    finding.rule_id,
                    finding.severity.value,
                    finding.attack_vector.value,
                    evidence_text,
                )
            console.print(table)
        else:
            console.print("No findings.")

    if verdict.verdict == "BLOCK":
        raise SystemExit(2)
