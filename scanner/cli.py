from __future__ import annotations

import json
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from scanner.aggregator import fuse_layer1
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
@click.argument("target", type=click.Path(exists=True, path_type=Path))
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
    target: Path,
    source_files: tuple[Path, ...],
    source_directory: Path | None,
    json_output: bool,
    sarif_out: Path | None,
) -> None:
    console = Console()
    started = time.perf_counter()

    try:
        manifest = parse_target(target)
        engine = Layer1RuleEngine()
        l1_report = engine.evaluate(
            manifest,
            source_files=[str(p.resolve()) for p in source_files] if source_files else None,
            source_directory=str(source_directory.resolve()) if source_directory else None,
        )
        verdict = fuse_layer1(manifest, l1_report)
        verdict.total_scan_time_ms = int((time.perf_counter() - started) * 1000)
    except Exception as exc:
        console.print(f"[bold red]Scan failed:[/bold red] {exc}")
        raise SystemExit(1) from exc

    if sarif_out is not None:
        sarif_out.parent.mkdir(parents=True, exist_ok=True)
        sarif_out.write_text(json.dumps(verdict.to_sarif(), indent=2), encoding="utf-8")

    if json_output:
        console.print(json.dumps(verdict.model_dump(mode="json"), indent=2))
    else:
        console.print(
            f"[{_verdict_style(verdict.verdict)}]{verdict.verdict}[/{_verdict_style(verdict.verdict)}] "
            f"{verdict.skill_name} ({verdict.framework})"
        )
        console.print(
            f"Risk score: {verdict.fused_risk_score:.4f} | Confidence: {verdict.confidence:.2f} | Findings: {len(verdict.all_findings)}"
        )

        if verdict.all_findings:
            table = Table(show_header=True, header_style="bold")
            table.add_column("Rule")
            table.add_column("Severity")
            table.add_column("Vector")
            table.add_column("Evidence")
            for finding in verdict.all_findings:
                evidence = finding.evidence[0] if finding.evidence else None
                if evidence is None:
                    evidence_text = "-"
                elif evidence.file_path and evidence.line_number:
                    evidence_text = f"{Path(evidence.file_path).name}:{evidence.line_number}"
                elif evidence.field_name:
                    evidence_text = evidence.field_name
                else:
                    evidence_text = evidence.snippet or "-"
                table.add_row(
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

