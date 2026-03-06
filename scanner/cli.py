from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.tree import Tree

from scanner.aggregator import fuse_layer1, fuse_layers, fuse_layers_l3
from scanner.layer1_static.parser import parse_target
from scanner.layer1_static.rule_engine import Layer1RuleEngine

# ── Severity colour map ──────────────────────────────────────────────────────
_SEV_COLOR: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}


def _severity_color(sev: str) -> str:
    return _SEV_COLOR.get(sev, "white")


def _verdict_style(verdict: str) -> str:
    if verdict == "BLOCK":
        return "bold red"
    if verdict == "WARN":
        return "bold yellow"
    return "bold green"


def _print_verdict_panel(console: Console, verdict) -> None:
    """Print a rich boxed panel summarising the scan verdict."""
    v = verdict.verdict
    if v == "BLOCK":
        border_style = "red"
        emoji = "⛔"
    elif v == "WARN":
        border_style = "yellow"
        emoji = "⚠"
    else:
        border_style = "green"
        emoji = "✅"

    layers_str = " + ".join(verdict.layers_executed)
    line1 = (
        f"[bold]{emoji}  {v}[/bold]   "
        f"{escape(verdict.skill_name)}  ({escape(verdict.framework)})"
    )
    line2 = (
        f"Risk: [bold]{verdict.fused_risk_score:.4f}[/bold]  "
        f"Confidence: {verdict.confidence:.2f}  "
        f"Layers: {layers_str}  "
        f"Scan: {verdict.total_scan_time_ms} ms"
    )
    console.print(Panel(f"{line1}\n{line2}", border_style=border_style, box=box.ROUNDED))


# ── HTML report builder ──────────────────────────────────────────────────────

_HTML_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: #f1f5f9; color: #1e293b; line-height: 1.6;
}
.container { max-width: 980px; margin: 0 auto; padding: 32px 24px; }
header {
  background: #0f172a; color: white; padding: 20px 28px; margin-bottom: 24px;
  border-radius: 10px; display: flex; justify-content: space-between; align-items: center;
}
header h1 { font-size: 1.2rem; font-weight: 700; }
header .meta { font-size: 0.8rem; color: #94a3b8; margin-top: 3px; }
.verdict-card {
  background: white; border-radius: 10px; padding: 22px 24px; margin-bottom: 20px;
  box-shadow: 0 1px 4px rgba(0,0,0,0.08); border-left: 6px solid var(--vc);
  display: flex; align-items: center; gap: 18px; flex-wrap: wrap;
}
.verdict-emoji { font-size: 2.6rem; line-height: 1; }
.verdict-label { font-size: 2rem; font-weight: 900; color: var(--vc); letter-spacing: 0.07em; }
.verdict-stats { display: flex; gap: 10px; flex-wrap: wrap; margin-left: auto; }
.stat-chip {
  background: #f1f5f9; border: 1px solid #e2e8f0; padding: 5px 14px;
  border-radius: 20px; font-size: 0.78rem; color: #475569;
}
.stat-chip .val { font-weight: 700; color: #1e293b; }
.score-row { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }
.score-chip {
  background: white; border: 1px solid #e2e8f0; border-radius: 8px;
  padding: 8px 16px; font-size: 0.8rem; box-shadow: 0 1px 2px rgba(0,0,0,0.05);
}
.score-chip .sc-label { color: #64748b; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em; }
.score-chip .sc-val { font-weight: 800; color: #1e293b; font-size: 0.95rem; }
.card {
  background: white; border-radius: 10px; padding: 22px 24px; margin-bottom: 20px;
  box-shadow: 0 1px 4px rgba(0,0,0,0.08);
}
.card-title {
  font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.12em;
  color: #94a3b8; padding-bottom: 12px; border-bottom: 1px solid #f1f5f9; margin-bottom: 16px;
}
table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
th {
  text-align: left; padding: 9px 12px; background: #f8fafc; color: #64748b;
  font-weight: 600; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.07em;
  border-bottom: 2px solid #e2e8f0;
}
td { padding: 11px 12px; border-bottom: 1px solid #f8fafc; vertical-align: top; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #fafbfc; }
.badge {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 0.7rem; font-weight: 700; letter-spacing: 0.05em; white-space: nowrap;
}
.layer-tag {
  display: inline-block; padding: 2px 7px; border-radius: 4px;
  font-size: 0.7rem; font-weight: 700; background: #e2e8f0; color: #475569;
}
.conf-wrap { display: flex; align-items: center; gap: 7px; }
.conf-bar { width: 44px; height: 6px; background: #e2e8f0; border-radius: 3px; overflow: hidden; }
.conf-fill { height: 100%; border-radius: 3px; }
.finding-card {
  border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px 18px;
  margin-bottom: 14px; border-left-width: 4px;
}
.finding-card-title { font-size: 0.87rem; font-weight: 700; margin-bottom: 14px; }
.finding-section { margin-bottom: 12px; }
.finding-section:last-child { margin-bottom: 0; }
.fsec-label {
  font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.12em;
  color: #94a3b8; margin-bottom: 4px;
}
.fsec-content { font-size: 0.855rem; color: #334155; }
pre.snippet {
  background: #1e293b; color: #e2e8f0; padding: 12px 16px; border-radius: 6px;
  font-size: 0.77rem; overflow-x: auto; margin-top: 8px; white-space: pre-wrap;
  word-break: break-all;
  font-family: 'JetBrains Mono', 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
}
.ev-quote {
  background: #f8fafc; border-left: 3px solid #cbd5e1; padding: 9px 13px;
  border-radius: 0 6px 6px 0; font-size: 0.84rem; color: #475569;
  font-style: italic; margin-top: 6px; word-break: break-word;
}
.l2-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 16px; }
.l2-item .l2-label { font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: #94a3b8; margin-bottom: 3px; }
.l2-item .l2-val { font-size: 0.9rem; font-weight: 600; color: #1e293b; }
.l2-quote {
  background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px;
  padding: 14px 18px; font-style: italic; color: #334155; font-size: 0.87rem;
  margin-top: 12px; line-height: 1.7;
}
.field-row { display: flex; align-items: center; gap: 10px; padding: 5px 0; }
.field-name { width: 220px; font-family: monospace; font-size: 0.77rem; color: #475569; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.field-bar-wrap { flex: 1; background: #f1f5f9; border-radius: 3px; height: 8px; overflow: hidden; }
.field-bar-fill { height: 100%; border-radius: 3px; background: #ef4444; }
.field-score-val { width: 36px; text-align: right; font-weight: 700; font-size: 0.78rem; color: #ef4444; }
.perm-group { margin-bottom: 14px; }
.perm-group-title { font-size: 0.8rem; font-weight: 700; margin-bottom: 8px; }
.perm-chip {
  display: inline-block; padding: 3px 10px; border-radius: 4px;
  font-size: 0.77rem; margin: 3px; font-family: monospace;
}
.rem-list { list-style: none; }
.rem-list li {
  padding: 10px 0 10px 28px; border-bottom: 1px solid #f8fafc;
  font-size: 0.875rem; color: #334155; position: relative;
}
.rem-list li:last-child { border-bottom: none; }
.rem-list li::before { content: "→"; position: absolute; left: 4px; color: #94a3b8; font-weight: 700; }
footer { text-align: center; color: #94a3b8; font-size: 0.76rem; padding: 24px; }
@media (max-width: 640px) {
  .l2-grid { grid-template-columns: 1fr; }
  .verdict-stats { justify-content: flex-start; }
  .field-name { width: 130px; }
}
"""

# Severity → (badge inline style, border hex color)
_HTML_SEV = {
    "CRITICAL": ("background:#fef2f2;color:#dc2626;border:1px solid #fecaca", "#dc2626"),
    "HIGH":     ("background:#fff7ed;color:#ea580c;border:1px solid #fed7aa", "#ea580c"),
    "MEDIUM":   ("background:#fefce8;color:#ca8a04;border:1px solid #fef08a", "#ca8a04"),
    "LOW":      ("background:#eff6ff;color:#2563eb;border:1px solid #bfdbfe", "#2563eb"),
    "INFO":     ("background:#f8fafc;color:#6b7280;border:1px solid #e2e8f0", "#6b7280"),
}
_HTML_VERDICT_COLOR = {"BLOCK": "#dc2626", "WARN": "#d97706", "SAFE": "#16a34a"}


def _build_html_report(verdict, l2_report, l3_report, manifest, l1_report) -> str:
    """Return a self-contained styled HTML security report."""
    from html import escape as h

    v = verdict.verdict
    vc = _HTML_VERDICT_COLOR.get(v, "#6b7280")
    emoji = {"BLOCK": "⛔", "WARN": "⚠️", "SAFE": "✅"}.get(v, "")
    layers_str = " + ".join(verdict.layers_executed)
    scanned_at = verdict.scanned_at.strftime("%Y-%m-%d %H:%M:%S UTC")

    l1_ids = {id(m) for m in l1_report.matches}
    l3_ids = {id(m) for m in l3_report.matches} if l3_report is not None else set()

    def _layer(finding: object) -> str:
        if id(finding) in l1_ids:
            return "L1"
        if id(finding) in l3_ids:
            return "L3"
        return "L2"

    def _badge(sev: str) -> str:
        style, _ = _HTML_SEV.get(sev, _HTML_SEV["INFO"])
        return f'<span class="badge" style="{style}">{h(sev)}</span>'

    def _sev_border(sev: str) -> str:
        return _HTML_SEV.get(sev, _HTML_SEV["INFO"])[1]

    def _conf_html(conf: float, sev: str) -> str:
        color = _HTML_SEV.get(sev, _HTML_SEV["INFO"])[1]
        pct = int(conf * 100)
        return (
            f'<div class="conf-wrap">'
            f'<div class="conf-bar"><div class="conf-fill" style="width:{pct}%;background:{color}"></div></div>'
            f'<span style="font-size:0.78rem;font-weight:700;color:{color}">{pct}%</span>'
            f'</div>'
        )

    # ── Header ────────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Scan Report — {h(verdict.skill_name)}</title>
<style>:root{{--vc:{vc}}}{_HTML_CSS}</style>
</head>
<body>
<div class="container">
<header>
  <div>
    <h1>🛡️ Agentic Scanner — Security Report</h1>
    <div class="meta">{h(verdict.skill_name)} &nbsp;·&nbsp; {h(verdict.framework)} &nbsp;·&nbsp; {scanned_at}</div>
  </div>
  <div style="font-size:2rem">🔍</div>
</header>
"""

    # ── Verdict card ──────────────────────────────────────────────────────────
    html += f"""
<div class="verdict-card">
  <div class="verdict-emoji">{emoji}</div>
  <div class="verdict-label">{h(v)}</div>
  <div class="verdict-stats">
    <div class="stat-chip">Risk &nbsp;<span class="val">{verdict.fused_risk_score:.4f}</span></div>
    <div class="stat-chip">Confidence &nbsp;<span class="val">{verdict.confidence:.0%}</span></div>
    <div class="stat-chip">Layers &nbsp;<span class="val">{h(layers_str)}</span></div>
    <div class="stat-chip">Findings &nbsp;<span class="val">{len(verdict.all_findings)}</span></div>
    <div class="stat-chip">Scan &nbsp;<span class="val">{verdict.total_scan_time_ms} ms</span></div>
  </div>
</div>
"""

    # ── Per-layer score breakdown ─────────────────────────────────────────────
    def _score_bar(score: float, color: str = "#3b82f6") -> str:
        pct = int(score * 100)
        # colour shifts red as score rises
        if score >= 0.75:
            color = "#dc2626"
        elif score >= 0.35:
            color = "#d97706"
        else:
            color = "#16a34a"
        return (
            f'<div style="display:flex;align-items:center;gap:10px">'
            f'<div style="flex:1;background:#f1f5f9;border-radius:4px;height:10px;overflow:hidden">'
            f'<div style="width:{pct}%;height:100%;background:{color};border-radius:4px"></div>'
            f'</div>'
            f'<span style="width:46px;text-align:right;font-weight:800;font-size:0.85rem;color:{color}">{score:.4f}</span>'
            f'</div>'
        )

    html += '<div class="card">\n<div class="card-title">Layer Score Analysis</div>\n'
    html += (
        f'<div style="font-size:0.8rem;color:#64748b;margin-bottom:18px">'
        f'Fused risk score <strong style="color:#1e293b">{verdict.fused_risk_score:.4f}</strong>'
        f' is the weighted average of all executed layer scores. '
        f'<strong>BLOCK</strong> ≥ 0.75 &nbsp;·&nbsp; <strong>WARN</strong> ≥ 0.35'
        f'</div>'
    )

    # L1 row
    html += (
        f'<div style="margin-bottom:18px">'
        f'<div style="display:flex;justify-content:space-between;margin-bottom:6px">'
        f'<span style="font-weight:700;font-size:0.85rem">Layer 1 &mdash; Static Analysis</span>'
        f'<span style="font-size:0.75rem;color:#64748b">'
        f'{len(l1_report.matches)} rule match(es) &nbsp;·&nbsp; '
        f'unicode={l1_report.invisible_unicode_detected} &nbsp;·&nbsp; '
        f'subprocess={l1_report.subprocess_in_tool_body} &nbsp;·&nbsp; '
        f'undecl_net={l1_report.undeclared_network_access}'
        f'</span></div>'
        f'{_score_bar(verdict.l1_score)}'
        f'</div>'
    )

    # L2 row
    if l2_report is not None and verdict.l2_score is not None:
        if l2_report.local_model_used and l2_report.local_model_escalated:
            l2_mode_label = "Local LoRA pre-filter → escalated to Claude Haiku"
            local_v = f"<strong>{h(l2_report.local_model_verdict or 'N/A')}</strong>"
            local_c = f"{l2_report.local_model_confidence:.0%}" if l2_report.local_model_confidence is not None else "N/A"
            l2_llm_detail = (
                f"Local LLM verdict: {local_v} ({local_c}) "
                f"→ Haiku made final call ({l2_report.llm_tokens_used:,} tokens)"
            )
        elif l2_report.local_model_used:
            l2_mode_label = "Local LoRA pre-filter only (confident — Haiku not called)"
            l2_llm_detail = (
                f"Local LLM verdict: <strong>{h(l2_report.llm_judge_verdict or 'N/A')}</strong> "
                f"· confidence {l2_report.llm_judge_confidence:.0%} "
                f"· tokens saved (no API call)"
            )
        else:
            l2_mode_label = "Claude Haiku only"
            l2_llm_detail = (
                f"LLM verdict: <strong>{h(l2_report.llm_judge_verdict or 'N/A')}</strong> "
                f"· confidence {l2_report.llm_judge_confidence:.0%} "
                f"· {l2_report.llm_tokens_used:,} tokens"
            )
        html += (
            f'<div style="margin-bottom:18px">'
            f'<div style="display:flex;justify-content:space-between;margin-bottom:6px">'
            f'<span style="font-weight:700;font-size:0.85rem">Layer 2 &mdash; Semantic / LLM Judge</span>'
            f'<span style="font-size:0.75rem;color:#64748b">{l2_mode_label}</span>'
            f'</div>'
            f'{_score_bar(verdict.l2_score)}'
            f'<div style="font-size:0.78rem;color:#475569;margin-top:6px;padding-left:4px">{l2_llm_detail}</div>'
            f'</div>'
        )

    # L3 row
    if l3_report is not None and verdict.l3_score is not None:
        l3_flags = []
        if l3_report.execve_detected:            l3_flags.append("execve ✗")
        if l3_report.undeclared_network_egress:  l3_flags.append("net_egress ✗")
        if l3_report.ptrace_attempted:           l3_flags.append("ptrace ✗")
        if l3_report.rwx_mmap_detected:          l3_flags.append("rwx_mmap ✗")
        if l3_report.high_entropy_output:        l3_flags.append("high_entropy ✗")
        if l3_report.filesystem_write_outside_scope: l3_flags.append("fs_write_scope ✗")
        flags_html = " &nbsp;·&nbsp; ".join(
            f'<span style="color:#dc2626;font-weight:700">{f}</span>' for f in l3_flags
        ) if l3_flags else '<span style="color:#16a34a">no critical flags</span>'
        html += (
            f'<div style="margin-bottom:18px">'
            f'<div style="display:flex;justify-content:space-between;margin-bottom:6px">'
            f'<span style="font-weight:700;font-size:0.85rem">Layer 3 &mdash; Dynamic Sandbox</span>'
            f'<span style="font-size:0.75rem;color:#64748b">'
            f'{len(l3_report.matches)} rule match(es) &nbsp;·&nbsp; '
            f'entropy={l3_report.trace.output_entropy:.2f}'
            f'</span></div>'
            f'{_score_bar(verdict.l3_score)}'
            f'<div style="font-size:0.78rem;color:#475569;margin-top:6px;padding-left:4px">{flags_html}</div>'
            f'</div>'
        )

    html += '</div>\n'

    # ── Findings table ────────────────────────────────────────────────────────
    if verdict.all_findings:
        html += f"""
<div class="card">
  <div class="card-title">Findings ({len(verdict.all_findings)})</div>
  <table>
    <thead>
      <tr>
        <th>Layer</th><th>Rule ID</th><th>Severity</th><th>Vector</th>
        <th>Confidence</th><th>Rationale</th>
      </tr>
    </thead>
    <tbody>
"""
        for finding in verdict.all_findings:
            sev = finding.severity.value
            rationale_short = (finding.rationale or "")[:90]
            if len(finding.rationale or "") > 90:
                rationale_short += "…"
            html += f"""      <tr>
        <td><span class="layer-tag">{_layer(finding)}</span></td>
        <td style="font-family:monospace;font-size:0.8rem;font-weight:600">{h(finding.rule_id)}</td>
        <td>{_badge(sev)}</td>
        <td style="font-size:0.78rem;color:#64748b">{h(finding.attack_vector.value)}</td>
        <td>{_conf_html(finding.confidence, sev)}</td>
        <td style="font-size:0.82rem;color:#334155">{h(rationale_short)}</td>
      </tr>
"""
        html += "    </tbody>\n  </table>\n</div>\n"
    else:
        html += '<div class="card"><p style="color:#64748b;font-style:italic">No findings detected.</p></div>\n'

    # ── Reasoning Breakdown ───────────────────────────────────────────────────
    if verdict.verdict != "SAFE" and verdict.all_findings:
        findings_to_show = list(verdict.all_findings)
        if len(findings_to_show) > 5:
            filtered = [f for f in findings_to_show if f.severity.value != "INFO"]
            if filtered:
                findings_to_show = filtered
        shown = findings_to_show[:6]
        remaining = len(findings_to_show) - len(shown)

        html += '<div class="card">\n<div class="card-title">Reasoning Breakdown</div>\n'
        for finding in shown:
            sev = finding.severity.value
            border_color = _sev_border(sev)
            ev = finding.evidence[0] if finding.evidence else None

            if ev is None:
                ev_loc = ""
                ev_snippet = ""
            elif ev.file_path and ev.line_number:
                ev_loc = f"{Path(ev.file_path).name} (line {ev.line_number})"
                ev_snippet = ev.snippet or ""
            elif ev.field_name:
                ev_loc = ev.field_name
                ev_snippet = ev.snippet or ""
            else:
                ev_loc = ""
                ev_snippet = (ev.snippet or "")[:300]

            is_py = ev is not None and (ev.file_path or "").endswith(".py") and ev_snippet

            html += f"""<div class="finding-card" style="border-left-color:{border_color}">
  <div class="finding-card-title">
    {_badge(sev)} &nbsp;
    <span style="font-family:monospace">{h(finding.rule_id)}</span>
    &nbsp;<span style="color:#94a3b8">·</span>&nbsp;
    {h(finding.rule_name)}
  </div>
  <div class="finding-section">
    <div class="fsec-label">Rationale</div>
    <div class="fsec-content">{h(finding.rationale)}</div>
  </div>
"""
            if ev_loc or ev_snippet:
                html += '  <div class="finding-section">\n    <div class="fsec-label">Evidence</div>\n'
                if ev_loc:
                    html += f'    <div class="fsec-content" style="font-family:monospace;font-size:0.8rem;color:#64748b;margin-bottom:6px">{h(ev_loc)}</div>\n'
                if ev_snippet:
                    lang = "python" if is_py else "text"
                    html += f'    <pre class="snippet" data-lang="{lang}">{h(ev_snippet[:400])}</pre>\n'
                html += '  </div>\n'

            html += f"""  <div class="finding-section">
    <div class="fsec-label">Remediation</div>
    <div class="fsec-content">{h(finding.remediation)}</div>
  </div>
</div>
"""
        if remaining > 0:
            html += (
                f'<p style="font-size:0.8rem;color:#94a3b8;margin-top:8px">'
                f'… and {remaining} more findings (export with --json-output for full list)</p>\n'
            )
        html += "</div>\n"

    # ── L2 Semantic Analysis ──────────────────────────────────────────────────
    if l2_report is not None and l2_report.llm_judge_evidence_summary:
        l2_v = l2_report.llm_judge_verdict or "N/A"
        l2_conf = l2_report.llm_judge_confidence
        l2_conf_str = f"{l2_conf:.0%}" if l2_conf is not None else "—"
        l2_v_color = {"MALICIOUS": "#dc2626", "SUSPICIOUS": "#d97706", "BENIGN": "#16a34a"}.get(l2_v, "#6b7280")

        if l2_report.local_model_used and l2_report.local_model_escalated:
            l2_mode = "Local → escalated to Haiku"
        elif l2_report.local_model_used:
            l2_mode = "Local (confident, no escalation)"
        else:
            l2_mode = "Claude Haiku"

        attacks = ", ".join(l2_report.llm_judge_attack_types) if l2_report.llm_judge_attack_types else "—"
        tokens = l2_report.llm_tokens_used

        html += f"""
<div class="card">
  <div class="card-title">L2 Semantic Analysis (LLM Judge)</div>
  <div class="l2-grid">
    <div class="l2-item">
      <div class="l2-label">LLM Verdict</div>
      <div class="l2-val" style="color:{l2_v_color}">{h(l2_v)} &nbsp;
        <span style="font-weight:400;font-size:0.82rem;color:#64748b">({l2_conf_str} confidence)</span>
      </div>
    </div>
    <div class="l2-item">
      <div class="l2-label">Inference Mode</div>
      <div class="l2-val">{h(l2_mode)}</div>
    </div>
    <div class="l2-item">
      <div class="l2-label">Attack Types</div>
      <div class="l2-val" style="font-size:0.82rem">{h(attacks)}</div>
    </div>
    <div class="l2-item">
      <div class="l2-label">Tokens Consumed</div>
      <div class="l2-val">{tokens:,}</div>
    </div>
  </div>
  <div class="l2-quote">"{h(l2_report.llm_judge_evidence_summary)}"</div>
"""
        if l2_report.field_risk_scores:
            top_fields = sorted(
                l2_report.field_risk_scores.items(), key=lambda kv: kv[1], reverse=True
            )[:5]
            html += '<div style="margin-top:18px"><div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:#94a3b8;margin-bottom:10px">Field Risk Scores</div>'
            for fname, fscore in top_fields:
                bar_pct = int(fscore * 100)
                html += f"""<div class="field-row">
  <div class="field-name" title="{h(fname)}">{h(fname)}</div>
  <div class="field-bar-wrap"><div class="field-bar-fill" style="width:{bar_pct}%"></div></div>
  <div class="field-score-val">{fscore:.2f}</div>
</div>
"""
            html += "</div>\n"
        html += "</div>\n"

    # ── Permission Delta ──────────────────────────────────────────────────────
    perm_delta = manifest.permission_delta
    under = perm_delta.get("under_declared", [])
    over = perm_delta.get("over_declared", [])
    if under or over:
        html += '<div class="card">\n<div class="card-title">Permission Analysis</div>\n'
        if under:
            html += '<div class="perm-group"><div class="perm-group-title" style="color:#dc2626">⚠ Under-declared — used in code, not listed in manifest</div>'
            for p in under:
                html += f'<span class="perm-chip" style="background:#fef2f2;color:#dc2626;border:1px solid #fecaca">{h(str(p))}</span>'
            html += "</div>\n"
        if over:
            html += '<div class="perm-group"><div class="perm-group-title" style="color:#d97706">ℹ Over-declared — listed in manifest, not found in code</div>'
            for p in over:
                html += f'<span class="perm-chip" style="background:#fffbeb;color:#d97706;border:1px solid #fde68a">{h(str(p))}</span>'
            html += "</div>\n"
        html += "</div>\n"

    # ── Remediation Steps ─────────────────────────────────────────────────────
    if verdict.remediation_steps:
        html += '<div class="card">\n<div class="card-title">Remediation Steps</div>\n<ul class="rem-list">\n'
        for step in verdict.remediation_steps[:8]:
            html += f'<li>{h(step)}</li>\n'
        if len(verdict.remediation_steps) > 8:
            html += f'<li style="color:#94a3b8;font-style:italic">… and {len(verdict.remediation_steps) - 8} more</li>\n'
        html += "</ul>\n</div>\n"

    # ── Footer ────────────────────────────────────────────────────────────────
    html += f"""
<footer>
  Generated by <strong>agentic-scanner</strong> &nbsp;·&nbsp;
  Scan ID: <code>{verdict.scan_id}</code> &nbsp;·&nbsp; {scanned_at}
</footer>
</div>
</body>
</html>"""

    return html


# ── CLI scaffolding ──────────────────────────────────────────────────────────

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
@click.option(
    "--html-report",
    type=click.Path(path_type=Path),
    default=None,
    help="Write self-contained HTML report to the given file path.",
)
@click.option(
    "--pool-size",
    type=int,
    default=0,
    help="Pre-warm N containers for Layer 3 scanning (requires --dynamic). Default 0 = off.",
)
@click.option(
    "--local-model",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help=(
        "Path to finetuned LoRA adapter directory for Layer 2 pre-filtering "
        "(requires --semantic). The local model runs first and escalates to Haiku "
        "only when confidence < --escalation-threshold."
    ),
)
@click.option(
    "--escalation-threshold",
    type=float,
    default=0.80,
    show_default=True,
    help=(
        "Confidence threshold below which the local model escalates to Haiku "
        "(requires --local-model). Default: 0.80."
    ),
)
@click.option(
    "--l3-local-gate",
    is_flag=True,
    default=False,
    help=(
        "When --local-model is set, skip the Layer 3 AgentSimulator for README-only files "
        "if the local model is confident BENIGN. Reduces API calls on benign-majority corpora. "
        "Default OFF (AgentSimulator always runs)."
    ),
)
@click.option(
    "--slm-model",
    type=click.Path(path_type=Path),
    default=None,
    help=(
        "Path to the from-scratch 350M RoPE SLM directory for Layer 2 pre-filtering "
        "(requires --semantic). Uses zero external pretrained weights — supply-chain safe. "
        "Escalates to Haiku when confidence < --escalation-threshold. "
        "Takes priority over --local-model when both are specified."
    ),
)
@click.option(
    "--high-security",
    is_flag=True,
    default=False,
    help="Force LLM analysis (Layer 2) to escalate to Haiku regardless of the local model's confidence. Always runs full security checks.",
)
def scan_command(
    target: str,
    source_files: tuple[Path, ...],
    source_directory: Path | None,
    semantic: bool,
    dynamic: bool,
    json_output: bool,
    sarif_out: Path | None,
    html_report: Path | None,
    pool_size: int,
    local_model: Path | None,
    escalation_threshold: float,
    l3_local_gate: bool,
    slm_model: Path | None,
    high_security: bool,
) -> None:
    console = Console(record=True)
    started = time.perf_counter()

    if high_security:
        semantic = True
        dynamic = True

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
            if not os.environ.get("ANTHROPIC_API_KEY") and local_model is None and slm_model is None:
                console.print(
                    "[bold yellow]Warning:[/bold yellow] --semantic requires ANTHROPIC_API_KEY, "
                    "--local-model, or --slm-model to be set. Skipping Layer 2."
                )
            else:
                if local_model is not None and not local_model.exists():
                    console.print(
                        f"[bold yellow]Warning:[/bold yellow] --local-model path does not exist: "
                        f"{local_model}. Ignoring local model."
                    )
                    local_model = None
                if slm_model is not None and not slm_model.exists():
                    console.print(
                        f"[bold yellow]Warning:[/bold yellow] --slm-model path does not exist: "
                        f"{slm_model}. Ignoring SLM model."
                    )
                    slm_model = None
                from scanner.layer2_semantic import Layer2Analyzer
                applied_threshold = 1.01 if high_security else escalation_threshold
                analyzer = Layer2Analyzer(
                    local_model_path=local_model,
                    escalation_threshold=applied_threshold,
                    slm_model_path=slm_model,
                )
                l2_report = analyzer.analyze(manifest, l1_report)

        l3_report = None
        if dynamic:
            import docker as _docker
            _docker_available = False
            try:
                _docker.from_env().ping()
                _docker_available = True
            except Exception:
                if sys.platform == "darwin":
                    console.print("[dim]Docker not running — launching Docker Desktop…[/dim]")
                    subprocess.Popen(["open", "-a", "Docker"])
                    for _attempt in range(10):          # up to ~30 s
                        time.sleep(3)
                        try:
                            _docker.from_env().ping()
                            _docker_available = True
                            console.print("[dim]Docker Desktop ready.[/dim]")
                            break
                        except Exception:
                            pass
            if not _docker_available:
                console.print(
                    "[bold yellow]Warning:[/bold yellow] --dynamic requires a running Docker "
                    "daemon. Skipping Layer 3."
                )
            if _docker_available:
                from scanner.layer3_dynamic import Layer3DynamicAnalyzer
                _local_judge_for_l3 = None
                if l3_local_gate:
                    if local_model is None:
                        console.print(
                            "[bold yellow]Warning:[/bold yellow] --l3-local-gate has no effect "
                            "without --local-model. AgentSimulator will always run."
                        )
                    else:
                        from scanner.layer2_semantic.local_judge import LocalLLMJudge
                        _local_judge_for_l3 = LocalLLMJudge(
                            local_model, escalation_threshold
                        )
                analyzer3 = Layer3DynamicAnalyzer(
                    pool_size=pool_size,
                    local_judge=_local_judge_for_l3,
                )
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
        # ── 1. Verdict panel ──────────────────────────────────────────────────
        _print_verdict_panel(console, verdict)

        # ── 2. Per-layer score breakdown (when multiple layers ran) ───────────
        if l2_report is not None or l3_report is not None:
            parts = [f"L1: {verdict.l1_score:.4f}"]
            if l2_report is not None and verdict.l2_score is not None:
                parts.append(f"L2: {verdict.l2_score:.4f}")
            if l3_report is not None and verdict.l3_score is not None:
                parts.append(f"L3: {verdict.l3_score:.4f}")
            console.print("[dim]  " + "  |  ".join(parts) + "[/dim]")

        if l3_report is not None:
            console.print(
                f"[dim]  L3: execve={l3_report.execve_detected} | "
                f"net_egress={l3_report.undeclared_network_egress} | "
                f"entropy={l3_report.trace.output_entropy:.2f}[/dim]"
            )

        # ── 3. Enhanced findings table ─────────────────────────────────────────
        if verdict.all_findings:
            table = Table(show_header=True, header_style="bold", box=box.SIMPLE_HEAD)
            table.add_column("Layer", style="dim", width=5)
            table.add_column("Rule", no_wrap=True)
            table.add_column("Sev", no_wrap=True)
            table.add_column("Vector", no_wrap=True)
            table.add_column("Confidence", justify="right", no_wrap=True)
            table.add_column("Rationale")

            l1_ids = {id(m) for m in l1_report.matches}
            l3_ids = {id(m) for m in l3_report.matches} if l3_report is not None else set()

            for finding in verdict.all_findings:
                if id(finding) in l1_ids:
                    layer_label = "L1"
                elif id(finding) in l3_ids:
                    layer_label = "L3"
                else:
                    layer_label = "L2"

                sev_str = finding.severity.value
                sev_color = _severity_color(sev_str)
                conf_pct = int(finding.confidence * 100)
                conf_str = f"[{sev_color}]{conf_pct}%[/{sev_color}]"
                rationale_short = (finding.rationale or "")[:70]
                if len(finding.rationale or "") > 70:
                    rationale_short += "…"

                table.add_row(
                    layer_label,
                    finding.rule_id,
                    f"[{sev_color}]{sev_str}[/{sev_color}]",
                    finding.attack_vector.value,
                    conf_str,
                    rationale_short,
                )
            console.print(table)
        else:
            console.print("No findings.")

        # ── 4. Reasoning Breakdown ─────────────────────────────────────────────
        if verdict.verdict != "SAFE" and verdict.all_findings:
            console.rule("Reasoning Breakdown", style="dim")

            findings_to_show = list(verdict.all_findings)
            # Drop INFO-severity findings when there are many to avoid noise
            if len(findings_to_show) > 5:
                filtered = [f for f in findings_to_show if f.severity.value != "INFO"]
                if filtered:
                    findings_to_show = filtered

            shown = findings_to_show[:6]
            remaining = len(findings_to_show) - len(shown)

            l1_ids = {id(m) for m in l1_report.matches}
            l3_ids = {id(m) for m in l3_report.matches} if l3_report is not None else set()

            for finding in shown:
                sev_str = finding.severity.value
                sev_color = _severity_color(sev_str)
                title = (
                    f"[{sev_color}]"
                    f"[{sev_str}] {finding.rule_id} · {escape(finding.rule_name)}"
                    f"[/{sev_color}]"
                )

                # Evidence
                evidence = finding.evidence[0] if finding.evidence else None
                is_py_snippet = (
                    evidence is not None
                    and evidence.file_path is not None
                    and evidence.file_path.endswith(".py")
                    and bool(evidence.snippet)
                )

                if evidence is None:
                    ev_loc = "-"
                    ev_snippet_text = ""
                elif evidence.file_path and evidence.line_number:
                    ev_loc = f"{Path(evidence.file_path).name}  (line {evidence.line_number})"
                    ev_snippet_text = evidence.snippet or ""
                elif evidence.field_name:
                    ev_loc = evidence.field_name
                    ev_snippet_text = evidence.snippet or ""
                else:
                    ev_loc = "-"
                    ev_snippet_text = (evidence.snippet or "")[:200]

                # For non-Python evidence, embed a quoted snippet in the panel body
                inline_snippet = ""
                if ev_snippet_text and not is_py_snippet:
                    inline_snippet = f"\n  > {escape(ev_snippet_text[:200])}"

                body = (
                    f"[bold]Rationale:[/bold]\n"
                    f"  {escape(finding.rationale)}\n\n"
                    f"[bold]Evidence:[/bold]  {escape(ev_loc)}{inline_snippet}\n\n"
                    f"[bold]Remediation:[/bold]\n"
                    f"  {escape(finding.remediation)}"
                )
                console.print(
                    Panel(body, title=title, border_style=sev_color, box=box.ROUNDED)
                )

                # Python snippets are printed separately to avoid layout constraints
                if is_py_snippet:
                    start_line = evidence.line_number or 1  # type: ignore[union-attr]
                    console.print(
                        Syntax(
                            evidence.snippet,  # type: ignore[arg-type]
                            "python",
                            line_numbers=True,
                            start_line=start_line,
                            theme="monokai",
                        )
                    )

            if remaining > 0:
                console.print(
                    f"[dim]… and {remaining} more findings "
                    f"(use --json-output for full list)[/dim]"
                )

        # ── 5. L2 Semantic Reasoning panel ────────────────────────────────────
        if l2_report is not None and l2_report.llm_judge_evidence_summary:
            l2_v = l2_report.llm_judge_verdict or "N/A"
            l2_conf = l2_report.llm_judge_confidence
            l2_conf_str = f"{l2_conf:.2f}" if l2_conf is not None else "—"

            if l2_v == "MALICIOUS":
                l2_border = "red"
            elif l2_v == "SUSPICIOUS":
                l2_border = "yellow"
            else:
                l2_border = "green"

            if l2_report.local_model_used and l2_report.local_model_escalated:
                l2_mode = "local (escalated to Haiku)"
            elif l2_report.local_model_used:
                l2_mode = "local (confident)"
            else:
                l2_mode = "Haiku only"

            attacks = (
                ", ".join(l2_report.llm_judge_attack_types)
                if l2_report.llm_judge_attack_types
                else "—"
            )

            body_lines = [
                f"[bold]Verdict:[/bold]  {l2_v} (confidence {l2_conf_str})",
                f"[bold]Mode:[/bold]     {l2_mode}",
                f"[bold]Attack:[/bold]   {escape(attacks)}",
                "",
                f'  "[italic]{escape(l2_report.llm_judge_evidence_summary)}[/italic]"',
            ]

            # Top 3 field risk scores as a quick inline table
            if l2_report.field_risk_scores:
                top_fields = sorted(
                    l2_report.field_risk_scores.items(),
                    key=lambda kv: kv[1],
                    reverse=True,
                )[:3]
                body_lines.append("")
                body_lines.append("[bold]Field Risk Scores (top 3):[/bold]")
                for field_name, score in top_fields:
                    bar = "█" * max(1, int(score * 10))
                    body_lines.append(
                        f"  {escape(field_name):<20s}  {score:.2f}  [dim]{bar}[/dim]"
                    )

            console.print(
                Panel(
                    "\n".join(body_lines),
                    title="L2 Semantic Analysis",
                    border_style=l2_border,
                    box=box.ROUNDED,
                )
            )

        # ── 6. Permission Delta tree ───────────────────────────────────────────
        perm_delta = manifest.permission_delta
        under_declared = perm_delta.get("under_declared", [])
        over_declared = perm_delta.get("over_declared", [])
        if under_declared or over_declared:
            tree = Tree("[bold]Permission Analysis[/bold]")
            if under_declared:
                branch = tree.add(
                    "[red]Under-declared[/red] (used in code, not listed in manifest)"
                )
                for perm in under_declared:
                    branch.add(f"[red]{perm}[/red]")
            if over_declared:
                branch = tree.add(
                    "[yellow]Over-declared[/yellow] (listed in manifest, not found in code)"
                )
                for perm in over_declared:
                    branch.add(f"[yellow]{perm}[/yellow]")
            console.print(tree)

        # ── 7. Remediation Steps footer ────────────────────────────────────────
        if verdict.remediation_steps:
            steps = verdict.remediation_steps[:5]
            body = "\n".join(f"  • {escape(step)}" for step in steps)
            if len(verdict.remediation_steps) > 5:
                body += f"\n  [dim]… and {len(verdict.remediation_steps) - 5} more[/dim]"
            console.print(
                Panel(body, title="Remediation Steps", border_style="blue", box=box.ROUNDED)
            )

    if html_report is not None:
        html_report.parent.mkdir(parents=True, exist_ok=True)
        html_report.write_text(
            _build_html_report(verdict, l2_report, l3_report, manifest, l1_report),
            encoding="utf-8",
        )
        console.print(f"HTML report written to: [cyan]{html_report}[/cyan]")

    if verdict.verdict == "BLOCK":
        raise SystemExit(2)
