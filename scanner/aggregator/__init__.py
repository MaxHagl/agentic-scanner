from __future__ import annotations

from scanner.models import FinalVerdict, RiskReport_L1, Severity, SkillManifest
from scanner.models.risk_report import RiskReport_L2

_BLOCK_THRESHOLD = 0.75
_WARN_THRESHOLD  = 0.35


def _skill_name(manifest: SkillManifest, l1_name: str) -> str:
    return (
        manifest.mcp_server_name
        or str(manifest.raw_manifest_json.get("name", "")).strip()
        or l1_name
    )


def _verdict_from_score(score: float, critical_findings: list) -> str:
    if critical_findings or score >= _BLOCK_THRESHOLD:
        return "BLOCK"
    if score >= _WARN_THRESHOLD:
        return "WARN"
    return "SAFE"


def fuse_layer1(manifest: SkillManifest, report_l1: RiskReport_L1) -> FinalVerdict:
    """Produce a FinalVerdict from Layer 1 results only."""
    critical_findings = [m for m in report_l1.matches if m.severity == Severity.CRITICAL]
    verdict = _verdict_from_score(report_l1.composite_score, critical_findings)
    confidence = min(1.0, max(0.55, 0.55 + report_l1.composite_score * 0.4))
    hard_block_reasons = [f"{m.rule_id}: {m.rule_name}" for m in critical_findings]
    remediation_steps = list(dict.fromkeys(m.remediation for m in report_l1.matches if m.remediation))

    return FinalVerdict(
        skill_name=_skill_name(manifest, report_l1.skill_name),
        framework=manifest.framework.value,
        verdict=verdict,
        fused_risk_score=report_l1.composite_score,
        confidence=confidence,
        l1_score=report_l1.composite_score,
        all_findings=report_l1.matches,
        hard_block_reasons=hard_block_reasons,
        remediation_steps=remediation_steps[:10],
        layers_executed=["L1"],
    )


def fuse_layers(
    manifest: SkillManifest,
    report_l1: RiskReport_L1,
    report_l2: RiskReport_L2,
) -> FinalVerdict:
    """
    Produce a FinalVerdict by fusing Layer 1 and Layer 2 results.

    Score fusion: fused = (l1_score + l2_score) / 2
    Verdict thresholds are the same as L1-only: BLOCK ≥ 0.75, WARN ≥ 0.35.
    CRITICAL findings from either layer always trigger BLOCK regardless of score.
    """
    fused_score = round((report_l1.composite_score + report_l2.composite_score) / 2, 4)

    all_findings = report_l1.matches + report_l2.injection_matches
    critical_findings = [m for m in all_findings if m.severity == Severity.CRITICAL]
    verdict = _verdict_from_score(fused_score, critical_findings)

    confidence = min(1.0, max(0.55, 0.55 + fused_score * 0.4))
    hard_block_reasons = [f"{m.rule_id}: {m.rule_name}" for m in critical_findings]
    remediation_steps = list(dict.fromkeys(m.remediation for m in all_findings if m.remediation))

    return FinalVerdict(
        skill_name=_skill_name(manifest, report_l1.skill_name),
        framework=manifest.framework.value,
        verdict=verdict,
        fused_risk_score=fused_score,
        confidence=confidence,
        l1_score=report_l1.composite_score,
        l2_score=report_l2.composite_score,
        all_findings=all_findings,
        hard_block_reasons=hard_block_reasons,
        remediation_steps=remediation_steps[:10],
        layers_executed=["L1", "L2"],
        llm_tokens_consumed=report_l2.llm_tokens_used,
    )


__all__ = ["fuse_layer1", "fuse_layers"]
