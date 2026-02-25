from __future__ import annotations

from scanner.models import FinalVerdict, RiskReport_L1, Severity, SkillManifest


def fuse_layer1(manifest: SkillManifest, report_l1: RiskReport_L1) -> FinalVerdict:
    critical_findings = [m for m in report_l1.matches if m.severity == Severity.CRITICAL]
    if critical_findings or report_l1.composite_score >= 0.75:
        verdict = "BLOCK"
    elif report_l1.composite_score >= 0.35:
        verdict = "WARN"
    else:
        verdict = "SAFE"

    confidence = min(1.0, max(0.55, 0.55 + report_l1.composite_score * 0.4))
    hard_block_reasons = [f"{m.rule_id}: {m.rule_name}" for m in critical_findings]
    remediation_steps = list(dict.fromkeys(m.remediation for m in report_l1.matches if m.remediation))

    skill_name = (
        manifest.mcp_server_name
        or str(manifest.raw_manifest_json.get("name", "")).strip()
        or report_l1.skill_name
    )

    return FinalVerdict(
        skill_name=skill_name,
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


__all__ = ["fuse_layer1"]
