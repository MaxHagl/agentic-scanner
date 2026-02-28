"""
risk_report.py
──────────────
Output data contracts for each scanner layer and the final verdict.
Each layer produces a typed, immutable report.
The aggregator fuses them into a FinalVerdict.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, computed_field

from .skill_manifest import AttackVector, Severity


class Evidence(BaseModel):
    file_path: str | None = None
    line_number: int | None = None
    column: int | None = None
    snippet: str | None = None
    field_name: str | None = None
    byte_offset: int | None = None


class RuleMatch(BaseModel):
    rule_id: str
    rule_name: str
    severity: Severity
    attack_vector: AttackVector
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[Evidence] = Field(default_factory=list)
    rationale: str
    remediation: str
    tool_component: str = "agentic-scanner"
    tags: list[str] = Field(default_factory=list)


_WEIGHTS = {
    Severity.CRITICAL: 1.0, Severity.HIGH: 0.6,
    Severity.MEDIUM: 0.3,   Severity.LOW: 0.1, Severity.INFO: 0.0,
}
_LAMBDA = 1.2


def _score(matches: list[RuleMatch], bonus: float = 0.0) -> float:
    total = sum(_WEIGHTS[m.severity] * m.confidence for m in matches) + bonus
    return round(1.0 - math.exp(-_LAMBDA * total), 4)


class RiskReport_L1(BaseModel):
    scan_id: UUID = Field(default_factory=uuid4)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    skill_name: str
    framework: str
    matches: list[RuleMatch] = Field(default_factory=list)
    dependency_cve_count: int = 0
    typosquat_count: int = 0
    invisible_unicode_detected: bool = False
    dynamic_import_detected: bool = False
    subprocess_in_tool_body: bool = False
    undeclared_network_access: bool = False
    suspicious_dependency: bool = False

    @computed_field
    @property
    def composite_score(self) -> float:
        bonus = 0.0
        if self.invisible_unicode_detected:      bonus += 2.0
        if self.subprocess_in_tool_body and self.undeclared_network_access:
            bonus += 1.5
        return _score(self.matches, bonus)

    @computed_field
    @property
    def highest_severity(self) -> Severity:
        if not self.matches:
            return Severity.INFO
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return max(self.matches, key=lambda m: order.index(m.severity)).severity


class RiskReport_L2(BaseModel):
    scan_id: UUID = Field(default_factory=uuid4)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    injection_matches: list[RuleMatch] = Field(default_factory=list)
    llm_judge_verdict: str | None = None
    llm_judge_confidence: float | None = None
    llm_judge_attack_types: list[str] = Field(default_factory=list)
    llm_judge_evidence_summary: str | None = None
    llm_tokens_used: int = 0
    description_code_mismatch: bool = False
    permission_delta_critical: bool = False
    field_risk_scores: dict[str, float] = Field(default_factory=dict)

    @computed_field
    @property
    def composite_score(self) -> float:
        bonus = 0.0
        if self.llm_judge_verdict == "MALICIOUS" and self.llm_judge_confidence:
            bonus += 1.5 * self.llm_judge_confidence
        elif self.llm_judge_verdict == "SUSPICIOUS" and self.llm_judge_confidence:
            bonus += 0.7 * self.llm_judge_confidence
        if self.description_code_mismatch:  bonus += 0.8
        if self.permission_delta_critical:  bonus += 1.2
        return _score(self.injection_matches, bonus)


class ExecutionTrace(BaseModel):
    syscalls_observed: list[str] = Field(default_factory=list)
    files_read: list[str] = Field(default_factory=list)
    files_written: list[str] = Field(default_factory=list)
    network_connect_attempts: list[str] = Field(default_factory=list)
    dns_lookups_attempted: list[str] = Field(default_factory=list)
    env_vars_read: list[str] = Field(default_factory=list)
    processes_spawned: list[str] = Field(default_factory=list)
    output_entropy: float = 0.0
    execution_time_ms: int = 0
    exit_code: int = 0
    oom_killed: bool = False
    timeout_killed: bool = False


class RiskReport_L3(BaseModel):
    scan_id: UUID = Field(default_factory=uuid4)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    trace: ExecutionTrace = Field(default_factory=ExecutionTrace)
    matches: list[RuleMatch] = Field(default_factory=list)
    execve_detected: bool = False
    undeclared_network_egress: bool = False
    high_entropy_output: bool = False
    filesystem_write_outside_scope: bool = False
    ptrace_attempted: bool = False
    rwx_mmap_detected: bool = False
    # Agent simulation metadata (populated by _run_agent_simulation path only)
    agent_simulation_executed: bool = False
    agent_tool_call_count: int = 0

    @computed_field
    @property
    def composite_score(self) -> float:
        bonus = 0.0
        if self.execve_detected:               bonus += 2.0
        if self.ptrace_attempted:              bonus += 2.0
        if self.rwx_mmap_detected:             bonus += 1.5
        if self.undeclared_network_egress:     bonus += 1.5
        if self.high_entropy_output:           bonus += 0.8
        return _score(self.matches, bonus)


class FinalVerdict(BaseModel):
    scan_id: UUID = Field(default_factory=uuid4)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    skill_name: str
    framework: str
    verdict: str                          # "SAFE" | "WARN" | "BLOCK"
    fused_risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    l1_score: float = 0.0
    l2_score: float | None = None
    l3_score: float | None = None
    all_findings: list[RuleMatch] = Field(default_factory=list)
    hard_block_reasons: list[str] = Field(default_factory=list)
    remediation_steps: list[str] = Field(default_factory=list)
    layers_executed: list[str] = Field(default_factory=list)
    total_scan_time_ms: int = 0
    llm_tokens_consumed: int = 0

    def to_sarif(self) -> dict[str, Any]:
        """Serialize to SARIF 2.1.0 for GitHub Code Scanning integration."""
        level_map = {
            "INFO": "note", "LOW": "note",
            "MEDIUM": "warning", "HIGH": "error", "CRITICAL": "error"
        }
        results = []
        for f in self.all_findings:
            result: dict[str, Any] = {
                "ruleId": f.rule_id,
                "level": level_map[f.severity],
                "message": {"text": f.rationale},
                "properties": {
                    "attackVector": f.attack_vector,
                    "confidence": f.confidence,
                    "remediation": f.remediation,
                }
            }
            if f.evidence and f.evidence[0].file_path and f.evidence[0].line_number:
                ev = f.evidence[0]
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": ev.file_path},
                        "region": {"startLine": ev.line_number}
                    }
                }]
            results.append(result)
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "agentic-scanner", "version": "0.1.0"}}, "results": results}]
        }
