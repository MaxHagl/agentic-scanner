"""
scanner/layer2_semantic
───────────────────────
Layer 2: Semantic / LLM-backed analysis using Anthropic Claude Haiku.

Exports:
  Layer2Analyzer — orchestrates both analysis passes:
    1. PromptInjectionDetector  (T2/T3/T6/T7 semantic injection)
    2. ConsistencyChecker       (desc-code mismatch + permission delta)

Usage:
    analyzer = Layer2Analyzer()          # needs ANTHROPIC_API_KEY in env
    report = analyzer.analyze(manifest, l1_report)

For testing without a real API key, inject a mock AnthropicJudgeClient:
    from unittest.mock import MagicMock
    mock = MagicMock(spec=AnthropicJudgeClient)
    mock.call.return_value = (json.dumps({...}), 100)
    analyzer = Layer2Analyzer(client=mock)

Fail-open invariant: LLMJudgeError → RiskReport_L2 with llm_judge_verdict=None
and empty matches.  Layer 2 never raises to the CLI caller.
"""

from __future__ import annotations

import logging

from scanner.models import SkillManifest
from scanner.models.risk_report import RiskReport_L1, RiskReport_L2
from scanner.layer2_semantic.llm_judge import AnthropicJudgeClient, LLMJudgeError
from scanner.layer2_semantic.prompt_injection_detector import PromptInjectionDetector
from scanner.layer2_semantic.consistency_checker import ConsistencyChecker

logger = logging.getLogger(__name__)

__all__ = ["Layer2Analyzer"]


class Layer2Analyzer:
    """
    Orchestrates both Layer 2 semantic analysis passes.

    One shared AnthropicJudgeClient is constructed (or injected) and passed to
    both sub-analyzers so token counts accumulate over two API calls.
    """

    def __init__(self, client: AnthropicJudgeClient | None = None) -> None:
        # Build one shared client; sub-analyzers get the same instance.
        # If client=None and no ANTHROPIC_API_KEY, AnthropicJudgeClient raises ValueError —
        # that's intentional (configuration error, not a runtime API failure).
        if client is None:
            client = AnthropicJudgeClient()
        self._client = client
        self._injection_detector = PromptInjectionDetector(client=client)
        self._consistency_checker = ConsistencyChecker(client=client)

    def analyze(
        self,
        manifest: SkillManifest,
        l1_report: RiskReport_L1 | None = None,
    ) -> RiskReport_L2:
        """
        Run both semantic analysis passes and return a RiskReport_L2.

        On LLMJudgeError (API exhaustion), logs a warning and returns a
        minimal report with llm_judge_verdict=None (fail-open).
        """
        try:
            return self._run_analysis(manifest, l1_report)
        except LLMJudgeError as exc:
            logger.warning(
                "Layer2Analyzer: LLMJudgeError — failing open. "
                "No LLM verdict will be emitted. Error: %s",
                exc,
            )
            return RiskReport_L2(
                injection_matches=[],
                llm_judge_verdict=None,
                llm_judge_confidence=None,
                llm_judge_attack_types=[],
                llm_judge_evidence_summary=None,
                llm_tokens_used=0,
                description_code_mismatch=False,
                permission_delta_critical=False,
                field_risk_scores={},
            )

    def _run_analysis(
        self,
        manifest: SkillManifest,
        l1_report: RiskReport_L1 | None,
    ) -> RiskReport_L2:
        all_matches = []
        total_tokens = 0
        field_risk_scores: dict[str, float] = {}

        # ── Pass 1: Semantic injection detection ─────────────────────────────
        inj_matches, inj_response = self._injection_detector.detect(manifest)
        all_matches.extend(inj_matches)
        total_tokens += inj_response.tokens_used

        # Populate field_risk_scores from injection findings
        for finding in inj_response.findings:
            field_risk_scores[finding.field_name] = max(
                field_risk_scores.get(finding.field_name, 0.0),
                inj_response.confidence,
            )

        # ── Pass 2: Description-code consistency check ────────────────────────
        cc_matches, desc_mismatch, perm_critical = self._consistency_checker.check(
            manifest, l1_report
        )
        all_matches.extend(cc_matches)
        total_tokens += self._consistency_checker.last_tokens_used

        # Populate field_risk_scores from consistency findings
        for match in cc_matches:
            for ev in match.evidence:
                if ev.field_name:
                    field_risk_scores[ev.field_name] = max(
                        field_risk_scores.get(ev.field_name, 0.0),
                        match.confidence,
                    )

        # ── Determine overall LLM judge verdict ───────────────────────────────
        # Use the injection detector response as the primary verdict signal
        # (it covers more attack surface and has broader attack_types).
        llm_verdict: str | None = None
        llm_confidence: float | None = None
        llm_attack_types: list[str] = []
        llm_evidence_summary: str | None = None

        if inj_response.verdict not in ("PARSE_ERROR",):
            llm_verdict = inj_response.verdict
            llm_confidence = inj_response.confidence
            llm_attack_types = inj_response.attack_types
            llm_evidence_summary = inj_response.rationale or None

        return RiskReport_L2(
            injection_matches=all_matches,
            llm_judge_verdict=llm_verdict,
            llm_judge_confidence=llm_confidence,
            llm_judge_attack_types=llm_attack_types,
            llm_judge_evidence_summary=llm_evidence_summary,
            llm_tokens_used=total_tokens,
            description_code_mismatch=desc_mismatch,
            permission_delta_critical=perm_critical,
            field_risk_scores=field_risk_scores,
        )
