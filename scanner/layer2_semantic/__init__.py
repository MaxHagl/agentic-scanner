"""
scanner/layer2_semantic
───────────────────────
Layer 2: Semantic / LLM-backed analysis using Anthropic Claude Haiku.

Exports:
  Layer2Analyzer — orchestrates both analysis passes:
    1. PromptInjectionDetector  (T2/T3/T6/T7 semantic injection)
    2. ConsistencyChecker       (desc-code mismatch + permission delta)

Optionally uses a finetuned local LoRA model as a fast pre-filter:
    analyzer = Layer2Analyzer(local_model_path="finetuning/adapter")
    # → runs local model first; escalates to Haiku only when uncertain

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

import dataclasses
import logging
from pathlib import Path

from scanner.models import SkillManifest
from scanner.models.risk_report import RiskReport_L1, RiskReport_L2
from scanner.layer2_semantic.llm_judge import (
    AnthropicJudgeClient,
    JudgeResponse,
    LLMJudgeError,
    wrap_untrusted,
)
from scanner.layer2_semantic.prompt_injection_detector import (
    PromptInjectionDetector,
    _SYSTEM_PROMPT as _PI_SYSTEM_PROMPT,
)
from scanner.layer2_semantic.consistency_checker import ConsistencyChecker

logger = logging.getLogger(__name__)

__all__ = ["Layer2Analyzer"]


class Layer2Analyzer:
    """
    Orchestrates both Layer 2 semantic analysis passes.

    One shared AnthropicJudgeClient is constructed (or injected) and passed to
    both sub-analyzers so token counts accumulate over two API calls.

    When local_model_path is provided, a finetuned LocalLLMJudge is used as a
    pre-filter.  If the local model returns a confident verdict (confidence ≥
    escalation_threshold), that verdict is used directly and no Haiku API call
    is made.  Uncertain or PARSE_ERROR responses fall through to the full Haiku
    pipeline unchanged.
    """

    def __init__(
        self,
        client: AnthropicJudgeClient | None = None,
        local_model_path: str | Path | None = None,
        escalation_threshold: float = 0.80,
    ) -> None:
        # Build one shared client; sub-analyzers get the same instance.
        # If client=None and no ANTHROPIC_API_KEY, AnthropicJudgeClient raises ValueError —
        # that's intentional (configuration error, not a runtime API failure).
        if client is None:
            try:
                client = AnthropicJudgeClient()
            except ValueError as e:
                if local_model_path is None:
                    raise e
                logger.warning(f"Anthropic API key not found. Only local LLM will be used. ({e})")
                client = None
        self._client = client
        if self._client is not None:
            self._injection_detector = PromptInjectionDetector(client=client)
            self._consistency_checker = ConsistencyChecker(client=client)
        else:
            self._injection_detector = None
            self._consistency_checker = None

        # Optional local pre-filter (lazy-loaded inside LocalLLMJudge on first call)
        self._local_judge = None
        if local_model_path is not None:
            from scanner.layer2_semantic.local_judge import LocalLLMJudge
            self._local_judge = LocalLLMJudge(local_model_path, escalation_threshold)

    def analyze(
        self,
        manifest: SkillManifest,
        l1_report: RiskReport_L1 | None = None,
    ) -> RiskReport_L2:
        """
        Run both semantic analysis passes and return a RiskReport_L2.

        If a local model is configured, it runs first as a pre-filter:
          - Confident result (confidence ≥ threshold): return local verdict directly.
          - Uncertain or PARSE_ERROR: fall through to full Haiku pipeline.

        On LLMJudgeError (API exhaustion), logs a warning and returns a
        minimal report with llm_judge_verdict=None (fail-open).
        """
        local_verdict: str | None = None
        local_conf: float | None = None

        # ── Local model pre-filter ─────────────────────────────────────────────
        if self._local_judge is not None:
            try:
                local_response = self._local_judge.call(
                    _PI_SYSTEM_PROMPT,
                    wrap_untrusted(manifest.all_untrusted_text),
                )
                if local_response.verdict != "PARSE_ERROR":
                    local_verdict = local_response.verdict
                    local_conf = local_response.confidence

                if self._local_judge.is_confident(local_response):
                    logger.debug(
                        "LocalLLMJudge: confident verdict=%s (%.2f) — skipping Haiku",
                        local_response.verdict,
                        local_response.confidence,
                    )
                    return self._build_report_from_local(local_response, escalated=False)
                else:
                    logger.debug(
                        "LocalLLMJudge: uncertain (verdict=%s conf=%.2f) — escalating to Haiku",
                        local_response.verdict,
                        local_response.confidence,
                    )
                    # Fall through to full Haiku pipeline; mark escalated in result
            except Exception as exc:
                logger.warning(
                    "Layer2Analyzer: local model failed — escalating to Haiku. Error: %s", exc
                )

        # ── Full Haiku pipeline ────────────────────────────────────────────────
        if self._client is None or self._injection_detector is None or self._consistency_checker is None:
            logger.warning("No Anthropic client available for Layer 2 escalation — failing open.")
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
                local_model_used=self._local_judge is not None,
                local_model_escalated=True,
                local_model_verdict=local_verdict,
                local_model_confidence=local_conf,
            )

        try:
            report = self._run_analysis(manifest, l1_report)
            # Tag with local model metadata if we got here via escalation
            if self._local_judge is not None:
                return report.model_copy(
                    update={
                        "local_model_used": True, 
                        "local_model_escalated": True,
                        "local_model_verdict": local_verdict,
                        "local_model_confidence": local_conf
                    }
                )
            return report
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
                local_model_used=self._local_judge is not None,
                local_model_escalated=self._local_judge is not None,
                local_model_verdict=local_verdict,
                local_model_confidence=local_conf,
            )

    def _build_report_from_local(
        self,
        response: JudgeResponse,
        escalated: bool,
    ) -> RiskReport_L2:
        """
        Build a RiskReport_L2 from a confident local model response.

        The local model outputs verdict+confidence+rationale only.
        findings and injection_matches are empty — full findings only
        populate on Haiku escalation.
        """
        return RiskReport_L2(
            injection_matches=[],
            llm_judge_verdict=response.verdict if response.verdict != "PARSE_ERROR" else None,
            llm_judge_confidence=response.confidence if response.verdict != "PARSE_ERROR" else None,
            llm_judge_attack_types=response.attack_types,
            llm_judge_evidence_summary=response.rationale or None,
            llm_tokens_used=0,  # local model — no API tokens consumed
            description_code_mismatch=False,
            permission_delta_critical=False,
            field_risk_scores={},
            local_model_used=True,
            local_model_escalated=escalated,
            local_model_verdict=response.verdict if response.verdict != "PARSE_ERROR" else None,
            local_model_confidence=response.confidence if response.verdict != "PARSE_ERROR" else None,
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
