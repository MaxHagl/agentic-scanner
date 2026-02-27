"""
llm_judge.py
────────────
Low-level Anthropic API client for Layer 2 semantic analysis.

Provides:
  - wrap_untrusted()       mandatory XML wrapper for all attacker-controlled text
  - JudgeFinding           a single flagged location with attack type and severity
  - JudgeResponse          parsed output from the LLM judge
  - JudgeResponseParser    robust JSON → JudgeResponse (never raises)
  - AnthropicJudgeClient   thin Anthropic API wrapper (temperature=0, MAX_RETRIES=2)
  - LLMJudgeError          raised after all retries are exhausted

Security invariants enforced here:
  - wrap_untrusted() MUST be called on ALL attacker-controlled text before it
    enters any prompt.  Never skip this, even for content that "looks safe".
  - temperature=0.0 always — security classification must be deterministic.
  - PARSE_ERROR is fail-open: returns an empty JudgeResponse, never raises.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import re
import time
from typing import Any

logger = logging.getLogger(__name__)


# ─── Security boundary ────────────────────────────────────────────────────────

def wrap_untrusted(text: str) -> str:
    """
    Wrap attacker-controlled content in XML tags to prevent prompt injection.

    MUST be called on ALL untrusted text before it enters any prompt.
    Never skip this, even for content that "looks safe" — defense in depth.
    """
    return f"<untrusted_content>\n{text}\n</untrusted_content>"


# ─── Data types ───────────────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True)
class JudgeFinding:
    """A single location flagged by the LLM judge."""
    field_name: str       # e.g. "tool:search_web:description"
    evidence_quote: str   # exact quote from the content, capped at 200 chars
    attack_type: str      # e.g. "T2_PROMPT_INJECTION"
    severity: str         # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"


@dataclasses.dataclass(frozen=True)
class JudgeResponse:
    """Parsed output from one LLM judge call."""
    verdict: str                 # "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "PARSE_ERROR"
    confidence: float            # 0.0–1.0, clamped on parse
    attack_types: list[str]
    findings: list[JudgeFinding]
    rationale: str               # capped at 500 chars
    tokens_used: int = 0


class LLMJudgeError(RuntimeError):
    """Raised by GeminiJudgeClient after all retries are exhausted."""


# ─── Parser ───────────────────────────────────────────────────────────────────

class JudgeResponseParser:
    """
    Robust JSON → JudgeResponse parser.

    Design invariant: NEVER raises.  Any failure returns a JudgeResponse with
    verdict="PARSE_ERROR" so callers can treat it as fail-open.
    """

    _FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)
    _VALID_VERDICTS = {"CLEAN", "SUSPICIOUS", "MALICIOUS"}
    _VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    @classmethod
    def parse(cls, raw_text: str) -> JudgeResponse:
        """Parse raw LLM output into a JudgeResponse.  Never raises."""
        try:
            return cls._parse_inner(raw_text)
        except Exception as exc:
            logger.warning("JudgeResponseParser: failed to parse LLM output: %s", exc)
            return JudgeResponse(
                verdict="PARSE_ERROR",
                confidence=0.0,
                attack_types=[],
                findings=[],
                rationale=f"Parse error: {str(exc)[:200]}",
                tokens_used=0,
            )

    @classmethod
    def _parse_inner(cls, raw_text: str) -> JudgeResponse:
        text = raw_text.strip()

        # Strip markdown code fences if present (LLMs often wrap JSON in ```json)
        fence_match = cls._FENCE_RE.search(text)
        if fence_match:
            text = fence_match.group(1).strip()

        data: dict[str, Any] = json.loads(text)

        # Validate required top-level fields
        required = {"verdict", "confidence", "attack_types", "findings", "rationale"}
        missing = required - data.keys()
        if missing:
            raise ValueError(f"Missing required fields in judge response: {missing}")

        verdict = str(data["verdict"]).upper()
        if verdict not in cls._VALID_VERDICTS:
            raise ValueError(f"Invalid verdict: {verdict!r} (must be one of {cls._VALID_VERDICTS})")

        # Clamp confidence to [0.0, 1.0]
        confidence = float(data["confidence"])
        confidence = max(0.0, min(1.0, confidence))

        rationale = str(data.get("rationale", ""))[:500]
        attack_types = [str(a) for a in data.get("attack_types", [])]

        findings: list[JudgeFinding] = []
        for raw_f in data.get("findings", []):
            if not isinstance(raw_f, dict):
                continue
            severity = str(raw_f.get("severity", "MEDIUM")).upper()
            if severity not in cls._VALID_SEVERITIES:
                severity = "MEDIUM"
            findings.append(JudgeFinding(
                field_name=str(raw_f.get("field_name", "unknown")),
                evidence_quote=str(raw_f.get("evidence_quote", ""))[:200],
                attack_type=str(raw_f.get("attack_type", "T2_PROMPT_INJECTION")),
                severity=severity,
            ))

        return JudgeResponse(
            verdict=verdict,
            confidence=confidence,
            attack_types=attack_types,
            findings=findings,
            rationale=rationale,
            tokens_used=0,  # caller sets this from the actual API response
        )


# ─── Client ───────────────────────────────────────────────────────────────────

class AnthropicJudgeClient:
    """
    Thin wrapper around anthropic.Anthropic for security classification.

    Design invariants:
    - temperature=0.0 always — deterministic security classification
    - MAX_RETRIES attempts with 1-second back-off before raising LLMJudgeError
    - Raises ValueError immediately on construction if no injected client and
      no ANTHROPIC_API_KEY environment variable is set

    Inject a mock `client` in tests to avoid real API calls.
    """

    DEFAULT_MODEL = "claude-haiku-4-5-20251001"
    MAX_RETRIES = 2

    def __init__(
        self,
        client: Any | None = None,
        model: str | None = None,
    ) -> None:
        # Model resolution: arg → ANTHROPIC_MODEL env → DEFAULT_MODEL
        self._model = model or os.environ.get("ANTHROPIC_MODEL", self.DEFAULT_MODEL)

        if client is not None:
            self._client = client
        else:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError(
                    "ANTHROPIC_API_KEY environment variable not set. "
                    "Provide it or inject an anthropic.Anthropic instance for testing."
                )
            try:
                import anthropic  # type: ignore[import-untyped]
                self._client = anthropic.Anthropic(api_key=api_key)
            except ImportError as exc:
                raise ValueError(
                    f"anthropic package not available: {exc}. "
                    "Install it with: poetry add anthropic"
                ) from exc

    def call(self, system_prompt: str, user_message: str) -> tuple[str, int]:
        """
        Make one classification call to the Anthropic Messages API.

        Returns:
            (raw_response_text, tokens_used)

        Raises:
            LLMJudgeError: after MAX_RETRIES consecutive failures
        """
        last_exc: Exception | None = None
        for attempt in range(self.MAX_RETRIES):
            try:
                return self._call_once(system_prompt, user_message)
            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "AnthropicJudgeClient: attempt %d/%d failed: %s",
                    attempt + 1,
                    self.MAX_RETRIES,
                    exc,
                )
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(1.0)

        raise LLMJudgeError(
            f"Anthropic API call failed after {self.MAX_RETRIES} retries: {last_exc}"
        ) from last_exc

    def _call_once(self, system_prompt: str, user_message: str) -> tuple[str, int]:
        message = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
            temperature=0.0,
        )
        raw_text: str = message.content[0].text if message.content else ""
        tokens_used = 0
        if hasattr(message, "usage") and message.usage:
            tokens_used = (
                getattr(message.usage, "input_tokens", 0)
                + getattr(message.usage, "output_tokens", 0)
            )
        return raw_text, int(tokens_used)
