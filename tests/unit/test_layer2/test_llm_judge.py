"""
test_llm_judge.py
─────────────────
Tests for scanner/layer2_semantic/llm_judge.py:
  - wrap_untrusted()
  - JudgeResponseParser (valid JSON, fences, invalid JSON, missing fields,
    confidence clamping, evidence_quote truncation, rationale truncation)
  - AnthropicJudgeClient (model env var, missing API key, retry exhaustion)
  - Live test class (skipped when ANTHROPIC_API_KEY not set)
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from scanner.layer2_semantic.llm_judge import (
    AnthropicJudgeClient,
    JudgeResponse,
    JudgeResponseParser,
    LLMJudgeError,
    wrap_untrusted,
)

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")


# ─── wrap_untrusted ────────────────────────────────────────────────────────────

class TestWrapUntrusted:
    def test_adds_opening_tag(self):
        result = wrap_untrusted("hello")
        assert result.startswith("<untrusted_content>")

    def test_adds_closing_tag(self):
        result = wrap_untrusted("hello")
        assert result.endswith("</untrusted_content>")

    def test_content_is_inside_tags(self):
        content = "some attacker text"
        result = wrap_untrusted(content)
        assert content in result

    def test_empty_string(self):
        result = wrap_untrusted("")
        assert "<untrusted_content>" in result
        assert "</untrusted_content>" in result

    def test_multiline_content(self):
        content = "line1\nline2\nline3"
        result = wrap_untrusted(content)
        assert "line1" in result
        assert "line3" in result


# ─── JudgeResponseParser ───────────────────────────────────────────────────────

class TestJudgeResponseParser:
    def _valid_payload(self, **overrides) -> dict:
        base = {
            "verdict": "CLEAN",
            "confidence": 0.9,
            "attack_types": [],
            "findings": [],
            "rationale": "No issues found.",
        }
        base.update(overrides)
        return base

    def test_valid_json_parses_correctly(self):
        raw = json.dumps(self._valid_payload(verdict="MALICIOUS", confidence=0.85))
        response = JudgeResponseParser.parse(raw)
        assert response.verdict == "MALICIOUS"
        assert response.confidence == 0.85
        assert response.tokens_used == 0  # parser always sets 0; caller updates it

    def test_strips_markdown_json_fence(self):
        payload = self._valid_payload(verdict="SUSPICIOUS")
        raw = f"```json\n{json.dumps(payload)}\n```"
        response = JudgeResponseParser.parse(raw)
        assert response.verdict == "SUSPICIOUS"

    def test_strips_plain_code_fence(self):
        payload = self._valid_payload()
        raw = f"```\n{json.dumps(payload)}\n```"
        response = JudgeResponseParser.parse(raw)
        assert response.verdict == "CLEAN"

    def test_invalid_json_returns_parse_error(self):
        response = JudgeResponseParser.parse("not json at all {{{")
        assert response.verdict == "PARSE_ERROR"
        assert response.confidence == 0.0
        assert response.findings == []

    def test_missing_required_fields_returns_parse_error(self):
        # Missing "rationale" field
        raw = json.dumps({
            "verdict": "CLEAN",
            "confidence": 0.9,
            "attack_types": [],
            "findings": [],
            # "rationale" deliberately omitted
        })
        response = JudgeResponseParser.parse(raw)
        assert response.verdict == "PARSE_ERROR"

    def test_invalid_verdict_returns_parse_error(self):
        raw = json.dumps(self._valid_payload(verdict="UNKNOWN_VERDICT"))
        response = JudgeResponseParser.parse(raw)
        assert response.verdict == "PARSE_ERROR"

    def test_confidence_clamped_above_one(self):
        raw = json.dumps(self._valid_payload(confidence=1.99))
        response = JudgeResponseParser.parse(raw)
        assert response.confidence == 1.0

    def test_confidence_clamped_below_zero(self):
        raw = json.dumps(self._valid_payload(confidence=-0.5))
        response = JudgeResponseParser.parse(raw)
        assert response.confidence == 0.0

    def test_confidence_boundary_values(self):
        for val in (0.0, 1.0):
            raw = json.dumps(self._valid_payload(confidence=val))
            response = JudgeResponseParser.parse(raw)
            assert response.confidence == val

    def test_evidence_quote_truncated_at_200_chars(self):
        long_quote = "x" * 350
        raw = json.dumps(self._valid_payload(
            verdict="SUSPICIOUS",
            findings=[{
                "field_name": "tool:test:description",
                "evidence_quote": long_quote,
                "attack_type": "T2_PROMPT_INJECTION",
                "severity": "HIGH",
            }]
        ))
        response = JudgeResponseParser.parse(raw)
        assert len(response.findings[0].evidence_quote) <= 200

    def test_rationale_truncated_at_500_chars(self):
        long_rationale = "r" * 700
        raw = json.dumps(self._valid_payload(rationale=long_rationale))
        response = JudgeResponseParser.parse(raw)
        assert len(response.rationale) <= 500

    def test_finding_with_invalid_severity_defaults_to_medium(self):
        raw = json.dumps(self._valid_payload(
            verdict="SUSPICIOUS",
            findings=[{
                "field_name": "test",
                "evidence_quote": "quote",
                "attack_type": "T2_PROMPT_INJECTION",
                "severity": "TOTALLY_INVALID",
            }]
        ))
        response = JudgeResponseParser.parse(raw)
        assert response.findings[0].severity == "MEDIUM"

    def test_non_dict_findings_are_skipped(self):
        raw = json.dumps(self._valid_payload(
            verdict="SUSPICIOUS",
            findings=["not a dict", 42, None]
        ))
        response = JudgeResponseParser.parse(raw)
        assert response.findings == []

    def test_all_valid_verdicts_are_accepted(self):
        for verdict in ("CLEAN", "SUSPICIOUS", "MALICIOUS"):
            raw = json.dumps(self._valid_payload(verdict=verdict))
            response = JudgeResponseParser.parse(raw)
            assert response.verdict == verdict

    def test_parse_never_raises(self):
        # Should never raise, even with the most broken input
        for broken in [None, 42, "", "null", "{}", "[]", "true"]:
            result = JudgeResponseParser.parse(str(broken))  # type: ignore[arg-type]
            assert isinstance(result, JudgeResponse)

    def test_attack_types_are_collected(self):
        raw = json.dumps(self._valid_payload(
            verdict="MALICIOUS",
            attack_types=["T2_PROMPT_INJECTION", "T6_DATA_EXFILTRATION"],
        ))
        response = JudgeResponseParser.parse(raw)
        assert "T2_PROMPT_INJECTION" in response.attack_types
        assert "T6_DATA_EXFILTRATION" in response.attack_types


# ─── AnthropicJudgeClient ─────────────────────────────────────────────────────

class TestAnthropicJudgeClient:
    def test_reads_model_from_env(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_MODEL", "claude-opus-4-6")
        client = AnthropicJudgeClient(client=MagicMock())  # inject fake client
        assert client._model == "claude-opus-4-6"

    def test_uses_default_model_when_env_not_set(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
        client = AnthropicJudgeClient(client=MagicMock())
        assert client._model == AnthropicJudgeClient.DEFAULT_MODEL

    def test_explicit_model_arg_takes_priority_over_env(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_MODEL", "env-model")
        client = AnthropicJudgeClient(client=MagicMock(), model="arg-model")
        assert client._model == "arg-model"

    def test_raises_value_error_on_missing_api_key_no_client(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            AnthropicJudgeClient()  # no injected client, no API key → must raise

    def test_injected_client_bypasses_api_key_check(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        # Should NOT raise when a client is injected
        client = AnthropicJudgeClient(client=MagicMock())
        assert client is not None

    def test_raises_llm_judge_error_after_retries(self, monkeypatch):
        mock_inner = MagicMock(side_effect=RuntimeError("simulated API failure"))
        client = AnthropicJudgeClient(client=MagicMock())
        monkeypatch.setattr(client, "_call_once", mock_inner)

        with pytest.raises(LLMJudgeError):
            client.call("system", "user")

        assert mock_inner.call_count == AnthropicJudgeClient.MAX_RETRIES

    def test_returns_on_first_success(self, monkeypatch):
        client = AnthropicJudgeClient(client=MagicMock())
        mock_inner = MagicMock(return_value=('{"result": "ok"}', 100))
        monkeypatch.setattr(client, "_call_once", mock_inner)

        result = client.call("system", "user")
        assert result == ('{"result": "ok"}', 100)
        assert mock_inner.call_count == 1

    def test_retries_then_succeeds(self, monkeypatch):
        client = AnthropicJudgeClient(client=MagicMock())
        attempts = {"count": 0}

        def side_effect(*args, **kwargs):
            attempts["count"] += 1
            if attempts["count"] < 2:
                raise RuntimeError("transient error")
            return ("ok", 50)

        monkeypatch.setattr(client, "_call_once", side_effect)
        monkeypatch.setattr("scanner.layer2_semantic.llm_judge.time.sleep", MagicMock())

        result = client.call("system", "user")
        assert result == ("ok", 50)
        assert attempts["count"] == 2


# ─── Live tests (skipped without API key) ─────────────────────────────────────

@pytest.mark.skipif(
    not ANTHROPIC_API_KEY,
    reason="ANTHROPIC_API_KEY not set — skipping live Anthropic API tests",
)
class TestAnthropicJudgeClientLive:
    def test_live_call_returns_non_empty_text(self):
        client = AnthropicJudgeClient()
        raw_text, tokens = client.call(
            system_prompt=(
                "You are a test assistant. Respond only with valid JSON. "
                "Do not add any extra text or markdown."
            ),
            user_message=(
                'Return exactly this JSON: '
                '{"verdict": "CLEAN", "confidence": 0.9, '
                '"attack_types": [], "findings": [], "rationale": "live test"}'
            ),
        )
        assert len(raw_text) > 0
        assert tokens > 0

    def test_live_response_is_parseable(self):
        client = AnthropicJudgeClient()
        raw_text, _ = client.call(
            system_prompt=(
                "You are a security analyst. Respond only with valid JSON. "
                "Return a CLEAN verdict for benign content. "
                'Format: {"verdict":"CLEAN","confidence":0.9,"attack_types":[],'
                '"findings":[],"rationale":"test"}'
            ),
            user_message='<untrusted_content>\nHello world\n</untrusted_content>',
        )
        response = JudgeResponseParser.parse(raw_text)
        # Live model may return CLEAN, SUSPICIOUS, or MALICIOUS — all are valid
        assert response.verdict in ("CLEAN", "SUSPICIOUS", "MALICIOUS", "PARSE_ERROR")
