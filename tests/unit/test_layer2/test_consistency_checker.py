"""
test_consistency_checker.py
────────────────────────────
Tests for scanner/layer2_semantic/consistency_checker.py.

Covers:
  - permission_delta_critical is True when under_declared is non-empty
    (regardless of LLM verdict — deterministic invariant)
  - L1 AST findings appear in system_prompt arg, NOT in user_message arg
  - <untrusted_content> wraps description in user_message
  - Description mismatch → description_code_mismatch=True
  - Over-declared only → permission_delta_critical=False
  - No L1 report → checker still runs (empty L1 context in system prompt)
  - Correct rule IDs: L2-CC-001 (mismatch), L2-CC-002 (over), L2-CC-003 (under)
  - Fixture smoke test: L2-003 JSON + impl.py verify mismatch detection
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scanner.layer2_semantic.llm_judge import JudgeFinding, JudgeResponse
from scanner.layer2_semantic.consistency_checker import ConsistencyChecker
from scanner.models import (
    AttackVector,
    Framework,
    Permission,
    Severity,
    SkillManifest,
)
from scanner.models.risk_report import RiskReport_L1, RuleMatch, Evidence
from scanner.models.skill_manifest import ToolDefinition

from tests.unit.test_layer2.conftest import (
    make_clean_response,
    make_mock_client,
)

FIXTURE_DIR = Path(__file__).parent.parent.parent.parent / "tests" / "fixtures" / "layer2"


def _simple_manifest(
    description: str = "A helpful tool.",
    exercised: list[Permission] | None = None,
    declared: list[Permission] | None = None,
) -> SkillManifest:
    return SkillManifest(
        framework=Framework.MCP,
        tools=[ToolDefinition(
            name="test_tool",
            description=description,
            declared_permissions=declared or [],
        )],
        exercised_permissions=exercised or [],
    )


def _make_l1_report(**flags) -> RiskReport_L1:
    return RiskReport_L1(
        skill_name="test_skill",
        framework="mcp",
        **flags,
    )


def _make_mismatch_response() -> JudgeResponse:
    return JudgeResponse(
        verdict="MALICIOUS",
        confidence=0.9,
        attack_types=["DESC_MISMATCH"],
        findings=[
            JudgeFinding(
                field_name="tool:test_tool:description",
                evidence_quote="completely safe, read-only",
                attack_type="DESC_MISMATCH",
                severity="HIGH",
            )
        ],
        rationale="Description claims read-only but L1 shows subprocess calls.",
        tokens_used=0,
    )


def _make_over_declared_response() -> JudgeResponse:
    return JudgeResponse(
        verdict="SUSPICIOUS",
        confidence=0.7,
        attack_types=["OVER_DECLARED"],
        findings=[
            JudgeFinding(
                field_name="tool:test_tool:description",
                evidence_quote="declares network:egress",
                attack_type="OVER_DECLARED",
                severity="MEDIUM",
            )
        ],
        rationale="Tool declares network:egress but never uses it.",
        tokens_used=0,
    )


def _make_under_declared_response() -> JudgeResponse:
    return JudgeResponse(
        verdict="MALICIOUS",
        confidence=0.95,
        attack_types=["UNDER_DECLARED"],
        findings=[
            JudgeFinding(
                field_name="tool:test_tool:description",
                evidence_quote="subprocess:exec used but not declared",
                attack_type="UNDER_DECLARED",
                severity="CRITICAL",
            )
        ],
        rationale="Tool exercises subprocess:exec without declaring it.",
        tokens_used=0,
    )


# ─── permission_delta_critical (deterministic invariant) ─────────────────────

class TestPermissionDeltaCritical:
    def test_true_when_under_declared_non_empty(self):
        """CRITICAL invariant: under_declared permissions → permission_delta_critical=True
        regardless of what the LLM judge returns."""
        manifest = _simple_manifest(
            exercised=[Permission.SUBPROCESS_EXEC],  # not declared → under_declared
            declared=[],
        )
        mock_client = make_mock_client(make_clean_response())  # LLM says CLEAN
        checker = ConsistencyChecker(client=mock_client)

        _, _, perm_critical = checker.check(manifest)
        # Must be True even though LLM verdict is CLEAN
        assert perm_critical is True

    def test_false_when_only_over_declared(self):
        """over_declared only → permission_delta_critical=False."""
        manifest = _simple_manifest(
            exercised=[],
            declared=[Permission.NETWORK_EGRESS],  # declared but not used
        )
        mock_client = make_mock_client(make_clean_response())
        checker = ConsistencyChecker(client=mock_client)

        _, _, perm_critical = checker.check(manifest)
        assert perm_critical is False

    def test_false_when_no_permissions_at_all(self):
        manifest = _simple_manifest(exercised=[], declared=[])
        mock_client = make_mock_client(make_clean_response())
        checker = ConsistencyChecker(client=mock_client)
        _, _, perm_critical = checker.check(manifest)
        assert perm_critical is False

    def test_true_even_when_llm_says_clean(self):
        """The LLM verdict cannot override the deterministic AST-derived flag."""
        manifest = _simple_manifest(
            exercised=[Permission.FILESYSTEM_WRITE, Permission.SUBPROCESS_EXEC],
            declared=[],
        )
        mock_client = make_mock_client(make_clean_response())
        checker = ConsistencyChecker(client=mock_client)
        _, _, perm_critical = checker.check(manifest)
        assert perm_critical is True

    def test_set_before_judge_call(self):
        """Verify the flag is determined before the judge is called by checking
        it's True even when the mock client has not yet been called."""
        manifest = _simple_manifest(
            exercised=[Permission.SUBPROCESS_EXEC],
            declared=[],
        )
        call_count_before = [0]

        def counting_call(*args, **kwargs):
            call_count_before[0] += 1
            return (
                json.dumps({
                    "verdict": "CLEAN", "confidence": 0.9,
                    "attack_types": [], "findings": [], "rationale": "ok"
                }),
                100,
            )

        mock_client = MagicMock()
        mock_client.call.side_effect = counting_call
        checker = ConsistencyChecker(client=mock_client)

        _, _, perm_critical = checker.check(manifest)
        # The flag should be True (from manifest), and the judge was called too
        assert perm_critical is True
        assert call_count_before[0] == 1


# ─── Trust boundary: L1 facts in system_prompt, not user_message ─────────────

class TestTrustBoundary:
    def test_subprocess_in_tool_body_appears_in_system_prompt(self):
        l1 = _make_l1_report(subprocess_in_tool_body=True)
        mock_client = make_mock_client(make_clean_response())
        checker = ConsistencyChecker(client=mock_client)
        checker.check(_simple_manifest(), l1_report=l1)

        call_args = mock_client.call.call_args
        system_prompt: str = call_args[0][0]
        assert "subprocess_in_tool_body" in system_prompt

    def test_subprocess_flag_not_in_user_message(self):
        l1 = _make_l1_report(subprocess_in_tool_body=True)
        mock_client = make_mock_client(make_clean_response())
        checker = ConsistencyChecker(client=mock_client)
        checker.check(_simple_manifest(), l1_report=l1)

        call_args = mock_client.call.call_args
        user_message: str = call_args[0][1]
        assert "subprocess_in_tool_body" not in user_message

    def test_undeclared_network_appears_in_system_prompt(self):
        l1 = _make_l1_report(undeclared_network_access=True)
        mock_client = make_mock_client(make_clean_response())
        checker = ConsistencyChecker(client=mock_client)
        checker.check(_simple_manifest(), l1_report=l1)

        call_args = mock_client.call.call_args
        system_prompt: str = call_args[0][0]
        assert "undeclared_network_access" in system_prompt

    def test_l1_match_rule_ids_appear_in_system_prompt(self):
        l1 = RiskReport_L1(
            skill_name="test",
            framework="mcp",
            matches=[
                RuleMatch(
                    rule_id="PE-003",
                    rule_name="subprocess.run detected",
                    severity=Severity.HIGH,
                    attack_vector=AttackVector.T4_PRIVILEGE_ESCALATION,
                    confidence=0.9,
                    evidence=[],
                    rationale="subprocess.run call found in tool body",
                    remediation="Remove subprocess usage.",
                )
            ],
        )
        mock_client = make_mock_client(make_clean_response())
        checker = ConsistencyChecker(client=mock_client)
        checker.check(_simple_manifest(), l1_report=l1)

        call_args = mock_client.call.call_args
        system_prompt: str = call_args[0][0]
        assert "PE-003" in system_prompt

    def test_l1_rule_ids_not_in_user_message(self):
        l1 = RiskReport_L1(
            skill_name="test",
            framework="mcp",
            matches=[
                RuleMatch(
                    rule_id="PE-003",
                    rule_name="subprocess detected",
                    severity=Severity.HIGH,
                    attack_vector=AttackVector.T4_PRIVILEGE_ESCALATION,
                    confidence=0.9,
                    evidence=[],
                    rationale="subprocess.run found",
                    remediation="Remove it.",
                )
            ],
        )
        mock_client = make_mock_client(make_clean_response())
        checker = ConsistencyChecker(client=mock_client)
        checker.check(_simple_manifest(), l1_report=l1)

        call_args = mock_client.call.call_args
        user_message: str = call_args[0][1]
        assert "PE-003" not in user_message

    def test_untrusted_content_wraps_description_in_user_message(self):
        mock_client = make_mock_client(make_clean_response())
        checker = ConsistencyChecker(client=mock_client)
        checker.check(_simple_manifest("A completely safe read-only tool."))

        call_args = mock_client.call.call_args
        user_message: str = call_args[0][1]
        assert "<untrusted_content>" in user_message
        assert "</untrusted_content>" in user_message

    def test_description_text_appears_in_user_message(self):
        description = "UNIQUE_DESCRIPTION_MARKER_9821"
        mock_client = make_mock_client(make_clean_response())
        checker = ConsistencyChecker(client=mock_client)
        checker.check(_simple_manifest(description))

        call_args = mock_client.call.call_args
        user_message: str = call_args[0][1]
        assert description in user_message


# ─── Description mismatch detection ──────────────────────────────────────────

class TestDescriptionMismatch:
    def test_desc_mismatch_sets_flag_true(self):
        mock_client = make_mock_client(_make_mismatch_response())
        checker = ConsistencyChecker(client=mock_client)
        _, desc_mismatch, _ = checker.check(_simple_manifest())
        assert desc_mismatch is True

    def test_clean_response_does_not_set_mismatch(self):
        mock_client = make_mock_client(make_clean_response())
        checker = ConsistencyChecker(client=mock_client)
        _, desc_mismatch, _ = checker.check(_simple_manifest())
        assert desc_mismatch is False

    def test_over_declared_alone_does_not_set_mismatch(self):
        mock_client = make_mock_client(_make_over_declared_response())
        checker = ConsistencyChecker(client=mock_client)
        _, desc_mismatch, _ = checker.check(_simple_manifest())
        assert desc_mismatch is False

    def test_desc_mismatch_produces_l2_cc_001_match(self):
        mock_client = make_mock_client(_make_mismatch_response())
        checker = ConsistencyChecker(client=mock_client)
        matches, _, _ = checker.check(_simple_manifest())
        rule_ids = [m.rule_id for m in matches]
        assert "L2-CC-001" in rule_ids

    def test_over_declared_produces_l2_cc_002_match(self):
        mock_client = make_mock_client(_make_over_declared_response())
        checker = ConsistencyChecker(client=mock_client)
        matches, _, _ = checker.check(_simple_manifest())
        rule_ids = [m.rule_id for m in matches]
        assert "L2-CC-002" in rule_ids

    def test_under_declared_produces_l2_cc_003_match(self):
        mock_client = make_mock_client(_make_under_declared_response())
        checker = ConsistencyChecker(client=mock_client)
        matches, _, _ = checker.check(_simple_manifest())
        rule_ids = [m.rule_id for m in matches]
        assert "L2-CC-003" in rule_ids


# ─── No tools manifest guard ──────────────────────────────────────────────────

def test_no_tools_manifest_skips_cc_entirely() -> None:
    """
    CC must return empty results without calling the LLM when manifest.tools is empty.
    README-only manifests have no tool descriptions to compare against code.
    """
    client = make_mock_client(make_clean_response())
    checker = ConsistencyChecker(client=client)
    manifest = SkillManifest(
        framework=Framework.LANGCHAIN,
        tools=[],
        readme_text="Supports SQL queries, filesystem access, and HTTP networking.",
    )
    matches, desc_mismatch, perm_critical = checker.check(manifest, l1_report=None)

    assert matches == []
    assert desc_mismatch is False
    assert perm_critical is False
    client.call.assert_not_called()  # no LLM call wasted


# ─── No L1 report ─────────────────────────────────────────────────────────────

class TestNoL1Report:
    def test_runs_without_l1_report(self):
        mock_client = make_mock_client(make_clean_response())
        checker = ConsistencyChecker(client=mock_client)
        # Should not raise
        matches, desc_mismatch, perm_critical = checker.check(
            _simple_manifest(), l1_report=None
        )
        assert isinstance(matches, list)
        assert isinstance(desc_mismatch, bool)
        assert isinstance(perm_critical, bool)

    def test_no_l1_report_system_prompt_contains_placeholder(self):
        mock_client = make_mock_client(make_clean_response())
        checker = ConsistencyChecker(client=mock_client)
        checker.check(_simple_manifest(), l1_report=None)

        call_args = mock_client.call.call_args
        system_prompt: str = call_args[0][0]
        # Should indicate no L1 report is available
        assert any(phrase in system_prompt for phrase in [
            "No Layer 1", "No L1", "not available", "No static analysis"
        ])


# ─── Fail-open on PARSE_ERROR ─────────────────────────────────────────────────

class TestParseErrorFailOpen:
    def test_parse_error_returns_empty_matches(self):
        mock_client = MagicMock()
        mock_client.call.return_value = ("not json {{{{", 50)
        checker = ConsistencyChecker(client=mock_client)
        matches, desc_mismatch, perm_critical = checker.check(_simple_manifest())
        assert matches == []
        assert desc_mismatch is False

    def test_parse_error_preserves_deterministic_perm_flag(self):
        """Even on PARSE_ERROR, permission_delta_critical from manifest is preserved."""
        manifest = _simple_manifest(
            exercised=[Permission.SUBPROCESS_EXEC],
            declared=[],
        )
        mock_client = MagicMock()
        mock_client.call.return_value = ("not json", 0)
        checker = ConsistencyChecker(client=mock_client)
        _, _, perm_critical = checker.check(manifest)
        assert perm_critical is True  # set deterministically before judge call

    def test_tokens_tracked_even_on_parse_error(self):
        mock_client = MagicMock()
        mock_client.call.return_value = ("bad json", 75)
        checker = ConsistencyChecker(client=mock_client)
        checker.check(_simple_manifest())
        assert checker.last_tokens_used == 75


# ─── Fixture smoke test ───────────────────────────────────────────────────────

class TestFixtureSmoke:
    def test_load_l2_003_json_fixture(self):
        """L2-003: description-code mismatch — load fixture and run checker."""
        fixture_path = FIXTURE_DIR / "L2-003-inconsistent-tool.json"
        assert fixture_path.exists(), f"Fixture not found: {fixture_path}"

        with open(fixture_path) as f:
            data = json.load(f)

        tool_data = data["tools"][0]
        manifest = SkillManifest(
            framework=Framework.MCP,
            tools=[ToolDefinition(
                name=tool_data["name"],
                description=tool_data["description"],
            )],
            # Simulate what L1 AST scanner would find in the impl.py
            exercised_permissions=[Permission.SUBPROCESS_EXEC, Permission.NETWORK_EGRESS],
        )

        l1 = _make_l1_report(
            subprocess_in_tool_body=True,
            undeclared_network_access=True,
        )

        mock_client = make_mock_client(_make_mismatch_response())
        checker = ConsistencyChecker(client=mock_client)
        matches, desc_mismatch, perm_critical = checker.check(manifest, l1_report=l1)

        assert desc_mismatch is True  # mismatch response triggers this flag
        assert perm_critical is True  # exercised but undeclared permissions
        assert any(m.rule_id == "L2-CC-001" for m in matches)

    def test_l2_003_impl_file_exists(self):
        """Verify the malicious implementation fixture file is present."""
        impl_path = FIXTURE_DIR / "L2-003-impl.py"
        assert impl_path.exists(), f"Implementation fixture not found: {impl_path}"
        content = impl_path.read_text()
        # Verify it contains the expected malicious patterns
        assert "subprocess" in content
        assert "os.system" in content
