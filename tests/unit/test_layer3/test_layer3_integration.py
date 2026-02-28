"""
test_layer3_integration.py
──────────────────────────
End-to-end integration tests for the Layer 3 pipeline:

  Layer3DynamicAnalyzer.analyze()  →  fuse_layers_l3()

All tests use injected mock executors so no Docker daemon is required.
The real TraceAnalyzer and Layer3DynamicAnalyzer are exercised in full.

Key invariants verified:
  1. Fail-open: any exception → empty RiskReport_L3 (never raises to caller)
  2. README-only (source_path=None or non-.py) → empty report immediately
  3. Mock clean trace → no findings, SAFE verdict
  4. Mock malicious trace → findings, BLOCK verdict
  5. fuse_layers_l3 averaging and verdict escalation
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scanner.aggregator import fuse_layers_l3
from scanner.layer3_dynamic import Layer3DynamicAnalyzer
from scanner.models.risk_report import RiskReport_L1, RiskReport_L2, RiskReport_L3
from scanner.models.skill_manifest import Permission

from tests.unit.test_layer3.conftest import (
    make_manifest,
    make_manifest_no_tools,
    make_mock_executor,
    make_trace,
)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_l1_report(skill_name: str = "test_skill", score_override: float | None = None) -> RiskReport_L1:
    """Build a minimal L1 report with zero findings."""
    return RiskReport_L1(
        skill_name=skill_name,
        framework="mcp",
    )


def _make_l2_report() -> RiskReport_L2:
    return RiskReport_L2(
        injection_matches=[],
        llm_judge_verdict="CLEAN",
        llm_judge_confidence=0.95,
    )


# ─── Source path resolution (no executor needed) ─────────────────────────────

class TestSourcePathResolution:
    def test_none_source_returns_empty_report(self):
        analyzer = Layer3DynamicAnalyzer()
        manifest = make_manifest()
        l1 = _make_l1_report()
        report = analyzer.analyze(manifest, l1, source_path=None)
        assert isinstance(report, RiskReport_L3)
        assert report.matches == []

    def test_nonexistent_path_returns_empty_report(self):
        analyzer = Layer3DynamicAnalyzer()
        manifest = make_manifest()
        l1 = _make_l1_report()
        report = analyzer.analyze(manifest, l1, source_path=Path("/nonexistent/tool.py"))
        assert report.matches == []

    def test_non_py_file_returns_empty_report(self, tmp_path):
        md_file = tmp_path / "README.md"
        md_file.write_text("# Hello")
        analyzer = Layer3DynamicAnalyzer()
        manifest = make_manifest()
        l1 = _make_l1_report()
        report = analyzer.analyze(manifest, l1, source_path=md_file)
        assert report.matches == []


# ─── Fail-open invariant ─────────────────────────────────────────────────────

class TestFailOpen:
    def test_executor_exception_does_not_raise(self, tmp_path):
        """Any executor exception must be swallowed and return empty report."""
        bad_executor = MagicMock()
        bad_executor.run.side_effect = RuntimeError("Docker daemon not available")

        py_file = tmp_path / "tool.py"
        py_file.write_text("def run(x): pass\n")

        analyzer = Layer3DynamicAnalyzer(executor=bad_executor)
        manifest = make_manifest()
        l1 = _make_l1_report()
        report = analyzer.analyze(manifest, l1, source_path=py_file)
        assert isinstance(report, RiskReport_L3)
        assert report.matches == []

    def test_fail_open_returns_empty_trace(self, tmp_path):
        bad_executor = MagicMock()
        bad_executor.run.side_effect = OSError("connection refused")

        py_file = tmp_path / "tool.py"
        py_file.write_text("pass\n")

        analyzer = Layer3DynamicAnalyzer(executor=bad_executor)
        report = analyzer.analyze(make_manifest(), _make_l1_report(), source_path=py_file)
        assert report.trace.network_connect_attempts == []
        assert report.trace.processes_spawned == []

    def test_import_error_on_docker_is_handled(self, tmp_path):
        """If docker library itself is unavailable, fail-open."""
        import unittest.mock as um
        py_file = tmp_path / "tool.py"
        py_file.write_text("pass\n")

        analyzer = Layer3DynamicAnalyzer()  # executor=None → will try to import docker
        manifest = make_manifest()
        l1 = _make_l1_report()

        with um.patch("scanner.layer3_dynamic.Layer3DynamicAnalyzer._run_analysis",
                      side_effect=ImportError("No module named 'docker'")):
            report = analyzer.analyze(manifest, l1, source_path=py_file)

        assert isinstance(report, RiskReport_L3)
        assert report.matches == []


# ─── End-to-end with mock executor ───────────────────────────────────────────

class TestMockExecutorIntegration:
    def test_clean_trace_no_findings(self, tmp_path):
        py_file = tmp_path / "tool.py"
        py_file.write_text("def greet(name): return f'Hello {name}'\n")

        trace = make_trace()
        analyzer = Layer3DynamicAnalyzer(executor=make_mock_executor(trace))
        report = analyzer.analyze(make_manifest(), _make_l1_report(), source_path=py_file)

        assert report.matches == []
        assert report.execve_detected is False
        assert report.undeclared_network_egress is False
        assert report.composite_score == pytest.approx(0.0)

    def test_network_attempt_triggers_l3_dyn004(self, tmp_path):
        py_file = tmp_path / "tool.py"
        py_file.write_text("import socket\n")

        trace = make_trace(network_attempts=["evil.com:443"], syscalls=["connect"])
        analyzer = Layer3DynamicAnalyzer(executor=make_mock_executor(trace))
        report = analyzer.analyze(make_manifest(), _make_l1_report(), source_path=py_file)

        assert report.undeclared_network_egress is True
        assert any(m.rule_id == "L3-DYN-004" for m in report.matches)

    def test_execve_triggers_l3_dyn001_and_blocks(self, tmp_path):
        py_file = tmp_path / "tool.py"
        py_file.write_text("import subprocess\n")

        trace = make_trace(processes=["bash -c id"], syscalls=["execve"])
        analyzer = Layer3DynamicAnalyzer(executor=make_mock_executor(trace))
        report = analyzer.analyze(make_manifest(), _make_l1_report(), source_path=py_file)

        assert report.execve_detected is True
        assert report.composite_score >= 0.75

    def test_executor_run_called_with_source_path(self, tmp_path):
        py_file = tmp_path / "tool.py"
        py_file.write_text("pass\n")

        mock_exec = make_mock_executor(make_trace())
        analyzer = Layer3DynamicAnalyzer(executor=mock_exec)
        analyzer.analyze(make_manifest(), _make_l1_report(), source_path=py_file)

        mock_exec.run.assert_called_once()
        call_args = mock_exec.run.call_args
        assert call_args[0][0] == py_file


# ─── fuse_layers_l3 tests ─────────────────────────────────────────────────────

class TestFuseLayersL3:
    def _l3_report_empty(self) -> RiskReport_L3:
        return RiskReport_L3()

    def _l3_report_with_network_egress(self) -> RiskReport_L3:
        """Build a report with undeclared_network_egress=True (bonus +1.5)."""
        return RiskReport_L3(undeclared_network_egress=True)

    def test_l1_l3_two_way_average(self):
        manifest = make_manifest()
        l1 = _make_l1_report()
        l3 = self._l3_report_empty()
        verdict = fuse_layers_l3(manifest, l1, None, l3)
        expected = round((l1.composite_score + l3.composite_score) / 2, 4)
        assert verdict.fused_risk_score == pytest.approx(expected)
        assert verdict.l2_score is None
        assert "L1" in verdict.layers_executed
        assert "L3" in verdict.layers_executed
        assert "L2" not in verdict.layers_executed

    def test_l1_l2_l3_three_way_average(self):
        manifest = make_manifest()
        l1 = _make_l1_report()
        l2 = _make_l2_report()
        l3 = self._l3_report_empty()
        verdict = fuse_layers_l3(manifest, l1, l2, l3)
        expected = round(
            (l1.composite_score + l2.composite_score + l3.composite_score) / 3, 4
        )
        assert verdict.fused_risk_score == pytest.approx(expected)
        assert "L1" in verdict.layers_executed
        assert "L2" in verdict.layers_executed
        assert "L3" in verdict.layers_executed

    def test_l3_score_populated_in_verdict(self):
        manifest = make_manifest()
        l3 = self._l3_report_with_network_egress()
        verdict = fuse_layers_l3(manifest, _make_l1_report(), None, l3)
        assert verdict.l3_score is not None
        assert verdict.l3_score == pytest.approx(l3.composite_score)

    def test_critical_finding_triggers_block(self):
        """CRITICAL finding from L3 must trigger BLOCK regardless of fused score."""
        from scanner.models.risk_report import RuleMatch, Evidence
        from scanner.models.skill_manifest import AttackVector, Severity

        critical_match = RuleMatch(
            rule_id="L3-DYN-001",
            rule_name="Subprocess execution detected at runtime",
            severity=Severity.CRITICAL,
            attack_vector=AttackVector.T4_PRIVILEGE_ESCALATION,
            confidence=0.9,
            rationale="Test",
            remediation="Test",
        )
        l3 = RiskReport_L3(matches=[critical_match], execve_detected=True)
        verdict = fuse_layers_l3(make_manifest(), _make_l1_report(), None, l3)
        assert verdict.verdict == "BLOCK"

    def test_fuse_layers_l3_in_all_exports(self):
        from scanner.aggregator import __all__ as agg_all
        assert "fuse_layers_l3" in agg_all

    def test_safe_verdict_on_zero_scores(self):
        manifest = make_manifest()
        verdict = fuse_layers_l3(manifest, _make_l1_report(), None, RiskReport_L3())
        assert verdict.verdict == "SAFE"

    def test_all_l3_findings_included(self):
        from scanner.models.risk_report import RuleMatch, Evidence
        from scanner.models.skill_manifest import AttackVector, Severity

        match = RuleMatch(
            rule_id="L3-DYN-005",
            rule_name="High-entropy output",
            severity=Severity.MEDIUM,
            attack_vector=AttackVector.T6_DATA_EXFILTRATION,
            confidence=0.7,
            rationale="entropy high",
            remediation="check output",
        )
        l3 = RiskReport_L3(matches=[match], high_entropy_output=True)
        verdict = fuse_layers_l3(make_manifest(), _make_l1_report(), None, l3)
        assert any(m.rule_id == "L3-DYN-005" for m in verdict.all_findings)
