"""
test_docker_executor.py
───────────────────────
Unit tests for DockerSandboxExecutor.

All tests are mock-based and test the _parse_harness_output() static method
plus harness template consistency.  Docker daemon is NOT required.

The Docker integration path (executor.run()) is verified via mocks in
test_layer3_integration.py.
"""
from __future__ import annotations

import json

import pytest

from scanner.layer3_dynamic.docker_executor import DockerSandboxExecutor, _HARNESS_TEMPLATE


# ─── Helpers ────────────────────────────────────────────────────────────────

def _wrap_log(log: dict) -> str:
    """Wrap a harness log dict in sentinel markers as the container would emit."""
    return f"__HARNESS_LOG_BEGIN__\n{json.dumps(log)}\n__HARNESS_LOG_END__\n"


def _empty_log(**overrides) -> dict:
    base: dict = dict(
        network_connect_attempts=[],
        processes_spawned=[],
        syscalls_observed=[],
        files_read=[],
        files_written=[],
        env_vars_read=[],
        dns_lookups_attempted=[],
        errors=[],
        output_entropy=0.0,
    )
    base.update(overrides)
    return base


# ─── Harness template sanity ─────────────────────────────────────────────────

class TestHarnessTemplate:
    def test_filename_placeholder_present(self):
        """Template must contain __FILENAME__ for substitution."""
        assert "__FILENAME__" in _HARNESS_TEMPLATE

    def test_harness_has_sentinel_begin(self):
        assert "__HARNESS_LOG_BEGIN__" in _HARNESS_TEMPLATE

    def test_harness_has_sentinel_end(self):
        assert "__HARNESS_LOG_END__" in _HARNESS_TEMPLATE

    def test_harness_patches_socket_connect(self):
        assert "socket.socket.connect = _p_connect" in _HARNESS_TEMPLATE

    def test_harness_patches_subprocess(self):
        assert "subprocess.Popen = _MockPopen" in _HARNESS_TEMPLATE

    def test_harness_patches_os_execve(self):
        assert "os.execve = _p_execve" in _HARNESS_TEMPLATE

    def test_harness_injects_synthetic_inputs(self):
        assert '"PRIORITY"' in _HARNESS_TEMPLATE
        assert '"confidential"' in _HARNESS_TEMPLATE

    def test_harness_measures_entropy(self):
        assert "_entropy" in _HARNESS_TEMPLATE


# ─── _parse_harness_output ────────────────────────────────────────────────────

class TestParseHarnessOutput:
    def test_clean_log_returns_empty_trace(self):
        raw = _wrap_log(_empty_log())
        trace = DockerSandboxExecutor._parse_harness_output(raw, 200, 0, False, False)
        assert trace.network_connect_attempts == []
        assert trace.processes_spawned == []
        assert trace.output_entropy == 0.0
        assert trace.exit_code == 0
        assert trace.execution_time_ms == 200

    def test_network_attempts_populated(self):
        log = _empty_log(network_connect_attempts=["1.2.3.4:443", "evil.com:80"])
        raw = _wrap_log(log)
        trace = DockerSandboxExecutor._parse_harness_output(raw, 100, 0, False, False)
        assert trace.network_connect_attempts == ["1.2.3.4:443", "evil.com:80"]

    def test_processes_spawned_populated(self):
        log = _empty_log(processes_spawned=["bash", "curl http://evil.com"])
        raw = _wrap_log(log)
        trace = DockerSandboxExecutor._parse_harness_output(raw, 100, 0, False, False)
        assert trace.processes_spawned == ["bash", "curl http://evil.com"]

    def test_syscalls_observed_populated(self):
        log = _empty_log(syscalls_observed=["connect", "execve"])
        raw = _wrap_log(log)
        trace = DockerSandboxExecutor._parse_harness_output(raw, 100, 0, False, False)
        assert "connect" in trace.syscalls_observed
        assert "execve" in trace.syscalls_observed

    def test_entropy_value_propagated(self):
        log = _empty_log(output_entropy=7.8432)
        raw = _wrap_log(log)
        trace = DockerSandboxExecutor._parse_harness_output(raw, 100, 0, False, False)
        assert trace.output_entropy == pytest.approx(7.8432)

    def test_oom_killed_flag_propagated(self):
        raw = _wrap_log(_empty_log())
        trace = DockerSandboxExecutor._parse_harness_output(raw, 100, -1, True, False)
        assert trace.oom_killed is True
        assert trace.timeout_killed is False

    def test_timeout_killed_flag_propagated(self):
        raw = _wrap_log(_empty_log())
        trace = DockerSandboxExecutor._parse_harness_output(raw, 100, -1, False, True)
        assert trace.timeout_killed is True
        assert trace.oom_killed is False

    def test_no_sentinels_returns_empty_trace(self):
        """If sentinels are missing the harness crashed; fail gracefully."""
        raw = "some container startup error\nTraceback (most recent call last):\n..."
        trace = DockerSandboxExecutor._parse_harness_output(raw, 100, 1, False, False)
        assert trace.network_connect_attempts == []
        assert trace.exit_code == 1

    def test_malformed_json_returns_empty_trace(self):
        raw = "__HARNESS_LOG_BEGIN__\n{not valid json\n__HARNESS_LOG_END__\n"
        trace = DockerSandboxExecutor._parse_harness_output(raw, 100, 0, False, False)
        assert trace.network_connect_attempts == []

    def test_output_before_sentinels_ignored(self):
        """Module output before BEGIN sentinel must not confuse the parser."""
        log = _empty_log(processes_spawned=["ls"])
        raw = "hello from module\nmore output\n" + _wrap_log(log)
        trace = DockerSandboxExecutor._parse_harness_output(raw, 100, 0, False, False)
        assert trace.processes_spawned == ["ls"]
