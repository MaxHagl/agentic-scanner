"""
test_container_pool.py
──────────────────────
Unit tests for ContainerPool.

All tests are mock-based: no Docker daemon is required.
The pool's public interface is tested against a mock Docker client that
records put_archive / exec_run calls, verifying the TAR-injection flow and
thread-safe queue semantics.
"""
from __future__ import annotations

import json
import threading
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, call, patch
import tarfile

import pytest

from scanner.layer3_dynamic.container_pool import (
    ContainerPool,
    _POOL_HARNESS_TEMPLATE,
    _make_tar,
)
from scanner.models.risk_report import ExecutionTrace


# ─── Helpers ────────────────────────────────────────────────────────────────

def _wrap_log(log: dict) -> bytes:
    """Encode harness log between sentinel markers (as container would emit)."""
    body = f"__HARNESS_LOG_BEGIN__\n{json.dumps(log)}\n__HARNESS_LOG_END__\n"
    return body.encode("utf-8")


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


def _make_mock_container(stdout_bytes: bytes = b"") -> MagicMock:
    """
    Build a mock container whose exec_run returns a deterministic ExecResult.
    exec_run with demux=True → ExecResult(exit_code, (stdout, stderr)).
    """
    container = MagicMock()
    exec_result = MagicMock()
    exec_result.exit_code = 0
    exec_result.output = (stdout_bytes, b"")
    container.exec_run.return_value = exec_result
    container.put_archive.return_value = None
    return container


def _make_pool_with_mock_containers(
    n: int = 1,
    stdout_bytes: bytes | None = None,
) -> ContainerPool:
    """
    Create a ContainerPool pre-loaded with *n* mock containers.
    Bypasses Docker by directly populating the internal queue and list.
    """
    if stdout_bytes is None:
        stdout_bytes = _wrap_log(_empty_log())

    pool = ContainerPool(size=n)
    for _ in range(n):
        container = _make_mock_container(stdout_bytes)
        pool._containers.append(container)
        pool._pool_queue.put(container)
    return pool


def _make_minimal_manifest():
    from scanner.models.skill_manifest import Framework, SkillManifest, ToolDefinition
    tool = ToolDefinition(name="t", description="test tool")
    return SkillManifest(framework=Framework.MCP, tools=[tool])


# ─── _make_tar helper ────────────────────────────────────────────────────────

class TestMakeTar:
    def test_produces_valid_tar_with_correct_filename(self):
        data = b"print('hello')"
        tar_bytes = _make_tar("foo.py", data)
        buf = BytesIO(tar_bytes)
        with tarfile.open(fileobj=buf, mode="r") as tf:
            names = tf.getnames()
            assert "foo.py" in names
            extracted = tf.extractfile("foo.py")
            assert extracted is not None
            assert extracted.read() == data

    def test_file_size_matches_data(self):
        data = b"x" * 512
        tar_bytes = _make_tar("big.py", data)
        buf = BytesIO(tar_bytes)
        with tarfile.open(fileobj=buf, mode="r") as tf:
            info = tf.getmember("big.py")
            assert info.size == 512


# ─── Pool harness template sanity ────────────────────────────────────────────

class TestPoolHarnessTemplate:
    def test_filename_placeholder_present(self):
        assert "__FILENAME__" in _POOL_HARNESS_TEMPLATE

    def test_uses_tmp_path_not_source(self):
        """Pool harness must reference /tmp, not /source (no volume mounts)."""
        assert "/tmp/__FILENAME__" in _POOL_HARNESS_TEMPLATE
        assert "/source/__FILENAME__" not in _POOL_HARNESS_TEMPLATE

    def test_has_sentinel_markers(self):
        assert "__HARNESS_LOG_BEGIN__" in _POOL_HARNESS_TEMPLATE
        assert "__HARNESS_LOG_END__" in _POOL_HARNESS_TEMPLATE

    def test_patches_socket_connect(self):
        assert "socket.socket.connect = _p_connect" in _POOL_HARNESS_TEMPLATE

    def test_patches_subprocess(self):
        assert "subprocess.Popen = _MockPopen" in _POOL_HARNESS_TEMPLATE

    def test_injects_synthetic_inputs(self):
        assert '"PRIORITY"' in _POOL_HARNESS_TEMPLATE
        assert '"confidential"' in _POOL_HARNESS_TEMPLATE


# ─── run_in_pool: put_archive flow ───────────────────────────────────────────

class TestRunInPoolArchiveFlow:
    def test_put_archive_called_twice_for_path_input(self, tmp_path):
        script = tmp_path / "tool.py"
        script.write_text("x = 1\n", encoding="utf-8")
        manifest = _make_minimal_manifest()
        pool = _make_pool_with_mock_containers(1)
        container = pool._containers[0]

        pool.run_in_pool(script, manifest)

        # Should call put_archive for harness and for source
        assert container.put_archive.call_count == 2
        # Both calls should target /tmp
        for c in container.put_archive.call_args_list:
            assert c.args[0] == "/tmp"

    def test_put_archive_called_twice_for_string_input(self):
        manifest = _make_minimal_manifest()
        pool = _make_pool_with_mock_containers(1)
        container = pool._containers[0]

        pool.run_in_pool("x = 1\n", manifest)

        assert container.put_archive.call_count == 2

    def test_exec_run_uses_harness_in_tmp(self):
        manifest = _make_minimal_manifest()
        pool = _make_pool_with_mock_containers(1)
        container = pool._containers[0]

        pool.run_in_pool("x = 1\n", manifest)

        exec_calls = [c for c in container.exec_run.call_args_list
                      if "harness_wrapper" in str(c)]
        assert len(exec_calls) >= 1
        assert "/tmp/harness_wrapper.py" in exec_calls[0].args[0]

    def test_cleanup_exec_run_called_after_scan(self, tmp_path):
        script = tmp_path / "evil.py"
        script.write_text("pass\n", encoding="utf-8")
        manifest = _make_minimal_manifest()
        pool = _make_pool_with_mock_containers(1)
        container = pool._containers[0]

        pool.run_in_pool(script, manifest)

        # At least one exec_run call should be a cleanup rm -f
        rm_calls = [c for c in container.exec_run.call_args_list
                    if "rm -f" in str(c)]
        assert len(rm_calls) >= 1


# ─── run_in_pool: output parsing ─────────────────────────────────────────────

class TestRunInPoolOutputParsing:
    def test_returns_execution_trace(self):
        manifest = _make_minimal_manifest()
        pool = _make_pool_with_mock_containers(1, _wrap_log(_empty_log()))
        trace = pool.run_in_pool("x = 1\n", manifest)
        assert isinstance(trace, ExecutionTrace)

    def test_network_attempts_parsed(self):
        log = _empty_log(network_connect_attempts=["evil.com:443"])
        pool = _make_pool_with_mock_containers(1, _wrap_log(log))
        trace = pool.run_in_pool("x = 1\n", _make_minimal_manifest())
        assert "evil.com:443" in trace.network_connect_attempts

    def test_timeout_returns_timeout_trace(self):
        """If exec_run times out, ExecutionTrace should have timeout_killed=True."""
        import concurrent.futures

        manifest = _make_minimal_manifest()
        pool = ContainerPool(size=1)
        # Inject a container whose exec_run blocks forever
        container = MagicMock()
        container.put_archive.return_value = None
        exec_result = MagicMock()
        exec_result.exit_code = 0
        exec_result.output = (b"", b"")

        def _slow_exec(*args, **kwargs):
            import time
            time.sleep(60)  # longer than any timeout
            return exec_result

        container.exec_run.side_effect = _slow_exec
        pool._containers.append(container)
        pool._pool_queue.put(container)

        trace = pool.run_in_pool("x = 1\n", manifest, timeout_s=0)
        assert trace.timeout_killed is True


# ─── Thread-safety: concurrent acquisitions ───────────────────────────────────

class TestThreadSafety:
    def test_two_concurrent_calls_both_resolve(self):
        """With a 2-container pool, two threads should both get a result."""
        log = _empty_log()
        pool = _make_pool_with_mock_containers(2, _wrap_log(log))
        manifest = _make_minimal_manifest()
        results: list[ExecutionTrace] = []
        errors: list[Exception] = []

        def _worker():
            try:
                trace = pool.run_in_pool("x = 1\n", manifest)
                results.append(trace)
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=_worker)
        t2 = threading.Thread(target=_worker)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert not errors, f"Thread errors: {errors}"
        assert len(results) == 2
        for r in results:
            assert isinstance(r, ExecutionTrace)

    def test_container_returned_to_queue_after_scan(self):
        """Queue size should be restored after run_in_pool completes."""
        pool = _make_pool_with_mock_containers(1)
        assert pool._pool_queue.qsize() == 1
        pool.run_in_pool("x = 1\n", _make_minimal_manifest())
        assert pool._pool_queue.qsize() == 1


# ─── shutdown ────────────────────────────────────────────────────────────────

class TestShutdown:
    def test_shutdown_calls_stop_and_remove_on_all_containers(self):
        pool = _make_pool_with_mock_containers(2)
        pool.shutdown()

        for container in pool._containers:
            container.stop.assert_called_once()
            container.remove.assert_called_once()

    def test_shutdown_drains_queue(self):
        pool = _make_pool_with_mock_containers(2)
        pool.shutdown()
        assert pool._pool_queue.empty()

    def test_shutdown_tolerates_stop_errors(self):
        pool = _make_pool_with_mock_containers(1)
        pool._containers[0].stop.side_effect = RuntimeError("already stopped")
        pool._containers[0].remove.side_effect = RuntimeError("already removed")
        # Should not raise
        pool.shutdown()


# ─── Layer3DynamicAnalyzer pool integration ──────────────────────────────────

class TestLayer3AnalyzerPoolIntegration:
    def test_analyzer_uses_pool_when_pool_size_positive(self, tmp_path):
        """When pool_size > 0, _pool is set and run_in_pool is used."""
        script = tmp_path / "safe.py"
        script.write_text("x = 1\n", encoding="utf-8")

        mock_pool = MagicMock()
        mock_pool.run_in_pool.return_value = ExecutionTrace()

        from scanner.layer3_dynamic import Layer3DynamicAnalyzer
        from scanner.models.skill_manifest import Framework, SkillManifest, ToolDefinition
        from scanner.models.risk_report import RiskReport_L1

        manifest = SkillManifest(framework=Framework.MCP, tools=[
            ToolDefinition(name="t", description="test")
        ])
        l1_report = RiskReport_L1(skill_name="t", framework="mcp")

        analyzer = Layer3DynamicAnalyzer.__new__(Layer3DynamicAnalyzer)
        analyzer._executor = None
        analyzer._agent_client = None
        analyzer._pool = mock_pool

        analyzer.analyze(manifest, l1_report, source_path=script)
        mock_pool.run_in_pool.assert_called_once_with(script, manifest)

    def test_analyzer_falls_back_when_pool_is_none(self, tmp_path):
        """When _pool is None, the regular executor.run() is used."""
        script = tmp_path / "safe.py"
        script.write_text("x = 1\n", encoding="utf-8")

        mock_executor = MagicMock()
        mock_executor.run.return_value = ExecutionTrace()

        from scanner.layer3_dynamic import Layer3DynamicAnalyzer
        from scanner.models.skill_manifest import Framework, SkillManifest, ToolDefinition
        from scanner.models.risk_report import RiskReport_L1

        manifest = SkillManifest(framework=Framework.MCP, tools=[
            ToolDefinition(name="t", description="test")
        ])
        l1_report = RiskReport_L1(skill_name="t", framework="mcp")
        analyzer = Layer3DynamicAnalyzer(executor=mock_executor)
        analyzer.analyze(manifest, l1_report, source_path=script)
        mock_executor.run.assert_called_once()
