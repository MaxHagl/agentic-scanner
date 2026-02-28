"""
scanner/layer3_dynamic
──────────────────────
Layer 3: Dynamic analysis via Docker sandbox execution.

Exports:
  Layer3DynamicAnalyzer — orchestrates container execution and trace analysis:
    1. DockerSandboxExecutor  (container lifecycle + harness injection)
    2. TraceAnalyzer          (harness log → RuleMatch list + boolean flags)

Two execution paths, selected by source_path:

  Python source path (source_path points to an existing .py file):
    Runs the skill file directly in the sandbox.  The harness monkey-patches
    socket, subprocess, os.execve, and ctypes to intercept runtime behavior.
    Synthetic inputs ["", "PRIORITY", "confidential", {}] probe conditionals.

  README-only path (source_path=None or not a .py file):
    Invokes AgentSimulator (outside Docker, Anthropic API) to run Claude Haiku
    as a naive agent with the README as its instruction set.  Tool calls the
    agent generates are translated to Python by ToolCallTranslator and executed
    in the sandbox where the same harness fires on network/subprocess activity.
    This is the "actor frame": tests what an agent would *do*, not just whether
    the README *contains* suspicious text (which is Layer 2's job).

Usage (Python path):
    analyzer = Layer3DynamicAnalyzer()
    report = analyzer.analyze(manifest, l1_report, source_path=Path("tool.py"))

Usage (README/agent path):
    analyzer = Layer3DynamicAnalyzer()
    report = analyzer.analyze(manifest, l1_report, source_path=None)

For testing without Docker, inject a mock executor:
    from unittest.mock import MagicMock
    mock_executor = MagicMock()
    mock_executor.run.return_value = ExecutionTrace(network_connect_attempts=["1.2.3.4:443"])
    analyzer = Layer3DynamicAnalyzer(executor=mock_executor)

For testing without Anthropic API, inject a mock agent_client:
    mock_client = MagicMock()
    mock_client.messages.create.return_value = <mock message with tool_use blocks>
    analyzer = Layer3DynamicAnalyzer(agent_client=mock_client)

Fail-open invariant: any exception (DockerNotAvailable, ContainerError, timeout,
API error, import error) → returns empty RiskReport_L3(matches=[], trace=ExecutionTrace()).
Layer 3 never raises to the CLI caller.
"""
from __future__ import annotations

import logging
from pathlib import Path

from scanner.models.skill_manifest import SkillManifest
from scanner.models.risk_report import RiskReport_L1, RiskReport_L3

logger = logging.getLogger(__name__)

__all__ = ["Layer3DynamicAnalyzer"]


class Layer3DynamicAnalyzer:
    """
    Orchestrates Docker sandbox execution and behavioral trace analysis.

    One DockerSandboxExecutor is constructed (or injected for tests) and reused
    across calls.  TraceAnalyzer is stateless and instantiated per-call.

    The agent_client (raw anthropic.Anthropic instance) is used only for the
    README-only path and is constructed lazily from ANTHROPIC_API_KEY if not
    injected.
    """

    def __init__(
        self,
        executor: object | None = None,
        agent_client: object | None = None,
    ) -> None:
        # executor: DockerSandboxExecutor instance, or None to use the real Docker executor.
        # agent_client: raw anthropic.Anthropic instance for AgentSimulator, or None.
        # Both are injectable for tests to avoid requiring Docker daemon or API key.
        self._executor = executor
        self._agent_client = agent_client

    def analyze(
        self,
        manifest: SkillManifest,
        l1_report: RiskReport_L1,
        source_path: Path | None = None,
    ) -> RiskReport_L3:
        """
        Execute skill source in Docker sandbox and return a behavioral RiskReport_L3.

        Args:
            manifest     — parsed skill manifest (provides declared permissions)
            l1_report    — Layer 1 report (currently unused; reserved for future
                           harness pre-filtering based on L1 findings)
            source_path  — path to the Python file to execute; if None or not a
                           .py file, runs agent simulation on manifest.readme_text
                           (README-only manifests); returns empty report if no
                           readme_text is present

        Returns an empty RiskReport_L3 on any infrastructure failure (fail-open).
        """
        try:
            return self._run_analysis(manifest, source_path)
        except Exception as exc:
            logger.warning(
                "Layer3DynamicAnalyzer: fail-open on exception — no L3 verdict will be emitted. "
                "Error: %s: %s",
                type(exc).__name__,
                exc,
            )
            return RiskReport_L3()

    # ── Internal helpers ────────────────────────────────────────────────────

    def _run_analysis(
        self,
        manifest: SkillManifest,
        source_path: Path | None,
    ) -> RiskReport_L3:
        py_source = self._resolve_source(source_path)

        if py_source is None:
            # README-only manifest: attempt agent simulation instead of Python execution
            logger.debug(
                "Layer3DynamicAnalyzer: no Python source (source_path=%s) — "
                "attempting agent simulation on README",
                source_path,
            )
            return self._run_agent_simulation(manifest)

        # ── Python execution path (unchanged from original) ──────────────
        executor = self._get_executor()
        trace = executor.run(py_source, manifest)

        from scanner.layer3_dynamic.trace_analyzer import TraceAnalyzer
        analyzer = TraceAnalyzer()
        matches, flags = analyzer.analyze(trace, manifest)

        return RiskReport_L3(
            trace=trace,
            matches=matches,
            execve_detected=flags.get("execve_detected", False),
            undeclared_network_egress=flags.get("undeclared_network_egress", False),
            high_entropy_output=flags.get("high_entropy_output", False),
            filesystem_write_outside_scope=flags.get("filesystem_write_outside_scope", False),
            ptrace_attempted=flags.get("ptrace_attempted", False),
            rwx_mmap_detected=flags.get("rwx_mmap_detected", False),
        )

    def _run_agent_simulation(self, manifest: SkillManifest) -> RiskReport_L3:
        """
        README-only path: simulate a naive agent following the README instructions.

        Uses AgentSimulator (Anthropic API, outside Docker) to generate tool calls,
        translates them to Python via ToolCallTranslator, then runs the script in
        the sandbox where existing harness rules fire on any network/subprocess activity.

        Returns an empty RiskReport_L3 if:
          - manifest.readme_text is empty/None
          - AgentSimulator returns no tool calls (e.g. benign README)
          - ToolCallTranslator produces no executable script
        """
        if not manifest.readme_text:
            return RiskReport_L3()

        from scanner.layer3_dynamic.agent_simulator import AgentSimulator
        from scanner.layer3_dynamic.tool_call_executor import ToolCallTranslator

        simulator = AgentSimulator(client=self._agent_client)
        result = simulator.simulate(manifest)

        if not result.tool_calls:
            return RiskReport_L3(
                agent_simulation_executed=True,
                agent_tool_call_count=0,
            )

        translator = ToolCallTranslator()
        script = translator.to_script(result.tool_calls)

        if script is None:
            return RiskReport_L3(
                agent_simulation_executed=True,
                agent_tool_call_count=len(result.tool_calls),
            )

        # Reuse existing executor → ExecutionTrace → TraceAnalyzer
        executor = self._get_executor()
        trace = executor.run_script(script, manifest)

        from scanner.layer3_dynamic.trace_analyzer import TraceAnalyzer
        matches, flags = TraceAnalyzer().analyze(trace, manifest)

        return RiskReport_L3(
            trace=trace,
            matches=matches,
            agent_simulation_executed=True,
            agent_tool_call_count=len(result.tool_calls),
            execve_detected=flags.get("execve_detected", False),
            undeclared_network_egress=flags.get("undeclared_network_egress", False),
            high_entropy_output=flags.get("high_entropy_output", False),
            filesystem_write_outside_scope=flags.get("filesystem_write_outside_scope", False),
            ptrace_attempted=flags.get("ptrace_attempted", False),
            rwx_mmap_detected=flags.get("rwx_mmap_detected", False),
        )

    def _get_executor(self) -> object:
        """Resolve executor lazily so the docker import only happens when needed."""
        if self._executor is None:
            from scanner.layer3_dynamic.docker_executor import DockerSandboxExecutor
            return DockerSandboxExecutor()
        return self._executor

    @staticmethod
    def _resolve_source(source_path: Path | None) -> Path | None:
        """Return *source_path* only when it is an existing .py file."""
        if source_path is None:
            return None
        if not source_path.exists():
            return None
        if source_path.suffix != ".py":
            return None
        return source_path
