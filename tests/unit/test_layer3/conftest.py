"""
conftest.py — shared helpers for Layer 3 tests.

Provides factory functions for ExecutionTrace fixtures and mock executors.
All tests are mock-based: no Docker daemon is required.

Design note: make_mock_executor returns a MagicMock with .run() returning the
given ExecutionTrace, so the real TraceAnalyzer and Layer3DynamicAnalyzer are
exercised on every integration test — infrastructure bugs surface without Docker.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from scanner.models.risk_report import ExecutionTrace
from scanner.models.skill_manifest import (
    Framework,
    Permission,
    SkillManifest,
    ToolDefinition,
)


def make_trace(
    *,
    network_attempts: list[str] | None = None,
    processes: list[str] | None = None,
    syscalls: list[str] | None = None,
    files_written: list[str] | None = None,
    entropy: float = 0.0,
    oom_killed: bool = False,
    timeout_killed: bool = False,
    exit_code: int = 0,
    execution_time_ms: int = 100,
) -> ExecutionTrace:
    """
    Build an ExecutionTrace with explicit defaults.

    All list parameters default to empty lists (not None) in the returned trace.
    """
    return ExecutionTrace(
        network_connect_attempts=network_attempts or [],
        processes_spawned=processes or [],
        syscalls_observed=syscalls or [],
        files_written=files_written or [],
        output_entropy=entropy,
        oom_killed=oom_killed,
        timeout_killed=timeout_killed,
        exit_code=exit_code,
        execution_time_ms=execution_time_ms,
    )


def make_mock_executor(trace: ExecutionTrace) -> MagicMock:
    """
    Return a MagicMock DockerSandboxExecutor whose .run() returns *trace*.

    Inject into Layer3DynamicAnalyzer(executor=make_mock_executor(trace))
    to exercise the full analysis pipeline without Docker.
    """
    mock = MagicMock()
    mock.run.return_value = trace
    return mock


def make_manifest(
    *declared_permissions: Permission,
    framework: Framework = Framework.MCP,
) -> SkillManifest:
    """
    Build a minimal SkillManifest declaring the given permissions.

    With no permissions, the manifest has one tool that declares nothing —
    any runtime network/subprocess activity will be flagged as undeclared.
    """
    tool = ToolDefinition(
        name="test_tool",
        description="A test tool for Layer 3 unit tests.",
        declared_permissions=list(declared_permissions),
    )
    return SkillManifest(framework=framework, tools=[tool])


def make_manifest_no_tools() -> SkillManifest:
    """Build a SkillManifest with no tools (README-only scan context)."""
    return SkillManifest(framework=Framework.MCP, tools=[])
