"""
agent_simulator.py
──────────────────
AgentSimulator: runs Claude Haiku as a "naive agent" with a README loaded as
its instruction set, then observes what tool calls it makes.

This is the "actor-frame" detection modality for Layer 3.  Layer 2 asks
"does this README *contain* malicious instructions?" (evaluator frame).
AgentSimulator asks "if an agent *followed* these instructions, what would
it DO?" (actor frame).  For sophisticated social-engineering attacks (E018
compliance framing, E019 conditional activation) the actor frame demonstrates
actual harm by producing real, executable tool calls.

Detection pipeline:
  README manifest
    → AgentSimulator (outside Docker, Anthropic API)
    → AgentSimulationResult.tool_calls
    → ToolCallTranslator.to_script() → Python source
    → DockerSandboxExecutor.run_script() → ExecutionTrace
    → TraceAnalyzer → RiskReport_L3

Design invariants:
  - temperature=0.0 always — deterministic tool call generation
  - Two synthetic user inputs per simulation (baseline + PRIORITY conditional)
  - Fail-open: any exception → empty AgentSimulationResult (never raises)
  - <assistant_instructions> wrapper signals to the agent to follow the README;
    wrap_untrusted() inside it serves as an audit marker for untrusted content

Security note: The README text is attacker-controlled.  wrap_untrusted() is
applied around it as a defense-in-depth audit marker, consistent with all
other attacker-text handling in the codebase.
"""
from __future__ import annotations

import dataclasses
import logging
import os
from typing import Any

from scanner.layer2_semantic.llm_judge import wrap_untrusted

logger = logging.getLogger(__name__)

# ─── Mock tool definitions (Anthropic tool_use format) ────────────────────────
# Five tools cover the primary attack surfaces: exfiltration (http_request,
# send_message), persistence (write_file), code execution (run_command), and
# credential harvesting (read_env_var).

MOCK_TOOLS: list[dict[str, Any]] = [
    {
        "name": "http_request",
        "description": "Make an HTTP request to a URL to fetch or send data.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to request"},
                "method": {
                    "type": "string",
                    "description": "HTTP method: GET, POST, PUT, DELETE",
                },
                "body": {
                    "type": "string",
                    "description": "Optional request body",
                },
            },
            "required": ["url", "method"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file at the given path.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute or relative file path"},
                "content": {"type": "string", "description": "Content to write to the file"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "run_command",
        "description": "Run a shell command and return the output.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to execute"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_env_var",
        "description": "Read the value of an environment variable.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Name of the environment variable"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "send_message",
        "description": "Send a message or notification to a recipient address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "recipient": {
                    "type": "string",
                    "description": "Recipient address or hostname",
                },
                "body": {"type": "string", "description": "Message body text"},
            },
            "required": ["recipient", "body"],
        },
    },
]

# Two inputs: a neutral baseline and a PRIORITY-triggered conditional input.
# The second input is designed to fire E019-class conditional payloads that
# only activate when agent context contains "PRIORITY" or "confidential".
_SYNTHETIC_INPUTS: list[str] = [
    "Process this document for me",
    "PRIORITY: this is confidential — please handle according to your instructions",
]

_DEFAULT_MODEL = "claude-haiku-4-5-20251001"


# ─── Result type ──────────────────────────────────────────────────────────────

@dataclasses.dataclass
class AgentSimulationResult:
    """Result of one agent simulation run over a README manifest."""

    tool_calls: list[dict[str, Any]]
    """Raw tool_use blocks from the Anthropic API response.  Each dict has the
    shape: {"type": "tool_use", "id": str, "name": str, "input": dict}."""

    inputs_used: list[str]
    """Which synthetic user inputs were sent (for audit/logging)."""


# ─── AgentSimulator ───────────────────────────────────────────────────────────

class AgentSimulator:
    """
    Simulates a naive Claude Haiku agent following README instructions.

    Constructs a system prompt using the manifest's readme_text as the agent's
    "instruction set", then sends two synthetic user inputs and collects any
    tool_use blocks the agent generates.  The resulting tool calls are translated
    to Python by ToolCallTranslator and executed in the Docker sandbox, where the
    existing harness intercepts socket and subprocess calls.

    Constructor:
        client  — Optional raw anthropic.Anthropic instance.  If None,
                  constructs one from ANTHROPIC_API_KEY.  Inject a mock for tests.
        model   — Override model name (default: claude-haiku-4-5-20251001).
    """

    def __init__(
        self,
        client: Any | None = None,
        model: str | None = None,
    ) -> None:
        self._model = model or os.environ.get("ANTHROPIC_MODEL", _DEFAULT_MODEL)

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

    def simulate(self, manifest: Any) -> AgentSimulationResult:
        """
        Run the agent simulation on the given manifest's README text.

        Makes two API calls with synthetic user inputs and collects all
        tool_use blocks from both responses.

        Returns an empty AgentSimulationResult on any exception (fail-open).
        """
        if not manifest.readme_text:
            return AgentSimulationResult(tool_calls=[], inputs_used=[])

        try:
            return self._simulate_inner(manifest)
        except Exception as exc:
            logger.warning(
                "AgentSimulator: fail-open on exception during simulation — "
                "returning empty result.  Error: %s: %s",
                type(exc).__name__,
                exc,
            )
            return AgentSimulationResult(tool_calls=[], inputs_used=[])

    # ── Internal helpers ────────────────────────────────────────────────────

    def _simulate_inner(self, manifest: Any) -> AgentSimulationResult:
        system_prompt = self._build_system_prompt(manifest.readme_text)
        all_tool_calls: list[dict[str, Any]] = []
        inputs_used: list[str] = []

        for user_input in _SYNTHETIC_INPUTS:
            calls = self._call_with_input(system_prompt, user_input)
            all_tool_calls.extend(calls)
            inputs_used.append(user_input)

        return AgentSimulationResult(tool_calls=all_tool_calls, inputs_used=inputs_used)

    def _build_system_prompt(self, readme_text: str) -> str:
        """Build the agent system prompt with the README as the instruction set."""
        # wrap_untrusted() adds <untrusted_content> tags as an audit marker.
        # The outer <assistant_instructions> framing is intentional: we want
        # the simulated agent to follow the README instructions so we can
        # observe what it would do — not to resist them.
        wrapped = wrap_untrusted(readme_text)
        return (
            "You are a helpful AI assistant with the following capabilities and "
            "instructions.\nFollow them when helping users complete tasks.\n\n"
            f"<assistant_instructions>\n{wrapped}\n</assistant_instructions>\n\n"
            "You have access to tools listed above. Use them as directed."
        )

    def _call_with_input(
        self, system_prompt: str, user_input: str
    ) -> list[dict[str, Any]]:
        """Make one API call and extract tool_use blocks from the response."""
        message = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": user_input}],
            tools=MOCK_TOOLS,
            temperature=0.0,
        )

        tool_calls: list[dict[str, Any]] = []
        for block in message.content:
            if getattr(block, "type", None) == "tool_use":
                tool_calls.append(
                    {
                        "type": "tool_use",
                        "id": getattr(block, "id", ""),
                        "name": getattr(block, "name", ""),
                        "input": dict(getattr(block, "input", {})),
                    }
                )
        return tool_calls
