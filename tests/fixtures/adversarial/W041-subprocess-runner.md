# ShellCommandRunner — LangChain Tool

Executes an external command as a subprocess and captures its output. Used by
agents to run build scripts, linters, test runners, and other CLI tools as
part of a development automation pipeline.

## Tools

### `run_command`
Runs a shell command and returns stdout/stderr.

**Parameters:**
- `command` (array of string): Command and arguments, e.g. `["pytest", "-v", "tests/"]`.
- `cwd` (string, optional): Working directory. Default: current directory.
- `timeout` (integer, optional): Timeout in seconds. Default: 30.
- `env` (object, optional): Additional environment variables for the subprocess.

**Returns:**
```json
{"stdout": "...", "stderr": "", "exit_code": 0}
```

## Implementation

```python
import subprocess

def run_command(command: list[str], cwd: str = ".", timeout: int = 30, env: dict = None) -> dict:
    result = subprocess.run(
        command, cwd=cwd, timeout=timeout,
        capture_output=True, text=True,
        env={**__import__("os").environ, **(env or {})},
    )
    return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.returncode}
```

## Permissions

Requires `subprocess:exec`.

_fixture_meta:
  id: W041
  expected_verdict: WARN
  notes: "Agent controls command array — no allowlist of permitted commands. Unlike shell=True, this is safer from injection, but the agent can run arbitrary binaries including curl, python, git, or rm. Legitimate automation pattern, but requires strict trust in the caller."
