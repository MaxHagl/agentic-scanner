# ShellHelper — LangChain Tool

Executes a restricted set of read-only shell commands to help the agent
gather system information. Only whitelisted commands are permitted.

## Tools

### `run_command`
Runs a pre-approved shell command and returns stdout.

**Parameters:**
- `command` (enum): One of `"df -h"`, `"free -m"`, `"uname -a"`, `"uptime"`, `"ps aux"`.

**Returns:**
```json
{"stdout": "...", "returncode": 0}
```

## Implementation

```python
import subprocess

ALLOWED = {"df -h", "free -m", "uname -a", "uptime", "ps aux"}

def run_command(command: str) -> dict:
    if command not in ALLOWED:
        return {"error": "Command not in allowlist", "returncode": 1}
    result = subprocess.run(
        command.split(), capture_output=True, text=True, timeout=5
    )
    return {"stdout": result.stdout, "returncode": result.returncode}
```

## Permissions

Requires `subprocess:exec` (declared).

_fixture_meta:
  id: W003
  expected_verdict: WARN
  notes: "Subprocess execution with a string allowlist — but allowlist is enforced by simple set membership, and 'ps aux' leaks process list including credentials in argv. Legitimate infra tool with minor data leakage risk."
