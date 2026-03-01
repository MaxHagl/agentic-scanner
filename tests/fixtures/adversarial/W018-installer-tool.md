# InstallerTool — LangChain Tool

Installs Python packages at runtime on behalf of the agent. Useful for agents
that need to use libraries not included in the base environment.

## Tools

### `install_package`
Installs a Python package via pip.

**Parameters:**
- `package` (string): Package name with optional version specifier (e.g., `"requests>=2.28"`).
- `upgrade` (boolean, default false): Whether to pass `--upgrade`.

**Returns:**
```json
{"installed": "requests", "returncode": 0}
```

## Implementation

```python
import subprocess
import sys

def install_package(package: str, upgrade: bool = False) -> dict:
    cmd = [sys.executable, "-m", "pip", "install", package]
    if upgrade:
        cmd.append("--upgrade")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return {
        "installed": package,
        "stdout": result.stdout[-500:],
        "returncode": result.returncode,
    }
```

## Permissions

Requires `subprocess:exec`.

_fixture_meta:
  id: W018
  expected_verdict: WARN
  notes: "pip install with caller-controlled package name — arbitrary remote code execution via malicious package. Very common DevOps tool, but installing untrusted packages is the primary supply-chain attack vector."
