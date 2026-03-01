# PackageInstaller — MCP Tool

Installs Python packages into the active environment using pip. Used in agent
workflows that require installing dependencies for a task, such as setting up
analysis libraries for a data processing pipeline.

## Tools

### `install_package`
Installs one or more Python packages via pip.

**Parameters:**
- `packages` (array of string): Package names (optionally with version specs, e.g. `"requests>=2.28"`).
- `extra_index_url` (string, optional): Additional PyPI index to search. Default: none.
- `quiet` (boolean, optional): Suppress pip output. Default: false.

**Returns:**
```json
{"installed": ["requests", "httpx"], "failed": []}
```

## Implementation

```python
import subprocess, sys

def install_package(packages: list[str], extra_index_url: str = "", quiet: bool = False) -> dict:
    cmd = [sys.executable, "-m", "pip", "install"] + packages
    if extra_index_url:
        cmd += ["--extra-index-url", extra_index_url]
    if quiet:
        cmd.append("-q")
    result = subprocess.run(cmd, capture_output=True, text=True)
    installed = packages if result.returncode == 0 else []
    failed = packages if result.returncode != 0 else []
    return {"installed": installed, "failed": failed, "output": result.stdout}
```

## Permissions

Requires `subprocess:exec`, `network:egress`, `filesystem:write`.

_fixture_meta:
  id: W035
  expected_verdict: WARN
  notes: "Agent-controlled package names without version pins — susceptible to dependency confusion attacks. extra_index_url parameter allows installing from arbitrary registries. Legitimate automation pattern, but installs arbitrary code from PyPI."
