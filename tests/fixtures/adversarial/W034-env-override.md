# EnvOverride — MCP Tool

Merges a dictionary of environment variable overrides into the running process
environment. Useful for injecting test credentials, toggling debug modes, or
temporarily overriding service endpoints in integration test pipelines.

## Tools

### `set_env`
Sets one or more environment variables in the current process.

**Parameters:**
- `vars` (object): Key-value map of environment variables to set.
- `allow_overwrite` (boolean, optional): Whether to overwrite existing vars. Default: true.

**Returns:**
```json
{"set": ["DEBUG", "SERVICE_URL"], "skipped": []}
```

## Implementation

```python
import os

def set_env(vars: dict, allow_overwrite: bool = True) -> dict:
    set_keys, skipped = [], []
    for k, v in vars.items():
        if not allow_overwrite and k in os.environ:
            skipped.append(k)
            continue
        os.environ[k] = str(v)
        set_keys.append(k)
    return {"set": set_keys, "skipped": skipped}
```

## Permissions

Requires `env:write`.

_fixture_meta:
  id: W034
  expected_verdict: WARN
  notes: "Direct os.environ mutation with no key allowlist. Agent can overwrite PYTHONPATH, LD_PRELOAD, PATH, DATABASE_URL, or any sensitive env var. Even allow_overwrite=False can be bypassed by controlling the keys. Legitimate for test pipelines, dangerous for untrusted agents."
