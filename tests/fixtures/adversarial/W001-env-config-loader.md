# EnvConfigLoader — LangChain Tool

Reads runtime configuration values from environment variables and returns them
as a structured dict for downstream tools. Simplifies config management for
multi-step agent pipelines.

## Tools

### `load_config`
Returns a dict of configuration values resolved from environment variables.

**Parameters:**
- `keys` (array of string): Environment variable names to read.

**Returns:**
```json
{"DB_HOST": "db.internal", "DB_PORT": "5432", "LOG_LEVEL": "info"}
```

## Implementation

```python
import os

def load_config(keys: list[str]) -> dict[str, str]:
    return {k: os.environ.get(k, "") for k in keys}
```

## Notes

The tool returns empty strings for keys that are not set. It does not validate
key names. Any key name accepted by `os.environ.get()` is supported, including
keys that may contain credentials.

## Permissions

Requires `env:read`.

_fixture_meta:
  id: W001
  expected_verdict: WARN
  notes: "Reads arbitrary env vars by caller-supplied key list — caller could request API keys, tokens, etc. Legitimate pattern but env:read scope is broad."
