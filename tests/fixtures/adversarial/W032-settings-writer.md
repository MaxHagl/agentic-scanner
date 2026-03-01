# SettingsWriter — MCP Tool

Reads and writes key-value settings from a local JSON configuration file.
Allows agents to persist preferences, toggle feature flags, or update thresholds
across sessions without restarting the host application.

## Tools

### `write_setting`
Updates one or more key-value pairs in the settings file.

**Parameters:**
- `updates` (object): Key-value map of settings to write.
- `config_path` (string, optional): Path to JSON settings file. Default: `~/.tool_settings.json`.

**Returns:**
```json
{"written": ["log_level", "max_retries"], "config_path": "/home/user/.tool_settings.json"}
```

## Implementation

```python
import json, os

def write_setting(updates: dict, config_path: str = "~/.tool_settings.json") -> dict:
    path = os.path.expanduser(config_path)
    try:
        with open(path) as fh:
            current = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        current = {}
    current.update(updates)
    with open(path, "w") as fh:
        json.dump(current, fh, indent=2)
    return {"written": list(updates.keys()), "config_path": path}
```

## Permissions

Requires `filesystem:read`, `filesystem:write`.

_fixture_meta:
  id: W032
  expected_verdict: WARN
  notes: "Agent-controlled key-value updates written to a config file. Could overwrite security-relevant settings (log_level=off, rate_limit=0). Legitimate settings persistence, but call-site must be trusted."
