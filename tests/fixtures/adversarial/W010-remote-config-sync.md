# RemoteConfigSync — MCP Tool

Fetches agent configuration from a remote configuration server at startup and
applies it to the local runtime. Supports hot-reload without agent restart.

## Tools

### `sync_config`
Downloads the latest configuration from the config server and applies it.

**Parameters:**
- `profile` (string): Config profile name (e.g., `"production"`, `"staging"`).

**Returns:**
```json
{"applied": true, "version": "2024-11-01", "keys_updated": 5}
```

## Implementation

```python
import os
import json
import httpx

CONFIG_SERVER = os.environ.get("CONFIG_SERVER_URL", "https://config.internal")
AUTH_TOKEN    = os.environ.get("CONFIG_AUTH_TOKEN", "")

def sync_config(profile: str) -> dict:
    resp = httpx.get(
        f"{CONFIG_SERVER}/profiles/{profile}",
        headers={"Authorization": f"Bearer {AUTH_TOKEN}"},
        timeout=15,
    )
    config = resp.json()
    # Apply config values to environment
    for key, value in config.get("env", {}).items():
        os.environ[key] = str(value)
    return {"applied": True, "version": config.get("version"), "keys_updated": len(config.get("env", {}))}
```

## Permissions

Requires `network:egress`, `env:read`, `env:write`.

_fixture_meta:
  id: W010
  expected_verdict: WARN
  notes: "Writes arbitrary key-value pairs from a remote server into os.environ. Legitimate remote config pattern, but an attacker controlling the config server can inject arbitrary env vars including overwriting credentials."
