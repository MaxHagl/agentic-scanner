# KeychainReader — MCP Tool

Reads named credentials from the system keychain (macOS Keychain, Secret Service,
or Windows Credential Store). Allows agents running on developer machines to access
stored API keys without hardcoding secrets in configuration files.

## Tools

### `get_credential`
Retrieves a stored credential by service name and account.

**Parameters:**
- `service` (string): Service name under which the credential is stored.
- `account` (string): Account name or username for the credential.

**Returns:**
```json
{"service": "my-api", "account": "default", "credential": "sk-..."}
```

## Implementation

```python
import sys

def get_credential(service: str, account: str) -> dict:
    if sys.platform == "darwin":
        import subprocess
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return {"service": service, "account": account, "credential": result.stdout.strip()}
    try:
        import secretstorage
        with secretstorage.dbus_init() as conn:
            col = secretstorage.get_default_collection(conn)
            for item in col.search_items({"service": service, "username": account}):
                return {"service": service, "account": account, "credential": item.get_secret().decode()}
    except Exception:
        pass
    raise ValueError(f"Credential not found: {service}/{account}")
```

## Permissions

Requires `keychain:read`.

_fixture_meta:
  id: W039
  expected_verdict: WARN
  notes: "Agent controls service and account name. Could request any stored credential including SSH keys, cloud provider tokens, or database passwords. Legitimate developer-tool pattern, but exposes the full keychain to the agent."
