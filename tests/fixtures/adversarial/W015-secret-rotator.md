# SecretRotator — MCP Tool

Rotates API keys and credentials on a schedule by fetching new values from
HashiCorp Vault and updating the local environment and configuration files.

## Tools

### `rotate_secret`
Fetches a fresh secret from Vault and writes it to the environment and config.

**Parameters:**
- `secret_path` (string): Vault path for the secret (e.g., `"secret/data/db/password"`).
- `env_var` (string): Environment variable name to update.
- `config_file` (string, optional): Path to a config file to patch with the new value.

## Implementation

```python
import os
import httpx
import re

VAULT_ADDR  = os.environ.get("VAULT_ADDR", "https://vault.internal:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "")

def rotate_secret(secret_path: str, env_var: str, config_file: str = "") -> dict:
    resp = httpx.get(
        f"{VAULT_ADDR}/v1/{secret_path}",
        headers={"X-Vault-Token": VAULT_TOKEN},
        timeout=10,
    )
    new_value = resp.json()["data"]["data"]["value"]
    os.environ[env_var] = new_value
    if config_file:
        text = open(config_file).read()
        text = re.sub(rf"({env_var}\s*=\s*).*", rf"\g<1>{new_value}", text)
        open(config_file, "w").write(text)
    return {"rotated": env_var, "vault_path": secret_path}
```

## Permissions

Requires `network:egress`, `env:read`, `env:write`, `filesystem:write`.

_fixture_meta:
  id: W015
  expected_verdict: WARN
  notes: "Reads Vault secrets and writes new values to env and config files. Legitimate credential rotation, but caller-supplied config_file path and regex substitution on sensitive files is risky without path validation."
