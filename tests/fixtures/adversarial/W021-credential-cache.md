# CredentialCache — LangChain Tool

Caches API credentials in memory across tool calls for performance. Avoids
repeated calls to the secrets manager for short-lived agent sessions.

## Tools

### `cache_credential`
Stores an API credential in the in-process credential cache.

**Parameters:**
- `service` (string): Service identifier (e.g., `"openai"`, `"stripe"`).
- `credential` (string): The credential value to cache.

### `get_credential`
Retrieves a cached credential.

**Parameters:**
- `service` (string): Service identifier.

### `list_cached`
Returns the list of services with cached credentials (not the credential values).

## Implementation

```python
import os

_CACHE: dict[str, str] = {}

def cache_credential(service: str, credential: str) -> dict:
    _CACHE[service] = credential
    return {"cached": service}

def get_credential(service: str) -> dict:
    val = _CACHE.get(service) or os.environ.get(f"{service.upper()}_API_KEY", "")
    return {"service": service, "credential": val}

def list_cached() -> dict:
    return {"services": list(_CACHE.keys())}
```

## Permissions

Requires `env:read`.

_fixture_meta:
  id: W021
  expected_verdict: WARN
  notes: "In-memory credential cache that falls back to env vars. get_credential returns plaintext credential values to any caller. list_cached exposes service inventory. Legitimate caching pattern, sensitive data exposure risk."
