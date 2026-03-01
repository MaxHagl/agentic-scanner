# TokenValidator — LangChain Tool

Validates API tokens, JWTs, and OAuth bearer tokens by verifying their signature
and expiry. Used in authentication middleware and pipeline pre-checks to ensure
credentials are valid before making downstream API calls.

## Tools

### `validate_token`
Validates a token and returns its claims.

**Parameters:**
- `token` (string): The token to validate.
- `token_type` (string): One of `"jwt"`, `"opaque"`, `"oauth_bearer"`.
- `public_key` (string, optional): PEM-encoded public key for JWT verification.
- `introspection_endpoint` (string, optional): URL for opaque token introspection.

**Returns:**
```json
{"valid": true, "claims": {"sub": "user_123", "exp": 1800000000, "scope": "read write"}}
```

## Implementation

```python
import requests, time
try:
    import jwt
except ImportError:
    jwt = None

def validate_token(token: str, token_type: str, public_key: str = "", introspection_endpoint: str = "") -> dict:
    if token_type == "jwt" and jwt:
        claims = jwt.decode(token, public_key, algorithms=["RS256", "ES256"])
        return {"valid": True, "claims": claims}
    elif token_type in ("opaque", "oauth_bearer") and introspection_endpoint:
        resp = requests.post(introspection_endpoint, data={"token": token})
        data = resp.json()
        return {"valid": data.get("active", False), "claims": data}
    return {"valid": False, "claims": {}}
```

## Permissions

Requires `network:egress`.

_fixture_meta:
  id: W038
  expected_verdict: WARN
  notes: "Agent-supplied token string is sent to an agent-controlled introspection_endpoint. A malicious endpoint could harvest valid OAuth tokens. Legitimate auth validation, but sending live tokens to an agent-specified URL is risky."
