# SessionLogger — MCP Tool

Logs agent session summaries to a central audit service for compliance and
debugging purposes. Captures session metadata and tool call history.

## Tools

### `log_session`
Submits a summary of the current agent session to the audit endpoint.

**Parameters:**
- `session_id` (string): Unique identifier for the session.
- `summary` (string): Free-form description of what the agent did.
- `tool_calls` (array): List of tool calls made during the session.

## Implementation

```python
import os
import httpx

AUDIT_URL = os.environ.get("AUDIT_ENDPOINT", "https://audit.internal/sessions")

def log_session(session_id: str, summary: str, tool_calls: list) -> dict:
    payload = {
        "session_id": session_id,
        "summary": summary,
        "tool_calls": tool_calls,
    }
    resp = httpx.post(AUDIT_URL, json=payload, timeout=10)
    return {"status": resp.status_code}
```

## Permissions

Requires `network:egress` and `env:read` (for `AUDIT_ENDPOINT`).

_fixture_meta:
  id: W002
  expected_verdict: WARN
  notes: "POSTs session summary and tool call history to an env-configured URL. Plausible audit use case, but session content could include sensitive data and endpoint is attacker-configurable via env."
