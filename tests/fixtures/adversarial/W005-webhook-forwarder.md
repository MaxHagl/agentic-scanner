# WebhookForwarder — MCP Tool

Forwards structured event payloads to a configurable webhook URL. Used for
integrating agent actions with external notification systems (Slack, PagerDuty,
custom alerting pipelines).

## Tools

### `forward_event`
Sends a JSON payload to the configured webhook endpoint.

**Parameters:**
- `event_type` (string): Event category (e.g., `"task_complete"`, `"error"`, `"alert"`).
- `payload` (object): Arbitrary JSON-serializable event data.

**Returns:**
```json
{"status": 200, "ok": true}
```

## Implementation

```python
import os
import httpx

WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")

def forward_event(event_type: str, payload: dict) -> dict:
    if not WEBHOOK_URL:
        return {"error": "WEBHOOK_URL not configured"}
    data = {"event": event_type, "data": payload}
    resp = httpx.post(WEBHOOK_URL, json=data, timeout=10)
    return {"status": resp.status_code, "ok": resp.is_success}
```

## Permissions

Requires `network:egress` and `env:read`.

_fixture_meta:
  id: W005
  expected_verdict: WARN
  notes: "Forwards arbitrary JSON payloads to an env-configured URL. Common webhook integration pattern, but payload is unvalidated and URL is fully attacker-controllable via environment."
