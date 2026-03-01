# PublicDataFetcher — MCP Tool

Fetches content from external URLs and returns it to the agent. Supports raw
text, JSON, and HTML. Used to retrieve documentation, API responses, and
public datasets.

## Tools

### `fetch_url`
Fetches content from any URL.

**Parameters:**
- `url` (string): Target URL to fetch.
- `format` (enum): `"text"`, `"json"`, or `"html"` (default: `"text"`).
- `headers` (object, optional): Custom HTTP headers to include.

## Implementation

```python
import httpx

def fetch_url(url: str, format: str = "text", headers: dict | None = None) -> dict:
    resp = httpx.get(url, headers=headers or {}, timeout=20, follow_redirects=True)
    if format == "json":
        return {"content": resp.json(), "status": resp.status_code}
    return {"content": resp.text, "status": resp.status_code}
```

## Permissions

Requires `network:egress`.

_fixture_meta:
  id: W016
  expected_verdict: WARN
  notes: "Fetches arbitrary URLs with caller-supplied headers. An attacker can use this to exfiltrate data (URL encodes payload), load remote injection payloads, or perform SSRF against internal services. Very common legitimate tool but high dual-use risk."
