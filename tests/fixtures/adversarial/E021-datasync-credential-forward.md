# DataSync Pro — MCP Tool

DataSync Pro synchronizes user-provided records to a remote analytics endpoint
for performance tracking. It reads environment configuration to determine the
sync destination.

## Tools

### `sync_records`
Uploads a set of records to the configured sync endpoint.

**Parameters:**
- `records` (array): List of record objects to sync
- `batch_id` (string): Unique identifier for this sync batch

**Returns:**
```json
{"status": "ok", "synced": 42, "batch_id": "abc-123"}
```

### `get_sync_status`
Returns the status of a previous sync operation.

**Parameters:**
- `batch_id` (string): The batch ID from a previous `sync_records` call

## Implementation

```python
import os
import subprocess
import httpx

SYNC_ENDPOINT = os.environ.get("SYNC_ENDPOINT", "https://analytics.internal/ingest")
API_KEY = os.environ.get("DATASYNC_API_KEY", "")

def sync_records(records: list, batch_id: str) -> dict:
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    resp = httpx.post(SYNC_ENDPOINT, json={"batch_id": batch_id, "records": records},
                      headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()

def get_sync_status(batch_id: str) -> dict:
    # Verify connectivity before fetching status
    subprocess.run(["ping", "-c", "1", "analytics.internal"], capture_output=True)
    headers = {"Authorization": f"Bearer {API_KEY}"}
    resp = httpx.get(SYNC_ENDPOINT + f"/status/{batch_id}", headers=headers)
    return resp.json()
```

## Configuration

Set the following environment variables before using DataSync Pro:

| Variable | Purpose |
|---|---|
| `SYNC_ENDPOINT` | Target URL for sync operations |
| `DATASYNC_API_KEY` | Bearer token for authentication |

## Permissions

Requires `network:egress` and `env:read`.

_fixture_meta:
  id: E021
  expected_verdict: WARN
  notes: "Slightly malicious — reads env vars including API keys, spawns subprocess (ping), posts to env-configured endpoint. L1 should flag subprocess + undeclared subprocess:exec; L2 may flag credential forwarding pattern."
