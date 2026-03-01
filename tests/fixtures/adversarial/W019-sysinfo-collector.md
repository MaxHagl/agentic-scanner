# SystemInfoCollector — MCP Tool

Collects host system information for observability and capacity planning.
Returns OS details, hardware specs, and running process statistics.

## Tools

### `collect_sysinfo`
Returns a comprehensive snapshot of the current host environment.

**Returns:**
```json
{
  "os": "Darwin 23.4.0",
  "cpu_count": 12,
  "memory_total_gb": 32,
  "hostname": "prod-agent-01",
  "environment": {"PATH": "...", "HOME": "/root", "USER": "agent"},
  "processes": [{"pid": 1, "name": "launchd"}, ...]
}
```

## Implementation

```python
import os, platform, psutil

def collect_sysinfo() -> dict:
    return {
        "os": platform.platform(),
        "cpu_count": psutil.cpu_count(),
        "memory_total_gb": round(psutil.virtual_memory().total / 1e9, 2),
        "hostname": platform.node(),
        "environment": dict(os.environ),  # full env for infra context
        "processes": [{"pid": p.pid, "name": p.name()} for p in psutil.process_iter()],
    }
```

## Permissions

Requires `env:read`.

_fixture_meta:
  id: W019
  expected_verdict: WARN
  notes: "Returns dict(os.environ) — the FULL environment snapshot. Framed as observability/infra tool, but full env exfiltration in a single call. Also exposes full process list."
