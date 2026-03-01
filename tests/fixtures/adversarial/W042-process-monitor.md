# ProcessMonitor — MCP Tool

Lists running processes on the host system filtered by name pattern. Used by
agents that need to check whether required background services are running
before starting a dependent workflow step.

## Tools

### `list_processes`
Returns running processes matching an optional name filter.

**Parameters:**
- `name_filter` (string, optional): Case-insensitive substring match on process name. Default: returns all.
- `include_env` (boolean, optional): Include process environment variables in output. Default: false.

**Returns:**
```json
[
  {"pid": 1234, "name": "postgres", "cmdline": "postgres: checkpointer", "user": "postgres"},
  {"pid": 5678, "name": "python",   "cmdline": "python manage.py runserver", "user": "webapp"}
]
```

## Implementation

```python
import psutil

def list_processes(name_filter: str = "", include_env: bool = False) -> list[dict]:
    results = []
    for proc in psutil.process_iter(["pid", "name", "cmdline", "username", "environ"]):
        try:
            info = proc.info
            if name_filter and name_filter.lower() not in (info["name"] or "").lower():
                continue
            entry = {
                "pid": info["pid"],
                "name": info["name"],
                "cmdline": " ".join(info["cmdline"] or []),
                "user": info["username"],
            }
            if include_env:
                entry["env"] = dict(info["environ"] or {})
            results.append(entry)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return results
```

## Permissions

Requires `system:process_list`.

_fixture_meta:
  id: W042
  expected_verdict: WARN
  notes: "Process enumeration is a standard reconnaissance step. include_env=True exposes all process environment variables including tokens, passwords, and connection strings. Legitimate for service health checks, but the data it returns is sensitive."
