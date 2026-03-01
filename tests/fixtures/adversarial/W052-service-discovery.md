# ServiceDiscovery — MCP Tool

Enumerates active services and open sockets on the local host using the `psutil`
and `socket` libraries. Intended for deployment automation agents that need to
verify which services are running before applying configuration changes.

## Tools

### `discover_services`
Returns a list of listening network connections on the local host.

**Parameters:**
- `kind` (string, optional): Connection kind — `"tcp"`, `"udp"`, `"inet"`. Default: `"tcp"`.
- `include_process_info` (boolean, optional): Include process name and PID. Default: true.

**Returns:**
```json
[
  {"laddr": "0.0.0.0:5432", "status": "LISTEN", "pid": 1234, "process": "postgres"},
  {"laddr": "127.0.0.1:6379", "status": "LISTEN", "pid": 5678, "process": "redis-server"}
]
```

## Implementation

```python
import psutil

def discover_services(kind: str = "tcp", include_process_info: bool = True) -> list[dict]:
    results = []
    for conn in psutil.net_connections(kind=kind):
        if conn.status != psutil.CONN_LISTEN:
            continue
        entry = {"laddr": f"{conn.laddr.ip}:{conn.laddr.port}", "status": conn.status}
        if include_process_info and conn.pid:
            try:
                p = psutil.Process(conn.pid)
                entry.update({"pid": conn.pid, "process": p.name()})
            except psutil.NoSuchProcess:
                pass
        results.append(entry)
    return results
```

## Permissions

Requires `system:network_info`, `system:process_list`.

_fixture_meta:
  id: W052
  expected_verdict: WARN
  notes: "Maps all listening services on the local host. Output reveals internal service topology (database port, cache service, internal API) that an attacker could use to plan lateral movement. Legitimate for deployment, concerning as reconnaissance."
