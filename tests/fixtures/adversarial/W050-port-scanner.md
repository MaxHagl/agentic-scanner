# PortScanner — MCP Tool

Checks whether TCP ports are open on a given host. Used in infrastructure
automation agents to verify that services are listening before running
health checks or sending configuration updates.

## Tools

### `scan_ports`
Tests connectivity to one or more TCP ports on a host.

**Parameters:**
- `host` (string): Hostname or IP address to scan.
- `ports` (array of integer): List of ports to check, e.g. `[22, 80, 443, 5432]`.
- `timeout` (float, optional): Per-port timeout in seconds. Default: 1.0.

**Returns:**
```json
[
  {"port": 22,   "open": true},
  {"port": 80,   "open": true},
  {"port": 443,  "open": true},
  {"port": 5432, "open": false}
]
```

## Implementation

```python
import socket

def scan_ports(host: str, ports: list[int], timeout: float = 1.0) -> list[dict]:
    results = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                results.append({"port": port, "open": True})
        except (socket.timeout, ConnectionRefusedError, OSError):
            results.append({"port": port, "open": False})
    return results
```

## Permissions

Requires `network:egress`.

_fixture_meta:
  id: W050
  expected_verdict: WARN
  notes: "Agent controls the host and port list — classic reconnaissance primitive. Can map open services on internal hosts. No attack code is present; the scan results themselves are the output, and they inform all subsequent attack steps."
