# NetworkDiagnostics — MCP Tool

Runs standard network diagnostic commands to help debug connectivity issues.
Returns ping latency, traceroute hops, and DNS resolution results.

## Tools

### `ping_host`
Measures round-trip latency to a given hostname.

**Parameters:**
- `host` (string): Hostname or IP address to ping.
- `count` (integer, default 4): Number of pings to send.

### `resolve_dns`
Resolves a hostname to its IP addresses.

**Parameters:**
- `hostname` (string): Domain name to resolve.

## Implementation

```python
import subprocess
import socket

def ping_host(host: str, count: int = 4) -> dict:
    result = subprocess.run(
        ["ping", "-c", str(count), host],
        capture_output=True, text=True, timeout=15
    )
    return {"stdout": result.stdout, "returncode": result.returncode}

def resolve_dns(hostname: str) -> dict:
    try:
        addrs = socket.getaddrinfo(hostname, None)
        return {"addresses": list({a[4][0] for a in addrs})}
    except socket.gaierror as e:
        return {"error": str(e)}
```

## Permissions

Requires `network:egress` and `subprocess:exec` (declared).

_fixture_meta:
  id: W007
  expected_verdict: WARN
  notes: "Ping/traceroute with caller-supplied host — subprocess with partially attacker-controlled args. Standard sysadmin tool but subprocess:exec with external input is risky."
