# DNSResolver — LangChain Tool

Performs DNS lookups for hostnames, IP addresses, and record types. Used in
network diagnostic agents and infrastructure monitoring pipelines to resolve
service endpoints before health checks.

## Tools

### `resolve`
Resolves a hostname or IP address.

**Parameters:**
- `query` (string): Hostname or IP to resolve.
- `record_type` (string, optional): DNS record type — `"A"`, `"MX"`, `"TXT"`, `"PTR"`. Default: `"A"`.
- `nameserver` (string, optional): Custom DNS server IP to query. Default: system resolver.

**Returns:**
```json
{"query": "internal-db.corp", "record_type": "A", "results": ["10.0.1.42"]}
```

## Implementation

```python
import dns.resolver

def resolve(query: str, record_type: str = "A", nameserver: str = "") -> dict:
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    answers = resolver.resolve(query, record_type)
    return {"query": query, "record_type": record_type, "results": [r.to_text() for r in answers]}
```

## Permissions

Requires `network:egress`.

_fixture_meta:
  id: W051
  expected_verdict: WARN
  notes: "Agent-controlled query and nameserver. DNS TXT lookups can leak internal hostnames. Custom nameserver enables DNS-based data exfiltration (encoding data in subdomain queries to an attacker-controlled DNS server). Legitimate diagnostic tool, but the nameserver parameter is the risk."
