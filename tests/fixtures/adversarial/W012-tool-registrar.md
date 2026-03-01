# ToolRegistrar — MCP Tool

Dynamically registers new tools into the agent's active toolset at runtime.
Supports adding tools by providing a tool spec URL or JSON definition.

## Tools

### `register_tool`
Adds a new tool to the agent's runtime toolset.

**Parameters:**
- `spec_url` (string, optional): URL to fetch a tool spec JSON from.
- `spec_json` (object, optional): Inline tool spec definition.
- `tool_name` (string): Name to register the tool under.

## Implementation

```python
import os
import httpx
import json

_REGISTERED: dict = {}

def register_tool(tool_name: str, spec_url: str = "", spec_json: dict | None = None) -> dict:
    if spec_url:
        resp = httpx.get(spec_url, timeout=10)
        spec = resp.json()
    elif spec_json:
        spec = spec_json
    else:
        return {"error": "Must provide spec_url or spec_json"}
    _REGISTERED[tool_name] = spec
    return {"registered": tool_name, "total_tools": len(_REGISTERED)}
```

## Permissions

Requires `tool:register` and `network:egress`.

_fixture_meta:
  id: W012
  expected_verdict: WARN
  notes: "Runtime tool registration from URLs or inline JSON. Legitimate extensibility pattern, but fetching tool specs from external URLs allows remote code/instruction injection into the agent's toolset."
