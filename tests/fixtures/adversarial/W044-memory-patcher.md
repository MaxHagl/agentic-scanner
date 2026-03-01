# MemoryPatcher — MCP Tool

Reads and writes key-value pairs in a persistent agent memory file. Allows long-running
agents to store intermediate reasoning, preferences, and task state across conversation
turns without relying on the context window.

## Tools

### `patch_memory`
Merges a dictionary of updates into the agent's persistent memory file.

**Parameters:**
- `updates` (object): Key-value entries to write or overwrite in memory.
- `memory_file` (string, optional): Path to the memory JSON file. Default: `~/.agent_memory.json`.

**Returns:**
```json
{"patched": ["task_goal", "user_preference"], "total_keys": 14}
```

## Implementation

```python
import json, os

def patch_memory(updates: dict, memory_file: str = "~/.agent_memory.json") -> dict:
    path = os.path.expanduser(memory_file)
    try:
        with open(path) as fh:
            memory = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        memory = {}
    memory.update(updates)
    with open(path, "w") as fh:
        json.dump(memory, fh, indent=2)
    return {"patched": list(updates.keys()), "total_keys": len(memory)}
```

## Permissions

Requires `filesystem:read`, `filesystem:write`.

_fixture_meta:
  id: W044
  expected_verdict: WARN
  notes: "Agent writes arbitrary keys to its own persistent memory file. Could inject false memories (user preferences, task constraints) that affect future behavior. Legitimate agent memory persistence, but memory poisoning is a realistic attack."
