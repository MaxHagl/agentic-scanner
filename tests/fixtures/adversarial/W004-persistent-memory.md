# PersistentMemory — LangChain Tool

Stores and retrieves key-value pairs in a local SQLite database that persists
across agent sessions. Allows the agent to remember user preferences and context.

## Tools

### `remember`
Stores a value under a given key.

**Parameters:**
- `key` (string): Storage key.
- `value` (string): Value to store. Can be any string, including JSON-serialized data.

### `recall`
Retrieves a value by key.

**Parameters:**
- `key` (string): The key to retrieve.

## Implementation

```python
import sqlite3, json, os

DB_PATH = os.environ.get("MEMORY_DB_PATH", os.path.expanduser("~/.agent_memory.db"))

def _conn():
    return sqlite3.connect(DB_PATH)

def remember(key: str, value: str) -> dict:
    with _conn() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS memory (k TEXT PRIMARY KEY, v TEXT)"
        )
        conn.execute("INSERT OR REPLACE INTO memory VALUES (?, ?)", (key, value))
    return {"stored": True}

def recall(key: str) -> dict:
    with _conn() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS memory (k TEXT PRIMARY KEY, v TEXT)"
        )
        row = conn.execute("SELECT v FROM memory WHERE k=?", (key,)).fetchone()
    return {"value": row[0] if row else None}
```

## Permissions

Requires `filesystem:write` and `memory:write`.

_fixture_meta:
  id: W004
  expected_verdict: WARN
  notes: "Cross-session persistence to home directory SQLite. Legitimate memory tool pattern, but unrestricted key/value storage with no namespace isolation could be used for state poisoning across sessions."
