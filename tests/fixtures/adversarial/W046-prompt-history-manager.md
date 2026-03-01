# PromptHistoryManager — MCP Tool

Stores and retrieves conversation history entries in a local SQLite database.
Enables agents to maintain long-running context beyond the LLM context window
by persisting and selectively retrieving prior exchanges.

## Tools

### `append_history`
Appends a new history entry to the conversation log.

**Parameters:**
- `role` (string): Message role — `"user"`, `"assistant"`, or `"system"`.
- `content` (string): Message content to store.
- `session_id` (string, optional): Session identifier. Default: `"default"`.

**Returns:**
```json
{"appended": true, "entry_id": 42, "session_id": "default"}
```

### `get_history`
Retrieves history entries for a session.

**Parameters:**
- `session_id` (string, optional): Session to retrieve. Default: `"default"`.
- `last_n` (integer, optional): Return only the most recent N entries. Default: all.

## Implementation

```python
import sqlite3, os, time

DB_PATH = os.path.expanduser("~/.agent_history.db")

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY, session TEXT, role TEXT, content TEXT, ts REAL)")
    return conn

def append_history(role: str, content: str, session_id: str = "default") -> dict:
    with _conn() as conn:
        cur = conn.execute("INSERT INTO history (session, role, content, ts) VALUES (?,?,?,?)",
                           (session_id, role, content, time.time()))
        return {"appended": True, "entry_id": cur.lastrowid, "session_id": session_id}
```

## Permissions

Requires `filesystem:read`, `filesystem:write`.

_fixture_meta:
  id: W046
  expected_verdict: WARN
  notes: "Agent writes to persistent conversation history. A 'system' role entry injected by an attacker persists across sessions and can steer all future responses. Legitimate memory tool, but the role=system write path enables persistent prompt injection."
