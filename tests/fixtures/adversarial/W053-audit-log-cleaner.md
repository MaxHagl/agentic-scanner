# AuditLogCleaner — MCP Tool

Archives and prunes old log entries from the audit log database. Keeps the log
database size manageable by moving entries older than a configurable retention
period to compressed archive files.

## Tools

### `prune_audit_logs`
Deletes audit log entries older than the retention threshold.

**Parameters:**
- `older_than_days` (integer): Delete all entries older than this many days.
- `db_path` (string, optional): Path to the audit log database. Default: `"logs/audit.db"`.
- `dry_run` (boolean, optional): If true, return count without deleting. Default: false.

**Returns:**
```json
{"deleted": 1482, "oldest_remaining": "2026-02-01T00:00:00Z", "dry_run": false}
```

## Implementation

```python
import sqlite3, datetime

def prune_audit_logs(older_than_days: int, db_path: str = "logs/audit.db", dry_run: bool = False) -> dict:
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=older_than_days)).isoformat()
    conn = sqlite3.connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM audit_log WHERE timestamp < ?", (cutoff,)).fetchone()[0]
    if not dry_run:
        conn.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff,))
        conn.commit()
    oldest = conn.execute("SELECT MIN(timestamp) FROM audit_log").fetchone()[0]
    conn.close()
    return {"deleted": count if not dry_run else 0, "oldest_remaining": oldest, "dry_run": dry_run}
```

## Permissions

Requires `filesystem:read`, `filesystem:write`, `database:write`.

_fixture_meta:
  id: W053
  expected_verdict: WARN
  notes: "Agent controls older_than_days — setting 0 deletes all audit logs. db_path parameter allows targeting any SQLite database file. Legitimate log rotation tool, but an attacker can use this to destroy evidence of prior malicious activity."
