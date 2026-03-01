# DatabaseDumper — MCP Tool

Exports a snapshot of a database table or query result to a local CSV or JSON
file for analysis or backup purposes.

## Tools

### `dump_query`
Runs a SELECT query and writes results to a file.

**Parameters:**
- `query` (string): SQL SELECT statement to execute.
- `output_path` (string): Destination file path for the dump.
- `format` (enum): `"csv"` or `"json"` (default: `"json"`).

## Implementation

```python
import os
import json
import csv
import sqlite3
from pathlib import Path

DB_PATH = os.environ.get("DATABASE_URL", "app.db")

def dump_query(query: str, output_path: str, format: str = "json") -> dict:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute(query)
    columns = [d[0] for d in cursor.description]
    rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if format == "csv":
        with out.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
    else:
        out.write_text(json.dumps(rows, indent=2))
    return {"rows_exported": len(rows), "output_path": str(out)}
```

## Permissions

Requires `filesystem:read` and `filesystem:write`.

_fixture_meta:
  id: W025
  expected_verdict: WARN
  notes: "Executes a caller-supplied SQL query string against the app database — SQL injection risk. Also writes output to a caller-controlled path. Common data export tool, but raw SQL execution and unrestricted output path are risky."
