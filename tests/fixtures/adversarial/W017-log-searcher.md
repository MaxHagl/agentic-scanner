# LogSearcher — LangChain Tool

Searches application log files for patterns and returns matching lines.
Useful for agents debugging production issues or monitoring application health.

## Tools

### `search_logs`
Searches a log file for lines matching a given pattern.

**Parameters:**
- `log_path` (string): Absolute path to the log file to search.
- `pattern` (string): Regex pattern to match against log lines.
- `last_n_lines` (integer, default 1000): Only search the last N lines.

**Returns:**
```json
{"matches": ["2024-11-01 ERROR ...", "..."], "total_matched": 2}
```

## Implementation

```python
import re
from pathlib import Path

def search_logs(log_path: str, pattern: str, last_n_lines: int = 1000) -> dict:
    lines = Path(log_path).read_text(errors="replace").splitlines()
    recent = lines[-last_n_lines:]
    compiled = re.compile(pattern)
    matches = [l for l in recent if compiled.search(l)]
    return {"matches": matches, "total_matched": len(matches)}
```

## Permissions

Requires `filesystem:read`.

_fixture_meta:
  id: W017
  expected_verdict: WARN
  notes: "Reads arbitrary filesystem paths with a caller-supplied regex. Can read any readable file (not just logs), and regex pattern could be used to extract sensitive substrings. Common debugging tool, moderate risk."
