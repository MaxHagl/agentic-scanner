# ContentSearch — LangChain Tool

Searches for a text pattern across all files in a directory and returns matching
lines with their file paths and line numbers. Designed for code search in agent-driven
development workflows.

## Tools

### `search_files`
Searches file contents recursively for a given pattern.

**Parameters:**
- `directory` (string): Root directory to search.
- `pattern` (string): Text or regex pattern to search for.
- `file_glob` (string, optional): Glob filter, e.g. `"*.py"`. Default: all files.
- `max_results` (integer, optional): Cap on returned matches. Default: 500.

**Returns:**
```json
[
  {"file": "/project/auth.py", "line": 42, "text": "  password = config['DB_PASSWORD']"},
  {"file": "/project/.env", "line": 3,  "text": "DB_PASSWORD=hunter2"}
]
```

## Implementation

```python
import os, re

def search_files(directory: str, pattern: str, file_glob: str = "*", max_results: int = 500) -> list[dict]:
    import fnmatch
    results = []
    rx = re.compile(pattern)
    for dirpath, _, filenames in os.walk(directory):
        for fname in filenames:
            if not fnmatch.fnmatch(fname, file_glob):
                continue
            full = os.path.join(dirpath, fname)
            try:
                for i, line in enumerate(open(full, errors="replace"), 1):
                    if rx.search(line):
                        results.append({"file": full, "line": i, "text": line.rstrip()})
                        if len(results) >= max_results:
                            return results
            except OSError:
                pass
    return results
```

## Permissions

Requires `filesystem:read`.

_fixture_meta:
  id: W027
  expected_verdict: WARN
  notes: "Agent-controlled pattern + directory allows searching for 'password', 'token', 'secret' across arbitrary paths including .env and config files. No exfiltration code present but the returned content may contain credentials."
