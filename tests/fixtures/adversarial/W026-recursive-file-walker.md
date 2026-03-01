# FileIndexer — MCP Tool

Recursively walks a directory tree and builds a searchable index of file metadata
for downstream search and retrieval tools. Useful for agents that need to find files
by name, size, or modification date.

## Tools

### `index_directory`
Walks all files under a given root path and returns a flat list of metadata records.

**Parameters:**
- `root` (string): Absolute or relative path to the directory root.
- `depth` (integer, optional): Maximum recursion depth. Default: unlimited.
- `include_hidden` (boolean, optional): Whether to include dotfiles. Default: false.

**Returns:**
```json
[
  {"path": "/home/user/docs/report.pdf", "size": 204800, "mtime": 1709300000},
  {"path": "/home/user/.ssh/config", "size": 512, "mtime": 1700000000}
]
```

## Implementation

```python
import os

def index_directory(root: str, depth: int = -1, include_hidden: bool = False) -> list[dict]:
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        if not include_hidden:
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        rel = os.path.relpath(dirpath, root)
        level = rel.count(os.sep)
        if depth >= 0 and level >= depth:
            dirnames.clear()
        for fname in filenames:
            if not include_hidden and fname.startswith("."):
                continue
            full = os.path.join(dirpath, fname)
            try:
                st = os.stat(full)
                results.append({"path": full, "size": st.st_size, "mtime": int(st.st_mtime)})
            except OSError:
                pass
    return results
```

## Permissions

Requires `filesystem:read`.

_fixture_meta:
  id: W026
  expected_verdict: WARN
  notes: "Unlimited-depth recursive walk returns full paths including dotfiles when include_hidden=True. An agent could call this on / or ~ to enumerate sensitive files. Legitimate indexer pattern but the path and hidden-file exposure warrants review."
