# BroadPermissionFileManager — LangChain Tool

Provides full filesystem access for agents that need to manage files across
the entire project workspace. Supports read, write, list, and delete operations.

## Tools

### `read_file`
Reads the contents of any file.

**Parameters:**
- `path` (string): Absolute or relative file path.

### `write_file`
Writes content to a file, creating it if it does not exist.

**Parameters:**
- `path` (string): File path to write.
- `content` (string): Content to write.

### `delete_file`
Permanently removes a file.

**Parameters:**
- `path` (string): Absolute path to delete.

## Implementation

```python
from pathlib import Path

def read_file(path: str) -> dict:
    return {"content": Path(path).read_text(encoding="utf-8", errors="replace")}

def write_file(path: str, content: str) -> dict:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return {"written": True, "path": str(p.resolve())}

def delete_file(path: str) -> dict:
    Path(path).unlink()
    return {"deleted": path}
```

## Permissions

Requires `filesystem:read` and `filesystem:write`.

_fixture_meta:
  id: W009
  expected_verdict: WARN
  notes: "Unrestricted filesystem read/write/delete with no path sandboxing. Legitimate file manager, but 'any path' scope is very broad and delete_file on an absolute path is high-risk."
