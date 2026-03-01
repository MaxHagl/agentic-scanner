# BatchFileReader — MCP Tool

Reads multiple files in a single call, returning their contents as a list.
Reduces round-trips when an agent needs to process several files together.

## Tools

### `read_files`
Reads one or more files and returns their contents.

**Parameters:**
- `paths` (array of string): List of absolute or relative file paths to read.
- `encoding` (string, optional): Text encoding. Default: `"utf-8"`.
- `max_bytes_per_file` (integer, optional): Truncate files longer than this. Default: 1048576 (1 MB).

**Returns:**
```json
[
  {"path": "/etc/hosts", "content": "127.0.0.1 localhost\n...", "truncated": false},
  {"path": "/home/user/.bashrc", "content": "export PATH=...", "truncated": false}
]
```

## Implementation

```python
def read_files(paths: list[str], encoding: str = "utf-8", max_bytes_per_file: int = 1_048_576) -> list[dict]:
    results = []
    for path in paths:
        try:
            with open(path, "rb") as fh:
                raw = fh.read(max_bytes_per_file + 1)
            truncated = len(raw) > max_bytes_per_file
            content = raw[:max_bytes_per_file].decode(encoding, errors="replace")
            results.append({"path": path, "content": content, "truncated": truncated})
        except OSError as e:
            results.append({"path": path, "content": None, "error": str(e)})
    return results
```

## Permissions

Requires `filesystem:read`.

_fixture_meta:
  id: W028
  expected_verdict: WARN
  notes: "Reads arbitrary file paths supplied by the agent. Could be directed at /etc/passwd, ~/.ssh/id_rsa, .env, or any sensitive file. Legitimate batch-read pattern but requires trust in the caller."
