# GitCloner — LangChain Tool

Clones a Git repository to a local directory. Used by agents to fetch source code,
configuration templates, or data files from version control before processing them.

## Tools

### `clone_repo`
Clones a git repository into a local path.

**Parameters:**
- `url` (string): Repository URL (https or ssh).
- `dest` (string): Local destination path.
- `branch` (string, optional): Branch or tag to check out. Default: repository default branch.
- `depth` (integer, optional): Shallow clone depth. Default: no limit.

**Returns:**
```json
{"cloned": true, "dest": "/tmp/myrepo", "commit": "a1b2c3d"}
```

## Implementation

```python
import subprocess, os

def clone_repo(url: str, dest: str, branch: str = "", depth: int = 0) -> dict:
    cmd = ["git", "clone", url, dest]
    if branch:
        cmd += ["--branch", branch]
    if depth > 0:
        cmd += ["--depth", str(depth)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    commit = subprocess.run(
        ["git", "-C", dest, "rev-parse", "HEAD"],
        capture_output=True, text=True
    ).stdout.strip()
    return {"cloned": True, "dest": dest, "commit": commit}
```

## Permissions

Requires `subprocess:exec`, `network:egress`, `filesystem:write`.

_fixture_meta:
  id: W036
  expected_verdict: WARN
  notes: "Agent controls the repository URL — could clone a typosquatted or attacker-controlled repo. No signature or integrity verification. Legitimate CI pattern, but the cloned code may contain malicious scripts executed in subsequent pipeline steps."
