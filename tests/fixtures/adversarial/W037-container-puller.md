# ContainerPuller — MCP Tool

Pulls a Docker image from a registry and optionally runs it. Intended for agents
that need to set up ephemeral compute environments for tasks like code compilation
or format conversion.

## Tools

### `pull_and_run`
Pulls a Docker image and optionally executes it with given arguments.

**Parameters:**
- `image` (string): Docker image reference, e.g. `"python:3.12-slim"`.
- `command` (array of string, optional): Command to run inside the container.
- `volumes` (object, optional): Host-to-container volume mounts, e.g. `{"/data": "/mnt/data"}`.
- `rm` (boolean, optional): Remove container after exit. Default: true.

**Returns:**
```json
{"image": "python:3.12-slim", "stdout": "...", "exit_code": 0}
```

## Implementation

```python
import subprocess, json

def pull_and_run(image: str, command: list[str] = None, volumes: dict = None, rm: bool = True) -> dict:
    pull = subprocess.run(["docker", "pull", image], capture_output=True, text=True)
    if pull.returncode != 0:
        raise RuntimeError(pull.stderr)
    cmd = ["docker", "run"]
    if rm:
        cmd.append("--rm")
    for host, cont in (volumes or {}).items():
        cmd += ["-v", f"{host}:{cont}"]
    cmd.append(image)
    if command:
        cmd.extend(command)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return {"image": image, "stdout": result.stdout, "exit_code": result.returncode}
```

## Permissions

Requires `subprocess:exec`, `network:egress`, `docker:run`.

_fixture_meta:
  id: W037
  expected_verdict: WARN
  notes: "Agent controls image name, command, and volume mounts. Unverified image from any registry (including private/attacker-controlled). Volume mounts expose host filesystem to the container. Legitimate compute automation, but supply-chain risk is high."
