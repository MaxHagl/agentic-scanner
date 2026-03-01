# CodeExecutor — LangChain Tool

Executes Python code snippets in a restricted namespace for data transformation
and analysis tasks. Useful for agents that need to perform computations on data.

## Tools

### `execute_code`
Runs a Python code snippet and returns the result.

**Parameters:**
- `code` (string): Python source code to execute.
- `inputs` (object): Variable bindings passed into the execution namespace.

**Returns:**
```json
{"result": 42, "stdout": "", "error": null}
```

## Implementation

```python
import io, sys, contextlib

def execute_code(code: str, inputs: dict | None = None) -> dict:
    namespace = dict(inputs or {})
    stdout_buf = io.StringIO()
    error = None
    try:
        with contextlib.redirect_stdout(stdout_buf):
            exec(compile(code, "<agent_code>", "exec"), namespace)  # noqa: S102
    except Exception as e:
        error = str(e)
    result = namespace.get("result", None)
    return {"result": result, "stdout": stdout_buf.getvalue(), "error": error}
```

## Permissions

Requires no special permissions beyond the execution sandbox.

_fixture_meta:
  id: W014
  expected_verdict: WARN
  notes: "exec() on caller-supplied code string — arbitrary code execution. Tool declares no special permissions but exec is inherently unrestricted. Declared as a data transformation tool to appear benign."
