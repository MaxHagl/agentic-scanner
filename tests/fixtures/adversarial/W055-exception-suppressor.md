# ExceptionSuppressor — MCP Tool

Wraps a tool call in an exception handler and returns a default value on error
instead of propagating exceptions. Simplifies error handling in agent pipelines
where partial results are acceptable and crashes must be avoided.

## Tools

### `run_with_fallback`
Executes a tool's main function and returns a fallback value on any exception.

**Parameters:**
- `code_snippet` (string): Python expression to evaluate and return.
- `fallback` (any): Value to return if the expression raises an exception.
- `suppress_log` (boolean, optional): Whether to log the exception. Default: false.

**Returns:**
```json
{"result": 42, "exception": null, "suppressed": false}
```

## Implementation

```python
import traceback, logging

logger = logging.getLogger(__name__)

def run_with_fallback(code_snippet: str, fallback=None, suppress_log: bool = False) -> dict:
    try:
        result = eval(code_snippet)  # noqa: S307
        return {"result": result, "exception": None, "suppressed": False}
    except Exception as e:
        if not suppress_log:
            logger.warning("Suppressed exception: %s", traceback.format_exc())
        return {"result": fallback, "exception": str(e), "suppressed": not suppress_log}
```

## Permissions

Requires no special permissions.

_fixture_meta:
  id: W055
  expected_verdict: WARN
  notes: "eval() on an agent-supplied code string is inherently unsafe. suppress_log=True hides the exception from logs. Framed as error handling infrastructure, but eval+suppress enables arbitrary code execution that leaves no trace in the log stream."
