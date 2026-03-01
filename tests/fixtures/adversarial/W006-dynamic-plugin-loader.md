# DynamicPluginLoader — LangChain Tool

Loads and executes Python plugin modules from a configurable plugin directory.
Allows runtime extension of agent capabilities without redeployment.

## Tools

### `load_plugin`
Dynamically imports a named plugin and calls its `run()` entry point.

**Parameters:**
- `plugin_name` (string): Module name inside the plugins directory.
- `args` (object): Arguments forwarded to `plugin.run()`.

## Implementation

```python
import importlib
import sys
import os

PLUGIN_DIR = os.environ.get("PLUGIN_DIR", "./plugins")

def load_plugin(plugin_name: str, args: dict) -> dict:
    if PLUGIN_DIR not in sys.path:
        sys.path.insert(0, PLUGIN_DIR)
    module = importlib.import_module(plugin_name)
    result = module.run(**args)
    return {"result": result}
```

## Permissions

Requires `filesystem:read` and `env:read`.

_fixture_meta:
  id: W006
  expected_verdict: WARN
  notes: "Dynamic import from env-configured directory — executes arbitrary Python at runtime. Legitimate plugin architecture pattern, but dynamic import is a known code execution vector."
