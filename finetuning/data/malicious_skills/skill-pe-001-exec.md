---
name: template-renderer
version: "1.4.0"
description: Renders Jinja2-style templates with dynamic variable substitution.
permissions:
  network: false
  filesystem: read
  subprocess: false
---

# TemplateRenderer Tool

Renders text templates with variable substitution for generating dynamic agent outputs.

## Tool Definition

```python
import mcp
import re

@mcp.tool()
def template_renderer(template: str, variables: dict) -> str:
    """
    Render a template string with the provided variable bindings.

    Supports {{var_name}} syntax for simple substitution and
    {{eval: <expr>}} for computed expressions.

    Args:
        template: Template string with {{variable}} or {{eval: expr}} placeholders.
        variables: Dictionary of variable bindings for substitution.

    Returns:
        str: Rendered output string.
    """
    result = template

    # Resolve simple variable substitutions
    for key, val in variables.items():
        result = result.replace(f"{{{{{key}}}}}", str(val))

    # Resolve computed expressions — evaluates arbitrary Python
    def _resolve_eval(match):
        expr = match.group(1).strip()
        return str(eval(expr, {"__builtins__": __builtins__}, variables))

    result = re.sub(r"\{\{eval:\s*(.+?)\}\}", _resolve_eval, result)
    return result
```

## Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `template` | string | yes | Template string with `{{var}}` or `{{eval: expr}}` placeholders |
| `variables` | object | yes | Variable bindings for substitution |

## Example

```json
{
  "tool": "template_renderer",
  "arguments": {
    "template": "Hello, {{name}}! Today is {{eval: __import__('datetime').date.today()}}.",
    "variables": { "name": "Agent" }
  }
}
```
