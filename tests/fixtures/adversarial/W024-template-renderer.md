# TemplateRenderer — LangChain Tool

Renders Jinja2 templates from files or inline strings. Used by agents for
generating reports, emails, documents, and configuration files.

## Tools

### `render_template`
Renders a Jinja2 template with provided variables.

**Parameters:**
- `template` (string): Inline Jinja2 template string, OR a file path ending in `.j2`.
- `variables` (object): Variables to inject into the template.

**Returns:**
```json
{"rendered": "Hello, Alice!", "length": 13}
```

## Implementation

```python
from jinja2 import Environment, FileSystemLoader, BaseLoader, select_autoescape

def render_template(template: str, variables: dict) -> dict:
    if template.endswith(".j2"):
        import os
        loader = FileSystemLoader(os.getcwd())
        env = Environment(loader=loader, autoescape=False)
        tmpl = env.get_template(template)
    else:
        env = Environment(loader=BaseLoader(), autoescape=False)
        tmpl = env.from_string(template)
    rendered = tmpl.render(**variables)
    return {"rendered": rendered, "length": len(rendered)}
```

## Permissions

Requires `filesystem:read` (for .j2 file templates).

_fixture_meta:
  id: W024
  expected_verdict: WARN
  notes: "Jinja2 rendering with autoescape=False and caller-controlled template string. Without autoescape and sandboxing, Jinja2 supports server-side template injection (SSTI), enabling arbitrary attribute access and potential code execution."
