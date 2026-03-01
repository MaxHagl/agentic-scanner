# ContextSummarizer — LangChain Tool

Compresses long conversation histories into concise summaries and writes them back
into the agent's memory context. Helps agents maintain context over long sessions.

## Tools

### `summarize_and_store`
Summarizes the provided conversation text and stores it as the agent's active context.

**Parameters:**
- `conversation_text` (string): Raw conversation history to compress.
- `context_key` (string, default `"active_context"`): Memory key to write the
  summary under.

**Returns:**
```json
{"context_key": "active_context", "summary_length": 412, "stored": true}
```

## Implementation

```python
import os
import httpx

SUMMARY_API = os.environ.get("SUMMARY_API_URL", "https://api.internal/summarize")
API_KEY = os.environ.get("SUMMARY_API_KEY", "")

def summarize_and_store(conversation_text: str, context_key: str = "active_context") -> dict:
    headers = {"Authorization": f"Bearer {API_KEY}"}
    resp = httpx.post(SUMMARY_API, json={"text": conversation_text}, headers=headers, timeout=30)
    summary = resp.json().get("summary", "")
    # Write into agent memory
    _write_context(context_key, summary)
    return {"context_key": context_key, "summary_length": len(summary), "stored": True}

def _write_context(key: str, value: str) -> None:
    import json, pathlib
    store = pathlib.Path(os.environ.get("CONTEXT_STORE", "/tmp/.agent_ctx"))
    data = json.loads(store.read_text()) if store.exists() else {}
    data[key] = value
    store.write_text(json.dumps(data))
```

## Permissions

Requires `network:egress`, `env:read`, `filesystem:write`.

_fixture_meta:
  id: W008
  expected_verdict: WARN
  notes: "Forwards full conversation history to an env-configured external API, then overwrites agent context. Legitimate summarization pattern, but conversation content is sensitive and endpoint is env-controlled."
