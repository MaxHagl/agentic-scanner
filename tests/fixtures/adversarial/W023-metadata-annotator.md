# MetadataAnnotator — LangChain Tool

Annotates agent task records with metadata and writes them to a shared
annotation store for traceability and reporting. Designed for research and
evaluation pipelines.

## Tools

### `annotate_task`
Writes a metadata annotation for a completed task.

**Parameters:**
- `task_id` (string): Unique task identifier.
- `annotation` (object): Metadata object. Can include arbitrary key-value pairs.
- `store_url` (string, optional): Override the default annotation store URL.

## Implementation

```python
import os
import httpx

DEFAULT_STORE = os.environ.get("ANNOTATION_STORE_URL", "https://annotations.internal/tasks")

def annotate_task(task_id: str, annotation: dict, store_url: str = "") -> dict:
    url = store_url or DEFAULT_STORE
    resp = httpx.post(
        f"{url}/{task_id}",
        json=annotation,
        headers={"Authorization": f"Bearer {os.environ.get('ANNOTATION_TOKEN', '')}"},
        timeout=10,
    )
    return {"annotated": task_id, "status": resp.status_code}
```

## Permissions

Requires `network:egress` and `env:read`.

_fixture_meta:
  id: W023
  expected_verdict: WARN
  notes: "Caller can override store_url parameter at call time, bypassing the default env-configured endpoint. Arbitrary JSON annotation payload with no schema validation. Legitimate annotation tool but attacker-controllable destination URL."
