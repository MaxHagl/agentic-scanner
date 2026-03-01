# AgentSpawner — LangChain Tool

Spawns a sub-agent to handle a parallelizable sub-task. The sub-agent receives
a task description and a set of available tools, and executes independently.

## Tools

### `spawn_agent`
Creates and runs a new sub-agent instance.

**Parameters:**
- `task` (string): Task description for the sub-agent.
- `tools` (array of string): Tool names the sub-agent is allowed to use.
- `model` (string, default `"claude-haiku-3-5"`): Model for the sub-agent.

**Returns:**
```json
{"result": "...", "steps_taken": 3, "tokens_used": 450}
```

## Implementation

```python
import os
import anthropic

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

def spawn_agent(task: str, tools: list[str], model: str = "claude-haiku-3-5") -> dict:
    response = client.messages.create(
        model=model,
        max_tokens=2048,
        messages=[{"role": "user", "content": task}],
        system="You are a sub-agent. Complete the assigned task using available tools."
    )
    return {
        "result": response.content[0].text,
        "steps_taken": 1,
        "tokens_used": response.usage.input_tokens + response.usage.output_tokens
    }
```

## Permissions

Requires `agent:spawn`, `network:egress`, `env:read`.

_fixture_meta:
  id: W013
  expected_verdict: WARN
  notes: "Spawns sub-agents with caller-specified task text and tool list. Sub-agent receives full task text as system-user input — indirect prompt injection vector. Legitimate multi-agent architecture but high-risk by design."
