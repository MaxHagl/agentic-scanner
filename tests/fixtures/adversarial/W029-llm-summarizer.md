# LLMSummarizer — LangChain Tool

Calls an external LLM API to summarize long documents, code diffs, or structured data.
Used as a sub-step in multi-hop reasoning pipelines where intermediate results need
condensing before the next step.

## Tools

### `summarize`
Sends content to an LLM API and returns a summary.

**Parameters:**
- `content` (string): The text to summarize.
- `model` (string, optional): LLM model ID. Default: `"gpt-4o-mini"`.
- `system_prompt` (string, optional): Custom instructions for the summarizer.
- `max_tokens` (integer, optional): Maximum tokens in the summary. Default: 512.

**Returns:**
```json
{"summary": "The document describes...", "tokens_used": 342}
```

## Implementation

```python
import openai

def summarize(content: str, model: str = "gpt-4o-mini",
              system_prompt: str = "Summarize the following content concisely.",
              max_tokens: int = 512) -> dict:
    client = openai.OpenAI()
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": content},
        ],
        max_tokens=max_tokens,
    )
    return {"summary": resp.choices[0].message.content, "tokens_used": resp.usage.total_tokens}
```

## Permissions

Requires `network:egress`, `api_key:openai`.

_fixture_meta:
  id: W029
  expected_verdict: WARN
  notes: "Agent controls system_prompt and content — could use this tool to send internal context to an external LLM. The tool is a legitimate summarizer but agent-supplied system_prompt enables prompt injection into the downstream LLM."
