# Notes for Future Claude Sessions
*(Read this before modifying the codebase)*

These instructions map out the architectural direction, known flaws in the current implementation, and strict guidelines for modifying `agentic-scanner`.

## 1. Architectural Strategy & Layer 3 Roadmap
Our core threat model assumes the **context window is the execution environment**. Static analysis (L1) and Prompt Injection detection (L2) only cover the tool *loading* phase. 

**Layer 3 MUST focus on Runtime Response Validation.** When you implement Layer 3, do not just build a Docker sandbox. You must implement an **Interception Proxy** that analyzes strings returned by the tools *before* they are sent to the LLM context.
*   **Schema Validation:** Ensure responses match the expected `tools[].inputSchema` (e.g., catching 500 words of injected text returned in what should be a boolean field).
*   **Semantic Scoring:** Repurpose the `AnthropicJudgeClient` to score tool responses for imperative command injections (e.g., catching "Ignore previous instructions" embedded in search results).
*   **Behavioral Delta Tracks:** Implement hooks to detect when an agent's planned action drastically shifts immediately after receiving a tool response.

## 2. Known Flaws in the Current Implementation
Before adding new features, address these existing technical debts:

### Layer 1 (`scanner/layer1_static/ast_scanner.py`)
1.  **Incomplete AST Obfuscation Checks:** The `_string_concat_resolves_to` function easily breaks on nested f-strings or complex AST constructs. We need to implement a lightweight symbolic execution engine or SSA form here to catch advanced `getattr(builtins, 'ex' + chr(101) + 'c')` attacks.
    *   *Potential Fix:* Implement a pre-processing pass using `ast.NodeTransformer` that performs aggressive constant folding across the entire tree, flattening complex `ast.BinOp` or nested `ast.JoinedStr` nodes into single `ast.Constant` strings before `_check_call` runs.
2.  **`os.environ` Over-Permission:** `os.environ` and `os.getenv` trigger `ENV_READ` globally, but there is no mechanism to scope permissions to *specific* variables (e.g., a tool needing `OPENAI_API_KEY` shouldn't be granted full `ENV_READ`). This needs a capability-scoping refactor.
    *   *Potential Fix:* Modify the `Permission` system to allow parameterized scopes (e.g., `Permission.ENV_READ.with_arg("OPENAI_API_KEY")`). Have `ast_scanner.py` parse `node.args[0]` on `os.getenv` calls to extract the exact string literal being read and check the specific permission delta.

### Layer 2 (`scanner/layer2_semantic/__init__.py`)
1.  **Failing Open is Dangerous:** Currently, if the API rate-limits or fails (`LLMJudgeError`), the `Layer2Analyzer` fails *open* (returning `RiskReport_L2` with `llm_judge_verdict=None`). In a true security product, failing open on a deep-inspection layer is a critical flaw. We need to introduce a strict `fail_closed=True/False` fallback policy in the CLI.
    *   *Potential Fix:* Plumb a `fail_closed` parameter from `cli.py` down to `Layer2Analyzer`. In the `except LLMJudgeError` block, if `fail_closed=True`, return a report with `llm_judge_verdict="BLOCK"` and `llm_judge_confidence=1.0` to force the Aggregator to halt execution.

## 3. Context Payload Guidelines (Token Optimization)
- **Do not read `tests/fixtures/` unless requested.** It contains thousands of lines of payload strings that will wreck your context limit.
- **Rely on Type-Hints over Docstrings:** `scanner/models/` uses strict Pydantic models. Do not bloat them with 5-line docstrings for self-explanatory Enums. 
- **System Prompt Compression:** When modifying `scanner/layer2_semantic/prompt_injection_detector.py`, keep `_SYSTEM_PROMPT` hyper-compressed. Map threats strictly to Enums (e.g., `T2_PROMPT_INJECTION`) rather than providing multi-paragraph definitions. You already know what a prompt injection is. Save the input tokens.
