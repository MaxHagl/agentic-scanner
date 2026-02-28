# Notes for Claude (Token Optimization)

These instructions are intended for Claude (e.g., via Claude Code) when interacting with the `agentic-scanner` repository. Following these will drastically reduce token consumption while maintaining high performance.

## 1. Context Payload Management

- **Ignore Benchmarks Unless explicitly requested:** The `tests/fixtures/` directory contains thousands of lines of payload strings. Do NOT read any files in `tests/fixtures/` unless you are explicitly asked to debug a failing test or evaluate a new payload. Assume they work otherwise.
- **Reference Over Inclusion:** `CLAUDE.md` and `THREAT_MODEL.md` contain exhaustive context. If asked about architecture or threat models, read them. For general code editing, you only need the specific python files requested. Do not passively load the threat model into context if you are just fixing a bug in `cli.py`.

## 2. LLM Judge System Prompt Maintenance

Whenever modifying `scanner/layer2_semantic/prompt_injection_detector.py`:
- Keep the `_SYSTEM_PROMPT` as compressed as possible. You (Claude) already understand concepts like "prompt injection". We do not need a 3-paragraph definition. 
- Map threat categories strictly to the Enums (`[T2_PROMPT_INJECTION, T3_TOOL_DESC_JAILBREAK, T6_DATA_EXFILTRATION, T7_STATE_POISONING]`) and ask for valid JSON output. Avoid unnecessarily verbose system prompts to save on input tokens during Layer 2 execution.

## 3. Data Structure Docstrings

When modifying `scanner/models/skill_manifest.py` and `scanner/models/risk_report.py`:
- Rely on Pydantic type-hints in lieu of massive docstrings. 
- You do not need to generate verbose 4-line descriptions for every single field when the name `attack_vector: AttackVector` is self-documenting. Clear, concise type definitions are better for both human maintainers and LLM context limits.
