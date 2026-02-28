# Agentic-Scanner: Future Development Plans

This document outlines high-impact technical improvements to elevate `agentic-scanner` to an enterprise-grade security product.

## 1. Dynamic Analysis (Layer 3) Enhancements
- **Kernel-Level Tracing:** Replace the Python monkey-patching harness with eBPF (e.g., Tetragon/Tracee) or `ptrace` at the Docker host level to prevent sophisticated evasion techniques (like reading logs, reloading C-extensions, or inline assembly).
- **Execution Performance:** Improve scanning throughput by replacing the per-scan Docker container startup with a pool of "warm" sleeping containers or utilizing lightweight microVMs (e.g., Firecracker). 

## 2. Static Analysis (Layer 1) Enhancements
- **Advanced AST Taint Tracking:** Implement import alias tracking (e.g., `import requests as r; r.get()`) to prevent bypasses of the rigid AST `_call_name` checks.
- **Improved Obfuscation Detection:** Expand the string concatenation resolver to catch f-strings (`ast.JoinedStr`) and multi-line variable propagation.
- **Deserialization Rules:** Add `pickle`, `cPickle`, `marshal`, and `shelve` to the dangerous memory-unsafe modules list to catch RCE payloads.

## 3. Semantic Analysis (Layer 2) Enhancements
- **LLM Agnosticism:** Integrate an abstraction layer (like `litellm`) to allow users to swap Anthropic's Claude Haiku with OpenAI's `gpt-4o`, Google's `gemini-1.5-flash`, or local open-weights privacy models (e.g., Llama-3).
- **Adversarial Resiliency Testing (CI):** Implement automated evaluation of the `PromptInjectionDetector` system prompt against public injection datasets (such as Lakera Gandalf or SPIDER) to ensure continuous robustness against novel jailbreaks.

## 4. Usability and Reporting
- **Framework-Specific Capabilities:** Abstract the primitive OS `Permission` enum (like `filesystem:write`) into LangChain/MCP specific concepts (like `mcp_registry:mutation`) for improved end-user clarity.
- **Human-Readable Reporting:** Augment the existing JSON and SARIF CI/CD outputs with a generated HTML/PDF report to assist security analysts in reviewing complex Layer 2 reasoning and Layer 3 trace data.
