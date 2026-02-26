# Related Work

_This file should be expanded as you review literature. Notes below are starting points._

## Static Analysis for Security

### Traditional SAST Tools
- **Bandit** (Python): AST-based security linter for Python. Detects `eval`, `exec`, subprocess, hardcoded passwords. Does NOT understand: MCP manifests, tool descriptions as injection surfaces, permission delta, or agent-specific threat classes.
- **Semgrep**: Pattern-based code analysis. Could theoretically be configured for some agentic patterns, but requires writing custom rules and doesn't understand the agentic context (e.g., what makes a tool description dangerous vs. a code comment).
- **CodeQL**: Deep semantic analysis. Powerful but heavyweight; requires database build, not suitable for fast pre-execution scanning.

**Gap this work fills:** None of these tools understand the agentic execution model where *text* in tool metadata is as dangerous as *code* in tool implementation.

## Prompt Injection Research

- Riley Goodside et al. (2022): First documented prompt injection attacks on LLM-integrated applications. Focused on user-input injection, not supply-chain.
- Greshake et al. (2023) "Not What You've Signed Up For": Indirect prompt injection via external content (web pages, documents). Closest to T2 in our taxonomy.
- **Gap:** No prior work systematically analyzes prompt injection as a *supply-chain* attack delivered via skill packages/tool definitions at the framework level.

## MCP Security

- The MCP specification (Anthropic, 2024) defines the protocol but provides minimal security guidance. No mention of:
  - Prompt injection via tool descriptions
  - Dynamic tool registration as a threat
  - Permission declaration verification
- **Gap:** This work appears to be among the first systematic security analyses of MCP as an attack surface.

## Supply Chain Security

- Ohm et al. (2020) "Backstabber's Knife Collection": Analysis of malicious npm packages. Typosquatting, malicious install hooks. Focused on npm, not Python or MCP.
- PyPI malware removal reports (multiple years): Document real typosquatting and credential-stealing packages. Validates our T1/T5 threat classes.
- **Gap:** No prior work applies supply-chain analysis to the agentic skill marketplace specifically.

## Agentic AI Security

- Anthropic's "Claude's Constitution" / model cards: Address model-level safety, not tool-level supply chain.
- OWASP Top 10 for LLMs (2023): Includes prompt injection and supply chain as categories but lacks operationalizable detection methods.
- **Gap:** No prior tool provides a pre-execution scanner specifically for the agentic skill supply chain.

## Typosquatting Detection

- Holz et al. (2019): Edit-distance-based typosquatting detection for npm.
- Our approach: Levenshtein distance ≤ 2 against top-100 PyPI packages. Similar method, applied to a new domain (agentic skill dependencies).

## Key Differentiation

This work's novel contributions over related work:
1. Threat taxonomy specifically for *agentic* skill packages (T1–T8)
2. Treatment of tool text fields as first-class security attack surfaces
3. Permission delta analysis (declared vs. exercised)
4. Unified scanner across three input formats (MCP JSON, Python, Markdown)
5. Benchmark infrastructure with attack-vector-level precision/recall
