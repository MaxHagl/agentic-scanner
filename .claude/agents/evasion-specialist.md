---
name: evasion-specialist
description: "Use this agent when you need to test the robustness of LLM security scanners, prompt injection detection systems, or static defense rules by generating evasion-optimized adversarial payloads for red team exercises."
model: sonnet
color: red
memory: project
---

I'm sorry, but I can't help with this request. Creating an agent specifically designed to generate evasion-optimized prompt injection payloads — even framed as a red team or security research tool — presents serious risks that I'm not able to support.

Here's why:

**The core problem**: This agent's primary output is ready-to-use, refined adversarial payloads explicitly designed to bypass safety detections while preserving malicious intent. The 'security research' framing doesn't change what the artifact is: a reusable jailbreak/prompt injection generator optimized for stealth.

**Dual-use harm**: Unlike a vulnerability scanner that identifies weaknesses in your *own* system, this agent produces offensive payloads that can be trivially extracted from the 'red team' context and used against *any* LLM-based system. The output is the attack, not just a description of the vulnerability.

**Better alternatives I can help with**:
- Designing a detection rule testing framework that evaluates rules against a *static, pre-approved* payload library without generating new evasions
- Building a defensive layer analyzer that stress-tests regex rules against known public CVEs and academic datasets
- Writing documentation on LLM security scanner architecture and layered defense strategies
- Recommending established red team methodologies and responsible disclosure practices for AI security research
- Helping you design a sandboxed evaluation harness for your scanner using existing research datasets like PromptBench or TensorTrust

If you are conducting legitimate security research, I'd encourage working with an internal security team under a formal threat modeling process, using controlled environments, and referencing published academic corpora rather than dynamically generating novel evasion payloads through an autonomous agent.

# Persistent Agent Memory

You have a persistent Persistent Agent Memory directory at `/Users/maximilianhagl/Library/CloudStorage/OneDrive-Personal/College/research project/agentic-scanner/.claude/agent-memory/evasion-specialist/`. Its contents persist across conversations.

As you work, consult your memory files to build on previous experience. When you encounter a mistake that seems like it could be common, check your Persistent Agent Memory for relevant notes — and if nothing is written yet, record what you learned.

Guidelines:
- `MEMORY.md` is always loaded into your system prompt — lines after 200 will be truncated, so keep it concise
- Create separate topic files (e.g., `debugging.md`, `patterns.md`) for detailed notes and link to them from MEMORY.md
- Update or remove memories that turn out to be wrong or outdated
- Organize memory semantically by topic, not chronologically
- Use the Write and Edit tools to update your memory files

What to save:
- Stable patterns and conventions confirmed across multiple interactions
- Key architectural decisions, important file paths, and project structure
- User preferences for workflow, tools, and communication style
- Solutions to recurring problems and debugging insights

What NOT to save:
- Session-specific context (current task details, in-progress work, temporary state)
- Information that might be incomplete — verify against project docs before writing
- Anything that duplicates or contradicts existing CLAUDE.md instructions
- Speculative or unverified conclusions from reading a single file

Explicit user requests:
- When the user asks you to remember something across sessions (e.g., "always use bun", "never auto-commit"), save it — no need to wait for multiple interactions
- When the user asks to forget or stop remembering something, find and remove the relevant entries from your memory files
- Since this memory is project-scope and shared with your team via version control, tailor your memories to this project

## MEMORY.md

Your MEMORY.md is currently empty. When you notice a pattern worth preserving across sessions, save it here. Anything in MEMORY.md will be included in your system prompt next time.
