# Problem Statement & Motivation

## The Problem

Agentic AI systems (LLM-based agents with tool use) are increasingly deployed with access to third-party skill packages — MCP servers, LangChain Tools, LangGraph agents. These packages are:

- Loaded automatically at runtime from public registries
- Injected directly into the LLM's context window (tool descriptions, names)
- Granted system-level capabilities (network, filesystem, subprocess)
- Executed without meaningful security review

**The core vulnerability:** An attacker who controls any part of a skill package (the manifest, description text, implementation code, or dependencies) has a path to compromising the agent's behavior — silently, before any user interaction.

## Why Existing Defenses Are Insufficient

1. **Runtime sandboxing** (e.g., Docker) prevents execution-time damage but cannot prevent the LLM from being manipulated by injected instructions before code runs.
2. **Code review** by humans is not scalable as tool marketplaces grow to thousands of packages.
3. **LLM-level content filters** are insufficient — they operate on user messages, not on tool metadata loaded as system context.
4. **No standardized threat model** for agentic skill packages exists in the literature (as of 2026).

## Research Questions

1. **RQ1**: What are the distinct attack surfaces and threat classes that arise specifically from the agentic skill supply chain?
2. **RQ2**: Can a static (pre-execution) scanner detect the majority of these threats with high precision, without requiring LLM inference?
3. **RQ3**: What is the minimum detection architecture needed to achieve operationally useful recall (≥ 90%) at production-acceptable precision (≥ 85%)?
4. **RQ4**: Which threat classes are fundamentally undetectable at the static layer, and what complementary techniques are required?

## Scope

**In scope:**
- MCP (Model Context Protocol) server manifests and implementation code
- LangChain `Tool` / `BaseTool` definitions
- LangGraph `StateGraph` agent definitions
- README.md and documentation files loaded as agent context

**Out of scope:**
- Direct model jailbreaking via user messages
- Inference-time adversarial attacks
- Infrastructure-level attacks on the hosting environment

## Key Claim (Paper Thesis)

> A lightweight three-layer pre-execution scanner — combining static AST analysis, semantic LLM judgment, and dynamic sandbox execution — can reliably detect the majority of agentic skill supply-chain attacks before any code is executed, with precision and recall suitable for production deployment.

**Layer 1 alone** (static analysis, no LLM required) achieves 100% precision and recall on the current fixture set, covering 7 of 8 attack vector classes.
