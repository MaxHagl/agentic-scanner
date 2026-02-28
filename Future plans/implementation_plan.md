# Agentic-Scanner: Future Implementation Plan

This is a concise, phased roadmap for implementing the future architectural and machine learning enhancements.

## Phase 1: Core Architecture & Data Pipeline
1. **Synthetic Data Generation:** Build a prompt-driven pipeline (using Claude/GPT-4o) to expand the existing 78 test fixtures into 5,000+ synthetic `(markdown_description, expected_trace_json, payload)` training tuples.
2. **LLM Agnosticism:** Refactor Layer 2 (`llm_judge.py`) using `litellm` to decouple the scanner from Anthropic, enabling local model support.

## Phase 2: Local Model Finetuning
1. **Base Model Selection:** Select a highly performant, compact generative model suitable for local CPU/edge inference (e.g., Llama-3.2-1B or Qwen-1.5B).
2. **Finetuning & Optimization:** Finetune the model on the synthetic dataset to accurately predict expected execution traces based purely on markdown files. Export the model artifacts (e.g., GGUF or ONNX) to meet strict sub-500ms latency limits.

## Phase 3: Layer 3 Engine Hardening
1. **eBPF Tracing:** Replace the in-process Python monkey-patching harness with an OS-level eBPF monitor (like Tracee) for un-evadable syscall interception.
2. **Trace Divergence Engine:** Implement the core behavioral thesis: calculate the divergence between the *Predicted Trace* (from the local LLM) and the *Observed Trace* (from the Layer 3 Sandbox). Flag anomalies as `BLOCK`.

## Phase 4: Usability & CI/CD
1. **Warm Sandbox Pooling:** Transition the Docker Sandbox layer to use pre-warmed containers or microVMs (Firecracker) to drastically reduce per-scan latency in CI environments.
2. **Auditable Reporting:** Build a lightweight HTML/PDF report generator to visualize the `FinalVerdict` object, the L2 reasoning, and the L3 traces for security analysts.
