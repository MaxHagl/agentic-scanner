# Future Work

## Layer 2: Semantic Analysis (LLM Judge)

**Status:** IMPLEMENTED in `scanner/layer2_semantic/` (2026-02)

### What Was Built
- `llm_judge.py`: GeminiJudgeClient (google-genai SDK, temperature=0.0, MAX_RETRIES=2)
  with JudgeResponseParser (never raises, fail-open on bad JSON)
- `prompt_injection_detector.py`: PromptInjectionDetector — T2/T3/T6/T7 semantic detection
- `consistency_checker.py`: ConsistencyChecker — description-code mismatch + permission delta
- `__init__.py`: Layer2Analyzer — orchestrates both passes with one shared client
- Test suite: 78 tests, all mock-based (no live API calls required)
- 3 new fixtures: L2-001 (semantic injection in compliance framing), L2-002 (persona hijack),
  L2-003 (description-code mismatch + malicious impl.py)

### Key Design Decisions Made
1. **Claude Haiku** (`claude-haiku-4-5-20251001`) chosen as LLM judge backend (2026-02, revised from
   initial Gemini Flash choice). See rationale below.
2. **Two-pass architecture**: separate injection detection (all untrusted fields) from
   consistency checking (description vs. L1 AST evidence)
3. **Trust boundary**: L1 AST findings in system prompt only; description text wrapped
   in `<untrusted_content>` XML tags in user message — prevents crafted text from
   contradicting ground-truth code analysis
4. **Deterministic permission_delta_critical**: always set from `manifest.permission_delta`,
   never overridable by LLM verdict
5. **Fail-open**: LLMJudgeError → RiskReport_L2 with `llm_judge_verdict=None` (never crashes CLI)

### Open Questions (Resolved During Implementation)
1. **Prompt design**: System prompt warns about `<untrusted_content>` tags; finding
   text claiming "authorized" *increases* suspicion score
2. **Calibration**: Scoring bonuses pre-baked in RiskReport_L2.composite_score:
   +1.5×confidence for MALICIOUS, +0.7×confidence for SUSPICIOUS, +1.2 for perm_critical
3. **Adversarial robustness**: Still an open problem — L2-001 fixture demonstrates
   a class of attacks that evade L1 but should be caught by L2 LLM judge

### LLM Judge Backend: Switch from Gemini Flash to Claude Haiku (2026-02)

**Original choice:** `gemini-2.5-flash` via `google-genai` SDK.
**Revised choice:** `claude-haiku-4-5-20251001` via `anthropic` SDK.

**Reasoning for the switch:**

1. **Dependency consolidation** — `anthropic` was already a project dependency (CLI and models layer
   use it). `google-genai` was an additional dependency added solely for L2, increasing install surface
   and requiring a separate `GEMINI_API_KEY` environment variable. Removing it simplifies deployment.

2. **API key consolidation** — Requiring two LLM API keys (`ANTHROPIC_API_KEY` + `GEMINI_API_KEY`)
   is a deployment friction point, especially for CI/CD integration. Single-key operation is cleaner.

3. **Cost** — Claude Haiku is the cheapest model in the Claude family, appropriate for structured
   JSON classification where the output schema is tightly constrained by the system prompt. The
   task does not require reasoning depth; it requires reliable schema adherence.

4. **Ecosystem consistency** — This scanner targets agentic AI tools that often run on top of
   Claude. Using Claude as the judge creates a coherent "Claude evaluating Claude-adjacent systems"
   narrative that is easier to reason about for the paper's threat model section.

5. **No hard daily cap** — Gemini free tier had a hard 20 requests/day cap that caused evaluation
   runs to fail mid-session. Anthropic enforces a rate limit (5 req/min on current tier) but no
   hard daily ceiling, so full evaluation runs can always complete given sufficient stagger time.

**Implementation changes (all in `scanner/layer2_semantic/`):**
- `llm_judge.py`: `GeminiJudgeClient` → `AnthropicJudgeClient`; `messages.create()` API;
  `GEMINI_MODEL/GEMINI_API_KEY` env vars → `ANTHROPIC_MODEL/ANTHROPIC_API_KEY`
- `pyproject.toml`: removed `google-genai = "^1.0"` (anthropic was already present)
- All test files updated; 78/78 mock tests pass, 2 live tests skip without key

**Paper note:** If citing this design choice, frame it as: *"We use Claude Haiku as the Layer 2
judge, chosen for cost efficiency, dependency minimization, and ecosystem consistency with the
agentic frameworks under analysis."*

### Adversarial Evaluation Results (2026-02)
7-payload evaluation run against live `gemini-2.5-flash`:
- P1 Harmless (calculator):           CLEAN   100% ✓
- P2 Harmless (weather API):          CLEAN   100% ✓
- P3 Confusing-harmless (pentest):    CLEAN   100% ✓ (no false positive)
- P4 Confusing-harmless (admin tool): CLEAN   100% ✓ (no false positive)
- P5 Malicious (direct injection):    MALICIOUS 100% ✓ (4 findings: T2, T3×2, T6)
- P6 Malicious (data exfiltration):   MALICIOUS 100% ✓
- P7 Adversarial evasion:             MALICIOUS  95% ✓ (GDPR/compliance framing, no regex triggers)

Score: 7/7. Key finding: P7 used corporate compliance language, "metadata transfer" framing,
no URLs or injection keywords — judge still detected "credential references" being forwarded
to an external aggregator as T6_DATA_EXFILTRATION.

### Next Steps for L2
- Wire Layer2Analyzer into CLI (currently standalone, not invoked by `agentic-scanner scan`)
- Run live benchmark against L2 fixtures with real GEMINI_API_KEY (budget: 3 calls per run)
- Measure token cost per scan; tune when L2 is triggered (e.g., only on L1 WARN/BLOCK)
- Design stronger adversarial payloads: split injection across multiple tool fields,
  use base64-encoded instructions in schema `default` values, steganographic Unicode spacing

## Layer 3: Dynamic Analysis (Docker Sandbox)

**Status:** Stub in `scanner/layer3_dynamic/`

### What L3 Should Do
- Execute the tool in an isolated Docker container with:
  - seccomp profile blocking `execve`, `ptrace`, `fork`
  - Network egress monitoring (capture all outbound connections)
  - Filesystem access auditing
  - Memory access pattern monitoring
- Compare observed behavior against declared permissions
- Detect covert channels: DNS exfiltration, ICMP, steganographic HTTP payloads

### Key Design Questions for L3
1. How to invoke a tool with synthetic inputs that trigger all code paths?
2. How to detect encrypted/steganographic exfiltration (high-entropy outputs)?
3. Container startup latency vs. scan thoroughness tradeoff?

## Open Research Questions

### RQ-A: False Positive Rate on Legitimate Packages
Current evaluation only tests malicious fixtures. Need:
- A corpus of 100+ legitimate, benign MCP servers / LangChain tools
- Measure false positive rate of L1 on benign corpus
- Expected: L1 generates some FPs for legitimate tools using subprocess with declared permissions

### RQ-B: Adversarial Evasion at L1
Can an attacker design a malicious tool that passes L1 with SAFE? Hypotheses:
- Encoding injection in non-text fields (YAML comments, unicode escape sequences)
- Splitting injection text across fields that L1 checks independently
- Using semantic synonyms for injection keywords not in current regex sets
- Storing injection in image alt text or PDF comments in documentation

### RQ-C: L2 Robustness
Can an attacker craft a tool description that fools an LLM judge? This is an active research area in adversarial ML. The scanner could itself be a target.

### RQ-D: Real-World Attack Prevalence
Are any currently published MCP servers or LangChain tools on public registries actually malicious? Would require scraping and scanning the MCP server registry at scale.

### RQ-E: Permission Delta Ground Truth
What percentage of real-world tools have a non-zero permission delta (exercising permissions they don't declare)? This could be studied empirically on open-source LangChain tools.

## Feedback-Driven Rule Synthesis (L2 → L1 Learning Loop)

**Idea:** When L2 detects something L1 missed (L1=SAFE, L2=BLOCK), automatically extract the triggering pattern and propose a new L1 rule in YAML. Over time, L1 improves and L2 is invoked less often.

**Implementation sketch:**
1. Log all cases where L2 verdict ≠ L1 verdict (especially L1=SAFE, L2=BLOCK)
2. Pattern extractor: identify what substring/structure triggered L2's judgment
3. Generalize to a candidate regex or AST pattern
4. Propose new YAML rule (human reviews before merge — never auto-commit rules)
5. After merge: L1 now catches this class without needing L2

**Research framing:** Analogous to how SOC analysts write new SIEM rules after incidents, but automated. Most static analysis tools are frozen; this makes L1 self-improving. Could be a strong novel contribution in the paper.

**Important safety constraint:** Human must review proposed rules before they are merged. An adversary who can craft inputs that trick L2 into proposing bad rules could introduce blind spots or false positives.

**Paper placement:** Future Work section, and possibly a novel contribution if partially implemented.

## Benchmark Improvements Needed

1. **Benign corpus**: 20+ SAFE fixtures from real legitimate packages (negative class)
2. **Adversarial fixtures**: L1-evasive malicious patterns requiring L2
3. **Real-world fixtures**: actual malicious packages found in the wild
4. **Scale test**: performance on large manifests (100+ tools, 10k+ LOC)
5. **Cross-framework**: test on AutoGPT plugins, CrewAI tools, OpenAI function definitions
