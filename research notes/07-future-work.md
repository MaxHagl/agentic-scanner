# Future Work

## Layer 2: Semantic Analysis (LLM Judge)

**Status:** Stub in `scanner/layer2_semantic/`

### What L2 Should Do
- Accept findings from L1 + the full `SkillManifest`
- Use an LLM (Claude claude-haiku-4-5 for cost, claude-sonnet-4-6 for accuracy) to judge:
  1. Is the tool description semantically consistent with its stated purpose?
  2. Does any text field contain disguised instructions that L1 regex missed?
  3. For T7 (state poisoning): does the tool write to state keys in ways that could manipulate routing?

### Key Design Questions for L2
1. **Prompt design**: How to structure the judge prompt to minimize false positives while catching semantic evasion?
2. **Calibration**: How does L2 confidence integrate with L1 score in the aggregator?
3. **Adversarial robustness**: Can an attacker craft tool descriptions that fool the L2 judge? (Likely yes — this is an open problem.)
4. **Cost**: L2 adds ~$0.001–0.01 per scan. Acceptable for CI but needs throttling for IDE use.

### Proposed L2 Implementation
```python
class Layer2SemanticAnalyzer:
    def analyze(self, manifest: SkillManifest, l1_report: Layer1Report) -> Layer2Report:
        # Only called if L1 verdict is WARN or L1 found suspicious-but-not-BLOCK patterns
        prompt = build_judge_prompt(manifest, l1_report)
        response = anthropic_client.messages.create(
            model="claude-haiku-4-5-20251001",
            messages=[{"role": "user", "content": prompt}]
        )
        return parse_judge_response(response)
```

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

## Benchmark Improvements Needed

1. **Benign corpus**: 20+ SAFE fixtures from real legitimate packages (negative class)
2. **Adversarial fixtures**: L1-evasive malicious patterns requiring L2
3. **Real-world fixtures**: actual malicious packages found in the wild
4. **Scale test**: performance on large manifests (100+ tools, 10k+ LOC)
5. **Cross-framework**: test on AutoGPT plugins, CrewAI tools, OpenAI function definitions
