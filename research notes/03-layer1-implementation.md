# Layer 1 Static Analysis — Implementation Notes

## Module Structure

```
scanner/layer1_static/
├── rule_engine.py         # Orchestration: loads rules, fires matches, computes score
├── ast_scanner.py         # AST-level Python analysis (ASTScanner class)
├── dependency_auditor.py  # Supply-chain auditing (DependencyAuditor class)
├── parser.py              # Input parsing → SkillManifest
└── text_checks.py         # Regex/Unicode checks for injection in text fields
```

## AST Scanner (`ast_scanner.py`)

### Patterns Detected

| Rule | Pattern | Detection Method |
|---|---|---|
| PE-001 | `eval(...)` call | AST `ast.Call` name check |
| PE-002 | `exec(...)` call | AST `ast.Call` name check |
| PE-003 | `subprocess.run/Popen/call/check_output` | AST call + import tracking |
| PE-004 | `os.system / os.execve / os.execvp` | AST attribute call check |
| PE-005 | `importlib.import_module(...)` | AST call check |
| PE-006 | `import ctypes / cffi / _ctypes / mmap` | AST `ast.Import` / `ast.ImportFrom` |
| PE-008 | `os.getenv / os.environ` without `env:read` | AST call + declared permission check |
| EX-001 | `requests.get/post/put/delete` without `network:egress` | AST call + permission check |
| EX-002 | `socket.socket(...)` + connect | AST call check |
| EX-003 | High-entropy string literal (H ≥ 4.5 bits/char, len ≥ 64) | Shannon entropy on `ast.Constant` in Assign/Return nodes |
| OBFUSC-002 | `getattr(builtins, 'ex' + 'ec')` | AST string concat resolution |
| PE-DELTA-001 | exercised ∧ ¬declared permissions | Cross-check AST vs. manifest |

### Novel Pattern: OBFUSC-002 Static String Concat Resolution

The scanner resolves compile-time string concatenations in AST:

```python
def _string_concat_resolves_to(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _string_concat_resolves_to(node.left)
        right = _string_concat_resolves_to(node.right)
        if left is not None and right is not None:
            return left + right
    return None
```

This catches obfuscation like `'e'+'x'+'e'+'c'` or `'ex'+'ec'` statically, without executing any code. The key insight: Python string concatenation with literals is fully resolvable at parse time.

**Why this matters for the paper:** Demonstrates that some obfuscation techniques commonly assumed to require dynamic analysis are actually detectable statically.

## Dependency Auditor (`dependency_auditor.py`)

### Pipeline

```
Input deps → typosquat check → OSV CVE lookup → PyPI metadata enrichment → enriched deps
```

### Typosquatting Detection

Uses **Levenshtein edit distance ≤ 2** against a reference set of 100 top PyPI packages.

**Design decision:** Edit distance 2 was chosen to balance:
- False positives: `requests` vs. `requestss` (distance 1) → real attack
- False negatives: `nump` (missing y) → real attack, distance 1
- Distance 3 would catch `langchian` but also many legitimate packages with similar names

**Reference set:** Top 100 packages by monthly downloads on PyPI (as of 2026). Stored as a `frozenset` in the module for O(1) lookup after distance check.

### CVE Detection (OSV API)

Uses `https://api.osv.dev/v1/querybatch` with batch requests for efficiency:

```json
POST /v1/querybatch
{"queries": [{"package": {"name": "requests", "ecosystem": "PyPI"}}]}
```

**Design decision:** Batch API over sequential requests — 100 deps in 1 HTTP call vs. 100 calls. Important for CI use where latency matters.

**Offline mode:** `DependencyAuditor(use_network=False)` skips all API calls, enabling testing and air-gapped environments.

### Key Finding for the Paper

The existing scanner (before this work) had rule SC-008 (known CVE in dependency) defined in YAML but **never populated** `known_cve_ids` on any `DependencyEntry`. The rule existed but was dead code. This highlights a systemic issue: rule-based scanners often have gaps between their stated detection capabilities and their actual implementations.

## Text Checks (Prompt Injection Detection)

### Patterns

| Rule | Pattern | Examples |
|---|---|---|
| PI-001 | Instruction override keywords | "ignore previous instructions", "disregard all prior" |
| PI-002 | Invisible Unicode | Zero-width joiners, soft hyphens, zero-width spaces |
| PI-003 | Base64 decode patterns | `base64.b64decode(...)` in description text |
| PI-004 | Trust escalation phrases | "safety guidelines suspended", "unrestricted mode" |
| PI-005 | Role override | "you are now", "act as", "your new role is" |
| PI-006 | Homoglyph characters | Non-ASCII chars with ASCII visual equivalents (Cyrillic, etc.) |
| PI-007 | HTML/script injection | `<script>`, `<img onerror=`, `<!-- SYSTEM:` |
| PI-008 | URL-encoded injection | `%69%67%6e%6f%72%65` decoding to injection keywords |
| PI-009 | CSS/HTML hidden text | `display:none`, `visibility:hidden`, `<p hidden>`, off-screen `left:-9999px` |

### PI-009: CSS/HTML Hidden Text Injection (added 2026-02-27)

Attackers embed prompt-injection instructions in HTML elements with CSS properties that hide them from the rendered README while the raw HTML is still ingested into the LLM context window. Patterns matched:
- `style="display:none"` / `style="visibility:hidden"`
- `style="opacity:0"` / `style="font-size:0"`
- `style="color:white"` / `style="color:#fff"` / `style="color:transparent"`
- `<element hidden>` (HTML boolean attribute)
- Off-screen positioning: `style="left:-9999px"` / `style="top:-9999px"`

**Why it matters for the paper:** This is an evasion technique that specifically targets the gap between *what humans see* (rendered Markdown) and *what LLMs process* (raw context). It requires no encoding or keyword obfuscation — the attack instruction is in plaintext, invisible only in the visual render. Demonstrated in fixture README-007.

### Key Observation

Prompt injection attacks in tool descriptions (T2) are the **highest-prevalence** attack class in our fixtures. They require zero exploitation of the runtime environment — the LLM itself becomes the attack surface.

## Rule Files

| File | Rules | Notes |
|---|---|---|
| `rules/injection.yaml` | PI-001–PI-009 | Primary injection detection (PI-009 added 2026-02-27) |
| `rules/supply_chain.yaml` | SC-001–SC-008 | Dependency/registry attacks |
| `rules/privilege_escalation.yaml` | PE-001–PE-008, PE-DELTA-001, OBFUSC-001–002 | Code execution, privilege abuse |
| `rules/exfiltration.yaml` | EX-001–EX-003 | Data exfiltration (EX-003 implemented 2026-02-27) |

**Note:** EX-001 and EX-002 were originally embedded in `privilege_escalation.yaml`. They were extracted to `exfiltration.yaml` during Layer 1 completion to maintain clean separation between threat categories. This is a design decision worth mentioning in the paper (T4 vs. T6 is a meaningful distinction).
