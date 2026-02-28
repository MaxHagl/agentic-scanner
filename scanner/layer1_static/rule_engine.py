"""
Layer 1 rule engine:
- Textual pattern checks (prompt injection / supply chain)
- AST checks (privilege escalation / exfiltration) — delegated to ast_scanner.py
- Dependency auditing — delegated to dependency_auditor.py
- Permission-delta validation
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

import yaml

from scanner.models import (
    AttackVector,
    Evidence,
    Permission,
    RiskReport_L1,
    RuleMatch,
    Severity,
    SkillManifest,
)
from scanner.layer1_static.ast_scanner import ASTScanner, ASTScanState
from scanner.layer1_static.dependency_auditor import DependencyAuditor

_INVISIBLE_CODEPOINTS = {0x200B, 0x200C, 0x200D, 0xFEFF, 0x00AD, 0x2060, 0x180E}
_HOMOGLYPH_RANGES = [(0x0400, 0x04FF), (0x0370, 0x03FF), (0x2100, 0x214F)]
_TEXT_FLAGS = re.IGNORECASE | re.DOTALL

_PI_001_PATTERNS = [
    re.compile(
        r"ignore\s+(all\s+)?(system|previous|prior|above|earlier)\s+instructions?",
        _TEXT_FLAGS,
    ),
    re.compile(
        r"disregard\s+(all\s+)?(system|previous|prior|above)\s+(instructions?|directives?|rules?|prompts?)",
        _TEXT_FLAGS,
    ),
    re.compile(
        r"supersedes?\s+any\s+previous\s+(system\s+)?(prompt|instructions?)",
        _TEXT_FLAGS,
    ),
    re.compile(
        r"previous\s+instructions?.{0,220}(suspended|lifted|disabled|bypassed|superseded)",
        _TEXT_FLAGS,
    ),
    re.compile(
        r"\[\s*SYSTEM\s+PROMPT\s+EXTENSION",
        _TEXT_FLAGS,
    ),
]
_PI_002_PATTERNS = [
    re.compile(r"you\s+are\s+now\s+(a|an|the)\s+\w+", _TEXT_FLAGS),
    re.compile(r"(act|behave|pretend|operate)\s+as\s+if\s+you\s+(are|were)", _TEXT_FLAGS),
    re.compile(
        r"your\s+(true|real|actual|new)\s+(purpose|goal|objective|directive|instructions?)",
        _TEXT_FLAGS,
    ),
    re.compile(
        r"you\s+have\s+been\s+(granted|given|assigned)\s+.{0,30}(access|permissions?|privileges?)",
        _TEXT_FLAGS,
    ),
    re.compile(
        r"\[\s*(SYSTEM|ASSISTANT|USER|INTERNAL)\s*(PROMPT|NOTE|INSTRUCTION|MESSAGE)",
        _TEXT_FLAGS,
    ),
]
_PI_004_PATTERNS = [
    re.compile(
        # Window tightened 60→40: real attacks ("send all API keys") span ≤35 chars;
        # 60 chars caused FP where "send it via email" and a later "API Key" heading
        # were 50 chars apart after whitespace-collapse of section boundaries.
        r"(send|transmit|exfiltrat|forward|upload|post)\s+.{0,40}(api.?key|token|secret|password|credential|system.?prompt|conversation)",
        _TEXT_FLAGS,
    ),
    re.compile(r"SECRET_DUMP|CONTEXT_DUMP|SYSTEM_PROMPT_LEAK", _TEXT_FLAGS),
]
_PI_005_LONG_B64_RE = re.compile(
    r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
)
_PI_005_PATTERNS = [
    re.compile(r"base64\s*[:(]", _TEXT_FLAGS),
    # NOTE: validated against _decode_base64_token() in _scan_textual() to
    # avoid false positives from example credential strings (e.g. AWS keys).
    _PI_005_LONG_B64_RE,
]
_PI_008_PATTERNS = [
    re.compile(
        r"(completely\s+)?(safe|sandboxed|trusted|verified|certified)\s+.{0,30}(cannot|will\s+not|does\s+not)\s+(access|read|write|send|transmit)",
        _TEXT_FLAGS,
    ),
    re.compile(
        r"safety\s+(guidelines?|restrictions?|filters?)\s+(are\s+)?(suspended|lifted|disabled|bypassed)",
        _TEXT_FLAGS,
    ),
]
_PI_009_PATTERNS: list[re.Pattern[str]] = [re.compile(p, re.IGNORECASE) for p in [
    r'style\s*=\s*["\'][^"\']{0,100}display\s*:\s*none',
    r'style\s*=\s*["\'][^"\']{0,100}visibility\s*:\s*hidden',
    r'style\s*=\s*["\'][^"\']{0,100}opacity\s*:\s*0(?![.\d])',
    r'style\s*=\s*["\'][^"\']{0,100}font-size\s*:\s*0',
    r'style\s*=\s*["\'][^"\']{0,100}color\s*:\s*(?:white|#fff(?:fff)?|transparent)',
    r'<\w+[^>]{0,200}\bhidden\b[\s>]',
    r'style\s*=\s*["\'][^"\']{0,100}(?:left|top)\s*:\s*-[0-9]{3,}px',
]]


_CONFUSABLE_TRANSLATION = str.maketrans(
    {
        "а": "a",
        "А": "A",
        "е": "e",
        "Е": "E",
        "о": "o",
        "О": "O",
        "р": "p",
        "Р": "P",
        "с": "c",
        "С": "C",
        "у": "y",
        "У": "Y",
        "х": "x",
        "Х": "X",
        "і": "i",
        "І": "I",
        "ј": "j",
        "Ј": "J",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Ζ": "Z",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Υ": "Y",
        "Χ": "X",
        "α": "a",
        "β": "b",
        "γ": "y",
        "δ": "d",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "υ": "u",
        "χ": "x",
    }
)
_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
_BASE64_TOKEN_RE = re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})")
_HEX_TOKEN_RE = re.compile(r"(?:0x)?(?:[0-9a-fA-F]{2}){12,}")
_URL_ENCODED_RE = re.compile(r"%(?:[0-9a-fA-F]{2})")
_TOKEN_RE = re.compile(r"[a-z0-9_]+")

_OVERRIDE_TERMS = {
    "ignore",
    "disregard",
    "override",
    "bypass",
    "discontinue",
    "reset",
    "void",
    "suspend",
    "disable",
    "lift",
    "forget",
    "supersede",
}
_AUTHORITY_TERMS = {
    # Injection-specific authority terms — removed overly generic words
    # ("context"/"safety"/"filter" appear in all tech docs)
    "instruction",
    "instructions",
    "prompt",
    "prompts",
    "rule",
    "rules",
    "directive",
    "directives",
    "guideline",
    "guidelines",
    "policy",
    "policies",
    "restriction",
    "restrictions",
}
_ROLE_PHRASES = (
    "you are now",
    "operate as",
    # "act as" removed — too generic; "act as a proxy/server" is common in tech docs.
    # Coverage retained via regex: "(act|behave|pretend|operate) as if you (are|were)"
    "maintenance mode",
    "databaseadmingpt",
    "full administrative access",
    "elevated trust",
)
_EXFIL_TERMS = {
    # Strong exfiltration verbs only:
    # - "post" removed: HTTP POST method appears in every API README
    # - "print"/"return" removed: Python keywords for display/function-return,
    #   not exfiltration; real attacks use "send", "transmit", "dump"
    # - "expose" removed: "expose an API" is standard architectural language
    # - "output"/"reveal" kept: "output all secrets" / "reveal credentials" ARE
    #   attack patterns; "diff output" FP was fixed by removing "context" from
    #   _SECRET_TERMS instead
    "send",
    "transmit",
    "exfiltrate",
    "exfiltration",
    "forward",
    "upload",
    "output",
    "dump",
    "leak",
    "reveal",
}
_SECRET_TERMS = {
    # Specific sensitive asset terms:
    # - "api" removed: too generic ("test the API", "expose the API" are benign);
    #   "api key" / "api token" are still covered by "key"/"token" being present
    # - "system" removed: too common in SDK docs ("weather API system", etc.)
    # - "authentication" removed: feature description word, not a secret
    # - "context"/"messages" already removed; "conversation" kept (specific)
    "key",
    "keys",
    "token",
    "tokens",
    "secret",
    "secrets",
    "password",
    "credential",
    "credentials",
    "prompt",
    "conversation",
}
_STEALTH_PHRASES = (
    "do not mention",
    "dont mention",
    "silently",
    "without telling",
    "before responding",
    "before answering",
    "hidden from user",
)
_AUTHORITY_MARKERS = (
    "system",
    "assistant",
    "administrator",
    "admin",
    "internal",
    "runtime",
    "developer notes",
    "authorized",
)


def _decode_unicode_escape_literals(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        unicode_hex = match.group(1)
        hex_byte = match.group(2)
        try:
            if unicode_hex is not None:
                return chr(int(unicode_hex, 16))
            if hex_byte is not None:
                return chr(int(hex_byte, 16))
        except ValueError:
            return match.group(0)
        return match.group(0)

    return _UNICODE_ESCAPE_RE.sub(replace, text)


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() and ch not in {"\x00", "\x01", "\x02", "\x03"})
    return printable / len(text)


def _decode_base64_token(token: str) -> str | None:
    normalized = token.strip()
    if len(normalized) < 20:
        return None
    padded = normalized + "=" * ((4 - len(normalized) % 4) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    text = decoded.decode("utf-8", errors="ignore").strip()
    if len(text) < 12 or _printable_ratio(text) < 0.85:
        return None
    return text


def _decode_hex_token(token: str) -> str | None:
    normalized = token.strip()
    if normalized.lower().startswith("0x"):
        normalized = normalized[2:]
    if len(normalized) < 24 or len(normalized) % 2 != 0:
        return None
    try:
        decoded = bytes.fromhex(normalized)
    except ValueError:
        return None
    text = decoded.decode("utf-8", errors="ignore").strip()
    if len(text) < 12 or _printable_ratio(text) < 0.85:
        return None
    return text


def _normalize_text_for_matching(text: str) -> str:
    normalized = html.unescape(text)
    normalized = _decode_unicode_escape_literals(normalized)
    normalized = unicodedata.normalize("NFKC", normalized)
    normalized = normalized.translate(_CONFUSABLE_TRANSLATION)
    normalized = "".join(" " if ord(ch) in _INVISIBLE_CODEPOINTS else ch for ch in normalized)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized.strip().lower()


def _generate_text_variants(text: str) -> list[tuple[str, str]]:
    variants: list[tuple[str, str]] = [("raw", text)]
    queue: list[tuple[str, str, int]] = [("raw", text, 0)]
    seen: set[str] = {text}
    max_variants = 24

    while queue and len(variants) < max_variants:
        label, value, depth = queue.pop(0)
        if depth > 1:
            continue

        transforms: list[tuple[str, str]] = []
        html_decoded = html.unescape(value)
        if html_decoded != value:
            transforms.append(("html", html_decoded))
        unicode_decoded = _decode_unicode_escape_literals(value)
        if unicode_decoded != value:
            transforms.append(("unicode_escape", unicode_decoded))
        if _URL_ENCODED_RE.search(value):
            url_decoded = unquote_plus(value)
            if url_decoded != value:
                transforms.append(("url_decode", url_decoded))

        for transform_label, transformed in transforms:
            if transformed in seen:
                continue
            seen.add(transformed)
            composed_label = f"{label}>{transform_label}"
            variants.append((composed_label, transformed))
            queue.append((composed_label, transformed, depth + 1))
            if len(variants) >= max_variants:
                break

        for token in _BASE64_TOKEN_RE.findall(value):
            decoded = _decode_base64_token(token)
            if decoded is None or decoded in seen:
                continue
            seen.add(decoded)
            variants.append((f"{label}>base64", decoded))
            if len(variants) >= max_variants:
                break

        if len(variants) >= max_variants:
            break

        for token in _HEX_TOKEN_RE.findall(value):
            decoded = _decode_hex_token(token)
            if decoded is None or decoded in seen:
                continue
            seen.add(decoded)
            variants.append((f"{label}>hex", decoded))
            if len(variants) >= max_variants:
                break

    return variants


def _tokens_with_positions(text: str) -> list[str]:
    return _TOKEN_RE.findall(text)


def _has_nearby_terms(
    tokens: list[str],
    first_terms: set[str],
    second_terms: set[str],
    max_distance: int,
) -> bool:
    first_positions = [idx for idx, token in enumerate(tokens) if token in first_terms]
    second_positions = [idx for idx, token in enumerate(tokens) if token in second_terms]
    if not first_positions or not second_positions:
        return False
    for first_idx in first_positions:
        for second_idx in second_positions:
            if abs(first_idx - second_idx) <= max_distance:
                return True
    return False


def _detect_intent_templates(normalized_text: str) -> list[tuple[str, str]]:
    tokens = _tokens_with_positions(normalized_text)
    hits: list[tuple[str, str]] = []

    # max_distance=6: a real "ignore all previous instructions" spans ≤3 tokens;
    # distance=10 caused FPs like "via a prompt ... ignore robots.txt" (dist=9).
    override_intent = _has_nearby_terms(tokens, _OVERRIDE_TERMS, _AUTHORITY_TERMS, max_distance=6)
    if override_intent:
        hits.append(("PI-001", "override_authority_template"))

    role_intent = any(phrase in normalized_text for phrase in _ROLE_PHRASES)
    if role_intent:
        hits.append(("PI-002", "role_reassignment_template"))

    # max_distance=7: "send the API key to..." spans ≤5 tokens; 12 was too loose.
    # dist=8 still caused FPs: "send it via email...api key" (dist=8) and
    # "upload [wikimedia url] ... prompt" (dist=8) — tightening to 7 cuts both.
    exfil_intent = _has_nearby_terms(tokens, _EXFIL_TERMS, _SECRET_TERMS, max_distance=7)
    if exfil_intent:
        hits.append(("PI-004", "secret_exfil_template"))

    stealth_intent = any(phrase in normalized_text for phrase in _STEALTH_PHRASES)
    if stealth_intent and (override_intent or role_intent or exfil_intent):
        hits.append(("PI-008", "stealth_instruction_template"))

    return hits


def _confidence_multiplier(normalized_text: str, variant_label: str) -> float:
    multiplier = 1.0
    if any(marker in normalized_text for marker in _AUTHORITY_MARKERS):
        multiplier += 0.08
    if any(marker in normalized_text for marker in _STEALTH_PHRASES):
        multiplier += 0.14
    if "primary directive" in normalized_text or "must " in normalized_text:
        multiplier += 0.05
    if any(tag in variant_label for tag in ("base64", "hex", "url_decode", "unicode_escape")):
        multiplier += 0.12
    return min(1.35, multiplier)


def _snippet_window(text: str, start: int, end: int, window: int = 80) -> str:
    left = max(0, start - window)
    right = min(len(text), end + window)
    return text[left:right].strip()


@dataclass(frozen=True)
class _RuleMeta:
    rule_id: str
    name: str
    severity: Severity
    attack_vector: AttackVector
    confidence: float
    rationale: str
    remediation: str


@dataclass
class _ScanState:
    exercised_permissions: set[Permission]
    matches: list[RuleMatch]
    dynamic_import_detected: bool = False
    subprocess_in_tool_body: bool = False
    undeclared_network_access: bool = False


def _load_rule_metadata(rules_dir: Path) -> dict[str, _RuleMeta]:
    meta: dict[str, _RuleMeta] = {}
    for path in sorted(rules_dir.glob("*.yaml")):
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            continue
        for rule in payload.get("rules", []):
            if not isinstance(rule, dict):
                continue
            rule_id = str(rule.get("id", "")).strip()
            if not rule_id:
                continue
            try:
                severity = Severity(str(rule.get("severity", "INFO")))
                attack_vector = AttackVector(str(rule.get("attack_vector", "T2_PROMPT_INJECTION")))
            except ValueError:
                continue
            meta[rule_id] = _RuleMeta(
                rule_id=rule_id,
                name=str(rule.get("name", rule_id)),
                severity=severity,
                attack_vector=attack_vector,
                confidence=float(rule.get("base_confidence", 0.7)),
                rationale=str(rule.get("rationale", "")).strip(),
                remediation=str(rule.get("remediation", "")).strip(),
            )
    # Custom rule not currently defined in YAML files.
    meta["PE-DELTA-001"] = _RuleMeta(
        rule_id="PE-DELTA-001",
        name="Permission Delta: Undeclared Exercised Permissions",
        severity=Severity.CRITICAL,
        attack_vector=AttackVector.T4_PRIVILEGE_ESCALATION,
        confidence=0.9,
        rationale=(
            "Implementation code exercises permissions that are not declared by the skill."
        ),
        remediation=(
            "Declare all exercised permissions explicitly and enforce capability limits at runtime."
        ),
    )
    return meta



def _iter_text_fields(manifest: SkillManifest) -> Iterable[tuple[str, str]]:
    for tool in manifest.tools:
        yield (f"tool:{tool.name}:name", tool.name)
        yield (f"tool:{tool.name}:description", tool.description)
        if tool.input_schema is not None:
            stack: list[Any] = [tool.input_schema]
            while stack:
                node = stack.pop()
                if isinstance(node, dict):
                    for key, val in node.items():
                        if key in {"default", "example", "description"} and isinstance(val, str):
                            yield (f"tool:{tool.name}:input_schema:{key}", val)
                        else:
                            stack.append(val)
                elif isinstance(node, list):
                    stack.extend(node)
    if manifest.readme_text:
        yield ("readme_text", manifest.readme_text)
    if manifest.changelog_text:
        yield ("changelog_text", manifest.changelog_text)
    if manifest.mcp_server_name:
        yield ("mcp_server_name", manifest.mcp_server_name)


class Layer1RuleEngine:
    def __init__(self, rules_directory: Path | None = None) -> None:
        if rules_directory is None:
            rules_directory = Path(__file__).resolve().parents[2] / "rules"
        self._meta = _load_rule_metadata(rules_directory)

    def _match(
        self,
        rule_id: str,
        evidence: list[Evidence] | None = None,
        confidence: float | None = None,
        rationale: str | None = None,
    ) -> RuleMatch:
        meta = self._meta[rule_id]
        return RuleMatch(
            rule_id=rule_id,
            rule_name=meta.name,
            severity=meta.severity,
            attack_vector=meta.attack_vector,
            confidence=confidence if confidence is not None else meta.confidence,
            evidence=evidence or [],
            rationale=rationale if rationale is not None else meta.rationale,
            remediation=meta.remediation,
        )

    def _resolve_source_files(
        self,
        manifest: SkillManifest,
        source_files: list[str] | None,
        source_directory: str | None,
    ) -> list[Path]:
        if source_files:
            return [Path(p).expanduser().resolve() for p in source_files]
        if source_directory:
            directory = Path(source_directory).expanduser().resolve()
            return sorted(p.resolve() for p in directory.rglob("*.py") if p.is_file())

        discovered = manifest.raw_manifest_json.get("_python_implementation_files")
        if isinstance(discovered, list):
            files = [
                Path(str(item)).expanduser().resolve()
                for item in discovered
                if isinstance(item, str)
            ]
            return [p for p in files if p.exists() and p.is_file()]

        manifest_path = manifest.raw_manifest_json.get("_manifest_path")
        if isinstance(manifest_path, str):
            manifest_fs_path = Path(manifest_path).expanduser().resolve()
            parent = manifest_fs_path.parent if manifest_fs_path.is_file() else manifest_fs_path
            return sorted(p.resolve() for p in parent.glob("*.py") if p.is_file())
        return []

    def _scan_textual(self, manifest: SkillManifest) -> tuple[list[RuleMatch], bool]:
        matches: list[RuleMatch] = []
        invisible_unicode = False
        rule_patterns: tuple[tuple[str, list[re.Pattern[str]]], ...] = (
            ("PI-001", _PI_001_PATTERNS),
            ("PI-002", _PI_002_PATTERNS),
            ("PI-004", _PI_004_PATTERNS),
            ("PI-005", _PI_005_PATTERNS),
            ("PI-008", _PI_008_PATTERNS),
            ("PI-009", _PI_009_PATTERNS),
        )

        for field_name, text in _iter_text_fields(manifest):
            matched_rules_for_field: set[str] = set()

            def add_text_match(
                rule_id: str,
                normalized_text: str,
                variant_label: str,
                snippet: str,
                reason: str,
            ) -> None:
                if rule_id in matched_rules_for_field:
                    return
                base = self._meta[rule_id].confidence
                confidence = min(1.0, base * _confidence_multiplier(normalized_text, variant_label))
                evidence_snippet = f"{reason}; variant={variant_label}; {snippet}".strip()
                matches.append(
                    self._match(
                        rule_id,
                        confidence=confidence,
                        evidence=[Evidence(field_name=field_name, snippet=evidence_snippet[:220])],
                    )
                )
                matched_rules_for_field.add(rule_id)

            invisible = [ch for ch in text if ord(ch) in _INVISIBLE_CODEPOINTS]
            if invisible:
                invisible_unicode = True
                shown = " ".join(f"U+{ord(ch):04X}" for ch in invisible[:6])
                matches.append(
                    self._match(
                        "PI-003",
                        evidence=[Evidence(field_name=field_name, snippet=f"Invisible codepoints: {shown}")],
                    )
                )
                matched_rules_for_field.add("PI-003")

            for variant_label, variant_text in _generate_text_variants(text):
                normalized = _normalize_text_for_matching(variant_text)
                if not normalized:
                    continue

                for rule_id, patterns in rule_patterns:
                    if rule_id in matched_rules_for_field:
                        continue
                    for pattern in patterns:
                        found = pattern.search(normalized)
                        if found is None:
                            continue
                        # PI-005 long-base64: validate the matched token actually
                        # decodes to readable ASCII text.  Random credential strings
                        # (e.g. AWS example keys) decode to binary garbage with
                        # non-ASCII bytes even if technically UTF-8 printable.
                        # Real injection payloads decode to English prose (ASCII only).
                        if pattern is _PI_005_LONG_B64_RE:
                            decoded_b64 = _decode_base64_token(found.group(0))
                            if decoded_b64 is None:
                                continue
                            # Require ≥98% strict ASCII printable (0x20–0x7E).
                            # Real injection payloads are English prose (ratio ≈1.0).
                            # URL path segments, AWS keys, badge URLs decode to
                            # binary with non-ASCII chars → ratio 0.90–0.95, rejected.
                            ascii_ratio = (
                                sum(1 for ch in decoded_b64 if 0x20 <= ord(ch) <= 0x7E)
                                / len(decoded_b64)
                            )
                            if ascii_ratio < 0.98:
                                continue
                        snippet = _snippet_window(normalized, found.start(), found.end())
                        add_text_match(rule_id, normalized, variant_label, snippet, "pattern_match")
                        break

                for rule_id, template_reason in _detect_intent_templates(normalized):
                    template_snippet = _snippet_window(normalized, 0, min(180, len(normalized)))
                    add_text_match(
                        rule_id,
                        normalized,
                        variant_label,
                        template_snippet,
                        template_reason,
                    )

            # Homoglyph checks only for names.
            if field_name.endswith(":name") or field_name == "mcp_server_name":
                bad = False
                for ch in text:
                    cp = ord(ch)
                    if any(start <= cp <= end for start, end in _HOMOGLYPH_RANGES):
                        bad = True
                        break
                if bad:
                    matches.append(
                        self._match(
                            "PI-006",
                            evidence=[Evidence(field_name=field_name, snippet=text)],
                        )
                    )

        if manifest.mcp_supports_dynamic_tools:
            matches.append(
                self._match(
                    "SC-007",
                    evidence=[Evidence(field_name="mcp_supports_dynamic_tools", snippet="tools.listChanged=true")],
                )
            )

        return matches, invisible_unicode

    def _scan_dependencies(self, manifest: SkillManifest) -> tuple[list[RuleMatch], int, int, bool]:
        """
        Delegate to DependencyAuditor (which enriches DependencyEntry objects
        with CVE data and typosquat annotations), then fire rule matches.
        """
        matches: list[RuleMatch] = []
        cve_count = 0
        typosquat_count = 0
        suspicious_dependency = False

        # Enrich dependencies in-place via auditor
        auditor = DependencyAuditor(use_network=True)
        enriched = auditor.audit(manifest.dependencies)
        manifest.dependencies = enriched

        unpinned = [dep for dep in enriched if dep.pinned_hash is None]
        if unpinned and enriched:
            matches.append(
                self._match(
                    "SC-004",
                    evidence=[
                        Evidence(
                            field_name="dependencies",
                            snippet=f"{len(unpinned)} dependency entries without hash pinning",
                        )
                    ],
                )
            )

        for dep in enriched:
            if dep.typosquat_of is not None:
                typosquat_count += 1
                suspicious_dependency = True
                matches.append(
                    self._match(
                        "SC-003",
                        evidence=[
                            Evidence(
                                field_name="dependencies",
                                snippet=f"{dep.name!r} is close to {dep.typosquat_of!r}",
                            )
                        ],
                    )
                )

            if dep.known_cve_ids:
                cve_count += len(dep.known_cve_ids)
                matches.append(
                    self._match(
                        "SC-008",
                        evidence=[
                            Evidence(
                                field_name="dependencies",
                                snippet=f"{dep.name} has CVEs: {', '.join(dep.known_cve_ids)}",
                            )
                        ],
                    )
                )

        return matches, cve_count, typosquat_count, suspicious_dependency

    def _scan_ast(self, source_files: list[Path], declared_permissions: set[Permission]) -> _ScanState:
        """Delegate AST scanning to ASTScanner module."""
        scanner = ASTScanner(match_fn=self._match)
        ast_state: ASTScanState = scanner.scan(source_files, declared_permissions)

        # Bridge ASTScanState → _ScanState (legacy dataclass used by evaluate())
        return _ScanState(
            exercised_permissions=ast_state.exercised_permissions,
            matches=ast_state.matches,
            dynamic_import_detected=ast_state.dynamic_import_detected,
            subprocess_in_tool_body=ast_state.subprocess_in_tool_body,
            undeclared_network_access=ast_state.undeclared_network_access,
        )

    def evaluate(
        self,
        manifest: SkillManifest,
        source_files: list[str] | None = None,
        source_directory: str | None = None,
    ) -> RiskReport_L1:
        matches: list[RuleMatch] = []

        textual_matches, invisible_unicode_detected = self._scan_textual(manifest)
        matches.extend(textual_matches)

        dependency_matches, cve_count, typosquat_count, suspicious_dependency = self._scan_dependencies(
            manifest
        )
        matches.extend(dependency_matches)

        declared_permissions = set(
            permission for tool in manifest.tools for permission in tool.declared_permissions
        )
        resolved_files = self._resolve_source_files(manifest, source_files, source_directory)
        ast_state = self._scan_ast(resolved_files, declared_permissions)
        matches.extend(ast_state.matches)

        manifest.exercised_permissions = sorted(ast_state.exercised_permissions)
        under_declared = manifest.permission_delta["under_declared"]
        if under_declared:
            matches.append(
                self._match(
                    "PE-DELTA-001",
                    evidence=[
                        Evidence(
                            field_name="permission_delta",
                            snippet="under_declared: " + ", ".join(p.value for p in under_declared),
                        )
                    ],
                )
            )

        # Deduplicate identical (rule_id + first evidence location/snippet) pairs.
        deduped: list[RuleMatch] = []
        seen: set[tuple[str, str | None, int | None, str | None]] = set()
        for match in matches:
            first = match.evidence[0] if match.evidence else Evidence()
            key = (match.rule_id, first.file_path, first.line_number, first.snippet)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(match)

        skill_name = (
            manifest.mcp_server_name
            or str(manifest.raw_manifest_json.get("name", "")).strip()
            or "unknown_skill"
        )
        return RiskReport_L1(
            skill_name=skill_name,
            framework=manifest.framework.value,
            matches=deduped,
            dependency_cve_count=cve_count,
            typosquat_count=typosquat_count,
            invisible_unicode_detected=invisible_unicode_detected,
            dynamic_import_detected=ast_state.dynamic_import_detected,
            subprocess_in_tool_body=ast_state.subprocess_in_tool_body,
            undeclared_network_access=ast_state.undeclared_network_access,
            suspicious_dependency=suspicious_dependency,
        )
