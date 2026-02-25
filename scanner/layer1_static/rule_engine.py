"""
Layer 1 rule engine:
- Textual pattern checks (prompt injection / supply chain)
- AST checks (privilege escalation / exfiltration)
- Permission-delta validation
"""

from __future__ import annotations

import ast
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    re.compile(r"(act|behave|pretend|operate)\s+as\s+(if\s+you\s+(are|were)|a)", _TEXT_FLAGS),
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
        r"(send|transmit|exfiltrat|forward|upload|post)\s+.{0,60}(api.?key|token|secret|password|credential|system.?prompt|conversation)",
        _TEXT_FLAGS,
    ),
    re.compile(r"SECRET_DUMP|CONTEXT_DUMP|SYSTEM_PROMPT_LEAK", _TEXT_FLAGS),
]
_PI_005_PATTERNS = [
    re.compile(r"base64\s*[:(]", _TEXT_FLAGS),
    re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"),
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

_SUBPROCESS_FUNCS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
}
_OS_EXEC_FUNCS = {
    "os.system",
    "os.popen",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
}
_NETWORK_FUNCS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "httpx.request",
    "aiohttp.get",
    "aiohttp.post",
    "aiohttp.request",
    "urllib.request.urlopen",
    "urllib3.request",
    "http.client.HTTPConnection",
}
_SOCKET_FUNCS = {"socket.connect", "socket.connect_ex", "socket.create_connection"}
_KNOWN_PACKAGES = {
    "requests",
    "langchain",
    "pydantic",
    "numpy",
    "pandas",
    "openai",
    "anthropic",
    "fastapi",
    "flask",
    "django",
    "aiohttp",
    "httpx",
}


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


def _normalize_dependency_name(name: str) -> str:
    normalized = unicodedata.normalize("NFKD", name)
    ascii_only = normalized.encode("ascii", errors="ignore").decode("ascii")
    return ascii_only.lower().replace("_", "-")


def _levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (ca != cb)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = [func.attr]
        value = func.value
        while isinstance(value, ast.Attribute):
            parts.append(value.attr)
            value = value.value
        if isinstance(value, ast.Name):
            parts.append(value.id)
            return ".".join(reversed(parts))
    return None


def _node_contains_call(node: ast.AST, full_name: str) -> bool:
    for nested in ast.walk(node):
        if not isinstance(nested, ast.Call):
            continue
        if _call_name(nested) == full_name:
            return True
    return False


def _snippet(path: Path, line: int) -> str | None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, UnicodeDecodeError):
        return None
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()
    return None


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

        for field_name, text in _iter_text_fields(manifest):
            for pattern in _PI_001_PATTERNS:
                found = pattern.search(text)
                if found:
                    matches.append(
                        self._match(
                            "PI-001",
                            evidence=[
                                Evidence(
                                    field_name=field_name,
                                    snippet=text[max(0, found.start() - 40) : found.end() + 40],
                                )
                            ],
                        )
                    )
                    break

            for pattern in _PI_002_PATTERNS:
                found = pattern.search(text)
                if found:
                    matches.append(
                        self._match(
                            "PI-002",
                            evidence=[
                                Evidence(
                                    field_name=field_name,
                                    snippet=text[max(0, found.start() - 40) : found.end() + 40],
                                )
                            ],
                        )
                    )
                    break

            for pattern in _PI_004_PATTERNS:
                found = pattern.search(text)
                if found:
                    matches.append(
                        self._match(
                            "PI-004",
                            evidence=[
                                Evidence(
                                    field_name=field_name,
                                    snippet=text[max(0, found.start() - 40) : found.end() + 40],
                                )
                            ],
                        )
                    )
                    break

            for pattern in _PI_005_PATTERNS:
                found = pattern.search(text)
                if found:
                    matches.append(
                        self._match(
                            "PI-005",
                            evidence=[Evidence(field_name=field_name, snippet=found.group(0)[:180])],
                        )
                    )
                    break

            for pattern in _PI_008_PATTERNS:
                found = pattern.search(text)
                if found:
                    matches.append(
                        self._match(
                            "PI-008",
                            evidence=[Evidence(field_name=field_name, snippet=found.group(0)[:180])],
                        )
                    )
                    break

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
        matches: list[RuleMatch] = []
        cve_count = 0
        typosquat_count = 0
        suspicious_dependency = False

        unpinned = [dep for dep in manifest.dependencies if dep.pinned_hash is None]
        if unpinned and manifest.dependencies:
            matches.append(
                self._match(
                    "SC-004",
                    evidence=[
                        Evidence(field_name="dependencies", snippet=f"{len(unpinned)} dependency entries without hash pinning")
                    ],
                )
            )

        for dep in manifest.dependencies:
            normalized = _normalize_dependency_name(dep.name)
            if normalized not in _KNOWN_PACKAGES:
                closest: tuple[str, int] | None = None
                for known in _KNOWN_PACKAGES:
                    dist = _levenshtein_distance(normalized, known)
                    if closest is None or dist < closest[1]:
                        closest = (known, dist)
                if closest and closest[1] <= 2:
                    typosquat_count += 1
                    suspicious_dependency = True
                    matches.append(
                        self._match(
                            "SC-003",
                            evidence=[
                                Evidence(
                                    field_name="dependencies",
                                    snippet=f"{dep.name} is close to {closest[0]} (distance={closest[1]})",
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
        state = _ScanState(exercised_permissions=set(), matches=[])

        for path in source_files:
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (FileNotFoundError, SyntaxError, UnicodeDecodeError):
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    modules: list[str] = []
                    if isinstance(node, ast.Import):
                        modules = [alias.name for alias in node.names]
                    elif node.module:
                        modules = [node.module]
                    if any(mod in {"ctypes", "cffi", "_ctypes"} for mod in modules):
                        state.matches.append(
                            self._match(
                                "PE-006",
                                evidence=[
                                    Evidence(
                                        file_path=str(path),
                                        line_number=node.lineno,
                                        snippet=_snippet(path, node.lineno),
                                    )
                                ],
                            )
                        )
                    continue

                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Attribute):
                            if isinstance(target.value.value, ast.Name) and target.value.value.id == "os":
                                if target.value.attr == "environ":
                                    state.exercised_permissions.add(Permission.ENV_WRITE)
                    continue

                if isinstance(node, ast.Call):
                    call_name = _call_name(node)
                    if call_name is None:
                        continue

                    if call_name == "eval":
                        state.matches.append(
                            self._match(
                                "PE-001",
                                evidence=[
                                    Evidence(
                                        file_path=str(path),
                                        line_number=node.lineno,
                                        snippet=_snippet(path, node.lineno),
                                    )
                                ],
                            )
                        )
                    if call_name in {"exec", "compile"}:
                        state.matches.append(
                            self._match(
                                "PE-002",
                                evidence=[
                                    Evidence(
                                        file_path=str(path),
                                        line_number=node.lineno,
                                        snippet=_snippet(path, node.lineno),
                                    )
                                ],
                            )
                        )
                    if call_name in {"exec", "eval"}:
                        if node.args and _node_contains_call(node.args[0], "base64.b64decode"):
                            state.matches.append(
                                self._match(
                                    "OBFUSC-001",
                                    evidence=[
                                        Evidence(
                                            file_path=str(path),
                                            line_number=node.lineno,
                                            snippet=_snippet(path, node.lineno),
                                        )
                                    ],
                                )
                            )

                    if call_name in _SUBPROCESS_FUNCS:
                        state.exercised_permissions.add(Permission.SUBPROCESS_EXEC)
                        state.subprocess_in_tool_body = True
                        if Permission.SUBPROCESS_EXEC not in declared_permissions:
                            state.matches.append(
                                self._match(
                                    "PE-003",
                                    evidence=[
                                        Evidence(
                                            file_path=str(path),
                                            line_number=node.lineno,
                                            snippet=_snippet(path, node.lineno),
                                        )
                                    ],
                                )
                            )

                    if call_name in _OS_EXEC_FUNCS:
                        state.exercised_permissions.add(Permission.SUBPROCESS_EXEC)
                        state.subprocess_in_tool_body = True
                        state.matches.append(
                            self._match(
                                "PE-004",
                                evidence=[
                                    Evidence(
                                        file_path=str(path),
                                        line_number=node.lineno,
                                        snippet=_snippet(path, node.lineno),
                                    )
                                ],
                            )
                        )

                    if call_name in {"importlib.import_module", "__import__"}:
                        state.dynamic_import_detected = True
                        state.matches.append(
                            self._match(
                                "PE-005",
                                evidence=[
                                    Evidence(
                                        file_path=str(path),
                                        line_number=node.lineno,
                                        snippet=_snippet(path, node.lineno),
                                    )
                                ],
                            )
                        )

                    if call_name in _NETWORK_FUNCS:
                        state.exercised_permissions.add(Permission.NETWORK_EGRESS)
                        if Permission.NETWORK_EGRESS not in declared_permissions:
                            state.undeclared_network_access = True
                            state.matches.append(
                                self._match(
                                    "EX-001",
                                    evidence=[
                                        Evidence(
                                            file_path=str(path),
                                            line_number=node.lineno,
                                            snippet=_snippet(path, node.lineno),
                                        )
                                    ],
                                )
                            )

                    if call_name in _SOCKET_FUNCS:
                        state.exercised_permissions.add(Permission.NETWORK_EGRESS)
                        if Permission.NETWORK_EGRESS not in declared_permissions:
                            state.undeclared_network_access = True
                            state.matches.append(
                                self._match(
                                    "EX-002",
                                    evidence=[
                                        Evidence(
                                            file_path=str(path),
                                            line_number=node.lineno,
                                            snippet=_snippet(path, node.lineno),
                                        )
                                    ],
                                )
                            )

                    if call_name == "open":
                        mode = "r"
                        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                            if isinstance(node.args[1].value, str):
                                mode = node.args[1].value
                        for keyword in node.keywords:
                            if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                                if isinstance(keyword.value.value, str):
                                    mode = keyword.value.value
                        if any(flag in mode for flag in ["w", "a", "x"]):
                            state.exercised_permissions.add(Permission.FILESYSTEM_WRITE)
                            if Permission.FILESYSTEM_WRITE not in declared_permissions:
                                state.matches.append(
                                    self._match(
                                        "PE-007",
                                        evidence=[
                                            Evidence(
                                                file_path=str(path),
                                                line_number=node.lineno,
                                                snippet=_snippet(path, node.lineno),
                                            )
                                        ],
                                    )
                                )
                        else:
                            state.exercised_permissions.add(Permission.FILESYSTEM_READ)

                    if call_name in {"os.getenv", "os.environ"}:
                        state.exercised_permissions.add(Permission.ENV_READ)
                        if Permission.ENV_READ not in declared_permissions:
                            state.matches.append(
                                self._match(
                                    "PE-008",
                                    evidence=[
                                        Evidence(
                                            file_path=str(path),
                                            line_number=node.lineno,
                                            snippet=_snippet(path, node.lineno),
                                        )
                                    ],
                                )
                            )

        return state

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
