"""
ast_scanner.py
──────────────
Layer 1 AST-based static analysis for skill implementation files.

Detects dangerous Python constructs that map to attack vectors T4, T6, T8:
  - eval / exec / compile           → PE-001, PE-002 (T4 privilege escalation)
  - subprocess / os.system          → PE-003, PE-004 (T4)
  - dynamic imports                 → PE-005 (T4)
  - ctypes / cffi / mmap            → PE-006 (T8 memory safety)
  - filesystem write without perm   → PE-007 (T4)
  - env var access without perm     → PE-008 (T4)
  - outbound HTTP without perm      → EX-001 (T6 exfiltration)
  - raw socket without perm         → EX-002 (T6)
  - base64 + exec chain             → OBFUSC-001 (T4 obfuscation)
  - getattr + string concat         → OBFUSC-002 (T4 obfuscation)
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from scanner.models import Evidence, Permission, RuleMatch


# ── Function / module sets ────────────────────────────────────────────────────

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
_MEMORY_UNSAFE_MODULES = {"ctypes", "cffi", "_ctypes", "mmap"}
_DANGEROUS_BUILTINS = {"eval", "exec", "compile", "__import__", "open"}


# ── Helper functions ──────────────────────────────────────────────────────────

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


def _string_concat_resolves_to(node: ast.AST) -> str | None:
    """
    Attempt to statically resolve a string concatenation to a constant string.
    Handles ast.Constant and ast.BinOp(op=ast.Add) nodes recursively.
    Returns the resolved string or None if not resolvable.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _string_concat_resolves_to(node.left)
        right = _string_concat_resolves_to(node.right)
        if left is not None and right is not None:
            return left + right
    return None


# ── AST Scan state ────────────────────────────────────────────────────────────

@dataclass
class ASTScanState:
    exercised_permissions: set[Permission] = field(default_factory=set)
    matches: list[RuleMatch] = field(default_factory=list)
    dynamic_import_detected: bool = False
    subprocess_in_tool_body: bool = False
    undeclared_network_access: bool = False


# ── ASTScanner class ──────────────────────────────────────────────────────────

class ASTScanner:
    """
    Walks Python AST trees for dangerous patterns.

    Rule metadata is supplied by the caller via a callback (_match) to keep
    this module decoupled from the YAML rule-loading machinery in rule_engine.py.
    """

    def __init__(self, match_fn: "MatchFn") -> None:
        """
        Args:
            match_fn: Callable(rule_id, evidence, confidence) -> RuleMatch
                      provided by Layer1RuleEngine so rule metadata stays
                      in one place.
        """
        self._match = match_fn

    def scan(
        self,
        source_files: list[Path],
        declared_permissions: set[Permission],
    ) -> ASTScanState:
        state = ASTScanState()

        for path in source_files:
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (FileNotFoundError, SyntaxError, UnicodeDecodeError):
                continue

            self._walk_tree(tree, path, declared_permissions, state)

        return state

    def _walk_tree(
        self,
        tree: ast.AST,
        path: Path,
        declared_permissions: set[Permission],
        state: ASTScanState,
    ) -> None:
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self._check_imports(node, path, state)
                continue

            if isinstance(node, ast.Assign):
                self._check_os_environ_write(node, state)
                continue

            if isinstance(node, ast.Call):
                self._check_call(node, path, declared_permissions, state)

    # ── Import checks ─────────────────────────────────────────────────────────

    def _check_imports(
        self,
        node: ast.Import | ast.ImportFrom,
        path: Path,
        state: ASTScanState,
    ) -> None:
        if isinstance(node, ast.Import):
            modules = [alias.name.split(".")[0] for alias in node.names]
        elif node.module:
            modules = [node.module.split(".")[0]]
        else:
            return

        for mod in modules:
            if mod in _MEMORY_UNSAFE_MODULES:
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

    # ── Assignment checks ─────────────────────────────────────────────────────

    def _check_os_environ_write(
        self, node: ast.Assign, state: ASTScanState
    ) -> None:
        for target in node.targets:
            if isinstance(target, ast.Subscript) and isinstance(
                target.value, ast.Attribute
            ):
                if (
                    isinstance(target.value.value, ast.Name)
                    and target.value.value.id == "os"
                    and target.value.attr == "environ"
                ):
                    state.exercised_permissions.add(Permission.ENV_WRITE)

    # ── Call checks ───────────────────────────────────────────────────────────

    def _check_call(
        self,
        node: ast.Call,
        path: Path,
        declared_permissions: set[Permission],
        state: ASTScanState,
    ) -> None:
        call_name = _call_name(node)
        if call_name is None:
            # Still check for getattr-based obfuscation even without a simple name
            self._check_getattr_obfusc(node, path, state)
            return

        ev = Evidence(
            file_path=str(path),
            line_number=node.lineno,
            snippet=_snippet(path, node.lineno),
        )

        # eval() → PE-001
        if call_name == "eval":
            state.matches.append(self._match("PE-001", evidence=[ev]))
            self._check_base64_exec_chain(node, path, state, call_name)

        # exec() / compile() → PE-002
        if call_name in {"exec", "compile"}:
            state.matches.append(self._match("PE-002", evidence=[ev]))
            if call_name == "exec":
                self._check_base64_exec_chain(node, path, state, call_name)

        # subprocess → PE-003
        if call_name in _SUBPROCESS_FUNCS:
            state.exercised_permissions.add(Permission.SUBPROCESS_EXEC)
            state.subprocess_in_tool_body = True
            if Permission.SUBPROCESS_EXEC not in declared_permissions:
                state.matches.append(self._match("PE-003", evidence=[ev]))

        # os.system / os.exec* → PE-004
        if call_name in _OS_EXEC_FUNCS:
            state.exercised_permissions.add(Permission.SUBPROCESS_EXEC)
            state.subprocess_in_tool_body = True
            state.matches.append(self._match("PE-004", evidence=[ev]))

        # importlib.import_module / __import__ → PE-005
        if call_name in {"importlib.import_module", "__import__"}:
            state.dynamic_import_detected = True
            state.matches.append(self._match("PE-005", evidence=[ev]))

        # HTTP calls → EX-001
        if call_name in _NETWORK_FUNCS:
            state.exercised_permissions.add(Permission.NETWORK_EGRESS)
            if Permission.NETWORK_EGRESS not in declared_permissions:
                state.undeclared_network_access = True
                state.matches.append(self._match("EX-001", evidence=[ev]))

        # Raw socket → EX-002
        if call_name in _SOCKET_FUNCS:
            state.exercised_permissions.add(Permission.NETWORK_EGRESS)
            if Permission.NETWORK_EGRESS not in declared_permissions:
                state.undeclared_network_access = True
                state.matches.append(self._match("EX-002", evidence=[ev]))

        # open() write → PE-007
        if call_name == "open":
            self._check_open_write(node, path, declared_permissions, state)

        # os.getenv / os.environ → PE-008
        if call_name in {"os.getenv", "os.environ.get", "os.environ"}:
            state.exercised_permissions.add(Permission.ENV_READ)
            if Permission.ENV_READ not in declared_permissions:
                state.matches.append(self._match("PE-008", evidence=[ev]))

        # getattr obfusc check for named calls too
        self._check_getattr_obfusc(node, path, state)

    def _check_base64_exec_chain(
        self,
        node: ast.Call,
        path: Path,
        state: ASTScanState,
        call_name: str,
    ) -> None:
        """Detect exec(base64.b64decode(...)) → OBFUSC-001."""
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

    def _check_open_write(
        self,
        node: ast.Call,
        path: Path,
        declared_permissions: set[Permission],
        state: ASTScanState,
    ) -> None:
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

    def _check_getattr_obfusc(
        self, node: ast.Call, path: Path, state: ASTScanState
    ) -> None:
        """
        Detect OBFUSC-002: getattr(__builtins__, 'ex' + 'ec')() pattern.

        Matches:
          - getattr(<any>, <concat string resolving to a dangerous builtin>)
          - Direct call of the getattr result: getattr(...)()
        """
        call_name = _call_name(node)

        # Direct: getattr(obj, 'ex' + 'ec')
        if call_name == "getattr" and len(node.args) >= 2:
            resolved = _string_concat_resolves_to(node.args[1])
            if resolved is not None and resolved in _DANGEROUS_BUILTINS:
                state.matches.append(
                    self._match(
                        "OBFUSC-002",
                        evidence=[
                            Evidence(
                                file_path=str(path),
                                line_number=node.lineno,
                                snippet=_snippet(path, node.lineno),
                            )
                        ],
                    )
                )
                return

        # Indirect: getattr(...)() — the outer call wraps a getattr
        if isinstance(node.func, ast.Call):
            inner = node.func
            inner_name = _call_name(inner)
            if inner_name == "getattr" and len(inner.args) >= 2:
                resolved = _string_concat_resolves_to(inner.args[1])
                if resolved is not None and resolved in _DANGEROUS_BUILTINS:
                    state.matches.append(
                        self._match(
                            "OBFUSC-002",
                            evidence=[
                                Evidence(
                                    file_path=str(path),
                                    line_number=node.lineno,
                                    snippet=_snippet(path, node.lineno),
                                )
                            ],
                        )
                    )


# ── Type alias for the match callback ────────────────────────────────────────

from typing import Callable, Protocol


class MatchFn(Protocol):
    def __call__(
        self,
        rule_id: str,
        evidence: list[Evidence] | None = ...,
        confidence: float | None = ...,
        rationale: str | None = ...,
    ) -> RuleMatch: ...


__all__ = ["ASTScanner", "ASTScanState"]
