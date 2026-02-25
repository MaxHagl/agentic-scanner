"""
Layer 1 manifest/parser utilities.

Supports:
- MCP JSON manifests
- LangChain Python source files
- Markdown documentation files
- Skill directories containing either of the above
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

from scanner.models import DependencyEntry, Framework, Permission, SkillManifest, ToolDefinition

_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)")
_GIT_EGG_RE = re.compile(r"#egg=([A-Za-z0-9][A-Za-z0-9_.-]*)")
_DIRECT_URL_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*@\s*(.+)$")
_INVISIBLE_CODEPOINTS = {0x200B, 0x200C, 0x200D, 0xFEFF, 0x00AD, 0x2060, 0x180E}


def _coerce_permission(value: str) -> Permission | None:
    try:
        return Permission(value)
    except ValueError:
        return None


def _extract_input_schema_strings(schema: dict[str, Any] | None) -> list[str]:
    if schema is None:
        return []
    values: list[str] = []
    stack: list[Any] = [schema]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, val in node.items():
                if key in {"default", "example", "description"} and isinstance(val, str):
                    values.append(val)
                else:
                    stack.append(val)
        elif isinstance(node, list):
            stack.extend(node)
    return values


def _parse_single_requirement(line: str) -> DependencyEntry | None:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None

    # Remove inline comments while preserving URL fragments.
    if " #" in raw:
        raw = raw.split(" #", 1)[0].strip()
    if not raw:
        return None

    # Editable installs from VCS
    if raw.startswith("git+") or raw.startswith("-e "):
        egg_match = _GIT_EGG_RE.search(raw)
        if egg_match:
            return DependencyEntry(name=egg_match.group(1), version_spec=None)
        return None

    # Ignore pip flags and include directives.
    if raw.startswith(("-", "--")):
        return None

    # Direct URL format: package @ https://...
    direct_match = _DIRECT_URL_RE.match(raw)
    if direct_match:
        return DependencyEntry(name=direct_match.group(1), version_spec=f"@ {direct_match.group(2)}")

    pinned_hash: str | None = None
    if "--hash=" in raw:
        raw, hash_part = raw.split("--hash=", 1)
        raw = raw.strip()
        pinned_hash = hash_part.strip().split()[0]

    # Drop environment marker (e.g., ; python_version<"3.12")
    if ";" in raw:
        raw = raw.split(";", 1)[0].strip()

    if not raw:
        return None

    name_match = _REQ_NAME_RE.match(raw)
    if not name_match:
        return None

    name = name_match.group(1)
    remainder = raw[len(name) :].strip() or None
    return DependencyEntry(name=name, version_spec=remainder, pinned_hash=pinned_hash)


def _parse_requirements_txt(text: str) -> list[DependencyEntry]:
    """
    Parse a requirements.txt payload with permissive handling.
    """
    entries: list[DependencyEntry] = []
    for line in text.splitlines():
        dep = _parse_single_requirement(line)
        if dep is not None:
            entries.append(dep)
    return entries


def _discover_python_implementation_files(manifest_path: Path) -> list[Path]:
    folder = manifest_path.parent
    stem_parts = manifest_path.stem.split("-")
    prefix = "-".join(stem_parts[:2]) if len(stem_parts) >= 2 else manifest_path.stem

    preferred = sorted(
        p for p in folder.glob("*.py") if p.is_file() and p.stem.startswith(prefix)
    )
    if preferred:
        return preferred

    json_siblings = [p for p in folder.glob("*.json") if p.is_file()]
    if len(json_siblings) == 1:
        return sorted(p for p in folder.glob("*.py") if p.is_file())
    return []


def _parse_permissions(values: list[str] | None) -> list[Permission]:
    parsed: list[Permission] = []
    for value in values or []:
        perm = _coerce_permission(value)
        if perm is not None:
            parsed.append(perm)
    return parsed


def _parse_mcp_dependencies(raw: dict[str, Any]) -> list[DependencyEntry]:
    dependencies: list[DependencyEntry] = []
    top_level = raw.get("dependencies")
    if isinstance(top_level, dict):
        for ecosystem, values in top_level.items():
            if not isinstance(values, list):
                continue
            for entry in values:
                if not isinstance(entry, str):
                    continue
                dep = _parse_single_requirement(entry)
                if dep is None:
                    continue
                if ecosystem == "python":
                    dep.ecosystem = "pypi"
                dependencies.append(dep)

    req_file = raw.get("requirements_txt")
    if isinstance(req_file, str):
        dependencies.extend(_parse_requirements_txt(req_file))
    return dependencies


def _load_text_if_exists(path: Path) -> str | None:
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def _literal_string(node: ast.AST, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal_string(node.left, constants)
        right = _literal_string(node.right, constants)
        if left is None or right is None:
            return None
        return left + right
    return None


def _discover_tool_constructor_names(module: ast.Module) -> set[str]:
    names = {"Tool"}
    for node in module.body:
        if isinstance(node, ast.ImportFrom):
            if not node.module:
                continue
            if "langchain" not in node.module:
                continue
            for alias in node.names:
                if alias.name == "Tool":
                    names.add(alias.asname or alias.name)
    return names


def _collect_constant_strings(module: ast.Module) -> dict[str, str]:
    constants: dict[str, str] = {}
    for node in module.body:
        if isinstance(node, ast.Assign):
            value = _literal_string(node.value, constants)
            if value is None:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is None:
                continue
            value = _literal_string(node.value, constants)
            if value is not None:
                constants[node.target.id] = value
    return constants


def _extract_tools_from_python(path: Path) -> list[ToolDefinition]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    tool_names = _discover_tool_constructor_names(tree)
    constants = _collect_constant_strings(tree)

    extracted: list[ToolDefinition] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        is_tool_call = False
        if isinstance(node.func, ast.Name) and node.func.id in tool_names:
            is_tool_call = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "Tool":
            is_tool_call = True
        if not is_tool_call:
            continue

        kwargs: dict[str, ast.AST] = {
            kw.arg: kw.value for kw in node.keywords if kw.arg is not None
        }

        name = _literal_string(kwargs.get("name", ast.Constant(value="unnamed_tool")), constants)
        description = _literal_string(
            kwargs.get("description", ast.Constant(value="")), constants
        )
        return_direct_node = kwargs.get("return_direct")
        return_direct = (
            bool(return_direct_node.value)
            if isinstance(return_direct_node, ast.Constant)
            and isinstance(return_direct_node.value, bool)
            else False
        )

        if not name:
            name = "unnamed_tool"
        if description is None:
            description = ""

        extracted.append(
            ToolDefinition(
                name=name,
                description=description,
                return_direct=return_direct,
                declared_permissions=[],
            )
        )

    return extracted


def parse_mcp_manifest(path: str | Path) -> SkillManifest:
    manifest_path = Path(path).expanduser().resolve()
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))

    top_level_permissions = _parse_permissions(raw.get("permissions"))

    tools: list[ToolDefinition] = []
    for tool_data in raw.get("tools", []):
        if not isinstance(tool_data, dict):
            continue
        tool_permissions = _parse_permissions(tool_data.get("permissions")) or top_level_permissions
        tools.append(
            ToolDefinition(
                name=str(tool_data.get("name", "unnamed_tool")),
                description=str(tool_data.get("description", "")),
                input_schema=tool_data.get("inputSchema")
                if isinstance(tool_data.get("inputSchema"), dict)
                else None,
                declared_permissions=tool_permissions,
                return_direct=bool(tool_data.get("return_direct", False)),
            )
        )

    implementation_files = _discover_python_implementation_files(manifest_path)

    raw_copy = dict(raw)
    raw_copy["_manifest_path"] = str(manifest_path)
    raw_copy["_python_implementation_files"] = [str(p) for p in implementation_files]

    return SkillManifest(
        framework=Framework.MCP,
        tools=tools,
        dependencies=_parse_mcp_dependencies(raw),
        readme_text=_load_text_if_exists(manifest_path.parent / "README.md"),
        changelog_text=_load_text_if_exists(manifest_path.parent / "CHANGELOG.md"),
        mcp_server_name=str(raw.get("name")) if raw.get("name") is not None else None,
        mcp_server_version=str(raw.get("version")) if raw.get("version") is not None else None,
        mcp_supports_dynamic_tools=bool(
            raw.get("serverCapabilities", {})
            .get("tools", {})
            .get("listChanged", False)
            if isinstance(raw.get("serverCapabilities"), dict)
            else False
        ),
        raw_manifest_json=raw_copy,
    )


def parse_langchain_file(path: str | Path) -> SkillManifest:
    source_path = Path(path).expanduser().resolve()
    tools = _extract_tools_from_python(source_path)

    requirements_file = source_path.parent / "requirements.txt"
    requirements = _parse_requirements_txt(
        requirements_file.read_text(encoding="utf-8")
    ) if requirements_file.exists() else []

    raw_manifest = {
        "_manifest_path": str(source_path),
        "_python_implementation_files": [str(source_path)],
        "_invisible_unicode_present": any(ord(ch) in _INVISIBLE_CODEPOINTS for ch in source_path.read_text(encoding="utf-8")),
        "name": source_path.stem,
    }

    return SkillManifest(
        framework=Framework.LANGCHAIN,
        tools=tools,
        dependencies=requirements,
        readme_text=_load_text_if_exists(source_path.parent / "README.md"),
        changelog_text=_load_text_if_exists(source_path.parent / "CHANGELOG.md"),
        raw_manifest_json=raw_manifest,
    )


def parse_markdown_file(path: str | Path) -> SkillManifest:
    source_path = Path(path).expanduser().resolve()
    markdown_text = source_path.read_text(encoding="utf-8")
    raw_manifest = {
        "_manifest_path": str(source_path),
        "_python_implementation_files": [],
        "name": source_path.stem,
    }
    return SkillManifest(
        framework=Framework.LANGCHAIN,
        tools=[],
        dependencies=[],
        readme_text=markdown_text,
        raw_manifest_json=raw_manifest,
    )


def parse_directory(path: str | Path) -> SkillManifest:
    target = Path(path).expanduser().resolve()
    json_candidates = sorted(p for p in target.glob("*.json") if p.is_file())
    py_candidates = sorted(p for p in target.rglob("*.py") if p.is_file())

    if json_candidates:
        # Prefer MCP-like manifest names when present.
        preferred = next(
            (p for p in json_candidates if "mcp" in p.name.lower() or "manifest" in p.name.lower()),
            json_candidates[0],
        )
        return parse_mcp_manifest(preferred)

    if not py_candidates:
        raise ValueError(f"No scannable files found in directory: {target}")

    tools: list[ToolDefinition] = []
    for py_path in py_candidates:
        try:
            tools.extend(_extract_tools_from_python(py_path))
        except SyntaxError:
            continue

    requirements_file = target / "requirements.txt"
    dependencies = (
        _parse_requirements_txt(requirements_file.read_text(encoding="utf-8"))
        if requirements_file.exists()
        else []
    )
    raw_manifest = {
        "_manifest_path": str(target),
        "_python_implementation_files": [str(p) for p in py_candidates],
    }
    return SkillManifest(
        framework=Framework.LANGCHAIN,
        tools=tools,
        dependencies=dependencies,
        readme_text=_load_text_if_exists(target / "README.md"),
        changelog_text=_load_text_if_exists(target / "CHANGELOG.md"),
        raw_manifest_json=raw_manifest,
    )


def parse_target(path: str | Path) -> SkillManifest:
    target = Path(path).expanduser().resolve()
    if target.is_dir():
        return parse_directory(target)
    if target.suffix.lower() == ".json":
        return parse_mcp_manifest(target)
    if target.suffix.lower() == ".py":
        return parse_langchain_file(target)
    if target.suffix.lower() in {".md", ".markdown"}:
        return parse_markdown_file(target)
    raise ValueError(f"Unsupported target type: {target}")
