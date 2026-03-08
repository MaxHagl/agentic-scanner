"""
finetuning/harvest_mcp_corpus.py
──────────────────────────────────
Harvest MCP/agent code from on-disk repos into new pretrain corpus shards.

Adds five shards to finetuning/pretrain_corpus_full/shards/:
  mcp_python_source.txt   — Python source from MCP repos (original + extra)
  mcp_readmes.txt         — MCP server README files + SKILL.md
  mcp_json_manifests.txt  — MCP JSON tool manifests
  agent_frameworks.txt    — All agent framework Python source (all subdirs of repos-dir)
  skill_files.txt         — Benign SKILL.md (GitHub) + malicious SKILL.md (hand-crafted)

Scope rationale:
  mcp_python_source:  @mcp.tool() implementations — what the scanner classifies
  mcp_readmes:        Tool description markdown (README*) and formal skill
                      manifests (SKILL.md with YAML frontmatter) — exact scanner
                      input format for markdown targets
  mcp_json_manifests: JSON with top-level "tools" array — MCP manifest format
                      (the third scanner input type, alongside .py and .md)
  agent_frameworks:   All Python repos under repos-dir (LangChain, AutoGen,
                      crewAI, Haystack, Semantic Kernel, Pydantic AI, Composio,
                      smolagents and any future additions)
  skill_files:        The inference-distribution-aligned shard — SKILL.md files
                      are exactly what the scanner classifies; including both benign
                      and malicious variants in pretraining teaches the encoder the
                      benign/malicious contrast in that exact format.

Deliberately excluded from mcp_readmes:
  All other *.md files (docs/, .agents/rules/, troubleshooting guides,
  env-var references, config templates) — these are *about* tools, not
  *defining* them, and would dilute the domain signal.

Shard format: one document per line (UTF-8).
    Embedded newlines within source files are replaced with a single space
    so that pretrain.py's `text.splitlines()` sees each file as one doc.
    The tokenizer still learns all Python keywords and identifiers.

Supply-chain integrity:
    SHA256 of each shard is recorded in manifest.json alongside doc/byte counts.
    Re-running the script is idempotent: existing entries with the same source
    name are replaced.

Usage:
    poetry run python finetuning/harvest_mcp_corpus.py

    # With additional repos and skill files (after running download_agent_repos.py):
    poetry run python finetuning/harvest_mcp_corpus.py \\
        --clones-dir       benchmarks/ecosystem_local_400/clones \\
        --extra-clones-dir benchmarks/ecosystem_local_400/additional_clones \\
        --repos-dir        benchmarks/repos \\
        --benign-skills-dir  finetuning/data/benign_skills \\
        --malicious-skills-dir finetuning/data/malicious_skills \\
        --output-dir       finetuning/pretrain_corpus_full
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent

# ── Skip filters ─────────────────────────────────────────────────────────────

# Directories anywhere in the path that indicate generated / non-source content
_SKIP_DIRS: frozenset[str] = frozenset({
    "__pycache__", ".git", ".hg", "node_modules",
    ".venv", "venv", "env", ".env",
    "dist", "build", "_build", "site-packages",
    ".eggs", "*.egg-info",
})

# Max source file size — skip likely-generated or vendored blobs
_MAX_PY_BYTES: int = 50_000  # 50 KB

# Min text length — skip stub / placeholder files
_MIN_TEXT_CHARS: int = 100

# JSON filenames that are project metadata, not MCP manifests
_JSON_SKIP_NAMES: frozenset[str] = frozenset({
    "package.json", "package-lock.json", "npm-shrinkwrap.json",
    "tsconfig.json", "tsconfig.base.json", "tsconfig.build.json",
    "jest.config.json", "babel.config.json", ".eslintrc.json",
    ".prettierrc.json", "lerna.json", ".babelrc",
    "composer.json", "bower.json",
})


def _path_has_skip_dir(path: Path) -> bool:
    """Return True if any component of the path is in _SKIP_DIRS."""
    for part in path.parts:
        if part in _SKIP_DIRS:
            return True
    return False


def _should_skip_py(path: Path) -> bool:
    """Return True if a .py file should be excluded from the corpus."""
    name = path.name
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    if "migration" in name.lower():
        return True
    try:
        if path.stat().st_size > _MAX_PY_BYTES:
            return True
    except OSError:
        return True
    if _path_has_skip_dir(path):
        return True
    return False


def _repo_name(base_dir: Path, path: Path) -> str:
    """Extract the top-level repo name relative to base_dir."""
    try:
        rel = path.relative_to(base_dir)
        return rel.parts[0]
    except (ValueError, IndexError):
        return path.parent.name


def _flatten(text: str) -> str:
    """Replace embedded newlines with a space (shard format: one doc per line)."""
    return " ".join(text.splitlines())


# ── Harvest functions ─────────────────────────────────────────────────────────

def harvest_mcp_python(*clones_dirs: Path) -> list[str]:
    """
    Walk one or more MCP ecosystem clone directories, collect Python source files.

    Accepts multiple directories (e.g. original clones + additional_clones).
    Each file becomes one shard line prefixed with:
        # MCP server: <repo_name>
    """
    lines: list[str] = []
    total_skipped = 0

    for clones_dir in clones_dirs:
        if not clones_dir.exists():
            print(f"[WARN] MCP clones dir not found: {clones_dir}", file=sys.stderr)
            continue

        skipped = 0
        dir_count = 0
        for py_path in sorted(clones_dir.rglob("*.py")):
            if not py_path.is_file():
                continue
            if _should_skip_py(py_path):
                skipped += 1
                continue
            try:
                source = py_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not source.strip():
                continue
            repo = _repo_name(clones_dir, py_path)
            doc = f"# MCP server: {repo}\n{source}"
            lines.append(_flatten(doc))
            dir_count += 1

        total_skipped += skipped
        print(f"      {clones_dir.name}: {dir_count:,} Python files  ({skipped:,} skipped)")

    print(f"      Total: {len(lines):,} Python files  ({total_skipped:,} skipped)")
    return lines


def harvest_mcp_readmes(*clones_dirs: Path) -> list[str]:
    """
    Walk one or more MCP ecosystem clone directories, collect only:
      - README* files (README.md, README.rst, README — repo-level tool descriptions)
      - SKILL.md files (formal agentic skill manifests with YAML frontmatter)

    These are the exact formats parse_target() classifies at inference time.
    All other .md files (docs/, troubleshooting, config guides, rules) are excluded
    because they describe tools rather than defining them.

    Each file becomes one shard line prefixed with:
        # MCP README: <repo_name>    (for README* files)
        # MCP SKILL: <repo_name>     (for SKILL.md files)
    """
    lines: list[str] = []
    n_readmes = n_skills = n_stub = 0

    for clones_dir in clones_dirs:
        if not clones_dir.exists():
            print(f"[WARN] MCP clones dir not found: {clones_dir}", file=sys.stderr)
            continue

        # ── README* files ─────────────────────────────────────────────────────
        for path in sorted(clones_dir.rglob("README*")):
            if not path.is_file():
                continue
            if _path_has_skip_dir(path):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if len(content) < _MIN_TEXT_CHARS:
                n_stub += 1
                continue
            repo = _repo_name(clones_dir, path)
            doc = f"# MCP README: {repo}\n{content}"
            lines.append(_flatten(doc))
            n_readmes += 1

        # ── SKILL.md files (formal agentic skill manifests) ───────────────────
        for path in sorted(clones_dir.rglob("SKILL.md")):
            if not path.is_file():
                continue
            if _path_has_skip_dir(path):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if len(content) < _MIN_TEXT_CHARS:
                n_stub += 1
                continue
            repo = _repo_name(clones_dir, path)
            doc = f"# MCP SKILL: {repo}\n{content}"
            lines.append(_flatten(doc))
            n_skills += 1

    print(
        f"      Collected {len(lines):,} files  "
        f"(README: {n_readmes:,}, SKILL.md: {n_skills:,}, stub/empty skipped: {n_stub:,})"
    )
    return lines


def harvest_mcp_json(*clones_dirs: Path) -> list[str]:
    """
    Walk one or more MCP ecosystem clone directories, collect JSON files that
    are MCP tool manifests.

    A file qualifies if:
      - Not a known project-metadata filename (package.json, tsconfig.json, etc.)
      - Parses as a JSON object with a top-level "tools" key
      - "tools" is a non-empty list (avoids empty stubs)
      - File size ≤ 200 KB

    Each file becomes one shard line prefixed with:
        # MCP manifest: <repo_name>
    """
    lines: list[str] = []
    n_skip_name = n_skip_parse = n_skip_notool = 0

    for clones_dir in clones_dirs:
        if not clones_dir.exists():
            print(f"[WARN] MCP clones dir not found: {clones_dir}", file=sys.stderr)
            continue

        for json_path in sorted(clones_dir.rglob("*.json")):
            if not json_path.is_file():
                continue
            if json_path.name in _JSON_SKIP_NAMES:
                n_skip_name += 1
                continue
            if _path_has_skip_dir(json_path):
                continue
            try:
                size = json_path.stat().st_size
            except OSError:
                continue
            if size > 200_000:  # 200 KB cap for JSON
                continue

            try:
                data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                n_skip_parse += 1
                continue

            if not isinstance(data, dict):
                continue
            tools = data.get("tools")
            if not isinstance(tools, list) or len(tools) == 0:
                n_skip_notool += 1
                continue

            repo = _repo_name(clones_dir, json_path)
            # Pretty-print JSON so tokens are well-formed (keys, values, braces)
            pretty = json.dumps(data, indent=2, ensure_ascii=False)
            doc = f"# MCP manifest: {repo}\n{pretty}"
            lines.append(_flatten(doc))

    print(
        f"      Collected {len(lines):,} JSON manifests  "
        f"(skipped: {n_skip_name:,} metadata names, "
        f"{n_skip_parse:,} parse errors, {n_skip_notool:,} no tools key)"
    )
    return lines


def harvest_agent_frameworks(repos_dir: Path) -> list[str]:
    """
    Walk ALL subdirectories of repos_dir and collect Python source.

    Originally hardcoded to langchain/ and autogen/; now discovers every
    subdirectory automatically so that newly downloaded repos (crewAI, Haystack,
    semantic-kernel, pydantic-ai, composio, smolagents) are picked up without
    changing this script.

    Each file becomes one shard line prefixed with:
        # Agent framework: <dirname>
    """
    if not repos_dir.exists():
        print(f"[WARN] Repos dir not found: {repos_dir}", file=sys.stderr)
        return []

    lines: list[str] = []
    frameworks = sorted(p for p in repos_dir.iterdir() if p.is_dir())

    if not frameworks:
        print(f"[WARN] No subdirectories found in {repos_dir}", file=sys.stderr)
        return []

    for fw_dir in frameworks:
        framework = fw_dir.name
        fw_count = 0
        skipped = 0
        for py_path in sorted(fw_dir.rglob("*.py")):
            if not py_path.is_file():
                continue
            if _should_skip_py(py_path):
                skipped += 1
                continue
            try:
                source = py_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not source.strip():
                continue
            doc = f"# Agent framework: {framework}\n{source}"
            lines.append(_flatten(doc))
            fw_count += 1
        print(f"      {framework}: {fw_count:,} Python files  ({skipped:,} skipped)")

    return lines


def harvest_skill_files(
    benign_skills_dir: Path | None,
    malicious_skills_dir: Path | None,
) -> list[str]:
    """
    Collect SKILL.md files from the benign and malicious skill directories.

    These are the most inference-distribution-aligned documents in the corpus:
    SKILL.md is exactly the format the scanner classifies at inference time.

    benign_skills_dir:   Downloaded from GitHub (CLEAN examples)
    malicious_skills_dir: Hand-crafted attack fixtures (MALICIOUS examples)

    Each file becomes one shard line prefixed with:
        # Skill file (benign): <filename>
        # Skill file (malicious): <filename>
    """
    lines: list[str] = []
    n_benign = n_malicious = n_skip = 0

    if benign_skills_dir and benign_skills_dir.exists():
        for path in sorted(benign_skills_dir.glob("*.md")):
            if not path.is_file():
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if len(content) < _MIN_TEXT_CHARS:
                n_skip += 1
                continue
            doc = f"# Skill file (benign): {path.name}\n{content}"
            lines.append(_flatten(doc))
            n_benign += 1
    elif benign_skills_dir:
        print(f"[WARN] Benign skills dir not found: {benign_skills_dir}", file=sys.stderr)

    if malicious_skills_dir and malicious_skills_dir.exists():
        for path in sorted(malicious_skills_dir.glob("*.md")):
            if not path.is_file():
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if len(content) < _MIN_TEXT_CHARS:
                n_skip += 1
                continue
            doc = f"# Skill file (malicious): {path.name}\n{content}"
            lines.append(_flatten(doc))
            n_malicious += 1
    elif malicious_skills_dir:
        print(f"[WARN] Malicious skills dir not found: {malicious_skills_dir}", file=sys.stderr)

    print(
        f"      Collected {len(lines):,} skill files  "
        f"(benign: {n_benign:,}, malicious: {n_malicious:,}, stub/empty skipped: {n_skip:,})"
    )
    return lines


# ── Shard I/O ─────────────────────────────────────────────────────────────────

def write_shard(lines: list[str], shard_path: Path) -> tuple[str, int, int]:
    """
    Write lines to shard_path (one document per line).

    Returns:
        sha256_hex  — SHA-256 hex digest of the raw bytes written
        doc_count   — number of lines (documents)
        byte_count  — byte size of the file
    """
    shard_path.parent.mkdir(parents=True, exist_ok=True)
    blob = "\n".join(lines) + "\n"
    data = blob.encode("utf-8")
    sha256 = hashlib.sha256(data).hexdigest()
    shard_path.write_bytes(data)
    return sha256, len(lines), len(data)


# ── Manifest update ───────────────────────────────────────────────────────────

def update_manifest(output_dir: Path, new_sources: list[dict]) -> None:
    """
    Append new source entries to manifest.json (idempotent — replaces existing
    entries with the same source name).  Recomputes aggregate totals.
    """
    manifest_path = output_dir / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    else:
        manifest = {
            "mode": "full",
            "total_documents": 0,
            "total_bytes": 0,
            "sources": [],
        }

    new_names = {s["source"] for s in new_sources}
    manifest["sources"] = [
        s for s in manifest["sources"] if s["source"] not in new_names
    ]
    manifest["sources"].extend(new_sources)

    manifest["total_documents"] = sum(
        s.get("doc_count", 0) for s in manifest["sources"]
    )
    manifest["total_bytes"] = sum(
        s.get("byte_count", 0) for s in manifest["sources"]
    )

    manifest_path.write_text(json.dumps(manifest, indent=4), encoding="utf-8")
    print(
        f"[OK] manifest.json updated → "
        f"{manifest['total_documents']:,} total docs, "
        f"{manifest['total_bytes'] / 1e6:.1f} MB total"
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Harvest MCP/agent code from on-disk repos into new pretrain corpus shards. "
            "Writes mcp_python_source.txt, mcp_readmes.txt (README* + SKILL.md), "
            "mcp_json_manifests.txt, agent_frameworks.txt, and skill_files.txt."
        )
    )
    parser.add_argument(
        "--clones-dir",
        type=Path,
        default=_ROOT / "benchmarks" / "ecosystem_local_400" / "clones",
        help="MCP ecosystem clones directory (original 392 repos).",
    )
    parser.add_argument(
        "--extra-clones-dir",
        type=Path,
        default=None,
        help="Additional MCP ecosystem clones (from download_agent_repos.py). Optional.",
    )
    parser.add_argument(
        "--repos-dir",
        type=Path,
        default=_ROOT / "benchmarks" / "repos",
        help="Agent framework repos directory (all subdirs are walked).",
    )
    parser.add_argument(
        "--benign-skills-dir",
        type=Path,
        default=None,
        help="Directory of benign SKILL.md files downloaded from GitHub. Optional.",
    )
    parser.add_argument(
        "--malicious-skills-dir",
        type=Path,
        default=_HERE / "data" / "malicious_skills",
        help="Directory of hand-crafted malicious SKILL.md training files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_HERE / "pretrain_corpus_full",
        help="Pretrain corpus directory to extend.",
    )
    args = parser.parse_args()

    shards_dir = args.output_dir / "shards"
    new_sources: list[dict] = []

    # Collect clones dirs (filter out None / non-existent extras)
    clones_dirs: list[Path] = [args.clones_dir]
    if args.extra_clones_dir is not None:
        clones_dirs.append(args.extra_clones_dir)

    origins = " + ".join(str(d) for d in clones_dirs)

    # ── Shard 1: MCP Python source ────────────────────────────────────────────
    print(f"[1/5] Harvesting MCP Python source from:\n      {origins}")
    lines = harvest_mcp_python(*clones_dirs)
    sha, n_docs, n_bytes = write_shard(lines, shards_dir / "mcp_python_source.txt")
    print(f"      → {n_docs:,} docs, {n_bytes / 1e6:.1f} MB  (sha256: {sha[:16]}...)")
    new_sources.append({
        "source": "MCP Python source (S20)",
        "sha256_shard": sha, "doc_count": n_docs, "byte_count": n_bytes,
        "origin": origins,
    })

    # ── Shard 2: MCP READMEs + SKILL.md ──────────────────────────────────────
    print(f"\n[2/5] Harvesting MCP READMEs + SKILL.md from:\n      {origins}")
    lines = harvest_mcp_readmes(*clones_dirs)
    sha, n_docs, n_bytes = write_shard(lines, shards_dir / "mcp_readmes.txt")
    print(f"      → {n_docs:,} docs, {n_bytes / 1e6:.1f} MB  (sha256: {sha[:16]}...)")
    new_sources.append({
        "source": "MCP READMEs (S21)",
        "sha256_shard": sha, "doc_count": n_docs, "byte_count": n_bytes,
        "origin": origins,
    })

    # ── Shard 3: MCP JSON manifests ───────────────────────────────────────────
    print(f"\n[3/5] Harvesting MCP JSON manifests from:\n      {origins}")
    lines = harvest_mcp_json(*clones_dirs)
    sha, n_docs, n_bytes = write_shard(lines, shards_dir / "mcp_json_manifests.txt")
    print(f"      → {n_docs:,} docs, {n_bytes / 1e6:.1f} MB  (sha256: {sha[:16]}...)")
    new_sources.append({
        "source": "MCP JSON tool manifests (S23)",
        "sha256_shard": sha, "doc_count": n_docs, "byte_count": n_bytes,
        "origin": origins,
    })

    # ── Shard 4: Agent frameworks (all subdirs of repos_dir) ─────────────────
    print(f"\n[4/5] Harvesting agent framework Python from:\n      {args.repos_dir}")
    lines = harvest_agent_frameworks(args.repos_dir)
    sha, n_docs, n_bytes = write_shard(lines, shards_dir / "agent_frameworks.txt")
    print(f"      → {n_docs:,} docs, {n_bytes / 1e6:.1f} MB  (sha256: {sha[:16]}...)")
    new_sources.append({
        "source": "Agent framework source — all repos in repos-dir (S22)",
        "sha256_shard": sha, "doc_count": n_docs, "byte_count": n_bytes,
        "origin": str(args.repos_dir),
    })

    # ── Shard 5: Skill files (benign + malicious SKILL.md) ───────────────────
    benign_dir = args.benign_skills_dir
    malicious_dir = args.malicious_skills_dir
    print(f"\n[5/5] Harvesting skill files")
    if benign_dir:
        print(f"      benign:   {benign_dir}")
    if malicious_dir:
        print(f"      malicious:{malicious_dir}")
    lines = harvest_skill_files(benign_dir, malicious_dir)
    sha, n_docs, n_bytes = write_shard(lines, shards_dir / "skill_files.txt")
    print(f"      → {n_docs:,} docs, {n_bytes / 1e6:.1f} MB  (sha256: {sha[:16]}...)")
    new_sources.append({
        "source": "Skill files — benign + malicious SKILL.md (S24)",
        "sha256_shard": sha, "doc_count": n_docs, "byte_count": n_bytes,
        "origin": f"{benign_dir} + {malicious_dir}",
    })

    # ── Update manifest ───────────────────────────────────────────────────────
    print()
    update_manifest(args.output_dir, new_sources)

    # ── Summary ───────────────────────────────────────────────────────────────
    shard_file_map = {
        "MCP Python source (S20)":                               "mcp_python_source.txt",
        "MCP READMEs (S21)":                                     "mcp_readmes.txt",
        "MCP JSON tool manifests (S23)":                         "mcp_json_manifests.txt",
        "Agent framework source — all repos in repos-dir (S22)": "agent_frameworks.txt",
        "Skill files — benign + malicious SKILL.md (S24)":       "skill_files.txt",
    }
    total_new_mb = sum(s["byte_count"] for s in new_sources) / 1e6
    total_new_docs = sum(s["doc_count"] for s in new_sources)
    print(f"\nNew shards written to: {shards_dir}")
    for s in new_sources:
        name = shard_file_map.get(s["source"], "unknown.txt")
        print(
            f"  {name:<36s}  {s['doc_count']:>6,} docs  "
            f"{s['byte_count'] / 1e6:>6.1f} MB"
        )
    print(f"  {'TOTAL NEW':36s}  {total_new_docs:>6,} docs  {total_new_mb:>6.1f} MB")


if __name__ == "__main__":
    main()
