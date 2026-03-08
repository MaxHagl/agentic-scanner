"""
finetuning/download_agent_repos.py
────────────────────────────────────
Downloads additional agent framework repos, MCP ecosystem repos, and
benign SKILL.md files to expand the pretrain corpus and classifier data.

Actions performed:
  1. Clone 6 agent framework repos (hardcoded URLs, --depth=1):
       crewAI, haystack, semantic-kernel, pydantic-ai, composio, smolagents
     → benchmarks/repos/<name>/

  2. Search GitHub API for up to --mcp-extra-count more MCP repos
     (q="topic:mcp language:python", paginated 100/page).
     Skips repos already cloned in benchmarks/ecosystem_local_400/clones/.
     Clones to benchmarks/ecosystem_local_400/additional_clones/.

  3. Search GitHub code API for filename:SKILL.md, download raw content,
     save to finetuning/data/benign_skills/ as <owner>__<repo>__SKILL.md.

Authentication:
  Set GITHUB_TOKEN env var for 5,000 req/hr instead of 60 req/hr.
  Falls back gracefully to unauthenticated if not set.

Usage:
    # Authenticated (recommended):
    GITHUB_TOKEN=ghp_... poetry run python finetuning/download_agent_repos.py

    # Explicit paths and limits:
    poetry run python finetuning/download_agent_repos.py \\
        --frameworks-dir  benchmarks/repos \\
        --mcp-extra-dir   benchmarks/ecosystem_local_400/additional_clones \\
        --mcp-clones-dir  benchmarks/ecosystem_local_400/clones \\
        --skill-files-dir finetuning/data/benign_skills \\
        --mcp-extra-count 500

Supply-chain note:
    All cloned repos use --depth=1 (no history, minimal attack surface).
    SKILL.md downloads are raw GitHub content only — no execution.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterator
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import json

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent

# ── Agent framework repos ──────────────────────────────────────────────────────

_FRAMEWORK_REPOS: list[tuple[str, str]] = [
    ("crewai",           "https://github.com/crewAIInc/crewAI"),
    ("haystack",         "https://github.com/deepset-ai/haystack"),
    ("semantic-kernel",  "https://github.com/microsoft/semantic-kernel"),
    ("pydantic-ai",      "https://github.com/pydantic/pydantic-ai"),
    ("composio",         "https://github.com/ComposioHQ/composio"),
    ("smolagents",       "https://github.com/huggingface/smolagents"),
]


# ── GitHub API helpers ─────────────────────────────────────────────────────────

_GITHUB_API = "https://api.github.com"
_GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")


def _gh_headers() -> dict[str, str]:
    headers: dict[str, str] = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "agentic-scanner-corpus-builder/1.0",
    }
    if _GITHUB_TOKEN:
        headers["Authorization"] = f"token {_GITHUB_TOKEN}"
    return headers


def _gh_get(url: str, params: dict | None = None) -> dict | list:
    """Perform a GitHub API GET request with basic rate-limit handling."""
    if params:
        query = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{query}"
    req = Request(url, headers=_gh_headers())
    for attempt in range(3):
        try:
            with urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            if e.code == 403:
                # Rate limited — wait and retry
                retry_after = int(e.headers.get("Retry-After", "60"))
                print(f"  [RATE LIMIT] Waiting {retry_after}s before retry {attempt + 1}/3 …")
                time.sleep(retry_after)
            elif e.code == 422:
                raise RuntimeError(f"GitHub API validation error: {e.read().decode()}")
            else:
                raise
        except URLError as e:
            if attempt < 2:
                print(f"  [WARN] Network error ({e}), retrying in 5s …")
                time.sleep(5)
            else:
                raise
    raise RuntimeError(f"GitHub API request failed after 3 attempts: {url}")


def _search_mcp_repos(count: int) -> Iterator[dict]:
    """
    Yield up to `count` GitHub repo items matching topic:mcp + language:python.
    Paginates at 100 items/page.
    """
    per_page = 100
    page = 1
    yielded = 0

    while yielded < count:
        remaining = count - yielded
        per = min(per_page, remaining)
        try:
            result = _gh_get(
                f"{_GITHUB_API}/search/repositories",
                params={
                    "q": "topic:mcp+language:python",
                    "sort": "stars",
                    "order": "desc",
                    "per_page": per,
                    "page": page,
                },
            )
        except Exception as e:
            print(f"  [WARN] Search page {page} failed: {e}", file=sys.stderr)
            break

        items = result.get("items", [])
        if not items:
            break

        for item in items:
            if yielded >= count:
                break
            yield item
            yielded += 1

        page += 1
        # Respect secondary rate limits — pause between pages
        time.sleep(1)


def _search_skill_md_files(max_results: int = 500) -> Iterator[dict]:
    """
    Yield up to max_results GitHub code-search items for filename:SKILL.md.
    Each item has 'url', 'html_url', 'repository' sub-dict.
    """
    per_page = 100
    page = 1
    yielded = 0

    while yielded < max_results:
        try:
            result = _gh_get(
                f"{_GITHUB_API}/search/code",
                params={
                    "q": "filename:SKILL.md",
                    "per_page": per_page,
                    "page": page,
                },
            )
        except Exception as e:
            print(f"  [WARN] Code search page {page} failed: {e}", file=sys.stderr)
            break

        items = result.get("items", [])
        if not items:
            break

        for item in items:
            if yielded >= max_results:
                break
            yield item
            yielded += 1

        page += 1
        time.sleep(2)  # Code search has stricter secondary rate limits


def _download_raw(raw_url: str) -> str | None:
    """Download raw file content from a GitHub raw URL."""
    req = Request(raw_url, headers={"User-Agent": "agentic-scanner-corpus-builder/1.0"})
    try:
        with urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  [WARN] Download failed ({raw_url}): {e}", file=sys.stderr)
        return None


# ── Git clone helper ───────────────────────────────────────────────────────────

def _git_clone(url: str, dest: Path, depth: int = 1) -> bool:
    """
    Clone a git repo to dest with --depth=depth. Returns True on success.
    Skips if dest already exists and is non-empty.
    """
    if dest.exists() and any(dest.iterdir()):
        print(f"      Already exists, skipping: {dest.name}")
        return True

    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", f"--depth={depth}", "--quiet", url, str(dest)]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            print(
                f"      [WARN] git clone failed for {url}: {result.stderr.strip()[:200]}",
                file=sys.stderr,
            )
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"      [WARN] git clone timed out for {url}", file=sys.stderr)
        return False
    except FileNotFoundError:
        print("  [ERROR] git not found in PATH", file=sys.stderr)
        return False


# ── Step 1: Clone agent frameworks ────────────────────────────────────────────

def clone_frameworks(frameworks_dir: Path) -> int:
    """Clone the 6 agent framework repos. Returns count of successful clones."""
    frameworks_dir.mkdir(parents=True, exist_ok=True)
    n_ok = 0
    for name, url in _FRAMEWORK_REPOS:
        dest = frameworks_dir / name
        print(f"  {name} → {dest.relative_to(_ROOT)}")
        if _git_clone(url, dest):
            n_ok += 1
    return n_ok


# ── Step 2: Clone additional MCP repos ────────────────────────────────────────

def clone_extra_mcp_repos(
    extra_dir: Path,
    existing_clones_dir: Path,
    count: int,
) -> int:
    """
    Search GitHub for MCP repos and clone up to `count` new ones.
    Skips repos whose names already exist in existing_clones_dir.
    """
    extra_dir.mkdir(parents=True, exist_ok=True)

    existing_names: set[str] = set()
    if existing_clones_dir.exists():
        existing_names = {p.name for p in existing_clones_dir.iterdir() if p.is_dir()}

    also_existing = {p.name for p in extra_dir.iterdir() if p.is_dir()} if extra_dir.exists() else set()
    skip_names = existing_names | also_existing

    print(f"  Existing repos to skip: {len(skip_names)}")

    n_ok = 0
    n_skip = 0
    n_fail = 0

    for item in _search_mcp_repos(count * 2):  # over-fetch to account for skips
        if n_ok >= count:
            break

        full_name = item.get("full_name", "")
        repo_name = item.get("name", "")
        clone_url = item.get("clone_url", "")

        if not clone_url:
            continue
        if repo_name in skip_names:
            n_skip += 1
            continue

        dest = extra_dir / repo_name
        print(f"  [{n_ok + 1}/{count}] {full_name}")
        if _git_clone(clone_url, dest):
            n_ok += 1
            skip_names.add(repo_name)
        else:
            n_fail += 1

    print(f"  Cloned: {n_ok}  skipped: {n_skip}  failed: {n_fail}")
    return n_ok


# ── Step 3: Download benign SKILL.md files ────────────────────────────────────

def download_benign_skills(skill_files_dir: Path, max_files: int = 500) -> int:
    """
    Search GitHub for SKILL.md files and download their raw content.
    Saves each as <owner>__<repo>__SKILL.md in skill_files_dir.
    Returns count of successfully downloaded files.
    """
    skill_files_dir.mkdir(parents=True, exist_ok=True)

    n_ok = 0
    n_skip = 0
    n_fail = 0

    for item in _search_skill_md_files(max_results=max_files * 2):
        if n_ok >= max_files:
            break

        repo = item.get("repository", {})
        owner = repo.get("owner", {}).get("login", "unknown")
        repo_name = repo.get("name", "unknown")
        file_name = item.get("name", "SKILL.md")
        path_in_repo = item.get("path", file_name)

        # Construct raw URL
        default_branch = repo.get("default_branch", "main")
        raw_url = (
            f"https://raw.githubusercontent.com/{owner}/{repo_name}"
            f"/{default_branch}/{path_in_repo}"
        )

        out_name = f"{owner}__{repo_name}__SKILL.md"
        out_path = skill_files_dir / out_name

        if out_path.exists():
            n_skip += 1
            continue

        content = _download_raw(raw_url)
        if content is None or len(content) < 100:
            n_fail += 1
            continue

        out_path.write_text(content, encoding="utf-8")
        n_ok += 1

        if n_ok % 25 == 0:
            print(f"  Downloaded {n_ok} SKILL.md files …")

        time.sleep(0.5)  # Polite rate limiting

    print(f"  SKILL.md downloaded: {n_ok}  skipped: {n_skip}  failed: {n_fail}")
    return n_ok


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Download agent framework repos, additional MCP repos, "
            "and benign SKILL.md files for corpus expansion."
        )
    )
    parser.add_argument(
        "--frameworks-dir",
        type=Path,
        default=_ROOT / "benchmarks" / "repos",
        help="Directory to clone agent framework repos into.",
    )
    parser.add_argument(
        "--mcp-extra-dir",
        type=Path,
        default=_ROOT / "benchmarks" / "ecosystem_local_400" / "additional_clones",
        help="Directory to clone additional MCP repos into.",
    )
    parser.add_argument(
        "--mcp-clones-dir",
        type=Path,
        default=_ROOT / "benchmarks" / "ecosystem_local_400" / "clones",
        help="Existing MCP clones dir (used to skip already-cloned repos).",
    )
    parser.add_argument(
        "--skill-files-dir",
        type=Path,
        default=_HERE / "data" / "benign_skills",
        help="Directory to save downloaded SKILL.md files.",
    )
    parser.add_argument(
        "--mcp-extra-count",
        type=int,
        default=500,
        help="Number of additional MCP repos to clone (default: 500).",
    )
    parser.add_argument(
        "--skill-files-count",
        type=int,
        default=500,
        help="Max benign SKILL.md files to download (default: 500).",
    )
    parser.add_argument(
        "--skip-frameworks",
        action="store_true",
        help="Skip Step 1 (framework cloning).",
    )
    parser.add_argument(
        "--skip-mcp",
        action="store_true",
        help="Skip Step 2 (additional MCP repos).",
    )
    parser.add_argument(
        "--skip-skills",
        action="store_true",
        help="Skip Step 3 (SKILL.md downloads).",
    )
    args = parser.parse_args()

    if not _GITHUB_TOKEN:
        print(
            "[WARN] GITHUB_TOKEN not set — using unauthenticated API (60 req/hr).\n"
            "       Set GITHUB_TOKEN for 5,000 req/hr.",
            file=sys.stderr,
        )

    # ── Step 1: Agent framework repos ─────────────────────────────────────────
    if not args.skip_frameworks:
        print(f"\n[Step 1/3] Cloning {len(_FRAMEWORK_REPOS)} agent framework repos")
        print(f"           → {args.frameworks_dir}")
        n = clone_frameworks(args.frameworks_dir)
        print(f"           Done: {n}/{len(_FRAMEWORK_REPOS)} repos available")
    else:
        print("\n[Step 1/3] Skipped (--skip-frameworks)")

    # ── Step 2: Additional MCP repos ──────────────────────────────────────────
    if not args.skip_mcp:
        print(f"\n[Step 2/3] Cloning up to {args.mcp_extra_count} additional MCP repos")
        print(f"           → {args.mcp_extra_dir}")
        n = clone_extra_mcp_repos(
            extra_dir=args.mcp_extra_dir,
            existing_clones_dir=args.mcp_clones_dir,
            count=args.mcp_extra_count,
        )
        print(f"           Done: {n} repos cloned")
    else:
        print("\n[Step 2/3] Skipped (--skip-mcp)")

    # ── Step 3: Benign SKILL.md files ─────────────────────────────────────────
    if not args.skip_skills:
        print(f"\n[Step 3/3] Downloading up to {args.skill_files_count} benign SKILL.md files")
        print(f"           → {args.skill_files_dir}")
        n = download_benign_skills(
            skill_files_dir=args.skill_files_dir,
            max_files=args.skill_files_count,
        )
        print(f"           Done: {n} SKILL.md files saved")
    else:
        print("\n[Step 3/3] Skipped (--skip-skills)")

    print("\nAll steps complete.")
    print("Next: run harvest_mcp_corpus.py with --extra-clones-dir and --skill-files-dir flags.")


if __name__ == "__main__":
    main()
