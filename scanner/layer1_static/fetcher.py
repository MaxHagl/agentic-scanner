"""
scanner/layer1_static/fetcher.py
─────────────────────────────────
Remote URL → local temp file, ready for parse_target().

Supports:
  • github.com/owner/repo/blob/branch/file  → raw.githubusercontent.com
  • github.com/owner/repo                   → raw.githubusercontent.com/.../main/README.md
  • Any other https:// URL passed through unchanged

Security invariants:
  • timeout=10s  — no hanging on slow servers
  • max_bytes=10 MB — no memory-bomb from adversarial large files
  • Fetched content enters the normal untrusted scan pipeline unchanged
"""

from __future__ import annotations

import re
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

# ── URL normalisation regexes ────────────────────────────────────────────────

_GITHUB_BLOB_RE = re.compile(
    r"https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)"
)
_GITHUB_REPO_RE = re.compile(
    r"https://github\.com/([^/]+)/([^/]+)/?$"
)

_SAFE_EXTENSIONS = {".json", ".py", ".md", ".markdown"}


def _normalize_github_url(url: str) -> str:
    """Convert a github.com browser URL to its raw.githubusercontent.com equivalent.

    Examples
    --------
    - github.com/owner/repo/blob/main/file.json
      → raw.githubusercontent.com/owner/repo/main/file.json
    - github.com/owner/repo
      → raw.githubusercontent.com/owner/repo/main/README.md
    - raw.githubusercontent.com/... (already raw) → unchanged
    """
    m = _GITHUB_BLOB_RE.match(url)
    if m:
        owner, repo, branch, path = m.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"

    m = _GITHUB_REPO_RE.match(url)
    if m:
        owner, repo = m.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/main/README.md"

    return url  # already raw or non-GitHub HTTPS


def fetch_to_tempfile(
    url: str,
    timeout: int = 10,
    max_bytes: int = 10_485_760,  # 10 MB
) -> Path:
    """Fetch *url*, write content to a temp file, return its :class:`Path`.

    The file extension is inferred from the URL so that
    :func:`~scanner.layer1_static.parser.parse_target` dispatches correctly.
    Defaults to ``.md`` for unknown / missing extensions.

    **The caller is responsible for unlinking the temp file** when done
    (e.g. ``path.unlink(missing_ok=True)`` in a ``finally`` block).

    Parameters
    ----------
    url:
        HTTP(S) URL to fetch.  GitHub blob URLs are automatically converted to
        raw.githubusercontent.com equivalents.
    timeout:
        Socket timeout in seconds.
    max_bytes:
        Maximum response body size.  Raises :exc:`ValueError` if exceeded.

    Raises
    ------
    ValueError
        If the downloaded content exceeds *max_bytes*.
    urllib.error.URLError
        On any network-level failure (DNS, connection refused, timeout, …).
    """
    raw_url = _normalize_github_url(url)
    req = urllib.request.Request(
        raw_url,
        headers={"User-Agent": "agentic-scanner/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        content = resp.read(max_bytes + 1)

    if len(content) > max_bytes:
        raise ValueError(
            f"Remote content exceeds {max_bytes // 1_048_576} MB limit"
        )

    # Infer extension from the URL path (strip query string first)
    ext = Path(raw_url.split("?")[0]).suffix.lower()
    if ext not in _SAFE_EXTENSIONS:
        ext = ".md"  # safe default — parse_target handles Markdown well

    tmp = tempfile.NamedTemporaryFile(suffix=ext, delete=False)
    tmp.write(content)
    tmp.close()
    return Path(tmp.name)
