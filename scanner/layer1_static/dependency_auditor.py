"""
dependency_auditor.py
─────────────────────
Layer 1 dependency supply-chain auditor.

For each dependency in a SkillManifest:
  1. Typosquatting detection (Levenshtein distance ≤ 2 against top-100 PyPI packages)
  2. OSV vulnerability lookup  (https://api.osv.dev/v1/querybatch)
  3. PyPI metadata check       (package age, maintainer count via pypi.org/pypi/<pkg>/json)

Results are written back into DependencyEntry fields:
  - known_cve_ids   → SC-008
  - typosquat_of    → SC-003
  - osv_risk_score  → used by aggregator

All network calls are best-effort: failures degrade gracefully to local-only analysis.
"""

from __future__ import annotations

import json
import unicodedata
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from scanner.models import DependencyEntry


# ── Top-100 PyPI packages by download count (snapshot) ───────────────────────
# Source: https://hugovk.github.io/top-pypi-packages/
# Used as the reference set for typosquatting detection.

_KNOWN_PACKAGES: frozenset[str] = frozenset(
    {
        "boto3",
        "botocore",
        "s3transfer",
        "urllib3",
        "setuptools",
        "requests",
        "certifi",
        "charset-normalizer",
        "idna",
        "six",
        "python-dateutil",
        "packaging",
        "pip",
        "wheel",
        "pyparsing",
        "awscli",
        "colorama",
        "pyyaml",
        "tqdm",
        "click",
        "pydantic",
        "attrs",
        "cryptography",
        "cffi",
        "pycparser",
        "importlib-metadata",
        "zipp",
        "typing-extensions",
        "platformdirs",
        "markupsafe",
        "jinja2",
        "pillow",
        "numpy",
        "pandas",
        "scipy",
        "matplotlib",
        "scikit-learn",
        "torch",
        "tensorflow",
        "keras",
        "transformers",
        "huggingface-hub",
        "tokenizers",
        "datasets",
        "accelerate",
        "openai",
        "anthropic",
        "langchain",
        "langchain-core",
        "langchain-community",
        "langchain-openai",
        "langgraph",
        "fastapi",
        "uvicorn",
        "starlette",
        "httpx",
        "httpcore",
        "anyio",
        "sniffio",
        "flask",
        "django",
        "sqlalchemy",
        "alembic",
        "psycopg2",
        "pymongo",
        "redis",
        "celery",
        "kombu",
        "aiohttp",
        "aiosignal",
        "multidict",
        "frozenlist",
        "yarl",
        "async-timeout",
        "grpcio",
        "protobuf",
        "google-auth",
        "google-api-core",
        "google-cloud-core",
        "googleapis-common-protos",
        "azure-core",
        "msrest",
        "docker",
        "paramiko",
        "pynacl",
        "bcrypt",
        "pyopenssl",
        "rich",
        "typer",
        "toml",
        "tomli",
        "filelock",
        "fsspec",
        "joblib",
        "threadpoolctl",
        "regex",
        "nltk",
        "spacy",
        "gensim",
        "pytest",
        "pytest-cov",
        "coverage",
        "mypy",
        "ruff",
        "black",
        "isort",
    }
)

# ── OSV API ───────────────────────────────────────────────────────────────────

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"
_REQUEST_TIMEOUT = 8  # seconds


def _http_post_json(url: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "agentic-scanner/0.1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return None


def _http_get_json(url: str) -> dict[str, Any] | None:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "agentic-scanner/0.1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return None


def _query_osv_batch(
    deps: list[DependencyEntry],
) -> dict[str, list[str]]:
    """
    Query OSV for CVEs in a single batch request.

    Returns: {dep_name: [cve_id, ...]}
    """
    queries = []
    index_map: list[str] = []  # maps query index → dep.name

    for dep in deps:
        version = _extract_pinned_version(dep.version_spec)
        query: dict[str, Any] = {
            "package": {
                "name": dep.name,
                "ecosystem": _ecosystem_for_osv(dep.ecosystem),
            }
        }
        if version:
            query["version"] = version
        queries.append(query)
        index_map.append(dep.name)

    if not queries:
        return {}

    response = _http_post_json(_OSV_BATCH_URL, {"queries": queries})
    if response is None:
        return {}

    result: dict[str, list[str]] = {}
    for idx, batch_result in enumerate(response.get("results", [])):
        if not isinstance(batch_result, dict):
            continue
        vulns = batch_result.get("vulns", [])
        if not vulns:
            continue
        dep_name = index_map[idx]
        cve_ids: list[str] = []
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("id", ""))
            # Prefer CVE IDs; fall back to OSV IDs (e.g. GHSA-...)
            aliases = vuln.get("aliases", [])
            cve_alias = next(
                (a for a in aliases if isinstance(a, str) and a.startswith("CVE-")),
                None,
            )
            cve_ids.append(cve_alias or vuln_id)
        result[dep_name] = cve_ids

    return result


def _query_pypi_metadata(name: str) -> dict[str, Any] | None:
    """Return PyPI metadata dict for a package, or None on failure."""
    url = _PYPI_JSON_URL.format(package=name)
    return _http_get_json(url)


def _ecosystem_for_osv(ecosystem: str) -> str:
    mapping = {"pypi": "PyPI", "npm": "npm", "cargo": "crates.io", "go": "Go"}
    return mapping.get(ecosystem, "PyPI")


def _extract_pinned_version(version_spec: str | None) -> str | None:
    """
    Try to extract a concrete version from a version spec like ==1.2.3.
    Returns None if the spec is not an exact pin.
    """
    if not version_spec:
        return None
    spec = version_spec.strip()
    if spec.startswith("=="):
        return spec[2:].strip()
    return None


# ── Typosquatting ─────────────────────────────────────────────────────────────

def _normalize_dep_name(name: str) -> str:
    normalized = unicodedata.normalize("NFKD", name)
    ascii_only = normalized.encode("ascii", errors="ignore").decode("ascii")
    return ascii_only.lower().replace("_", "-")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            curr.append(min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def _find_typosquat(name: str) -> str | None:
    """
    Return the closest known-good package name if the distance is ≤ 2,
    otherwise None.
    """
    normalized = _normalize_dep_name(name)
    if normalized in _KNOWN_PACKAGES:
        return None  # Exact match — not a typosquat

    best_name: str | None = None
    best_dist = 3  # threshold: only report if distance ≤ 2
    for known in _KNOWN_PACKAGES:
        dist = _levenshtein(normalized, known)
        if dist < best_dist:
            best_dist = dist
            best_name = known
    return best_name if best_dist <= 2 else None


# ── PyPI metadata ─────────────────────────────────────────────────────────────

def _package_age_days(pypi_data: dict[str, Any]) -> int | None:
    """Extract package age in days from PyPI JSON response."""
    info = pypi_data.get("info", {})
    # Look at upload_time of the first release
    releases = pypi_data.get("releases", {})
    if not releases:
        return None
    oldest_upload: str | None = None
    for version_files in releases.values():
        for file_entry in version_files:
            upload_time = file_entry.get("upload_time")
            if upload_time and (oldest_upload is None or upload_time < oldest_upload):
                oldest_upload = upload_time
    if not oldest_upload:
        return None
    try:
        dt = datetime.fromisoformat(oldest_upload.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return None


def _maintainer_count(pypi_data: dict[str, Any]) -> int | None:
    """Best-effort maintainer count from PyPI JSON."""
    info = pypi_data.get("info", {})
    # PyPI JSON doesn't expose maintainer list directly, but maintainer field
    # is a single string. We treat it as 1 if set, None otherwise.
    if info.get("maintainer") or info.get("author"):
        return 1
    return None


# ── DependencyAuditor ─────────────────────────────────────────────────────────

class DependencyAuditor:
    """
    Enriches DependencyEntry objects with CVE and provenance data.

    Usage:
        auditor = DependencyAuditor()
        enriched = auditor.audit(manifest.dependencies)
        # enriched[i].known_cve_ids is now populated if OSV found vulnerabilities
    """

    def __init__(self, use_network: bool = True) -> None:
        """
        Args:
            use_network: Set to False to disable all external API calls
                         (useful for offline testing / CI without internet).
        """
        self._use_network = use_network

    def audit(self, deps: list[DependencyEntry]) -> list[DependencyEntry]:
        """
        Return a new list of DependencyEntry with enriched fields.
        Original objects are not mutated.
        """
        if not deps:
            return []

        # Step 1: typosquatting (pure local, no network)
        enriched = [self._check_typosquat(dep) for dep in deps]

        if not self._use_network:
            return enriched

        # Step 2: OSV batch CVE lookup
        cve_map = _query_osv_batch(enriched)
        enriched = [
            dep.model_copy(update={"known_cve_ids": cve_map.get(dep.name, dep.known_cve_ids)})
            for dep in enriched
        ]

        # Step 3: PyPI metadata (package age)
        enriched = [self._enrich_pypi(dep) for dep in enriched]

        return enriched

    def _check_typosquat(self, dep: DependencyEntry) -> DependencyEntry:
        if dep.typosquat_of is not None:
            return dep  # Already annotated
        closest = _find_typosquat(dep.name)
        if closest is not None:
            return dep.model_copy(update={"typosquat_of": closest})
        return dep

    def _enrich_pypi(self, dep: DependencyEntry) -> DependencyEntry:
        if dep.ecosystem != "pypi":
            return dep
        data = _query_pypi_metadata(dep.name)
        if data is None:
            return dep
        age = _package_age_days(data)
        maintainers = _maintainer_count(data)
        updates: dict[str, object] = {}
        if age is not None:
            updates["osv_risk_score"] = max(0.0, 1.0 - age / 365.0) if age < 365 else 0.0
        return dep.model_copy(update=updates) if updates else dep


__all__ = ["DependencyAuditor"]
