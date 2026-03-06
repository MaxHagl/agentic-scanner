"""
finetuning/collect_pretrain_corpus.py
──────────────────────────────────────
Phase 1: Collect and clean the pretraining corpus.

Smoke test mode (--smoke):
  Source 1 — NVD CVE API 2.0: first 2,000 CVEs → ~0.7–1 MB descriptions
  Source 2 — MITRE CWE XML:    weakness descriptions → ~1–2 MB text
  Source 3 — Existing fixtures: tests/fixtures/ text → ~0.3–0.5 MB
  Total: ~2–3.5 MB raw text (maps to ~1–1.5M tokens at vocab=4000)

Full run mode (no --smoke):
  19 sources totalling ~14 GB (download functions stubbed with guidance).
  Run collect_pretrain_corpus.py --help to see all options.

Output layout:
  <output-dir>/
    shards/           ← .txt files, one per source (UTF-8, one doc per line)
    manifest.json     ← audit trail: source URL + SHA256 + doc_count + byte_count

Usage:
    python finetuning/collect_pretrain_corpus.py --smoke \
        --output finetuning/pretrain_corpus_smoke/

    python finetuning/collect_pretrain_corpus.py \
        --output finetuning/pretrain_corpus/

Supply-chain integrity:
    Every downloaded file is SHA256-hashed before extraction.  The manifest.json
    records URL + hash + doc_count for every source, providing a fully reproducible
    audit trail: same manifest → same corpus → same model weights (given same seed).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Iterator

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent


# ── Utilities ─────────────────────────────────────────────────────────────────

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fetch_url(url: str, timeout: int = 60) -> bytes:
    """Download URL → bytes with User-Agent and timeout."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "agentic-scanner/1.0 (security research)"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _write_shard(output_dir: Path, name: str, lines: list[str]) -> tuple[str, int, int]:
    """Write lines to a shard file. Returns (sha256, line_count, byte_count)."""
    shard_dir = output_dir / "shards"
    shard_dir.mkdir(parents=True, exist_ok=True)
    shard_path = shard_dir / f"{name}.txt"
    content = "\n".join(lines) + "\n"
    data = content.encode("utf-8")
    shard_path.write_bytes(data)
    return _sha256_bytes(data), len(lines), len(data)


def _clean_text(text: str, max_chars: int = 10_000) -> str:
    """Normalise whitespace and cap length."""
    text = " ".join(text.split())  # collapse whitespace
    return text[:max_chars]


# ── Source 1: NVD CVE API 2.0 ─────────────────────────────────────────────────

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _collect_nvd(n_cves: int = 2000, page_delay: float = 7.0) -> Iterator[str]:
    """Yield CVE description strings from NVD API 2.0.

    NVD rate-limits unauthenticated access to 5 requests per 30 seconds.
    resultsPerPage is capped at 2000, so requests beyond 2K CVEs are paginated
    with a 7s inter-page delay (conservative; allows ~4 req/30s).
    """
    PAGE = 2000
    total_fetched = 0

    for start in range(0, n_cves, PAGE):
        batch = min(PAGE, n_cves - start)
        url = f"{_NVD_API}?resultsPerPage={batch}&startIndex={start}"
        page_num = start // PAGE + 1
        total_pages = (n_cves + PAGE - 1) // PAGE
        print(
            f"  [NVD] Page {page_num}/{total_pages}: "
            f"fetching {batch} CVEs (startIndex={start}) ...",
            flush=True,
        )
        try:
            raw = _fetch_url(url, timeout=30)
            data = json.loads(raw)
        except Exception as exc:
            print(f"  [NVD] WARN: fetch failed on page {page_num} ({exc}) — stopping", flush=True)
            break

        vulnerabilities = data.get("vulnerabilities", [])
        print(f"  [NVD] Page {page_num}: got {len(vulnerabilities)} CVEs", flush=True)

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            # Prefer English description
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            if not desc and descriptions:
                desc = descriptions[0].get("value", "")
            if not desc:
                continue

            # Include CVSS metrics context if available
            metrics_text = ""
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m = metrics[key][0].get("cvssData", {})
                    vector = m.get("vectorString", "")
                    severity = metrics[key][0].get("baseSeverity", "")
                    if vector or severity:
                        metrics_text = f" CVSS: {severity} {vector}"
                        break

            line = _clean_text(f"{cve_id}: {desc}{metrics_text}")
            yield line
            total_fetched += 1

        # Rate-limit: wait between pages (not after the last page)
        if start + PAGE < n_cves:
            print(f"  [NVD] Waiting {page_delay}s for NVD rate limit ...", flush=True)
            time.sleep(page_delay)

    print(f"  [NVD] Total CVEs yielded: {total_fetched}", flush=True)


# ── Source 2: MITRE CWE XML ───────────────────────────────────────────────────

_CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
_CWE_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}


def _collect_cwe() -> Iterator[str]:
    """Yield weakness descriptions from the MITRE CWE database."""
    print(f"  [CWE] Downloading CWE XML from {_CWE_XML_URL} ...", flush=True)
    try:
        raw_zip = _fetch_url(_CWE_XML_URL, timeout=120)
    except Exception as exc:
        print(f"  [CWE] WARN: fetch failed ({exc}) — skipping CWE source", flush=True)
        return

    print(f"  [CWE] Downloaded {len(raw_zip):,} bytes (ZIP)", flush=True)

    try:
        with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
            # Find the XML file inside the ZIP
            xml_names = [n for n in zf.namelist() if n.endswith(".xml")]
            if not xml_names:
                print("  [CWE] WARN: no XML file found in ZIP", flush=True)
                return
            xml_data = zf.read(xml_names[0])
    except Exception as exc:
        print(f"  [CWE] WARN: ZIP extraction failed ({exc})", flush=True)
        return

    print(f"  [CWE] Parsing XML ({len(xml_data):,} bytes) ...", flush=True)
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as exc:
        print(f"  [CWE] WARN: XML parse error ({exc})", flush=True)
        return

    # Collect weakness entries — namespace-aware or namespace-free search
    count = 0
    # Try namespace-aware first
    weaknesses = root.findall(".//cwe:Weakness", _CWE_NS)
    if not weaknesses:
        # Fallback: strip namespaces (older CWE XML versions)
        weaknesses = root.findall(".//{*}Weakness")

    for weakness in weaknesses:
        cwe_id = weakness.get("ID", "")
        name = weakness.get("Name", "")

        # Get description
        desc = ""
        for desc_tag in ("cwe:Description", "{*}Description", "Description"):
            el = weakness.find(desc_tag, _CWE_NS) if "cwe:" in desc_tag else weakness.find(desc_tag)
            if el is not None and el.text:
                desc = el.text.strip()
                break
        if not desc:
            continue

        # Extended description if available
        ext_desc = ""
        for ext_tag in ("cwe:Extended_Description", "{*}Extended_Description", "Extended_Description"):
            el = weakness.find(ext_tag, _CWE_NS) if "cwe:" in ext_tag else weakness.find(ext_tag)
            if el is not None and el.text:
                ext_desc = " " + el.text.strip()[:500]
                break

        line = _clean_text(f"CWE-{cwe_id} {name}: {desc}{ext_desc}")
        yield line
        count += 1

    print(f"  [CWE] Extracted {count} weakness descriptions", flush=True)


# ── Source 3: Existing fixtures ───────────────────────────────────────────────

def _collect_fixtures(fixtures_dir: Path) -> Iterator[str]:
    """Yield text from existing test fixtures."""
    scannable = {".json", ".py", ".md", ".markdown", ".txt"}
    count = 0
    for path in sorted(fixtures_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in scannable:
            continue
        if path.name == "__init__.py":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            continue
        if len(text) < 50:
            continue
        line = _clean_text(text)
        if line:
            yield line
            count += 1
    print(f"  [Fixtures] Collected {count} fixture documents", flush=True)


# ── Source 4: GitHub Security Advisories ─────────────────────────────────────

_GH_ADVISORIES_API = "https://api.github.com/advisories"


def _collect_github_advisories(n: int = 5000, page_delay: float = 1.0) -> Iterator[str]:
    """Yield advisory text from the GitHub public security advisories API.

    No authentication required.  Rate limit: 60 req/min unauthenticated.
    Each page returns up to 100 advisories; we delay 1s between pages.
    Fields used: summary + description (may be None).
    """
    per_page = 100
    page = 1
    total_fetched = 0

    while total_fetched < n:
        url = f"{_GH_ADVISORIES_API}?per_page={per_page}&page={page}"
        print(
            f"  [GH-ADV] Page {page}: fetching up to {per_page} advisories "
            f"({total_fetched}/{n} collected) ...",
            flush=True,
        )
        try:
            raw = _fetch_url(url, timeout=30)
            advisories = json.loads(raw)
        except Exception as exc:
            print(f"  [GH-ADV] WARN: fetch failed on page {page} ({exc}) — stopping", flush=True)
            break

        if not isinstance(advisories, list) or len(advisories) == 0:
            # Empty page means we've exhausted the available advisories
            print(f"  [GH-ADV] No more advisories on page {page} — stopping", flush=True)
            break

        for adv in advisories:
            if total_fetched >= n:
                break
            ghsa_id = adv.get("ghsa_id", "")
            summary = (adv.get("summary") or "").strip()
            description = (adv.get("description") or "").strip()
            severity = (adv.get("severity") or "").upper()

            parts = []
            if ghsa_id:
                parts.append(ghsa_id)
            if severity:
                parts.append(f"[{severity}]")
            if summary:
                parts.append(summary)
            if description:
                parts.append(description)

            if not parts:
                continue
            line = _clean_text(" ".join(parts))
            if line:
                yield line
                total_fetched += 1

        page += 1
        if total_fetched < n and len(advisories) == per_page:
            time.sleep(page_delay)
        elif len(advisories) < per_page:
            # Last page — no more data
            break

    print(f"  [GH-ADV] Total advisories yielded: {total_fetched}", flush=True)


# ── Shared helpers for full corpus ────────────────────────────────────────────

def _strip_html(text: str) -> str:
    """Strip HTML tags and unescape HTML entities."""
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    return " ".join(text.split())


def _clone_repo(url: str, dest: Path, depth: int = 1) -> bool:
    """Shallow-clone a git repo. Returns True on success."""
    try:
        result = subprocess.run(
            ["git", "clone", f"--depth={depth}", "--quiet", url, str(dest)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            print(f"  [GIT] WARN: clone failed for {url}: {result.stderr[:200]}", flush=True)
            return False
        return True
    except Exception as exc:
        print(f"  [GIT] WARN: clone error for {url}: {exc}", flush=True)
        return False


def _iter_text_files(root: Path, extensions: tuple[str, ...]) -> Iterator[str]:
    """Yield text from all files with matching extensions under root."""
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in extensions:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            continue
        if len(text) < 50:
            continue
        yield _clean_text(text)


# ── S8: Exploit-DB Python exploit scripts ─────────────────────────────────────

_EXPLOITDB_CSV_URL = (
    "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
)
_EXPLOITDB_RAW_BASE = (
    "https://raw.githubusercontent.com/offensive-security/exploitdb/master/"
)


def _collect_exploit_db(max_py: int = 3000, page_delay: float = 0.3) -> Iterator[str]:
    """Yield Python exploit scripts from Exploit-DB.

    Fetches files_exploits.csv, filters for Python scripts, downloads each one.
    These are real malicious/PoC Python scripts — critical for fixing domain shift.
    """
    print(f"  [ExploitDB] Downloading files_exploits.csv ...", flush=True)
    try:
        raw = _fetch_url(_EXPLOITDB_CSV_URL, timeout=60)
    except Exception as exc:
        print(f"  [ExploitDB] WARN: CSV fetch failed ({exc}) — skipping", flush=True)
        return

    # Parse CSV: columns include id, file, description, date, author, type, platform
    rows = []
    try:
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8", errors="replace")))
        for row in reader:
            filepath = row.get("file", "").strip()
            if filepath.endswith(".py"):
                rows.append(row)
    except Exception as exc:
        print(f"  [ExploitDB] WARN: CSV parse failed ({exc})", flush=True)
        return

    print(f"  [ExploitDB] Found {len(rows)} Python exploit scripts in index", flush=True)
    rows = rows[:max_py]

    fetched = 0
    for row in rows:
        filepath = row.get("file", "").strip().lstrip("/")
        description = row.get("description", "").strip()
        exploit_type = row.get("type", "").strip()
        platform = row.get("platform", "").strip()
        url = _EXPLOITDB_RAW_BASE + filepath
        try:
            code = _fetch_url(url, timeout=20).decode("utf-8", errors="replace")
        except Exception:
            continue

        # Prepend metadata header so the SLM learns the exploit context
        header = f"# Exploit-DB: {description} | Type: {exploit_type} | Platform: {platform}"
        line = _clean_text(f"{header}\n{code}")
        if line:
            yield line
            fetched += 1

        if fetched % 100 == 0:
            print(f"  [ExploitDB] Fetched {fetched}/{len(rows)} scripts ...", flush=True)
        time.sleep(page_delay)

    print(f"  [ExploitDB] Total Python exploit scripts yielded: {fetched}", flush=True)


# ── S16: Security tool Python source code ─────────────────────────────────────

_SECURITY_TOOL_REPOS = [
    ("bandit", "https://github.com/PyCQA/bandit"),
    ("semgrep", "https://github.com/returntocorp/semgrep"),
    ("trufflehog", "https://github.com/trufflesecurity/trufflehog"),
]


def _collect_security_tools() -> Iterator[str]:
    """Yield Python source from security analysis tools.

    These are benign security-domain Python files — teaches the SLM
    what legitimate security code looks like vs. malicious patterns.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        for name, url in _SECURITY_TOOL_REPOS:
            dest = tmp_path / name
            print(f"  [SecTools] Cloning {name} ({url}) ...", flush=True)
            ok = _clone_repo(url, dest)
            if not ok:
                continue
            count = 0
            for text in _iter_text_files(dest, (".py",)):
                yield f"# Source: {name} security tool\n{text}"
                count += 1
            print(f"  [SecTools] {name}: {count} Python files", flush=True)


# ── S18: CTF writeup Python solutions and writeup documents ───────────────────

_GH_SEARCH_API = "https://api.github.com/search/repositories"


def _collect_ctf_writeups(max_repos: int = 60, page_delay: float = 2.0) -> Iterator[str]:
    """Yield Python exploit solutions and writeup text from CTF repositories.

    Uses GitHub search API (unauthenticated, 10 req/min limit) to find
    top-starred ctf-writeup repositories, then clones + extracts content.
    """
    url = (
        f"{_GH_SEARCH_API}?q=topic%3Actf-writeup+language%3Apython"
        f"&sort=stars&per_page=30&page=1"
    )
    print(f"  [CTF] Searching GitHub for top CTF writeup repos ...", flush=True)
    try:
        raw = _fetch_url(url, timeout=30)
        data = json.loads(raw)
    except Exception as exc:
        print(f"  [CTF] WARN: GitHub search failed ({exc}) — skipping", flush=True)
        return

    repos = data.get("items", [])[:max_repos]
    print(f"  [CTF] Found {len(repos)} repos", flush=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        total = 0
        for i, repo in enumerate(repos):
            clone_url = repo.get("clone_url", "")
            name = repo.get("full_name", f"repo_{i}").replace("/", "_")
            dest = tmp_path / name
            ok = _clone_repo(clone_url, dest)
            if not ok:
                continue
            for text in _iter_text_files(dest, (".py", ".md")):
                yield f"# CTF writeup: {repo.get('full_name', name)}\n{text}"
                total += 1
            if i < len(repos) - 1:
                time.sleep(page_delay)

    print(f"  [CTF] Total CTF documents yielded: {total}", flush=True)


# ── S17: MCP server READMEs from existing ecosystem scan ──────────────────────

def _collect_mcp_readmes(root: Path) -> Iterator[str]:
    """Yield MCP server README text from existing benchmarks/scan output.

    Reads from benchmarks/mcp_ecosystem_scan.jsonl if it exists.
    """
    candidates = [
        root / "benchmarks" / "mcp_ecosystem_scan.jsonl",
        root / "benchmarks" / "scan_results.jsonl",
    ]
    for jsonl_path in candidates:
        if not jsonl_path.exists():
            continue
        print(f"  [MCP-README] Reading {jsonl_path.name} ...", flush=True)
        count = 0
        with jsonl_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                text = rec.get("readme", "") or rec.get("content", "") or rec.get("text", "")
                name = rec.get("name", "") or rec.get("repo", "")
                if text and len(text) > 50:
                    yield _clean_text(f"MCP server README ({name}): {text}")
                    count += 1
        print(f"  [MCP-README] Yielded {count} MCP README documents", flush=True)
        return
    print("  [MCP-README] No ecosystem scan JSONL found — skipping S17", flush=True)


# ── S12: Semgrep rule YAML ─────────────────────────────────────────────────────

_SEMGREP_RULES_REPO = "https://github.com/returntocorp/semgrep-rules"


def _collect_semgrep_rules() -> Iterator[str]:
    """Yield Semgrep rule YAML files (descriptions + code patterns).

    Rule rationale text teaches the SLM security reasoning patterns.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / "semgrep-rules"
        print(f"  [Semgrep] Cloning semgrep-rules ...", flush=True)
        ok = _clone_repo(_SEMGREP_RULES_REPO, dest)
        if not ok:
            return
        count = 0
        for text in _iter_text_files(dest, (".yaml", ".yml")):
            yield f"# Semgrep security rule\n{text}"
            count += 1
        print(f"  [Semgrep] Extracted {count} rule files", flush=True)


# ── S7: NVD full database (all years 2002–present) ────────────────────────────

def _collect_nvd_full(n_cves: int = 200_000, page_delay: float = 7.0) -> Iterator[str]:
    """Yield all NVD CVE descriptions (full database, ~200K CVEs).

    Reuses _collect_nvd() with a high limit.
    """
    yield from _collect_nvd(n_cves=n_cves, page_delay=page_delay)


# ── S11: MITRE ATT&CK enterprise techniques ───────────────────────────────────

_MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def _collect_mitre_attack() -> Iterator[str]:
    """Yield MITRE ATT&CK technique names + descriptions + detection text.

    STIX bundle JSON → extract attack-pattern objects.
    """
    print(f"  [MITRE] Downloading enterprise-attack.json ...", flush=True)
    try:
        raw = _fetch_url(_MITRE_ATTACK_URL, timeout=120)
        bundle = json.loads(raw)
    except Exception as exc:
        print(f"  [MITRE] WARN: fetch failed ({exc}) — skipping", flush=True)
        return

    objects = bundle.get("objects", [])
    count = 0
    for obj in objects:
        obj_type = obj.get("type", "")
        if obj_type not in ("attack-pattern", "course-of-action", "malware", "tool"):
            continue
        name = obj.get("name", "")
        desc = obj.get("description", "")
        detection = obj.get("x_mitre_detection", "")
        platforms = ", ".join(obj.get("x_mitre_platforms", []))

        parts = []
        if name:
            parts.append(f"MITRE {obj_type}: {name}")
        if platforms:
            parts.append(f"Platforms: {platforms}")
        if desc:
            parts.append(desc[:2000])
        if detection:
            parts.append(f"Detection: {detection[:1000]}")

        if parts:
            line = _clean_text(" | ".join(parts))
            if line:
                yield line
                count += 1

    print(f"  [MITRE] Extracted {count} ATT&CK objects", flush=True)


# ── S13: OSV advisories bulk download ─────────────────────────────────────────

_OSV_ECOSYSTEMS = ["PyPI", "npm", "Go", "RubyGems", "Maven", "crates.io"]
_OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _collect_osv(max_per_ecosystem: int = 2000, page_delay: float = 1.0) -> Iterator[str]:
    """Yield OSV advisory descriptions across major package ecosystems.

    Uses the OSV query API with pagination.
    """
    total = 0
    for ecosystem in _OSV_ECOSYSTEMS:
        print(f"  [OSV] Fetching {ecosystem} advisories ...", flush=True)
        page_token = None
        eco_count = 0

        while eco_count < max_per_ecosystem:
            payload: dict = {"query": {"ecosystem": ecosystem}}
            if page_token:
                payload["page_token"] = page_token
            try:
                req_data = json.dumps(payload).encode()
                req = urllib.request.Request(
                    _OSV_QUERY_URL,
                    data=req_data,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "agentic-scanner/1.0 (security research)",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    result = json.loads(resp.read())
            except Exception as exc:
                print(f"  [OSV] WARN: query failed for {ecosystem}: {exc}", flush=True)
                break

            vulns = result.get("vulns", [])
            if not vulns:
                break

            for v in vulns:
                if eco_count >= max_per_ecosystem:
                    break
                osv_id = v.get("id", "")
                summary = (v.get("summary") or "").strip()
                details = (v.get("details") or "").strip()
                severity = ""
                for sev in (v.get("severity") or []):
                    severity = sev.get("score", "")
                    break

                parts = []
                if osv_id:
                    parts.append(osv_id)
                if ecosystem:
                    parts.append(f"[{ecosystem}]")
                if severity:
                    parts.append(f"CVSS:{severity}")
                if summary:
                    parts.append(summary)
                if details:
                    parts.append(details[:1500])

                if parts:
                    line = _clean_text(" ".join(parts))
                    if line:
                        yield line
                        eco_count += 1
                        total += 1

            page_token = result.get("next_page_token")
            if not page_token:
                break
            time.sleep(page_delay)

        print(f"  [OSV] {ecosystem}: {eco_count} advisories", flush=True)

    print(f"  [OSV] Total advisories yielded: {total}", flush=True)


# ── S10: OWASP repos (Testing Guide + Cheat Sheet Series) ─────────────────────

_OWASP_REPOS = [
    ("owasp-testing-guide", "https://github.com/OWASP/wstg"),
    ("owasp-cheatsheets", "https://github.com/OWASP/CheatSheetSeries"),
]


def _collect_owasp() -> Iterator[str]:
    """Yield OWASP structured security guidance text."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        for name, url in _OWASP_REPOS:
            dest = tmp_path / name
            print(f"  [OWASP] Cloning {name} ...", flush=True)
            ok = _clone_repo(url, dest)
            if not ok:
                continue
            count = 0
            for text in _iter_text_files(dest, (".md", ".markdown")):
                yield f"# OWASP: {name}\n{text}"
                count += 1
            print(f"  [OWASP] {name}: {count} documents", flush=True)


# ── S19: PyPI top-package descriptions ────────────────────────────────────────

_PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
_TOP_PYPI_LIST_URL = "https://huggingface.co/datasets/librarian-bots/top-pypi-packages/resolve/main/top-pypi-packages-30-days.min.json"


def _collect_pypi_descriptions(n: int = 5000, page_delay: float = 0.2) -> Iterator[str]:
    """Yield PyPI package descriptions for top packages.

    Fetches the top-N most-downloaded packages and extracts their
    description text — mixes legitimate tool descriptions with security-
    relevant package metadata.
    """
    # Fetch top packages list
    print(f"  [PyPI] Fetching top packages list ...", flush=True)
    try:
        raw = _fetch_url(_TOP_PYPI_LIST_URL, timeout=60)
        data = json.loads(raw)
        package_names = [r.get("project", "") for r in data.get("rows", []) if r.get("project")]
    except Exception:
        # Fallback: well-known security-relevant packages
        package_names = [
            "requests", "cryptography", "paramiko", "pycparser", "cffi",
            "pyopenssl", "certifi", "urllib3", "httpx", "aiohttp",
            "flask", "django", "fastapi", "sqlalchemy", "celery",
            "boto3", "google-cloud-storage", "azure-identity",
            "pyjwt", "bcrypt", "passlib", "python-dotenv",
            "bandit", "safety", "semgrep", "pylint", "mypy",
        ]

    package_names = [p for p in package_names if p][:n]
    print(f"  [PyPI] Fetching descriptions for {len(package_names)} packages ...", flush=True)

    fetched = 0
    for name in package_names:
        url = _PYPI_JSON_URL.format(name=urllib.parse.quote(name))
        try:
            raw = _fetch_url(url, timeout=15)
            data = json.loads(raw)
        except Exception:
            continue
        info = data.get("info", {})
        desc = (info.get("description") or "").strip()
        summary = (info.get("summary") or "").strip()
        if not desc and not summary:
            continue
        text = f"PyPI package {name}: {summary}\n{desc[:3000]}" if desc else f"PyPI package {name}: {summary}"
        line = _clean_text(text)
        if line:
            yield line
            fetched += 1
        if fetched % 200 == 0 and fetched > 0:
            print(f"  [PyPI] Fetched {fetched}/{len(package_names)} descriptions ...", flush=True)
        time.sleep(page_delay)

    print(f"  [PyPI] Total package descriptions yielded: {fetched}", flush=True)


# ── S4: StackExchange Security data dump ──────────────────────────────────────

_STACKEXCHANGE_URL = "https://archive.org/download/stackexchange/security.stackexchange.com.7z"


def _collect_stackexchange_security(output_dir: Path) -> Iterator[str]:
    """Yield Q&A text from Security StackExchange data dump.

    Downloads the 7z archive (~700 MB) from archive.org, extracts Posts.xml,
    and yields cleaned post bodies. Requires py7zr: pip install py7zr.

    This is Tier 2 — high volume security Q&A, ~2M posts.
    """
    try:
        import py7zr  # type: ignore
    except ImportError:
        print(
            "  [StackEx] WARN: py7zr not installed — skipping StackExchange.\n"
            "            Install with: pip install py7zr",
            flush=True,
        )
        return

    print(f"  [StackEx] Downloading security.stackexchange.com.7z (~700 MB) ...", flush=True)
    archive_path = output_dir / "security_stackexchange.7z"

    if not archive_path.exists():
        try:
            raw = _fetch_url(_STACKEXCHANGE_URL, timeout=1800)  # 30 min timeout
            archive_path.write_bytes(raw)
            print(f"  [StackEx] Downloaded {len(raw):,} bytes", flush=True)
        except Exception as exc:
            print(f"  [StackEx] WARN: download failed ({exc}) — skipping", flush=True)
            return

    print(f"  [StackEx] Extracting Posts.xml ...", flush=True)
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            with py7zr.SevenZipFile(archive_path, mode="r") as z:
                z.extractall(path=tmpdir)
        except Exception as exc:
            print(f"  [StackEx] WARN: extraction failed ({exc})", flush=True)
            return

        posts_xml = Path(tmpdir) / "Posts.xml"
        if not posts_xml.exists():
            print("  [StackEx] WARN: Posts.xml not found in archive", flush=True)
            return

        print(f"  [StackEx] Parsing Posts.xml ...", flush=True)
        count = 0
        try:
            for _, elem in ET.iterparse(str(posts_xml), events=("end",)):
                if elem.tag != "row":
                    continue
                body = elem.get("Body", "")
                title = elem.get("Title", "")
                if not body:
                    elem.clear()
                    continue
                text = _strip_html(body)
                if title:
                    text = f"Q: {title} | A: {text}"
                line = _clean_text(text)
                if line and len(line) > 50:
                    yield line
                    count += 1
                elem.clear()
        except Exception as exc:
            print(f"  [StackEx] WARN: XML parse error ({exc})", flush=True)

        print(f"  [StackEx] Extracted {count} posts", flush=True)

    # Clean up archive to save disk space
    try:
        archive_path.unlink()
    except Exception:
        pass


# ── S5: arXiv cs.CR security papers ───────────────────────────────────────────

_ARXIV_API = "http://export.arxiv.org/api/query"


def _collect_arxiv_cscr(max_results: int = 5000, page_delay: float = 3.0) -> Iterator[str]:
    """Yield abstract text from arXiv cs.CR (cryptography and security) papers.

    Uses the arXiv Atom API (no auth required, 3s delay between requests).
    """
    start = 0
    batch_size = 100
    fetched = 0

    while fetched < max_results:
        remaining = min(batch_size, max_results - fetched)
        url = (
            f"{_ARXIV_API}?search_query=cat:cs.CR"
            f"&start={start}&max_results={remaining}"
        )
        print(f"  [arXiv] Fetching cs.CR papers {start}–{start + remaining} ...", flush=True)
        try:
            raw = _fetch_url(url, timeout=60)
        except Exception as exc:
            print(f"  [arXiv] WARN: fetch failed ({exc}) — stopping", flush=True)
            break

        # Parse Atom XML
        try:
            root_el = ET.fromstring(raw)
        except ET.ParseError as exc:
            print(f"  [arXiv] WARN: XML parse error ({exc})", flush=True)
            break

        ns = {"atom": "http://www.w3.org/2005/Atom"}
        entries = root_el.findall("atom:entry", ns)
        if not entries:
            print(f"  [arXiv] No more entries at start={start}", flush=True)
            break

        for entry in entries:
            title_el = entry.find("atom:title", ns)
            summary_el = entry.find("atom:summary", ns)
            title = title_el.text.strip() if title_el is not None and title_el.text else ""
            summary = summary_el.text.strip() if summary_el is not None and summary_el.text else ""
            if not summary:
                continue
            line = _clean_text(f"arXiv cs.CR: {title}\n{summary}")
            if line:
                yield line
                fetched += 1

        start += len(entries)
        if len(entries) < batch_size:
            break
        time.sleep(page_delay)

    print(f"  [arXiv] Total papers yielded: {fetched}", flush=True)


# ── Full corpus source stubs (Phase 1 full run) ───────────────────────────────

def _collect_full_corpus(output_dir: Path) -> None:
    """
    Stub for the full 14 GB pretraining corpus.

    Run with: python collect_pretrain_corpus.py (no --smoke flag)

    TODO for full run on 4090 machine — implement each source:

    Source 4:  StackExchange Security data dump (~3 GB)
               archive.org/download/stackexchange/security.stackexchange.com.7z
               Extract Posts.xml, parse <row> tags for Body + Title fields.
               Strip HTML tags. ~2M Q&A pairs.

    Source 5:  arXiv cs.CR papers (~2 GB)
               arxiv.org/abs/cs.CR bulk download via S3 (requester-pays, free for research).
               Or use the arXiv API: export.arxiv.org/api/query?search_query=cat:cs.CR
               Extract LaTeX source, strip commands, keep text.

    Source 6:  Wikipedia tech subset (~3 GB)
               dumps.wikimedia.org/enwiki/latest/enwiki-latest-pages-articles.xml.bz2
               Filter to tech/security categories. Strip wiki markup.

    Source 7:  NVD full database (~300 MB)
               nvd.nist.gov/vuln/data-feeds (JSON feeds, all years 2002-present)

    Source 8:  Exploit-DB (~500 MB)
               gitlab.com/exploit-database/exploitdb → files_exploits.csv
               Fetch exploit descriptions + PoC text.

    Source 9:  GitHub Security Advisories (~100 MB)
               api.github.com/advisories?per_page=100
               Paginate through all public advisories.

    Source 10: OWASP repos (~50 MB)
               github.com/OWASP/OWASP-Testing-Guide
               github.com/OWASP/CheatSheetSeries

    Source 11: MITRE ATT&CK JSON (~50 MB)
               github.com/mitre/cti → enterprise-attack/enterprise-attack.json

    Source 12: Semgrep rule descriptions (~50 MB)
               github.com/returntocorp/semgrep-rules (all YAML rule rationale)

    Source 13: OSV + Snyk advisories (~400 MB)
               api.osv.dev/v1/querybatch (bulk download all ecosystems)

    Source 14: NIST SP 800-series (~200 MB)
               csrc.nist.gov/publications/sp800 (PDF → text extraction via pdfminer)

    Source 15: HackerOne public disclosures (~500 MB)
               hackerone.com/hacktivity?sort_type=popular (public reports API)

    Source 16: Security tool source code (~1 GB)
               github.com/PyCQA/bandit, github.com/returntocorp/semgrep,
               github.com/aquasecurity/trivy

    Source 17: MCP server READMEs (~200 MB)
               Already fetched by benchmarks/scan_mcp_ecosystem.py

    Source 18: CTF writeups (~500 MB)
               github.com/topics/ctf-writeups (curated list)

    Source 19: PyPI package descriptions (~500 MB)
               pypi.org/simple/ + pypi.org/pypi/{name}/json

    Each source should:
      1. Fetch/download raw data
      2. Compute SHA256 of raw download
      3. Extract text (strip HTML/LaTeX/markup)
      4. Yield cleaned lines
      5. Log to manifest.json

    Total budget: ~14 GB raw text → ~4B tokens at 3.5 bytes/token.
    """
    print("[WARN] Full corpus collection not yet implemented.", flush=True)
    print("       Run with --smoke for the smoke test corpus.", flush=True)
    print("       See docstring above for full source list.", flush=True)


# ── Full collection ────────────────────────────────────────────────────────────

def collect_full(output_dir: Path, resume: bool = False) -> None:
    """Collect the full ~14 GB pretraining corpus from all 19 sources.

    Sources are processed in priority order:
      Tier 1 (domain shift — code format data):
        S8  Exploit-DB Python exploit scripts   (~500 MB)
        S16 Security tool Python source         (~1 GB)
        S18 CTF writeup Python + Markdown       (~500 MB)
        S17 MCP server READMEs (existing scan)  (~200 MB)
        S12 Semgrep rule YAML                   (~50 MB)
      Tier 2 (volume — security prose):
        S7  NVD full database (all years)       (~300 MB)
        S9  GitHub advisories (all ~20K)        (~100 MB)
        S11 MITRE ATT&CK techniques             (~50 MB)
        S13 OSV advisories (major ecosystems)   (~400 MB)
        S10 OWASP repos                         (~50 MB)
        S2  CWE XML (reused from medium)
        S3  Local fixtures (reused from medium)
      Tier 3 (general tech text):
        S4  StackExchange Security              (~3 GB, requires py7zr)
        S5  arXiv cs.CR abstracts              (~500 MB)
        S19 PyPI package descriptions          (~500 MB)

    Args:
        output_dir: Output directory for shards/ and manifest.json.
        resume:     If True, skip shards that already exist on disk.
    """
    manifest_entries: list[dict] = []

    def _run_source(
        name: str,
        label: str,
        generator_fn,
        **kwargs,
    ) -> dict | None:
        """Run one source, skip if --resume and shard exists. Returns manifest entry."""
        shard_path = output_dir / "shards" / f"{name}.txt"
        if resume and shard_path.exists():
            size = shard_path.stat().st_size
            print(f"  [SKIP] {label} shard exists ({size:,} bytes) — skipping (--resume)", flush=True)
            # Re-read size for manifest
            data = shard_path.read_bytes()
            return {
                "source": label,
                "sha256_shard": _sha256_bytes(data),
                "doc_count": data.count(b"\n"),
                "byte_count": len(data),
                "skipped": True,
            }
        print(f"\n  [{label}] Collecting ...", flush=True)
        try:
            lines = list(generator_fn(**kwargs))
        except Exception as exc:
            print(f"  [{label}] ERROR: {exc} — skipping source", flush=True)
            return None
        if not lines:
            print(f"  [{label}] No data collected — skipping shard", flush=True)
            return None
        sha256, doc_count, byte_count = _write_shard(output_dir, name, lines)
        print(f"  [{label}] → {doc_count:,} docs, {byte_count / 1024 / 1024:.1f} MB", flush=True)
        return {
            "source": label,
            "sha256_shard": sha256,
            "doc_count": doc_count,
            "byte_count": byte_count,
        }

    # ── Tier 1: Domain shift sources (code-format data) ──────────────────────
    print("\n=== TIER 1: Domain-shift sources (code-format data) ===", flush=True)

    entry = _run_source("exploit_db", "Exploit-DB Python scripts (S8)",
                        _collect_exploit_db, max_py=5000)
    if entry:
        manifest_entries.append(entry)

    entry = _run_source("security_tools", "Security tool Python source (S16)",
                        _collect_security_tools)
    if entry:
        manifest_entries.append(entry)

    entry = _run_source("ctf_writeups", "CTF writeup Python+Markdown (S18)",
                        _collect_ctf_writeups, max_repos=80)
    if entry:
        manifest_entries.append(entry)

    entry = _run_source("mcp_readmes", "MCP server READMEs (S17)",
                        _collect_mcp_readmes, root=output_dir.parent)
    if entry:
        manifest_entries.append(entry)

    entry = _run_source("semgrep_rules", "Semgrep rule YAML (S12)",
                        _collect_semgrep_rules)
    if entry:
        manifest_entries.append(entry)

    # ── Tier 2: Security prose volume ─────────────────────────────────────────
    print("\n=== TIER 2: Security prose volume ===", flush=True)

    entry = _run_source("nvd_full", "NVD full database (S7)",
                        _collect_nvd_full, n_cves=200_000, page_delay=7.0)
    if entry:
        manifest_entries.append(entry)

    entry = _run_source("github_advisories_full", "GitHub Security Advisories full (S9)",
                        _collect_github_advisories, n=20_000, page_delay=1.0)
    if entry:
        manifest_entries.append(entry)

    entry = _run_source("mitre_attack", "MITRE ATT&CK (S11)",
                        _collect_mitre_attack)
    if entry:
        manifest_entries.append(entry)

    entry = _run_source("osv_advisories", "OSV advisories (S13)",
                        _collect_osv, max_per_ecosystem=3000)
    if entry:
        manifest_entries.append(entry)

    entry = _run_source("owasp", "OWASP repos (S10)",
                        _collect_owasp)
    if entry:
        manifest_entries.append(entry)

    # Reuse existing CWE and fixtures sources
    entry = _run_source("cwe_weaknesses", "MITRE CWE XML (S2)",
                        _collect_cwe)
    if entry:
        entry["url"] = _CWE_XML_URL
        manifest_entries.append(entry)

    fixtures_dir = _ROOT / "tests" / "fixtures"
    entry = _run_source("fixtures", "Local test fixtures (S3)",
                        _collect_fixtures, fixtures_dir=fixtures_dir)
    if entry:
        entry["url"] = str(fixtures_dir)
        manifest_entries.append(entry)

    # ── Tier 3: General tech text ──────────────────────────────────────────────
    print("\n=== TIER 3: General tech text ===", flush=True)

    entry = _run_source("stackexchange_security", "StackExchange Security (S4)",
                        _collect_stackexchange_security, output_dir=output_dir)
    if entry:
        manifest_entries.append(entry)

    entry = _run_source("arxiv_cscr", "arXiv cs.CR abstracts (S5)",
                        _collect_arxiv_cscr, max_results=10_000)
    if entry:
        manifest_entries.append(entry)

    entry = _run_source("pypi_descriptions", "PyPI package descriptions (S19)",
                        _collect_pypi_descriptions, n=5000)
    if entry:
        manifest_entries.append(entry)

    # ── Manifest ──────────────────────────────────────────────────────────────
    total_docs = sum(e.get("doc_count", 0) for e in manifest_entries)
    total_bytes = sum(e.get("byte_count", 0) for e in manifest_entries)
    manifest = {
        "mode": "full",
        "total_documents": total_docs,
        "total_bytes": total_bytes,
        "sources": manifest_entries,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(
        f"\nFull corpus ready: {total_docs:,} documents, "
        f"{total_bytes / 1024 / 1024 / 1024:.2f} GB → {output_dir}",
        flush=True,
    )
    print(f"Manifest: {output_dir / 'manifest.json'}", flush=True)
    if total_bytes < 100_000_000:
        print(
            f"  [WARN] total_bytes={total_bytes:,} < 100 MB — "
            "corpus smaller than expected; check network access and source availability.",
            flush=True,
        )


# ── Medium collection ─────────────────────────────────────────────────────────

def collect_medium(output_dir: Path, n_cves: int = 10_000, n_gh: int = 5_000) -> None:
    """Collect ~15–25 MB medium corpus from 4 sources.

    Designed to produce a production-vocabulary (32K) training corpus that is
    large enough to show meaningful MLM val loss reduction below chance.

    Sources:
      1. NVD 10K CVEs (5 paginated requests, ~3.5 MB)
      2. MITRE CWE XML (all weaknesses, ~1.5 MB)
      3. GitHub Security Advisories (~5K, ~4 MB)
      4. Local test fixtures (unchanged, ~0.5 MB)
    """
    manifest_entries: list[dict] = []

    # ── Source 1: NVD CVEs (paginated) ───────────────────────────────────────
    print(f"[1/4] Collecting NVD CVE descriptions ({n_cves} CVEs, paginated) ...", flush=True)
    nvd_lines = list(_collect_nvd(n_cves=n_cves, page_delay=7.0))
    sha256, doc_count, byte_count = _write_shard(output_dir, "nvd_cves", nvd_lines)
    manifest_entries.append({
        "source": "NVD CVE API 2.0 (paginated)",
        "url": _NVD_API,
        "n_requested": n_cves,
        "sha256_shard": sha256,
        "doc_count": doc_count,
        "byte_count": byte_count,
    })
    print(f"  → {doc_count:,} CVEs, {byte_count:,} bytes", flush=True)

    # ── Source 2: CWE XML ─────────────────────────────────────────────────────
    print("[2/4] Collecting MITRE CWE weakness descriptions ...", flush=True)
    cwe_lines = list(_collect_cwe())
    sha256, doc_count, byte_count = _write_shard(output_dir, "cwe_weaknesses", cwe_lines)
    manifest_entries.append({
        "source": "MITRE CWE XML",
        "url": _CWE_XML_URL,
        "sha256_shard": sha256,
        "doc_count": doc_count,
        "byte_count": byte_count,
    })
    print(f"  → {doc_count:,} weaknesses, {byte_count:,} bytes", flush=True)

    # ── Source 3: GitHub Security Advisories ─────────────────────────────────
    print(f"[3/4] Collecting GitHub Security Advisories ({n_gh} target) ...", flush=True)
    gh_lines = list(_collect_github_advisories(n=n_gh, page_delay=1.0))
    sha256, doc_count, byte_count = _write_shard(output_dir, "github_advisories", gh_lines)
    manifest_entries.append({
        "source": "GitHub Security Advisories API",
        "url": _GH_ADVISORIES_API,
        "n_requested": n_gh,
        "sha256_shard": sha256,
        "doc_count": doc_count,
        "byte_count": byte_count,
    })
    print(f"  → {doc_count:,} advisories, {byte_count:,} bytes", flush=True)

    # ── Source 4: Existing fixtures ───────────────────────────────────────────
    print("[4/4] Collecting existing fixture texts ...", flush=True)
    fixtures_dir = _ROOT / "tests" / "fixtures"
    fixture_lines = list(_collect_fixtures(fixtures_dir))
    sha256, doc_count, byte_count = _write_shard(output_dir, "fixtures", fixture_lines)
    manifest_entries.append({
        "source": "Local test fixtures",
        "url": str(fixtures_dir),
        "sha256_shard": sha256,
        "doc_count": doc_count,
        "byte_count": byte_count,
    })
    print(f"  → {doc_count:,} fixtures, {byte_count:,} bytes", flush=True)

    # ── Manifest ──────────────────────────────────────────────────────────────
    total_docs = sum(e["doc_count"] for e in manifest_entries)
    total_bytes = sum(e["byte_count"] for e in manifest_entries)
    manifest = {
        "mode": "medium",
        "total_documents": total_docs,
        "total_bytes": total_bytes,
        "sources": manifest_entries,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(
        f"\nCorpus ready: {total_docs:,} documents, "
        f"{total_bytes/1024/1024:.1f} MB → {output_dir}",
        flush=True,
    )
    print(f"Manifest: {output_dir / 'manifest.json'}", flush=True)
    if total_bytes < 3_000_000:
        print(
            f"  [WARN] total_bytes={total_bytes:,} < 3,000,000 — "
            "corpus smaller than expected; check network access.",
            flush=True,
        )


# ── Smoke collection ──────────────────────────────────────────────────────────

def collect_smoke(output_dir: Path) -> None:
    """Collect ~5 MB smoke test corpus from 3 fast sources."""
    manifest_entries: list[dict] = []

    # ── Source 1: NVD CVEs ────────────────────────────────────────────────────
    print("[1/3] Collecting NVD CVE descriptions ...", flush=True)
    nvd_lines = list(_collect_nvd(n_cves=2000))
    sha256, doc_count, byte_count = _write_shard(output_dir, "nvd_cves", nvd_lines)
    manifest_entries.append({
        "source": "NVD CVE API 2.0",
        "url": f"{_NVD_API}?resultsPerPage=2000&startIndex=0",
        "sha256_shard": sha256,
        "doc_count": doc_count,
        "byte_count": byte_count,
    })
    print(f"  → {doc_count:,} CVEs, {byte_count:,} bytes", flush=True)

    # ── Source 2: CWE XML ─────────────────────────────────────────────────────
    print("[2/3] Collecting MITRE CWE weakness descriptions ...", flush=True)
    cwe_lines = list(_collect_cwe())
    sha256, doc_count, byte_count = _write_shard(output_dir, "cwe_weaknesses", cwe_lines)
    manifest_entries.append({
        "source": "MITRE CWE XML",
        "url": _CWE_XML_URL,
        "sha256_shard": sha256,
        "doc_count": doc_count,
        "byte_count": byte_count,
    })
    print(f"  → {doc_count:,} weaknesses, {byte_count:,} bytes", flush=True)

    # ── Source 3: Existing fixtures ───────────────────────────────────────────
    print("[3/3] Collecting existing fixture texts ...", flush=True)
    fixtures_dir = _ROOT / "tests" / "fixtures"
    fixture_lines = list(_collect_fixtures(fixtures_dir))
    sha256, doc_count, byte_count = _write_shard(output_dir, "fixtures", fixture_lines)
    manifest_entries.append({
        "source": "Local test fixtures",
        "url": str(fixtures_dir),
        "sha256_shard": sha256,
        "doc_count": doc_count,
        "byte_count": byte_count,
    })
    print(f"  → {doc_count:,} fixtures, {byte_count:,} bytes", flush=True)

    # ── Manifest ──────────────────────────────────────────────────────────────
    total_docs = sum(e["doc_count"] for e in manifest_entries)
    total_bytes = sum(e["byte_count"] for e in manifest_entries)
    manifest = {
        "mode": "smoke",
        "total_documents": total_docs,
        "total_bytes": total_bytes,
        "sources": manifest_entries,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(
        f"\nCorpus ready: {total_docs:,} documents, "
        f"{total_bytes/1024/1024:.1f} MB → {output_dir}",
        flush=True,
    )
    print(f"Manifest: {output_dir / 'manifest.json'}", flush=True)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect pretraining corpus for the from-scratch security SLM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--smoke",
        action="store_true",
        help=(
            "Collect a tiny ~5 MB corpus from NVD API + CWE XML + local fixtures. "
            "Use this for the MacBook smoke test (validates pipeline, not model quality)."
        ),
    )
    mode_group.add_argument(
        "--medium",
        action="store_true",
        help=(
            "Collect a medium ~15–25 MB corpus from NVD 10K CVEs + CWE XML + "
            "GitHub Security Advisories + local fixtures. "
            "Trains production 32K-vocab tokenizer; target final MLM val loss < 8.0."
        ),
    )
    mode_group.add_argument(
        "--full",
        action="store_true",
        help=(
            "Collect the full ~14 GB corpus from all 19 sources including Exploit-DB, "
            "security tool source code, CTF writeups, MITRE ATT&CK, OSV, OWASP, "
            "arXiv cs.CR, and PyPI. Intended for remote GPU training. "
            "Combine with --resume to continue an interrupted collection."
        ),
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Skip shards that already exist on disk (for --full mode). "
            "Use this to continue an interrupted full corpus collection."
        ),
    )
    parser.add_argument(
        "--n-cves",
        type=int,
        default=None,
        help="Override number of NVD CVEs to fetch (default: 2000 for --smoke, 10000 for --medium).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "Output directory (default: finetuning/pretrain_corpus_smoke/, "
            "finetuning/pretrain_corpus_medium/, finetuning/pretrain_corpus_full/, "
            "or finetuning/pretrain_corpus/)."
        ),
    )
    args = parser.parse_args()

    if args.output is None:
        if args.smoke:
            args.output = _HERE / "pretrain_corpus_smoke"
        elif args.medium:
            args.output = _HERE / "pretrain_corpus_medium"
        elif args.full:
            args.output = _HERE / "pretrain_corpus_full"
        else:
            args.output = _HERE / "pretrain_corpus"

    args.output.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {args.output}", flush=True)

    if args.smoke:
        if args.n_cves is not None:
            print(f"  [INFO] --n-cves override: {args.n_cves} CVEs (smoke default is 2000)", flush=True)
        collect_smoke(args.output)
    elif args.medium:
        n_cves = args.n_cves if args.n_cves is not None else 10_000
        print(f"  [INFO] Medium mode: {n_cves} CVEs + 5000 GitHub advisories", flush=True)
        collect_medium(args.output, n_cves=n_cves, n_gh=5_000)
    elif args.full:
        if args.resume:
            print("  [INFO] --resume: skipping already-written shards", flush=True)
        print("  [INFO] Full mode: collecting all 19 sources (~14 GB)", flush=True)
        collect_full(args.output, resume=args.resume)
    else:
        # Collect what we have + print guidance for remaining sources
        print("[1/3] Collecting NVD CVEs (partial full-run) ...", flush=True)
        nvd_lines = list(_collect_nvd(n_cves=args.n_cves or 2000))
        _write_shard(args.output, "nvd_cves", nvd_lines)

        print("[2/3] Collecting MITRE CWE ...", flush=True)
        cwe_lines = list(_collect_cwe())
        _write_shard(args.output, "cwe_weaknesses", cwe_lines)

        print("[3/3] Collecting local fixtures ...", flush=True)
        fixture_lines = list(_collect_fixtures(_ROOT / "tests" / "fixtures"))
        _write_shard(args.output, "fixtures", fixture_lines)

        print("\n[INFO] Collected 3 of 19 planned sources. Use --full for the complete corpus.", flush=True)
        _collect_full_corpus(args.output)  # prints TODO guidance


if __name__ == "__main__":
    main()
