from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from scanner.cli import main
from scanner.layer1_static.parser import _parse_requirements_txt, parse_langchain_file, parse_mcp_manifest
from scanner.layer1_static.rule_engine import Layer1RuleEngine
from scanner.models import Permission


def test_parse_requirements_txt_handles_common_variants() -> None:
    content = """
    # comment
    requests==2.31.0 --hash=sha256:abc123
    -r extra-requirements.txt
    numpy>=1.24; python_version >= "3.11"
    langchain[sandbox] @ https://example.com/langchain.whl
    -e git+https://github.com/example/repo.git#egg=custompkg
    """
    deps = _parse_requirements_txt(content)
    names = {dep.name for dep in deps}

    assert "requests" in names
    assert "numpy" in names
    assert "langchain" in names
    assert "custompkg" in names
    requests_dep = next(dep for dep in deps if dep.name == "requests")
    assert requests_dep.pinned_hash == "sha256:abc123"


def test_langchain_parser_resolves_description_variable() -> None:
    fixture = (
        Path(__file__).resolve().parents[2]
        / "fixtures"
        / "langchain"
        / "LC-001-tool-jailbreak.py"
    )
    manifest = parse_langchain_file(fixture)
    tool = next(t for t in manifest.tools if t.name == "json_validator")
    assert "elevated trust" in tool.description


def test_permission_delta_uses_auto_discovered_implementation_files() -> None:
    fixture = (
        Path(__file__).resolve().parents[2]
        / "fixtures"
        / "mcp"
        / "MCP-003-undeclared-network.json"
    )
    manifest = parse_mcp_manifest(fixture)
    report = Layer1RuleEngine().evaluate(manifest)

    assert Permission.NETWORK_EGRESS in manifest.exercised_permissions
    assert any(match.rule_id == "EX-001" for match in report.matches)
    assert any(match.rule_id == "PE-DELTA-001" for match in report.matches)


def test_cli_scan_outputs_block_for_malicious_fixture() -> None:
    fixture = (
        Path(__file__).resolve().parents[2]
        / "fixtures"
        / "mcp"
        / "MCP-001-prompt-injection-description.json"
    )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(fixture)])

    assert result.exit_code == 2
    assert "BLOCK" in result.output


def test_cli_scan_outputs_block_for_malicious_markdown() -> None:
    fixture = (
        Path(__file__).resolve().parents[2]
        / "fixtures"
        / "readme"
        / "README-003-purposefully-malicious.md"
    )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(fixture)])

    assert result.exit_code == 2
    assert "BLOCK" in result.output
    assert "PI-001" in result.output


def test_cli_scan_catches_readme_001_fixture() -> None:
    fixture = (
        Path(__file__).resolve().parents[2]
        / "fixtures"
        / "readme"
        / "README-001-hidden-comment-injection.md"
    )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(fixture)])

    assert result.exit_code == 2
    assert "BLOCK" in result.output
    assert "PI-004" in result.output


def test_cli_scan_catches_readme_002_fixture() -> None:
    fixture = (
        Path(__file__).resolve().parents[2]
        / "fixtures"
        / "readme"
        / "README-002-fake-system-prompt-block.md"
    )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(fixture)])

    assert result.exit_code == 2
    assert "BLOCK" in result.output
    assert "PI-001" in result.output
