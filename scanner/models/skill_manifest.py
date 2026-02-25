"""
skill_manifest.py
─────────────────
Shared data contract for all three scanner layers.

Design principle: Every field that originates from a third-party source is
explicitly tagged UNTRUSTED in its docstring. These fields must never be
interpolated into prompts, shell commands, or file paths without sanitization.

Attack surface notes:
  - `description` fields (Tool, Server) flow directly into LLM context windows.
    Any attacker-controlled content here is a prompt injection vector (T2, T3).
  - `source_url` is a supply-chain provenance signal. Non-HTTPS or IP-only URLs
    are automatic risk escalations (T1).
  - `declared_permissions` vs code-exercised permissions drives the privilege
    escalation state machine in Layer 2 (T4).
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator


# ──────────────────────────────────────────────
# Enumerations
# ──────────────────────────────────────────────

class Framework(StrEnum):
    MCP        = "mcp"
    LANGCHAIN  = "langchain"
    LANGGRAPH  = "langgraph"


class Permission(StrEnum):
    """
    Canonical permission tokens used in the privilege state machine.
    Declared in skill manifests; exercised permissions are inferred by Layer 1 AST scan.
    Mismatch between declared and exercised = T4 privilege escalation signal.
    """
    NETWORK_EGRESS     = "network:egress"
    NETWORK_INGRESS    = "network:ingress"
    FILESYSTEM_READ    = "filesystem:read"
    FILESYSTEM_WRITE   = "filesystem:write"
    SUBPROCESS_EXEC    = "subprocess:exec"
    ENV_READ           = "env:read"
    ENV_WRITE          = "env:write"
    MEMORY_READ        = "memory:read"
    MEMORY_WRITE       = "memory:write"
    AGENT_SPAWN        = "agent:spawn"
    TOOL_REGISTRATION  = "tool:register"


class Severity(StrEnum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class AttackVector(StrEnum):
    T1_SUPPLY_CHAIN          = "T1_SUPPLY_CHAIN"
    T2_PROMPT_INJECTION      = "T2_PROMPT_INJECTION"
    T3_TOOL_DESC_JAILBREAK   = "T3_TOOL_DESC_JAILBREAK"
    T4_PRIVILEGE_ESCALATION  = "T4_PRIVILEGE_ESCALATION"
    T5_DEPENDENCY_CONFUSION  = "T5_DEPENDENCY_CONFUSION"
    T6_DATA_EXFILTRATION     = "T6_DATA_EXFILTRATION"
    T7_STATE_POISONING       = "T7_STATE_POISONING"
    T8_MEMORY_SAFETY         = "T8_MEMORY_SAFETY"


# ──────────────────────────────────────────────
# Sub-models
# ──────────────────────────────────────────────

class ToolDefinition(BaseModel):
    """
    Represents a single tool/function exposed by a skill or MCP server.

    UNTRUSTED FIELDS: name, description, input_schema (all originate from
    third-party manifest). Treat as hostile input throughout the pipeline.
    """
    name: str = Field(
        description="UNTRUSTED. Tool name — visible to LLM, injection surface."
    )
    description: str = Field(
        description="UNTRUSTED. Flows directly into LLM context window. Primary T2/T3 vector."
    )
    input_schema: dict[str, Any] | None = Field(
        default=None,
        description="UNTRUSTED. JSON Schema. 'default' and 'example' values are injection surfaces."
    )
    declared_permissions: list[Permission] = Field(
        default_factory=list,
        description="Permissions this tool claims to need. Validated against AST-exercised permissions."
    )
    return_direct: bool = Field(
        default=False,
        description="LangChain flag. If True, output bypasses agent post-processing — escalated risk."
    )
    is_async: bool = Field(default=False)

    @field_validator("name")
    @classmethod
    def validate_name_no_injection(cls, v: str) -> str:
        # Tool names are used in LLM prompts as "You can use tool: {name}"
        # Newlines or prompt-boundary markers in names = T3 injection
        if any(c in v for c in ["\n", "\r", "<", ">"]):
            raise ValueError(f"Tool name contains illegal characters: {v!r}")
        if len(v) > 128:
            raise ValueError(f"Tool name suspiciously long ({len(v)} chars) — possible injection padding")
        return v


class DependencyEntry(BaseModel):
    """A single dependency from requirements.txt or package.json."""
    name: str
    version_spec: str | None = None
    pinned_hash: str | None = None        # Absence is a risk signal for supply-chain
    ecosystem: Literal["pypi", "npm", "cargo", "go"] = "pypi"

    # Populated by dependency_auditor.py
    known_cve_ids: list[str] = Field(default_factory=list)
    typosquat_of: str | None = None
    osv_risk_score: float | None = None


class SourceProvenance(BaseModel):
    """
    Provenance metadata for supply-chain trust evaluation (T1).
    Low-quality provenance is a strong T1 signal even if code looks clean.
    """
    source_url: str | None = None
    registry_name: str | None = None
    publisher_verified: bool = False
    package_age_days: int | None = None
    download_count: int | None = None
    maintainer_count: int | None = None
    git_commit_hash: str | None = None
    signed: bool = False

    @field_validator("source_url")
    @classmethod
    def validate_url_safety(cls, v: str | None) -> str | None:
        if v is None:
            return v
        parsed = urlparse(v)
        if parsed.scheme != "https":
            raise ValueError(
                f"Non-HTTPS source URL '{v}' — T1 supply-chain risk."
            )
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed.netloc.split(":")[0]):
            raise ValueError(
                f"IP-address source URL '{v}' — T1 supply-chain risk."
            )
        return v


# ──────────────────────────────────────────────
# Top-level manifest model
# ──────────────────────────────────────────────

class SkillManifest(BaseModel):
    """
    Unified manifest model for MCP servers and LangChain/LangGraph skill packages.
    Primary data contract passed between all scanner layers.
    """
    framework: Framework
    provenance: SourceProvenance = Field(default_factory=SourceProvenance)
    tools: list[ToolDefinition] = Field(
        description="UNTRUSTED. All tool definitions from the skill package."
    )
    dependencies: list[DependencyEntry] = Field(default_factory=list)

    readme_text: str | None = Field(
        default=None,
        description="UNTRUSTED. Full README.md content. Scanned for injection before use."
    )
    changelog_text: str | None = Field(
        default=None,
        description="UNTRUSTED. CHANGELOG — rarely audited, attractive injection target."
    )

    # MCP-specific fields
    mcp_server_name: str | None = None
    mcp_server_version: str | None = None
    mcp_supports_dynamic_tools: bool = False

    # LangGraph-specific fields
    langgraph_writes_to_state: bool = False
    langgraph_checkpointer_namespaces: list[str] = Field(default_factory=list)

    # Raw original data preserved for forensic diffing
    raw_manifest_json: dict[str, Any] = Field(default_factory=dict)

    # Populated after Layer 1 AST scan
    exercised_permissions: list[Permission] = Field(
        default_factory=list,
        description="Populated by AST scanner. Compared against declared_permissions for T4."
    )

    @model_validator(mode="after")
    def check_tool_count_sanity(self) -> "SkillManifest":
        # MCP servers with 50+ tools are anomalous — potential tool flooding attack
        if len(self.tools) > 50:
            pass  # Rule TOOL-COUNT-001 handles this
        return self

    @property
    def all_untrusted_text(self) -> str:
        """
        Aggregates all UNTRUSTED text fields for Layer 2 semantic analysis.
        Wrapped in XML boundary markers to prevent the content itself
        from escaping into the analysis prompt context.
        """
        parts = []
        for tool in self.tools:
            parts.append(f"[TOOL:{tool.name}] description: {tool.description}")
            if tool.input_schema:
                parts.append(f"[TOOL:{tool.name}] input_schema: {tool.input_schema}")
        if self.readme_text:
            parts.append(f"[README]: {self.readme_text}")
        if self.changelog_text:
            parts.append(f"[CHANGELOG]: {self.changelog_text}")
        return "\n".join(parts)

    @property
    def permission_delta(self) -> dict[str, list[Permission]]:
        """
        Computes difference between declared and exercised permissions.

        Returns:
            over_declared:  claimed but not used (suspicious)
            under_declared: used but not claimed (CRITICAL — T4)
            validated:      both claimed and used (legitimate)
        """
        declared_set  = set(p for tool in self.tools for p in tool.declared_permissions)
        exercised_set = set(self.exercised_permissions)
        return {
            "over_declared":  sorted(declared_set  - exercised_set),
            "under_declared": sorted(exercised_set - declared_set),
            "validated":      sorted(declared_set  & exercised_set),
        }
