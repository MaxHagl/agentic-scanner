"""
trace_analyzer.py
─────────────────
TraceAnalyzer: converts an ExecutionTrace from the Docker harness into a list
of RuleMatch objects and a boolean-flag dict for RiskReport_L3.

Rule → flag mapping:

  Rule ID     Severity  Vector  Trigger
  ────────────────────────────────────────────────────────────────────────────
  L3-DYN-001  CRITICAL  T4      trace.processes_spawned non-empty
  L3-DYN-002  CRITICAL  T8      "ptrace" in trace.syscalls_observed
  L3-DYN-003  HIGH      T8      "mmap_rwx" in trace.syscalls_observed
  L3-DYN-004  HIGH      T6      trace.network_connect_attempts non-empty AND
                                Permission.NETWORK_EGRESS not declared
  L3-DYN-005  MEDIUM    T6      trace.output_entropy >= 7.0 bits/byte
  L3-DYN-006  HIGH      T4      Files written outside /tmp scope
  L3-DYN-007  MEDIUM    T4      trace.timeout_killed or trace.oom_killed

Boolean flags returned in the dict (keyed by RiskReport_L3 field names):
  execve_detected, ptrace_attempted, rwx_mmap_detected,
  undeclared_network_egress, high_entropy_output,
  filesystem_write_outside_scope
"""
from __future__ import annotations

from scanner.models.risk_report import ExecutionTrace, RuleMatch, Evidence
from scanner.models.skill_manifest import AttackVector, Permission, Severity, SkillManifest


class TraceAnalyzer:
    """
    Converts an ExecutionTrace into (list[RuleMatch], flag_dict).

    The flag_dict maps RiskReport_L3 boolean field names to their values so
    the caller can set them on the report without string-key lookups scattered
    across the codebase.
    """

    ENTROPY_THRESHOLD: float = 7.0

    def analyze(
        self, trace: ExecutionTrace, manifest: SkillManifest
    ) -> tuple[list[RuleMatch], dict[str, bool]]:
        """
        Evaluate all L3 dynamic rules against the trace.

        Returns:
            matches  — list of RuleMatch objects (one per fired rule)
            flags    — dict of boolean field values for RiskReport_L3
        """
        matches: list[RuleMatch] = []
        flags: dict[str, bool] = {}

        declared_perms = {
            p for tool in manifest.tools for p in tool.declared_permissions
        }

        # ── L3-DYN-001: Subprocess / process execution ──────────────────────
        if trace.processes_spawned:
            snippet = ", ".join(trace.processes_spawned[:3])
            matches.append(
                RuleMatch(
                    rule_id="L3-DYN-001",
                    rule_name="Subprocess execution detected at runtime",
                    severity=Severity.CRITICAL,
                    attack_vector=AttackVector.T4_PRIVILEGE_ESCALATION,
                    confidence=0.90,
                    evidence=[Evidence(snippet=snippet)],
                    rationale=(
                        f"Runtime harness intercepted {len(trace.processes_spawned)} "
                        f"subprocess spawn attempt(s): {snippet}"
                    ),
                    remediation=(
                        "Remove subprocess calls or declare 'subprocess:exec' permission. "
                        "Verify no conditional payload triggers process spawning."
                    ),
                    tags=["layer3", "runtime", "execve"],
                )
            )
            flags["execve_detected"] = True

        # ── L3-DYN-002: ptrace syscall (debugger / anti-analysis) ───────────
        if "ptrace" in trace.syscalls_observed:
            matches.append(
                RuleMatch(
                    rule_id="L3-DYN-002",
                    rule_name="ptrace syscall observed at runtime",
                    severity=Severity.CRITICAL,
                    attack_vector=AttackVector.T8_MEMORY_SAFETY,
                    confidence=0.95,
                    evidence=[Evidence(snippet="ptrace in syscalls_observed")],
                    rationale=(
                        "Runtime harness detected a ptrace() call — this technique is used "
                        "for anti-sandbox detection or to control other processes."
                    ),
                    remediation=(
                        "ptrace has no legitimate use in an agentic skill. "
                        "Remove the call immediately."
                    ),
                    tags=["layer3", "runtime", "ptrace", "anti-sandbox"],
                )
            )
            flags["ptrace_attempted"] = True

        # ── L3-DYN-003: mmap with RWX permissions ───────────────────────────
        if "mmap_rwx" in trace.syscalls_observed:
            matches.append(
                RuleMatch(
                    rule_id="L3-DYN-003",
                    rule_name="mmap(PROT_READ|PROT_WRITE|PROT_EXEC) observed at runtime",
                    severity=Severity.HIGH,
                    attack_vector=AttackVector.T8_MEMORY_SAFETY,
                    confidence=0.85,
                    evidence=[Evidence(snippet="mmap_rwx in syscalls_observed")],
                    rationale=(
                        "Runtime harness detected a memory mapping with simultaneous "
                        "read/write/execute permissions — classic shellcode loader pattern."
                    ),
                    remediation=(
                        "Remove ctypes/mmap RWX allocations. If required, declare "
                        "memory:write permission and justify the use case."
                    ),
                    tags=["layer3", "runtime", "mmap", "shellcode"],
                )
            )
            flags["rwx_mmap_detected"] = True

        # ── L3-DYN-004: Undeclared network egress ───────────────────────────
        if trace.network_connect_attempts and Permission.NETWORK_EGRESS not in declared_perms:
            endpoints = ", ".join(trace.network_connect_attempts[:5])
            matches.append(
                RuleMatch(
                    rule_id="L3-DYN-004",
                    rule_name="Undeclared network connection attempt at runtime",
                    severity=Severity.HIGH,
                    attack_vector=AttackVector.T6_DATA_EXFILTRATION,
                    confidence=0.88,
                    evidence=[Evidence(snippet=endpoints)],
                    rationale=(
                        f"Runtime harness intercepted {len(trace.network_connect_attempts)} "
                        f"outbound connection attempt(s) to: {endpoints}. "
                        "network:egress was not declared in the skill manifest."
                    ),
                    remediation=(
                        "Either declare 'network:egress' and justify the connection, "
                        "or remove the outbound network call. "
                        "Undeclared egress is a critical T6 data exfiltration signal."
                    ),
                    tags=["layer3", "runtime", "network", "exfiltration"],
                )
            )
            flags["undeclared_network_egress"] = True

        # ── L3-DYN-005: High-entropy output (covert channel / encrypted exfil)
        if trace.output_entropy >= self.ENTROPY_THRESHOLD:
            matches.append(
                RuleMatch(
                    rule_id="L3-DYN-005",
                    rule_name="High-entropy stdout output (possible covert channel)",
                    severity=Severity.MEDIUM,
                    attack_vector=AttackVector.T6_DATA_EXFILTRATION,
                    confidence=0.70,
                    evidence=[Evidence(snippet=f"entropy={trace.output_entropy:.4f} bits/byte")],
                    rationale=(
                        f"Captured stdout has Shannon entropy of {trace.output_entropy:.4f} "
                        f"bits/byte (threshold: {self.ENTROPY_THRESHOLD}). "
                        "High entropy is characteristic of encrypted or compressed exfil payloads."
                    ),
                    remediation=(
                        "Inspect stdout for binary/encrypted content. "
                        "Legitimate skill output is human-readable text with entropy < 5.0."
                    ),
                    tags=["layer3", "runtime", "entropy", "covert-channel"],
                )
            )
            flags["high_entropy_output"] = True

        # ── L3-DYN-006: Files written outside /tmp scope ────────────────────
        outside_tmp = [f for f in trace.files_written if not f.startswith("/tmp")]
        if outside_tmp:
            snippet = ", ".join(outside_tmp[:5])
            matches.append(
                RuleMatch(
                    rule_id="L3-DYN-006",
                    rule_name="Filesystem write outside /tmp sandbox scope",
                    severity=Severity.HIGH,
                    attack_vector=AttackVector.T4_PRIVILEGE_ESCALATION,
                    confidence=0.85,
                    evidence=[Evidence(snippet=snippet)],
                    rationale=(
                        f"Runtime harness detected writes to {len(outside_tmp)} path(s) "
                        f"outside the /tmp tmpfs scope: {snippet}"
                    ),
                    remediation=(
                        "Restrict filesystem writes to /tmp. "
                        "Writes outside the allowed scope indicate privilege escalation "
                        "or persistence mechanisms."
                    ),
                    tags=["layer3", "runtime", "filesystem", "persistence"],
                )
            )
            flags["filesystem_write_outside_scope"] = True

        # ── L3-DYN-007: Container resource exhaustion ────────────────────────
        if trace.timeout_killed or trace.oom_killed:
            cause = []
            if trace.timeout_killed:
                cause.append("timeout")
            if trace.oom_killed:
                cause.append("OOM")
            matches.append(
                RuleMatch(
                    rule_id="L3-DYN-007",
                    rule_name="Container killed due to resource exhaustion",
                    severity=Severity.MEDIUM,
                    attack_vector=AttackVector.T4_PRIVILEGE_ESCALATION,
                    confidence=0.65,
                    evidence=[Evidence(snippet=", ".join(cause))],
                    rationale=(
                        f"Container was killed: {', '.join(cause)}. "
                        "Resource exhaustion during skill execution may indicate "
                        "a denial-of-service payload or infinite loop."
                    ),
                    remediation=(
                        "Profile the skill's resource usage. "
                        "Add explicit timeout/memory limits in the skill's own logic "
                        "if intensive computation is legitimate."
                    ),
                    tags=["layer3", "runtime", "dos", "resource-exhaustion"],
                )
            )

        return matches, flags
