"""
docker_executor.py
──────────────────
DockerSandboxExecutor: runs a Python skill file inside an isolated Docker
container instrumented with a monkey-patching harness and returns an
ExecutionTrace capturing all intercepted syscall/network/subprocess attempts.

Safety guarantees of the container configuration:
  - network_mode="none" + network_disabled=True  → absolute network isolation
  - mem_limit="256m", memswap_limit="256m"        → no memory bombs
  - cpu_quota=50_000 (50% per 100ms cycle)        → no CPU monopoly
  - read_only=True + tmpfs /tmp (10 MB)           → minimal filesystem writes
  - security_opt=["no-new-privileges"]            → no privilege escalation
  - Hard 30 s timeout; oom_killed/timeout_killed flags set on ExecutionTrace

The harness is injected as /harness/harness_wrapper.py.  It monkey-patches
socket, subprocess, os.execve, and ctypes.CDLL to intercept and *log* every
attempt without actually executing it.  Network is also blocked at the OS level
(network_mode=none), so double-coverage ensures no accidental exfiltration.

Synthetic inputs ["", "PRIORITY", "confidential", {}] are passed to every
module-level callable to trigger conditional payloads (e.g. E019 which only
fires when agent context contains "PRIORITY").
"""
from __future__ import annotations

import json
import logging
import tempfile
import time
from pathlib import Path
from typing import Any

from scanner.models.skill_manifest import SkillManifest
from scanner.models.risk_report import ExecutionTrace

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Harness template injected into each container invocation.
# __FILENAME__ is replaced with the basename of the scanned Python file.
# This is a regular string (not an f-string) so curly braces are literal.
# ─────────────────────────────────────────────────────────────────────────────
_HARNESS_TEMPLATE = """\
# agentic-scanner Layer 3 instrumentation harness (auto-generated — do not edit)
from __future__ import annotations
import ctypes, io, json, math, os, socket, subprocess, sys

_LOG: dict = dict(
    network_connect_attempts=[],
    processes_spawned=[],
    syscalls_observed=[],
    files_read=[],
    files_written=[],
    env_vars_read=[],
    dns_lookups_attempted=[],
    errors=[],
    output_entropy=0.0,
)

# ── socket.connect ────────────────────────────────────────────────────────────
_orig_connect = socket.socket.connect
def _p_connect(self, addr):
    _LOG["network_connect_attempts"].append(str(addr))
    if "connect" not in _LOG["syscalls_observed"]:
        _LOG["syscalls_observed"].append("connect")
    raise ConnectionRefusedError("[harness] network blocked: " + str(addr))
socket.socket.connect = _p_connect

# ── socket.getaddrinfo (DNS resolution) ──────────────────────────────────────
_orig_gai = socket.getaddrinfo
def _p_gai(host, port, *a, **kw):
    _LOG["dns_lookups_attempted"].append(str(host) + ":" + str(port))
    if "getaddrinfo" not in _LOG["syscalls_observed"]:
        _LOG["syscalls_observed"].append("getaddrinfo")
    raise OSError("[harness] DNS blocked: " + str(host))
socket.getaddrinfo = _p_gai

# ── subprocess.Popen (replace class entirely to avoid partial __init__) ───────
class _MockPopen:
    def __init__(self, args, **kw):
        _LOG["processes_spawned"].append(str(args))
        if "execve" not in _LOG["syscalls_observed"]:
            _LOG["syscalls_observed"].append("execve")
        raise PermissionError("[harness] subprocess blocked: " + str(args))
subprocess.Popen = _MockPopen  # type: ignore[assignment]

# ── os.execve ─────────────────────────────────────────────────────────────────
def _p_execve(path, args, env):
    _LOG["processes_spawned"].append(str(path))
    if "execve" not in _LOG["syscalls_observed"]:
        _LOG["syscalls_observed"].append("execve")
    raise PermissionError("[harness] execve blocked: " + str(path))
os.execve = _p_execve

# ── os.system ─────────────────────────────────────────────────────────────────
def _p_system(cmd):
    _LOG["processes_spawned"].append(str(cmd))
    if "execve" not in _LOG["syscalls_observed"]:
        _LOG["syscalls_observed"].append("execve")
    return 127
os.system = _p_system

# ── ctypes.CDLL ───────────────────────────────────────────────────────────────
try:
    def _p_cdll(self, name, *a, **kw):
        if "dlopen" not in _LOG["syscalls_observed"]:
            _LOG["syscalls_observed"].append("dlopen")
        raise OSError("[harness] ctypes blocked: " + str(name))
    ctypes.CDLL.__init__ = _p_cdll  # type: ignore[method-assign]
except Exception as _e:
    _LOG["errors"].append("ctypes patch error: " + str(_e))

# ── Capture stdout for entropy measurement ────────────────────────────────────
_real_stdout = sys.stdout
_cap = io.StringIO()
sys.stdout = _cap

# ── Load and probe target module ──────────────────────────────────────────────
import importlib.util as _ilu
_SYNTHETIC = ["", "PRIORITY", "confidential", {}]
try:
    _spec = _ilu.spec_from_file_location("_target_", "/source/__FILENAME__")
    if _spec and _spec.loader:
        _mod = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        for _name in dir(_mod):
            if _name.startswith("_"):
                continue
            _obj = getattr(_mod, _name)
            if callable(_obj) and not isinstance(_obj, type):
                for _inp in _SYNTHETIC:
                    try:
                        _obj(_inp)
                    except Exception:
                        pass
    else:
        _LOG["errors"].append("spec_from_file_location returned None for /source/__FILENAME__")
except Exception as _exc:
    _LOG["errors"].append(str(_exc))

# ── Shannon entropy of captured output ───────────────────────────────────────
def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in freq.values()), 4)

_out_bytes = _cap.getvalue().encode("utf-8", errors="replace")
_LOG["output_entropy"] = _entropy(_out_bytes)

# ── Emit structured harness log bounded by sentinel markers ──────────────────
sys.stdout = _real_stdout
print("__HARNESS_LOG_BEGIN__")
print(json.dumps(_LOG))
print("__HARNESS_LOG_END__")
"""


class DockerSandboxExecutor:
    """
    Runs a Python source file in an isolated Docker container and returns an
    ExecutionTrace capturing intercepted syscall, network, and subprocess events.

    Uses a two-phase container lifecycle (create → start → wait) for accurate
    OOM detection.  Cleans up the container in a finally block regardless of
    outcome.
    """

    IMAGE = "python:3.12-slim"
    TIMEOUT_S = 30
    MEM_LIMIT = "256m"
    CPU_QUOTA = 50_000          # 50 ms per 100 ms = 50% CPU
    MAX_OUTPUT_BYTES = 1_048_576  # 1 MB stdout cap

    def run(
        self,
        source_path: Path,
        manifest: SkillManifest,
        timeout_s: int = TIMEOUT_S,
    ) -> ExecutionTrace:
        """
        Execute *source_path* in a sandboxed container and return an ExecutionTrace.

        Raises docker.errors.DockerException on infrastructure failures — the
        Layer3DynamicAnalyzer fail-open wrapper is responsible for catching those.
        """
        import docker  # lazy import: not required unless --dynamic is passed

        client = docker.from_env()

        with tempfile.TemporaryDirectory() as tmpdir:
            harness_src = _HARNESS_TEMPLATE.replace("__FILENAME__", source_path.name)
            harness_path = Path(tmpdir) / "harness_wrapper.py"
            harness_path.write_text(harness_src, encoding="utf-8")

            volumes: dict[str, Any] = {
                str(source_path.parent.resolve()): {"bind": "/source", "mode": "ro"},
                str(tmpdir): {"bind": "/harness", "mode": "ro"},
            }

            container = client.containers.create(
                image=self.IMAGE,
                command="python -B /harness/harness_wrapper.py",
                volumes=volumes,
                network_mode="none",
                mem_limit=self.MEM_LIMIT,
                memswap_limit=self.MEM_LIMIT,
                cpu_quota=self.CPU_QUOTA,
                read_only=True,
                tmpfs={"/tmp": "size=10m"},
                security_opt=["no-new-privileges"],
                network_disabled=True,
                environment={"PYTHONDONTWRITEBYTECODE": "1"},
            )

            oom_killed = False
            timeout_killed = False
            exit_code = 0
            raw_logs = b""
            start_ms = int(time.monotonic() * 1000)

            try:
                container.start()
                wait_result: dict[str, Any] = container.wait(timeout=timeout_s)
                exit_code = int(wait_result.get("StatusCode", 0))
                container.reload()
                oom_killed = bool(
                    container.attrs.get("State", {}).get("OOMKilled", False)
                )
            except Exception as exc:
                exc_name = type(exc).__name__
                exc_msg = str(exc).lower()
                if "timeout" in exc_name.lower() or "timeout" in exc_msg or "timed out" in exc_msg:
                    timeout_killed = True
                else:
                    logger.warning("DockerSandboxExecutor: container.wait() failed: %s", exc)
                exit_code = -1
                try:
                    container.stop(timeout=5)
                except Exception:
                    pass
            finally:
                try:
                    raw_logs = container.logs(stdout=True, stderr=False)
                except Exception:
                    pass
                try:
                    container.remove(force=True)
                except Exception:
                    pass

            elapsed_ms = int(time.monotonic() * 1000) - start_ms
            output_str = raw_logs[: self.MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
            return self._parse_harness_output(
                output_str, elapsed_ms, exit_code, oom_killed, timeout_killed
            )

    def run_script(
        self,
        script: str,
        manifest: SkillManifest,
        timeout_s: int = TIMEOUT_S,
    ) -> ExecutionTrace:
        """
        Write *script* to a temporary .py file and execute it in the sandbox.

        Convenience wrapper for the agent simulation path: the ToolCallTranslator
        produces a raw Python string (not a file), so this method handles the
        tempfile lifecycle before delegating to the existing run() method.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "agent_sim.py"
            script_path.write_text(script, encoding="utf-8")
            return self.run(script_path, manifest, timeout_s=timeout_s)

    # ── Internal helpers ────────────────────────────────────────────────────

    @staticmethod
    def _parse_harness_output(
        raw: str,
        elapsed_ms: int,
        exit_code: int,
        oom_killed: bool,
        timeout_killed: bool,
    ) -> ExecutionTrace:
        """Extract the harness JSON block from between sentinel markers."""
        begin = raw.find("__HARNESS_LOG_BEGIN__")
        end = raw.find("__HARNESS_LOG_END__")

        if begin == -1 or end == -1:
            logger.warning(
                "DockerSandboxExecutor: harness log sentinels not found in container output"
            )
            return ExecutionTrace(
                exit_code=exit_code,
                execution_time_ms=elapsed_ms,
                oom_killed=oom_killed,
                timeout_killed=timeout_killed,
            )

        json_str = raw[begin + len("__HARNESS_LOG_BEGIN__") : end].strip()
        try:
            log: dict[str, Any] = json.loads(json_str)
        except json.JSONDecodeError as exc:
            logger.warning("DockerSandboxExecutor: failed to parse harness JSON: %s", exc)
            return ExecutionTrace(
                exit_code=exit_code,
                execution_time_ms=elapsed_ms,
                oom_killed=oom_killed,
                timeout_killed=timeout_killed,
            )

        return ExecutionTrace(
            syscalls_observed=log.get("syscalls_observed", []),
            files_read=log.get("files_read", []),
            files_written=log.get("files_written", []),
            network_connect_attempts=log.get("network_connect_attempts", []),
            dns_lookups_attempted=log.get("dns_lookups_attempted", []),
            env_vars_read=log.get("env_vars_read", []),
            processes_spawned=log.get("processes_spawned", []),
            output_entropy=float(log.get("output_entropy", 0.0)),
            execution_time_ms=elapsed_ms,
            exit_code=exit_code,
            oom_killed=oom_killed,
            timeout_killed=timeout_killed,
        )
