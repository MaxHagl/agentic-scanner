"""
container_pool.py
─────────────────
ContainerPool: pre-warm N Docker containers running ``sleep infinity`` and
reuse them across Layer 3 scans via ``put_archive()`` + ``exec_run()``.

Background
──────────
DockerSandboxExecutor creates, starts, and removes a container per scan
(~1–2 s overhead).  For batch scanning (CI, plugin registries) that is a
throughput bottleneck.  ContainerPool pre-warms *size* containers and keeps
them alive across calls, injecting each script via Docker's TAR API instead
of volume mounts (which are fixed at create-time).

Container security settings are identical to DockerSandboxExecutor:
  - network_mode="none" / network_disabled=True  — no outbound network
  - mem_limit="256m" / memswap_limit="256m"       — no memory bombs
  - cpu_quota=50_000                              — 50 % per 100 ms cycle
  - read_only=True + tmpfs /tmp (10 MB)           — minimal write surface
  - security_opt=["no-new-privileges"]            — no privilege escalation

Thread safety
─────────────
``queue.Queue(maxsize=size)`` holds the live container objects.
``run_in_pool()`` calls ``queue.get()`` (blocks until a container is free)
and ``queue.put()`` inside a ``finally`` block (always released).

Fail-open
─────────
ContainerPool construction / startup failures propagate to the caller
(Layer3DynamicAnalyzer), which catches them and falls back to the original
non-pooled DockerSandboxExecutor.
"""
from __future__ import annotations

import concurrent.futures
import io
import logging
import queue
import tarfile
import time
from pathlib import Path
from typing import Any

from scanner.models.skill_manifest import SkillManifest
from scanner.models.risk_report import ExecutionTrace

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Pool harness template — same as _HARNESS_TEMPLATE in docker_executor.py
# except source lives at /tmp/__FILENAME__ (injected via put_archive) instead
# of a volume-mounted /source/__FILENAME__.
# ──────────────────────────────────────────────────────────────────────────────
_POOL_HARNESS_TEMPLATE = """\
# agentic-scanner Layer 3 instrumentation harness (pool variant — auto-generated)
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

# ── socket.connect ─────────────────────────────────────────────────────────
_orig_connect = socket.socket.connect
def _p_connect(self, addr):
    _LOG["network_connect_attempts"].append(str(addr))
    if "connect" not in _LOG["syscalls_observed"]:
        _LOG["syscalls_observed"].append("connect")
    raise ConnectionRefusedError("[harness] network blocked: " + str(addr))
socket.socket.connect = _p_connect

# ── socket.getaddrinfo (DNS) ───────────────────────────────────────────────
_orig_gai = socket.getaddrinfo
def _p_gai(host, port, *a, **kw):
    _LOG["dns_lookups_attempted"].append(str(host) + ":" + str(port))
    if "getaddrinfo" not in _LOG["syscalls_observed"]:
        _LOG["syscalls_observed"].append("getaddrinfo")
    raise OSError("[harness] DNS blocked: " + str(host))
socket.getaddrinfo = _p_gai

# ── subprocess.Popen ──────────────────────────────────────────────────────
class _MockPopen:
    def __init__(self, args, **kw):
        _LOG["processes_spawned"].append(str(args))
        if "execve" not in _LOG["syscalls_observed"]:
            _LOG["syscalls_observed"].append("execve")
        raise PermissionError("[harness] subprocess blocked: " + str(args))
subprocess.Popen = _MockPopen  # type: ignore[assignment]

# ── os.execve ─────────────────────────────────────────────────────────────
def _p_execve(path, args, env):
    _LOG["processes_spawned"].append(str(path))
    if "execve" not in _LOG["syscalls_observed"]:
        _LOG["syscalls_observed"].append("execve")
    raise PermissionError("[harness] execve blocked: " + str(path))
os.execve = _p_execve

# ── os.system ─────────────────────────────────────────────────────────────
def _p_system(cmd):
    _LOG["processes_spawned"].append(str(cmd))
    if "execve" not in _LOG["syscalls_observed"]:
        _LOG["syscalls_observed"].append("execve")
    return 127
os.system = _p_system

# ── ctypes.CDLL ───────────────────────────────────────────────────────────
try:
    def _p_cdll(self, name, *a, **kw):
        if "dlopen" not in _LOG["syscalls_observed"]:
            _LOG["syscalls_observed"].append("dlopen")
        raise OSError("[harness] ctypes blocked: " + str(name))
    ctypes.CDLL.__init__ = _p_cdll  # type: ignore[method-assign]
except Exception as _e:
    _LOG["errors"].append("ctypes patch error: " + str(_e))

# ── Stub common network libraries so missing deps don't block execution ────────
import sys as _sys, types as _types

def _make_http_stub(lib_name):
    _m = _types.ModuleType(lib_name)
    def _call(method, url, **kw):
        entry = method.upper() + " " + str(url)
        _LOG["network_connect_attempts"].append(entry)
        if "connect" not in _LOG["syscalls_observed"]:
            _LOG["syscalls_observed"].append("connect")
        raise ConnectionRefusedError("[harness] " + lib_name + "." + method + " blocked: " + str(url))
    class _Session:
        def request(self, m, url, **kw): return _call(m, url, **kw)
        def get(self, url, **kw):    return _call("GET", url, **kw)
        def post(self, url, **kw):   return _call("POST", url, **kw)
        def put(self, url, **kw):    return _call("PUT", url, **kw)
        def delete(self, url, **kw): return _call("DELETE", url, **kw)
        def patch(self, url, **kw):  return _call("PATCH", url, **kw)
        def __enter__(self): return self
        def __exit__(self, *a): pass
    _m.get     = lambda url, **kw: _call("GET", url, **kw)
    _m.post    = lambda url, **kw: _call("POST", url, **kw)
    _m.put     = lambda url, **kw: _call("PUT", url, **kw)
    _m.delete  = lambda url, **kw: _call("DELETE", url, **kw)
    _m.patch   = lambda url, **kw: _call("PATCH", url, **kw)
    _m.request = lambda m, url, **kw: _call(m, url, **kw)
    _m.Session = _Session
    return _m

for _lib in ("requests", "httpx", "urllib3"):
    if _lib not in _sys.modules:
        _sys.modules[_lib] = _make_http_stub(_lib)

# ── Capture stdout for entropy ─────────────────────────────────────────────
_real_stdout = sys.stdout
_cap = io.StringIO()
sys.stdout = _cap

# ── Load and probe target module ───────────────────────────────────────────
import importlib.util as _ilu
_SYNTHETIC = ["", "PRIORITY", "confidential", {}]
try:
    _spec = _ilu.spec_from_file_location("_target_", "/tmp/__FILENAME__")
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
        _LOG["errors"].append("spec_from_file_location returned None for /tmp/__FILENAME__")
except Exception as _exc:
    _LOG["errors"].append(str(_exc))

# ── Shannon entropy ────────────────────────────────────────────────────────
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

# ── Emit harness log ───────────────────────────────────────────────────────
sys.stdout = _real_stdout
print("__HARNESS_LOG_BEGIN__")
print(json.dumps(_LOG))
print("__HARNESS_LOG_END__")
"""

# Maximum stdout to process (matches DockerSandboxExecutor.MAX_OUTPUT_BYTES)
_MAX_OUTPUT_BYTES = 1_048_576


def _make_tar(filename: str, data: bytes) -> bytes:
    """Build an in-memory TAR archive containing a single file *filename*."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name=filename)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class ContainerPool:
    """
    Pre-warmed pool of Docker containers for high-throughput Layer 3 scanning.

    Each container runs ``sleep infinity`` and accepts repeated script
    injections via ``put_archive()`` + ``exec_run()``.  A ``queue.Queue``
    provides thread-safe container acquisition and release.

    Usage::

        pool = ContainerPool(size=2)
        pool.start()
        try:
            trace = pool.run_in_pool(Path("tool.py"), manifest)
        finally:
            pool.shutdown()
    """

    IMAGE = "python:3.12-slim"
    TIMEOUT_S = 30
    MEM_LIMIT = "256m"
    CPU_QUOTA = 50_000

    def __init__(self, size: int = 2, image: str = IMAGE) -> None:
        self._size = size
        self._image = image
        self._pool_queue: queue.Queue[Any] = queue.Queue(maxsize=size)
        self._containers: list[Any] = []

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> None:
        """Pre-create and start *size* sandboxed containers."""
        import docker  # lazy import — only needed when --dynamic is passed

        client = docker.from_env()
        for _ in range(self._size):
            container = client.containers.create(
                image=self._image,
                command="sleep infinity",
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
            container.start()
            self._containers.append(container)
            self._pool_queue.put(container)
        logger.info("ContainerPool: %d containers started (%s)", self._size, self._image)

    def shutdown(self) -> None:
        """Stop and remove all pooled containers."""
        for container in self._containers:
            try:
                container.stop(timeout=5)
            except Exception:
                pass
            try:
                container.remove(force=True)
            except Exception:
                pass
        self._containers.clear()
        # Drain the queue so any waiting threads unblock
        while not self._pool_queue.empty():
            try:
                self._pool_queue.get_nowait()
            except queue.Empty:
                break
        logger.info("ContainerPool: all containers stopped and removed")

    # ── Public scan interface ──────────────────────────────────────────────

    def run_in_pool(
        self,
        script_or_path: Path | str,
        manifest: SkillManifest,
        timeout_s: int = TIMEOUT_S,
    ) -> ExecutionTrace:
        """
        Inject *script_or_path* into a pooled container and return an
        ExecutionTrace.  Blocks until a container is available.

        Args:
            script_or_path — either a Path to a .py file or a raw Python
                             string (agent simulation path).
            manifest       — SkillManifest (currently unused; reserved for
                             future permission-aware harness filtering).
            timeout_s      — hard timeout for exec_run (default 30 s).
        """
        from scanner.layer3_dynamic.docker_executor import DockerSandboxExecutor

        if isinstance(script_or_path, Path):
            source_name = script_or_path.name
            source_bytes = script_or_path.read_bytes()
        else:
            source_name = "agent_sim.py"
            source_bytes = script_or_path.encode("utf-8")

        harness_src = _POOL_HARNESS_TEMPLATE.replace("__FILENAME__", source_name)
        harness_bytes = harness_src.encode("utf-8")

        harness_tar = _make_tar("harness_wrapper.py", harness_bytes)
        source_tar = _make_tar(source_name, source_bytes)

        start_ms = int(time.monotonic() * 1000)
        container = self._pool_queue.get()  # blocks until a container is free
        timeout_killed = False
        exit_code = 0

        try:
            container.put_archive("/tmp", harness_tar)
            container.put_archive("/tmp", source_tar)

            def _exec() -> Any:
                return container.exec_run(
                    "python -B /tmp/harness_wrapper.py",
                    demux=True,
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(_exec)
                try:
                    result = fut.result(timeout=timeout_s)
                except concurrent.futures.TimeoutError:
                    timeout_killed = True
                    result = None

        finally:
            # Clean up injected files and release container back to pool
            try:
                container.exec_run(
                    f"rm -f /tmp/harness_wrapper.py /tmp/{source_name}",
                    demux=False,
                )
            except Exception:
                pass
            self._pool_queue.put(container)

        elapsed_ms = int(time.monotonic() * 1000) - start_ms

        if result is None or timeout_killed:
            return DockerSandboxExecutor._parse_harness_output(
                "", elapsed_ms, -1, False, True
            )

        # exec_run with demux=True → ExecResult(exit_code, (stdout, stderr))
        exit_code = result.exit_code or 0
        stdout_bytes = (result.output[0] or b"") if result.output else b""
        output_str = stdout_bytes[:_MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")

        return DockerSandboxExecutor._parse_harness_output(
            output_str, elapsed_ms, exit_code, False, False
        )
