# MCP Ecosystem Security Scan Report

**Date:** 2026-03-01  
**Source:** awesome-mcp-servers curated list  
**Repos attempted:** 400  
**Repos successfully scanned:** 390  
**L2 semantic analysis:** disabled (L1 only)  
**Total L2 tokens consumed:** 0  

## Overall Verdict Distribution

### By File

| Verdict | Count | Percentage |
|---------|-------|------------|
| BLOCK | 1428 | 14.1% |
| WARN | 209 | 2.1% |
| SAFE | 8495 | 83.8% |

### By Repository

| Verdict | Repos | Percentage |
|---------|-------|------------|
| BLOCK | 225 | 57.7% |
| WARN | 8 | 2.1% |
| SAFE | 157 | 40.3% |

**Files scanned:** 10132 (8308 Python + 1824 Markdown)  
**Tool endpoints found:** 344  

## Most Frequently Triggered Rules

| Rule ID | Hit Count | Repos Affected |
|---------|-----------|----------------|
| `PE-008` | 2196 | 132 |
| `EX-003` | 1202 | 85 |
| `PE-DELTA-001` | 1066 | 154 |
| `SC-008` | 624 | 28 |
| `SC-004` | 613 | 33 |
| `PE-003` | 484 | 50 |
| `PE-007` | 329 | 62 |
| `EX-001` | 321 | 39 |
| `PI-004` | 155 | 91 |
| `PE-005` | 115 | 19 |
| `SC-003` | 73 | 21 |
| `PI-009` | 31 | 2 |
| `PI-001` | 24 | 17 |
| `PI-005` | 23 | 14 |
| `PI-003` | 22 | 20 |
| `PE-004` | 19 | 7 |
| `PE-002` | 14 | 7 |
| `PE-009` | 6 | 1 |
| `PE-006` | 6 | 3 |
| `PI-002` | 4 | 4 |

## Flagged Repositories (WARN / BLOCK)

*233 of 390 repos had at least one WARN or BLOCK finding.*

### 🔴 BLOCK — [1mcp-app__agent](https://github.com/1mcp-app/agent)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CHANGELOG.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # changelog all notable changes to this proj |

### 🔴 BLOCK — [Aganium__agenium](https://github.com/Aganium/agenium)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | pattern_match; variant=raw; ecret-token docker compose up -d ``` ## api endpoint |

### 🔴 BLOCK — [askbudi__roundtable](https://github.com/askbudi/roundtable)

Python files: 43 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.975 | — | `EX-003`, `PE-008`, `PE-008`, `PE-005`, `PE-005`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` |  Examples:   python -m roundtable_mcp_server                    # Start MCP serv |
| `availability_checker.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(self.availability_file, 'w') as f: |
| `terminal_ui.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | return os.environ.get("DEBUG", "").lower() in ("1", "true", "yes") |
| `config.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | env_value = os.environ.get(env_name) |
| `env_vars.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | value = os.environ.get(key) |
| `git_ops.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | res = subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True) |
| `env_manager.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(env_path, 'w', encoding='utf-8') as f: |
| `claude_act.py` | python | **BLOCK** | 0.894 | — | `PE-008`, `EX-003`, `EX-003`, `EX-003`, `PE-008`, `PE-DELTA-001` | DEFAULT_MODEL = os.getenv("CLAUDE_CODE_MODEL", "claude-sonnet-4-20250514") |
| `local_runtime.py` | python | **BLOCK** | 0.993 | — | `PE-007`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | with open(install_hash_path, 'w') as f: |
| `filesystem.py` | python | **BLOCK** | 0.996 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | subprocess.run(["git", "init"], cwd=repo_path, check=True) |
| `assets.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(path, "wb") as f: |
| `qwen_cli.py` | python | **BLOCK** | 0.886 | — | `PE-008`, `PE-007`, `PE-008`, `PE-DELTA-001` | env_cmd = os.getenv("QWEN_CMD") |
| `codex_cli.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | enable_resume = str(os.getenv("CLAUDABLE_CODEX_RESUME", "")).lower() in ( |
| `cursor_agent.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | if os.getenv("CURSOR_API_KEY"): |
| `gemini_cli.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | self._per_call_mode = os.getenv("GEMINI_PER_CALL", "1") == "1" |

### 🔴 BLOCK — [Data-Everything__mcp-server-templates](https://github.com/Data-Everything/mcp-server-templates)

Python files: 58 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `runner.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | subprocess.run( |
| `mcp_test_utils.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, check=False) |
| `build_docs.py` | python | **BLOCK** | 0.991 | — | `EX-003`, `PE-007`, `PE-007`, `PE-007`, `PE-003`, `PE-007`, `PE-DELTA-001` | # MCP Server Templates  Welcome to the MCP Server Templates documentation! This  |
| `mcp_endpoint_manager.py` | python | **BLOCK** | 0.975 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` |  const { Client } = require('@modelcontextprotocol/sdk/client/index.js'); const  |
| `check_pypi_version.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(setup_file, "w", encoding="utf-8") as f: |
| `docker_probe.py` | python | **BLOCK** | 1.000 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `EX-001`, `PE-DELTA-001` | result = subprocess.run( |
| `base_probe.py` | python | **BLOCK** | 0.959 | — | `PE-008`, `PE-008`, `PE-008`, `PE-003`, `PE-008`, `PE-DELTA-001` | DISCOVERY_TIMEOUT = int(os.environ.get("MCP_DISCOVERY_TIMEOUT", "60")) |
| `kubernetes_probe.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `tool_manager.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `config_processor.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `cache.py` | python | **BLOCK** | 0.886 | — | `PE-008`, `PE-008`, `PE-007`, `PE-DELTA-001` | MCP_DEFAULT_CACHE_MAX_AGE_HOURS = os.getenv("MCP_DEFAULT_CACHE_MAX_AGE_HOURS", 2 |
| `template_manager.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `tool_caller.py` | python | **BLOCK** | 0.900 | — | `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.post(url, json=data, timeout=self.timeout) |
| `podman.py` | python | **BLOCK** | 0.977 | — | `PE-008`, `PE-003`, `PE-003`, `PE-008`, `PE-DELTA-001` | STDIO_TIMEOUT = os.getenv("MCP_STDIO_TIMEOUT", 30) |
| `docker.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-008`, `PE-003`, `PE-004`, `PE-003`, `PE-003`, `PE-DELTA-001` | STDIO_TIMEOUT = os.getenv("MCP_STDIO_TIMEOUT", 30) |
| `image_utils.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | registry = os.getenv("MCP_DEFAULT_REGISTRY", "docker.io") |
| `cli.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | "backend_type": os.getenv( |
| `interactive_cli.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | backend = os.getenv("MCP_BACKEND", "docker") |
| `creation.py` | python | **BLOCK** | 1.000 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` |  """  import logging import os import sys  from fastmcp import FastMCP  logging. |
| `discovery.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `server.py` | python | **BLOCK** | 0.968 | — | `SC-004`, `SC-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | 1 dependency entries without hash pinning |
| `config.py` | python | **BLOCK** | 0.947 | — | `SC-004`, `SC-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | 1 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.991 | — | `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008` | 4 dependency entries without hash pinning |
| `server.py` | python | **BLOCK** | 0.998 | — | `SC-004`, `SC-008`, `SC-008`, `SC-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | 5 dependency entries without hash pinning |
| `config.py` | python | **BLOCK** | 0.993 | — | `SC-004`, `SC-008`, `SC-008`, `SC-008`, `PE-008`, `PE-DELTA-001` | 5 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.973 | — | `SC-004`, `SC-008`, `SC-008`, `SC-008` | 5 dependency entries without hash pinning |
| `README.md` | markdown | **WARN** | 0.484 | — | `PI-002` | role_reassignment_template; variant=raw; # 🚀 this project has moved! > ## ⚠️ **i |

### 🔴 BLOCK — [duaraghav8__MCPJungle](https://github.com/duaraghav8/MCPJungle)

Python files: 0 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.998 | — | `PI-003`, `PI-004`, `PI-001` | Invisible codepoints: U+200D |

### 🔴 BLOCK — [hashgraph-online__hashnet-mcp-js](https://github.com/hashgraph-online/hashnet-mcp-js)

Python files: 0 | Markdown files: 4 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `chat.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # chat feature implementation notes ## what  |

### 🔴 BLOCK — [juspay__neurolink](https://github.com/juspay/neurolink)

Python files: 2 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CHANGELOG.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; ## [9.15.0](https://github.com/juspay/neurol |
| `visual-verification.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | BASE_URL = os.environ.get("DOCS_URL", "http://localhost:3000") |

### 🔴 BLOCK — [K-Dense-AI__claude-skills-mcp](https://github.com/K-Dense-AI/claude-skills-mcp)

Python files: 16 | Markdown files: 10 | Tools: 6  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `sync-version.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `__main__.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | subprocess.run( |
| `backend_manager.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(["uvx", "--help"], capture_output=True, timeout=5) |
| `state_manager.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(self.state_file, "w") as f: |
| `config.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `skill_loader.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(cache_path, "w") as f: |
| `mcp_proxy.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | Path or pattern to match documents. Examples: 'scripts/example.py', 'scripts/*.p |
| `mcp_handlers.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | Path or pattern to match documents. Examples: 'scripts/example.py', 'scripts/*.p |

### 🔴 BLOCK — [merterbak__Grok-MCP](https://github.com/merterbak/Grok-MCP)

Python files: 4 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # grok-mcp mcp server for xai's grok api wit |
| `main.py` | python | **BLOCK** | 0.921 | — | `PI-004`, `PE-008`, `PE-DELTA-001` | secret_exfil_template; variant=raw; # grok-mcp mcp server for xai's grok api wit |
| `utils.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | XAI_API_KEY = os.getenv("XAI_API_KEY", "") |

### 🔴 BLOCK — [metatool-ai__metatool-app](https://github.com/metatool-ai/metatool-app)

Python files: 0 | Markdown files: 9 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README-oauth.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | pattern_match; variant=raw; />?code=...&state=... user->>client: authorization c |

### 🔴 BLOCK — [mindsdb__mindsdb](https://github.com/mindsdb/mindsdb)

Python files: 1374 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `setup.py` | python | **BLOCK** | 0.891 | — | `PE-002`, `PE-DELTA-001` | exec(fp.read(), about) |
| `__main__.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | if os.environ.get("ARROW_DEFAULT_MEMORY_POOL") is None: |
| `executor_test_base.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(cfg_file, "w") as fd: |
| `check_handler_coverage.py` | python | **BLOCK** | 0.947 | — | `PE-003`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | return subprocess.run(cmd, **kwargs) |
| `check_print_statements.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `check_requirements.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `http_test_helpers.py` | python | **BLOCK** | 0.900 | — | `EX-001`, `EX-001`, `PE-DELTA-001` | res = requests.get(f"{HTTP_API_ROOT}/predictors/", headers=headers) |
| `config.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | MINDSDB_PROTOCOL: str = os.getenv("MINDSDB_PROTOCOL", "http") |
| `metrics.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if os.environ.get('PROMETHEUS_MULTIPROC_DIR', None) is None: |
| `server.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | prometheus_dir = os.environ.get('PROMETHEUS_MULTIPROC_DIR', None) |
| `functions.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | container_id = os.environ.get("HOSTNAME", "<container_id>") |
| `auth.py` | python | **BLOCK** | 0.946 | — | `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | aws_token = requests.put("http://169.254.169.254/latest/api/token", headers={'X- |
| `wizards.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(file_path, 'wb') as f: |
| `config.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | use_docker_env: bool = os.environ.get("MINDSDB_DOCKER_ENV", False) is not False |
| `log.py` | python | **BLOCK** | 1.000 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `partitioning.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | max_threads = int(os.getenv('MINDSDB_MAX_PARTITIONING_THREADS', 10)) |
| `langfuse.py` | python | **BLOCK** | 0.975 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | LANGFUSE_PUBLIC_KEY = os.getenv("LANGFUSE_PUBLIC_KEY", "langfuse_public_key") |
| `cache.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(path, "wb") as fd: |
| `api_status.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(temp_file, "w") as f: |
| `fs.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | if os.environ.get("USE_PIDFILE") != "1": |
| `sentry.py` | python | **BLOCK** | 0.945 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | SENTRY_IO_DSN = os.environ.get("SENTRY_IO_DSN", "") |
| `2021-11-30_17c3d2384711_init.py` | python | **BLOCK** | 0.680 | — | `PE-002` | exec(code) |
| `api_handler_generator.py` | python | **BLOCK** | 0.900 | — | `EX-001`, `EX-001`, `PE-DELTA-001` | req = requests.request(self.endpoint.method, url, params=query, data=body, **kwa |
| `storage_handler.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | self.config = config if config else os.getenv('MDB_STORAGE_HANDLER_CONFIG') |
| `handler_utils.py` | python | **BLOCK** | 0.869 | — | `PE-008`, `PE-008`, `EX-003`, `EX-003`, `PE-DELTA-001` | api_key = os.getenv(f"{api_name.lower()}_api_key") |
| `install.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | sp = subprocess.Popen( |
| `settings.py` | python | **BLOCK** | 0.857 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` |  Below is a json representation of a table with information about {description}. |
| `file_reader.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `base_reranker.py` | python | **BLOCK** | 0.903 | — | `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | You are an expert reranker. Given a user query and a list of candidate documents |
| `document_loaders.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `ms_graph_api_utilities.py` | python | **BLOCK** | 0.946 | — | `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get(api_url, headers=headers, params=params) |
| `google_service_account_oauth_utilities.py` | python | **BLOCK** | 0.849 | — | `SC-004`, `EX-001`, `PE-DELTA-001` | 2 dependency entries without hash pinning |
| `google_user_oauth_utilities.py` | python | **BLOCK** | 0.849 | — | `SC-004`, `EX-001`, `PE-DELTA-001` | 2 dependency entries without hash pinning |
| `cohere_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `serpstack_tables.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | api_response = requests.get(base_url, params=params) |
| `serpstack_handler.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | api_request = requests.get(url) |
| `coinbase_handler.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get(url, headers=headers) |
| `lindorm_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `discord_tables.py` | python | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; nt` privileged intent the `send messages` permission |
| `__init__.py` | python | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; nt` privileged intent the `send messages` permission |
| `__about__.py` | python | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; nt` privileged intent the `send messages` permission |
| `discord_handler.py` | python | **BLOCK** | 0.984 | — | `PI-004`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | pattern_match; variant=raw; nt` privileged intent the `send messages` permission |
| `influxdb_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `influxdb_tables.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `sendinblue_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `sendinblue_tables.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `api.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | return requests.request(**kwargs) |
| `frappe_client.py` | python | **BLOCK** | 0.984 | — | `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | document_response = requests.get( |
| `oilpriceapi.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | resp = requests.get(url, headers=headers, params=params) |
| `openbb_handler.py` | python | **BLOCK** | 0.715 | — | `SC-004`, `SC-003` | 2 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.715 | — | `SC-004`, `SC-003` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.715 | — | `SC-004`, `SC-003` | 2 dependency entries without hash pinning |
| `openbb_tables.py` | python | **BLOCK** | 0.905 | — | `SC-004`, `SC-003`, `PE-001` | 2 dependency entries without hash pinning |
| `huggingface_handler.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 6 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 6 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 6 dependency entries without hash pinning |
| `settings.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 6 dependency entries without hash pinning |
| `finetune.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 6 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `couchbase_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `connection_args.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `strava_tables.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `strava_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `redshift_handler.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `dropbox_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `connection_args.py` | python | **BLOCK** | 0.789 | — | `SC-004`, `SC-008`, `EX-003` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `zotero_handler.py` | python | **BLOCK** | 0.785 | — | `SC-004`, `PE-008`, `PE-DELTA-001` | 1 dependency entries without hash pinning |
| `tdengine_handler.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 3 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 3 dependency entries without hash pinning |
| `connection_args.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 3 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 3 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `exceptions.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `huggingface_api_handler.py` | python | **BLOCK** | 0.911 | — | `SC-004`, `SC-008`, `PE-DELTA-001` | 3 dependency entries without hash pinning |
| `google_analytics_handler.py` | python | **BLOCK** | 0.721 | — | `SC-004`, `PE-DELTA-001` | 3 dependency entries without hash pinning |
| `faiss_index.py` | python | **BLOCK** | 0.721 | — | `SC-004`, `PE-DELTA-001` | 2 dependency entries without hash pinning |
| `google_books_handler.py` | python | **BLOCK** | 0.843 | — | `SC-004`, `PE-007`, `PE-DELTA-001` | 2 dependency entries without hash pinning |
| `ray_serve_handler.py` | python | **BLOCK** | 0.971 | — | `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | resp = requests.post(args['predict_url'], |
| `__init__.py` | python | **BLOCK** | 0.918 | — | `PI-004`, `SC-004`, `SC-008` | secret_exfil_template; variant=raw; # matrixone handler this is the implementati |
| `connection_args.py` | python | **BLOCK** | 0.918 | — | `PI-004`, `SC-004`, `SC-008` | secret_exfil_template; variant=raw; # matrixone handler this is the implementati |
| `__about__.py` | python | **BLOCK** | 0.918 | — | `PI-004`, `SC-004`, `SC-008` | secret_exfil_template; variant=raw; # matrixone handler this is the implementati |
| `matrixone_handler.py` | python | **BLOCK** | 0.918 | — | `PI-004`, `SC-004`, `SC-008` | secret_exfil_template; variant=raw; # matrixone handler this is the implementati |
| `elasticsearch_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `connection_args.py` | python | **BLOCK** | 0.789 | — | `SC-004`, `SC-008`, `EX-003` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `google_fit_handler.py` | python | **BLOCK** | 0.912 | — | `SC-004`, `PE-007`, `PE-007`, `PE-DELTA-001` | 6 dependency entries without hash pinning |
| `pirateweather_handler.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get(query) |
| `aqicn.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | resp = requests.get(url, params=newParams) |
| `financial_modeling_tables.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get(url, param) |
| `financial_modeling_handler.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get(base_url, param) |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `ms_teams_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `ms_graph_api_teams_client.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `ms_teams_tables.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `airtable_handler.py` | python | **BLOCK** | 0.900 | — | `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get(url, headers=headers) |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `crate_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `twitter_handler.py` | python | **BLOCK** | 0.952 | — | `SC-004`, `SC-008`, `EX-001`, `PE-DELTA-001` | 1 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `snowflake_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `auth_types.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `connection_args.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `tripadvisor_api.py` | python | **BLOCK** | 0.969 | — | `PI-004`, `EX-001`, `EX-001`, `PE-DELTA-001` | secret_exfil_template; variant=raw; # tripadvisor handler #5369 custom python wr |
| `__init__.py` | python | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # tripadvisor handler #5369 custom python wr |
| `tripadvisor_table.py` | python | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # tripadvisor handler #5369 custom python wr |
| `__about__.py` | python | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # tripadvisor handler #5369 custom python wr |
| `tripadvisor_handler.py` | python | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # tripadvisor handler #5369 custom python wr |
| `intercom_handler.py` | python | **BLOCK** | 0.900 | — | `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.request(method.upper(), url, headers=self._headers, params=p |
| `strapi_handler.py` | python | **BLOCK** | 0.946 | — | `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get(f"{self._base_url}", headers=headers) |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 5 dependency entries without hash pinning |
| `connection_args.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 5 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 5 dependency entries without hash pinning |
| `gcs_handler.py` | python | **BLOCK** | 0.911 | — | `SC-004`, `SC-008`, `PE-DELTA-001` | 5 dependency entries without hash pinning |
| `gcs_tables.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 5 dependency entries without hash pinning |
| `api.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | return requests.request(**kwargs) |
| `rocket_chat_tables.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `rocket_chat_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `dremio_handler.py` | python | **BLOCK** | 0.987 | — | `SC-004`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | 1 dependency entries without hash pinning |
| `instatus_handler.py` | python | **BLOCK** | 0.900 | — | `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.request(method, url, headers=headers, params=params, json=js |
| `__init__.py` | python | **BLOCK** | 0.744 | — | `PI-004`, `SC-004` | secret_exfil_template; variant=raw; # whatsapp handler whatsapp handler for mind |
| `whatsapp_handler.py` | python | **BLOCK** | 0.744 | — | `PI-004`, `SC-004` | secret_exfil_template; variant=raw; # whatsapp handler whatsapp handler for mind |
| `__about__.py` | python | **BLOCK** | 0.744 | — | `PI-004`, `SC-004` | secret_exfil_template; variant=raw; # whatsapp handler whatsapp handler for mind |
| `api.py` | python | **BLOCK** | 0.991 | — | `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | payload = requests.get(endpoint, params=params).json()["data"] |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `google_gemini_handler.py` | python | **BLOCK** | 0.963 | — | `SC-004`, `SC-008`, `PE-008`, `EX-001`, `PE-DELTA-001` | 2 dependency entries without hash pinning |
| `vertex_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `vertex_client.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `mlflow_handler.py` | python | **BLOCK** | 0.992 | — | `SC-004`, `SC-008`, `SC-008`, `EX-001`, `EX-001`, `PE-DELTA-001` | 2 dependency entries without hash pinning |
| `hn_handler.py` | python | **BLOCK** | 0.984 | — | `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get(url) |
| `eventstoredb_handler.py` | python | **BLOCK** | 0.991 | — | `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get(stream_endpoint, params=params, headers=self.headers, ve |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `connection_args.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `solr_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `shopify_handler.py` | python | **BLOCK** | 0.849 | — | `SC-004`, `EX-001`, `PE-DELTA-001` | 1 dependency entries without hash pinning |
| `zipcodebase.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | resp = requests.get(url, headers=headers, params=params) |
| `scylla_handler.py` | python | **BLOCK** | 0.849 | — | `SC-004`, `EX-001`, `PE-DELTA-001` | 1 dependency entries without hash pinning |
| `utils.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.request( |
| `qdrant_handler.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `connection_args.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `proc_wrapper.py` | python | **BLOCK** | 0.995 | — | `SC-004`, `SC-008`, `PE-009`, `PE-002`, `PE-007`, `PE-DELTA-001` | 2 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `connection_args.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `byom_handler.py` | python | **BLOCK** | 1.000 | — | `SC-004`, `SC-008`, `PE-008`, `PE-009`, `PE-009`, `PE-003`, `PE-009`, `PE-003`, `PE-003`, `PE-008`, `PE-007`, `PE-008`, `PE-DELTA-001` | 2 dependency entries without hash pinning |
| `pgvector_handler.py` | python | **BLOCK** | 0.887 | — | `SC-004`, `EX-003`, `PE-008`, `EX-003`, `EX-003`, `PE-DELTA-001` | 1 dependency entries without hash pinning |
| `pinot_handler.py` | python | **BLOCK** | 0.976 | — | `SC-004`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | 1 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `connection_args.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `couchbasevector_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |
| `openai_handler.py` | python | **BLOCK** | 0.974 | — | `SC-004`, `PE-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | 1 dependency entries without hash pinning |
| `groq_handler.py` | python | **BLOCK** | 0.834 | — | `SC-004`, `PE-008`, `PE-008`, `PE-DELTA-001` | 1 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `connection_args.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `cloud_spanner_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |
| `gmail_handler.py` | python | **BLOCK** | 0.843 | — | `SC-004`, `PE-007`, `PE-DELTA-001` | 1 dependency entries without hash pinning |
| `google_search_tables.py` | python | **BLOCK** | 0.973 | — | `SC-004`, `SC-008`, `SC-008`, `SC-008` | 5 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.973 | — | `SC-004`, `SC-008`, `SC-008`, `SC-008` | 5 dependency entries without hash pinning |
| `connection_args.py` | python | **BLOCK** | 0.973 | — | `SC-004`, `SC-008`, `SC-008`, `SC-008` | 5 dependency entries without hash pinning |
| `google_search_handler.py` | python | **BLOCK** | 0.973 | — | `SC-004`, `SC-008`, `SC-008`, `SC-008` | 5 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.973 | — | `SC-004`, `SC-008`, `SC-008`, `SC-008` | 5 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.699 | — | `PI-001` | override_authority_template; variant=raw; --- title: ollama sidebartitle: ollama |
| `ollama_handler.py` | python | **BLOCK** | 0.995 | — | `PI-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | override_authority_template; variant=raw; --- title: ollama sidebartitle: ollama |
| `__about__.py` | python | **BLOCK** | 0.699 | — | `PI-001` | override_authority_template; variant=raw; --- title: ollama sidebartitle: ollama |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `utils.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `plaid_tables.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `plaid_handler.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 2 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `connection_args.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `azure_blob_handler.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `__about__.py` | python | **BLOCK** | 0.916 | — | `SC-004`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `api.py` | python | **BLOCK** | 0.900 | — | `EX-001`, `EX-001`, `PE-DELTA-001` | resp = requests.get("https://api.npms.io/v2/package/" + package_name) |
| `utils.py` | python | **BLOCK** | 0.668 | — | `PE-009` | return pickle.loads(b) |
| `__init__.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | OTEL_SDK_FORCE_RUN = os.getenv("OTEL_SDK_FORCE_RUN", "false").lower() == "true" |
| `prepare.py` | python | **BLOCK** | 0.993 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | OTEL_EXPORTER_TYPE = os.getenv("OTEL_EXPORTER_TYPE", "console")  # console or ot |
| `profiling.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | MINDSDB_PROFILING_DB_HOST = os.environ.get("MINDSDB_PROFILING_DB_HOST") |
| `agent.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.post(self.sql_url, json={"query": sql_query}, headers=self.h |
| `__init__.py` | python | **BLOCK** | 0.789 | — | `EX-003`, `PE-008`, `PE-DELTA-001` |     Executes a SQL query against MindsDB.      A database must be specified eith |
| `middleware.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | SECRET_KEY = os.environ.get("AUTH_SECRET_KEY") or secrets.token_urlsafe(32) |
| `initialize.py` | python | **BLOCK** | 0.858 | — | `EX-001`, `PE-008`, `PE-DELTA-001` | res = requests.get( |
| `gui.py` | python | **BLOCK** | 0.942 | — | `EX-001`, `PE-007`, `PE-007`, `PE-DELTA-001` | response = requests.get(resource["url"]) |
| `auth.py` | python | **BLOCK** | 0.946 | — | `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get( |
| `handlers.py` | python | **BLOCK** | 0.876 | — | `EX-003`, `EX-003`, `PE-007`, `PE-DELTA-001` | BYOM is disabled on this server. To enable this feature, set the environment var |
| `agents.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | "openai_api_key", os.getenv("OPENAI_API_KEY") |
| `file.py` | python | **BLOCK** | 0.896 | — | `EX-001`, `PE-007`, `PE-DELTA-001` | with requests.get(url, stream=True) as r: |
| `functions.py` | python | **BLOCK** | 0.896 | — | `EX-001`, `PE-007`, `PE-DELTA-001` | response = requests.get(url) |
| `integrations.py` | python | **BLOCK** | 0.802 | — | `PE-005`, `PE-DELTA-001` | handler_module = importlib.import_module(f"{base_import}{handler_folder_name}") |
| `context_controller.py` | python | **BLOCK** | 0.668 | — | `PE-009` | steps_data = pickle.loads(data) |
| `db.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | data = Column(SecretDataJson(os.environ.get("MINDSDB_DATA_ENCRYPTION_TYPE", "non |
| `fs.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(dest_abs_path, "wb") as fd: |
| `to_markdown.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get(file_path_or_url) |
| `controller.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | cloud_pg_vector = os.environ.get("KB_PGVECTOR_URL") |
| `llm_client.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | azure_api_key = params.get("api_key") or os.getenv("AZURE_OPENAI_API_KEY") |
| `constants.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | MAX_INSERT_BATCH_SIZE = int(os.getenv("KB_MAX_INSERT_BATCH_SIZE", 50_000)) |
| `helpers.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | SELECT NAME, IMPORT_SUCCESS FROM information_schema.handlers WHERE type = 'data' |
| `process_cache.py` | python | **WARN** | 0.417 | — | `PE-005` | importlib.import_module(module_path) |
| `func_call_process.py` | python | **WARN** | 0.417 | — | `PE-005` | module = importlib.import_module(module_path) |
| `learn_process.py` | python | **WARN** | 0.417 | — | `PE-005` | module = importlib.import_module(module_path) |
| `update_engine_process.py` | python | **WARN** | 0.417 | — | `PE-005` | module = importlib.import_module(module_path) |
| `create_validation_process.py` | python | **WARN** | 0.417 | — | `PE-005` | module = importlib.import_module(module_path) |
| `update_process.py` | python | **WARN** | 0.417 | — | `PE-005` | module = importlib.import_module(module_path) |
| `predict_process.py` | python | **WARN** | 0.417 | — | `PE-005` | module = importlib.import_module(module_path) |
| `describe_process.py` | python | **WARN** | 0.417 | — | `PE-005` | module = importlib.import_module(module_path) |
| `create_engine_process.py` | python | **WARN** | 0.417 | — | `PE-005` | module = importlib.import_module(module_path) |
| `connection_args.py` | python | **WARN** | 0.467 | — | `SC-004`, `EX-003`, `EX-003` | 3 dependency entries without hash pinning |
| `yugabyte_handler.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | (OPTIONAL) comma seperated value of schema to be considered while querying |
| `prompts.py` | python | **WARN** | 0.660 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` |  MindsDB SQL is mostly compatible with MySQL and DuckDB syntax.  - ONLY use tabl |

### 🔴 BLOCK — [oxgeneral__agentnet](https://github.com/oxgeneral/agentnet)

Python files: 5 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server_http.py` | python | **BLOCK** | 0.971 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `server.py` | python | **BLOCK** | 0.971 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `registry.py` | python | **BLOCK** | 0.992 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | 2 dependency entries without hash pinning |
| `api.py` | python | **BLOCK** | 0.971 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `seed.py` | python | **BLOCK** | 0.971 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |

### 🔴 BLOCK — [particlefuture__1mcpserver](https://github.com/particlefuture/1mcpserver)

Python files: 8 | Markdown files: 5 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `mcp_servers.md` | markdown | **BLOCK** | 0.953 | — | `PI-002`, `PI-004`, `PI-001` | pattern_match; variant=raw; server to enable a human-in-the-loop workflow in too |
| `server.py` | python | **BLOCK** | 0.899 | — | `PE-008`, `EX-003`, `PE-008`, `EX-003`, `PE-008`, `PE-DELTA-001` | token = os.getenv("GITHUB_TOKEN", None) |
| `config.py` | python | **BLOCK** | 0.789 | — | `EX-003`, `PE-008`, `PE-DELTA-001` | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) |
| `server_list_sources.py` | python | **BLOCK** | 0.946 | — | `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get(repo_url, headers=HEADER) |
| `maintain.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get(url, headers=HEADER, timeout=10) |
| `server_landing_page.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | mcp.run(transport="streamable-http", host="0.0.0.0", port=int(os.getenv("PORT",  |
| `scrape.py` | python | **BLOCK** | 0.982 | — | `PE-008`, `PE-007`, `EX-001`, `EX-001`, `PE-008`, `EX-001`, `PE-DELTA-001` | BASE_DIR = os.getenv("DATADIR", "db") |

### 🔴 BLOCK — [portel-dev__ncp](https://github.com/portel-dev/ncp)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CHANGELOG.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # changelog ## [2.0.1](https://github.com/po |
| `CLAUDE.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; *: - detects malicious intent patterns: - data exfil |
| `README.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D |

### 🔴 BLOCK — [profullstack__mcp-server](https://github.com/profullstack/mcp-server)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # backlinks automation module an advanced mc |

### 🔴 BLOCK — [rupinder2__mcp-orchestrator](https://github.com/rupinder2/mcp-orchestrator)

Python files: 16 | Markdown files: 7 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `config_loader.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `main.py` | python | **BLOCK** | 0.985 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | storage_backend=os.getenv("STORAGE_BACKEND", "memory"), |

### 🔴 BLOCK — [sitbon__magg](https://github.com/sitbon/magg)

Python files: 62 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `authentication.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # magg authentication guide this guide cover |
| `auth.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(ssh_public_path, 'wb') as f: |
| `settings.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | return os.environ.get('MAGG_PRIVATE_KEY') |
| `process.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if not os.environ.get("NO_TERM", False): |
| `embedding.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | sys.stderr = open(os.devnull, 'w') |
| `config_reload.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(config_path, "w") as f: |
| `authentication.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | jwt = os.environ.get(args.env_var) |
| `fix_whitespace.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(filepath, 'w', encoding='utf-8') as f: |
| `terminal.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if os.environ.get("NO_RICH", "").lower() in ("1", "true", "yes"): |
| `catalog.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(self.catalog_path, 'w') as f: |
| `metadata.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `manager.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | log_level = log_level or os.getenv("FASTMCP_LOG_LEVEL", "CRITICAL").upper() or " |
| `defaults.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | "level": (os.getenv("MAGG_LOG_LEVEL") or "INFO").upper(), |
| `client.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | jwt = os.getenv("MAGG_JWT", os.getenv("MBRO_JWT", os.getenv("MCP_JWT", None))) |
| `arepl.py` | python | **BLOCK** | 0.979 | — | `PE-008`, `PE-008`, `PE-002`, `PE-002`, `PE-DELTA-001` | if os.getenv('PYTHON_BASIC_REPL'): |
| `server.py` | python | **WARN** | 0.579 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003` |   Please determine the following configuration: 1. name: A string, potentially u |
| `defaults.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` |  Magg (MCP Aggregator) manages and aggregates other MCP servers.  Key capabiliti |

### 🔴 BLOCK — [SureScaleAI__openai-gpt-image-mcp](https://github.com/SureScaleAI/openai-gpt-image-mcp)

Python files: 0 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D |

### 🔴 BLOCK — [sxhxliang__mcp-access-point](https://github.com/sxhxliang/mcp-access-point)

Python files: 1 | Markdown files: 5 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; 180 upstreams: # required upstream configuration - i |

### 🔴 BLOCK — [TheLunarCompany__lunar](https://github.com/TheLunarCompany/lunar)

Python files: 57 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CONTRIBUTING.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D |
| `lunar_selective_addon.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | self.lunar_api_key = os.environ.get("LUNAR_API_KEY", "") |
| `policies_reload.py` | python | **BLOCK** | 0.988 | — | `PE-004`, `PE-004`, `PE-004`, `PE-DELTA-001` | assert os.system("docker exec lunar-proxy apply_policies") == 0 |
| `flow.py` | python | **BLOCK** | 0.964 | — | `PE-004`, `PE-004`, `PE-DELTA-001` | assert os.system("docker exec lunar-proxy load_flows") == 0 |
| `discovered_endpoint_metrics.py` | python | **BLOCK** | 0.668 | — | `PE-001` | return eval(text) |
| `main.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 3 dependency entries without hash pinning |

### 🔴 BLOCK — [tigranbs__mcgravity](https://github.com/tigranbs/mcgravity)

Python files: 0 | Markdown files: 6 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # mcgravity <div align="center"> <img src="h |
| `architecture.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # mcgravity architecture this document descr |

### 🔴 BLOCK — [VeriTeknik__pluggedin-mcp-proxy](https://github.com/VeriTeknik/pluggedin-mcp-proxy)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # plugged.in mcp hub — proxy · knowledge · m |
| `RELEASE_NOTES_v1.0.0.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # release notes - v1.0.0 released: june 19,  |

### 🔴 BLOCK — [ViperJuice__mcp-gateway](https://github.com/ViperJuice/mcp-gateway)

Python files: 46 | Markdown files: 8 | Tools: 11  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # pmcp - progressive mcp <!-- mcp-name: io.g |
| `server.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if not os.environ.get(server.env_var): |
| `cli.py` | python | **BLOCK** | 0.976 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-007`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | if os.environ.get("PMCP_LOG_LEVEL"): |
| `identity.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | fd = open(_LOCK_FILE, "w") |
| `handlers.py` | python | **BLOCK** | 0.874 | — | `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | Request ID in format "server_name::local_id" from gateway.list_pending |
| `loader.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | env_path = os.environ.get("PMCP_CONFIG") |
| `guidance.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(output_path, "w") as f: |
| `code_patterns_loader.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `installer.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if not os.environ.get(env_var): |
| `loader.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `environment.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | path=os.environ.get("PATH", ""), |
| `refresher.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(cache_path, "w") as f: |
| `code_snippets_loader.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `config.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `manager.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `inlinedbaml.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | // BAML Function for matching capability requests to manifest entries // Returns |

### 🔴 BLOCK — [YangLiangwei__PersonalizationMCP](https://github.com/YangLiangwei/PersonalizationMCP)

Python files: 21 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 1.000 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | 47 dependency entries without hash pinning |
| `steam_mcp.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `EX-001`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | STEAM_API_KEY = os.getenv("STEAM_API_KEY") |
| `bilibili_mcp.py` | python | **BLOCK** | 0.925 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `EX-003`, `PE-DELTA-001` | sessdata = os.getenv("BILIBILI_SESSDATA") |
| `spotify_token_manager.py` | python | **BLOCK** | 0.886 | — | `PE-008`, `PE-008`, `PE-007`, `PE-DELTA-001` | self.client_id = os.getenv("SPOTIFY_CLIENT_ID") |
| `spotify_mcp.py` | python | **BLOCK** | 0.957 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | SPOTIFY_CLIENT_ID = os.getenv("SPOTIFY_CLIENT_ID") |
| `spotify_oauth_helper.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | self.redirect_uri = redirect_uri or os.getenv("SPOTIFY_REDIRECT_URI", "http://lo |
| `auto_refresh_youtube_token.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open('youtube_tokens.json', 'w') as f: |
| `youtube_mcp.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-008`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `EX-003`, `PE-008`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-007`, `PE-005`, `PE-DELTA-001` | YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY") |
| `youtube_oauth_helper.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(tokens_file, 'w') as f: |
| `youtube_token_manager.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(self.tokens_file, 'w') as f: |
| `platforms_config.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | config[var.lower()] = os.getenv(var) |
| `reddit_mcp.py` | python | **BLOCK** | 0.945 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | client_id = os.getenv("REDDIT_CLIENT_ID") |
| `reddit_token_manager.py` | python | **BLOCK** | 0.912 | — | `PE-007`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | with open(self.token_file, "w") as f: |

### 🔴 BLOCK — [8enSmith__mcp-open-library](https://github.com/8enSmith/mcp-open-library)

Python files: 0 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # mcp open library [![trust score](https://a |

### 🔴 BLOCK — [abhiemj__manim-mcp-server](https://github.com/abhiemj/manim-mcp-server)

Python files: 1 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `manim_server.py` | python | **BLOCK** | 0.950 | — | `PE-008`, `PE-003`, `PE-007`, `PE-DELTA-001` | MANIM_EXECUTABLE = os.getenv("MANIM_EXECUTABLE", "manim")   #MANIM_PATH "/Users/ |

### 🔴 BLOCK — [ahujasid__blender-mcp](https://github.com/ahujasid/blender-mcp)

Python files: 6 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `addon.py` | python | **BLOCK** | 1.000 | — | `EX-003`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-002`, `EX-001`, `PE-007`, `PE-007`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-007`, `EX-001`, `EX-001`, `PE-007`, `PE-DELTA-001` | k9TcfFoEhNd9cCPP2guHAHHHkctZHIRhZDywZ1euGUXwihbYLpOjQhofby80NJez |
| `server.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | host = os.getenv("BLENDER_HOST", DEFAULT_HOST) |
| `telemetry.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | base_dir = Path(os.environ.get('APPDATA', Path.home() / 'AppData' / 'Roaming')) |

### 🔴 BLOCK — [asmith26__jupytercad-mcp](https://github.com/asmith26/jupytercad-mcp)

Python files: 3 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |

### 🔴 BLOCK — [jupytercad__JupyterCAD](https://github.com/jupytercad/JupyterCAD)

Python files: 35 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `build_packages.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | subprocess.run(cmd.split(" "), check=True, cwd=cwd) |
| `dev-install.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | subprocess.run(cmd.split(" "), check=True, cwd=cwd, env=dict(**env_copy, **env)) |
| `cad_document.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(path, "w") as f: |
| `bump-version.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(ROOT / "pyproject.toml", "w") as f: |
| `handlers.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(Path(file_name).parents[0] / export_name, "w") as fobj: |
| `bump-version.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(ROOT / "pyproject.toml", "w") as f: |
| `conf.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | on_rtd = os.environ.get("READTHEDOCS", None) == "True" |
| `CHANGELOG.md` | markdown | **WARN** | 0.420 | — | `PI-005` | pattern_match; variant=raw; elog](https://github.com/jupytercad/jupytercad/compa |
| `setup.py` | python | **WARN** | 0.417 | — | `PE-005` | __import__("setuptools").setup() |
| `setup.py` | python | **WARN** | 0.417 | — | `PE-005` | __import__("setuptools").setup() |
| `setup.py` | python | **WARN** | 0.417 | — | `PE-005` | __import__("setuptools").setup() |
| `setup.py` | python | **WARN** | 0.417 | — | `PE-005` | __import__("setuptools").setup() |
| `setup.py` | python | **WARN** | 0.417 | — | `PE-005` | __import__("setuptools").setup() |

### 🔴 BLOCK — [burningion__video-editing-mcp](https://github.com/burningion/video-editing-mcp)

Python files: 7 | Markdown files: 2 | Tools: 21  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `run_manim.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | process = subprocess.Popen( |
| `server.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-001`, `PE-003`, `PE-007`, `PE-008`, `PE-003`, `PE-007`, `PE-DELTA-001` | if os.environ.get("VJ_API_KEY"): |
| `generate_charts.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `generate_opentimeline.py` | python | **BLOCK** | 0.920 | — | `PE-008`, `EX-001`, `PE-007`, `PE-DELTA-001` | vj = ApiClient(os.environ.get("VJ_API_KEY")) |

### 🔴 BLOCK — [ConstantineB6__comfy-pilot](https://github.com/ConstantineB6/comfy-pilot)

Python files: 2 | Markdown files: 6 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `NODE_TEMPLATE.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # comfyui custom node development guide ## f |
| `OFFICIAL_DOCS.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # official comfyui documentation source: [do |
| `__init__.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-007`, `PE-003`, `PE-007`, `PE-DELTA-001` | shell = os.environ.get("SHELL", "/bin/bash") |
| `mcp_server.py` | python | **BLOCK** | 1.000 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-003`, `EX-003`, `EX-001`, `PE-007`, `EX-001`, `PE-DELTA-001` | subprocess.run( |

### 🔴 BLOCK — [diivi__aseprite-mcp](https://github.com/diivi/aseprite-mcp)

Python files: 8 | Markdown files: 4 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `commands.py` | python | **BLOCK** | 0.911 | — | `PE-003`, `PE-008`, `PE-DELTA-001` | result = subprocess.run(cmd, check=True, capture_output=True, text=True) |

### 🔴 BLOCK — [GenWaveLLC__svgmaker-mcp](https://github.com/GenWaveLLC/svgmaker-mcp)

Python files: 0 | Markdown files: 8 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # svgmaker mcp server a powerful mcp server  |

### 🔴 BLOCK — [khglynn__spotify-bulk-actions-mcp](https://github.com/khglynn/spotify-bulk-actions-mcp)

Python files: 11 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `setup_auth.py` | python | **BLOCK** | 0.995 | — | `SC-004`, `SC-008`, `SC-008`, `SC-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | 6 dependency entries without hash pinning |
| `auth.py` | python | **BLOCK** | 0.928 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | client_id = os.getenv("SPOTIFY_CLIENT_ID") |
| `cache.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(cache_file, "w") as f: |

### 🔴 BLOCK — [molanojustin__smithsonian-mcp](https://github.com/molanojustin/smithsonian-mcp)

Python files: 29 | Markdown files: 6 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `museum_data.py` | python | **BLOCK** | 1.000 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | alexander. 1920. bulletin of the american museum of natural history. 43 art. 2 ( |
| `verify-setup.py` | python | **BLOCK** | 0.999 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-005`, `PE-008`, `PE-DELTA-001` | result = subprocess.run( |
| `collect_museum_object_types.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(output_file, "w") as f: |
| `comprehensive_object_type_search.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open("comprehensive_search_results.py", "w") as f: |
| `discover_museum_types.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(file_path, 'w') as f: |
| `targeted_additional_search.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open("updated_museum_types.py", "w") as f: |
| `prompts.py` | python | **WARN** | 0.660 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` |  objects. Please:   1. Search for relevant objects across different Smithsonian  |

### 🔴 BLOCK — [omni-mcp__isaac-sim-mcp](https://github.com/omni-mcp/isaac-sim-mcp)

Python files: 12 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `add_license_headers.py` | python | **BLOCK** | 0.846 | — | `EX-003`, `PE-007`, `PE-DELTA-001` | """ MIT License  Copyright (c) 2023-2025 omni-mcp  Permission is hereby granted, |
| `usd.py` | python | **BLOCK** | 0.890 | — | `PE-008`, `EX-001`, `PE-008`, `PE-DELTA-001` | self.api_key = os.environ.get("NVIDIA_API_KEY") |
| `extension.py` | python | **BLOCK** | 0.680 | — | `PE-002` | exec(code,  local_ns) |
| `gen3d.py` | python | **BLOCK** | 0.997 | — | `PE-008`, `PE-008`, `PE-008`, `EX-001`, `EX-001`, `EX-001`, `PE-008`, `PE-007`, `EX-001`, `EX-001`, `PE-DELTA-001` | self.api_key = os.environ.get("ARK_API_KEY") |

### 🔴 BLOCK — [PatrickPalmer__MayaMCP](https://github.com/PatrickPalmer/MayaMCP)

Python files: 18 | Markdown files: 1 | Tools: 1  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `maya_mcp_server.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |

### 🔴 BLOCK — [raveenb__fal-mcp-server](https://github.com/raveenb/fal-mcp-server)

Python files: 25 | Markdown files: 10 | Tools: 21  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # 🎨 fal.ai mcp server [![ci](https://github. |
| `fal_mcp.py` | python | **BLOCK** | 0.973 | — | `PI-004`, `SC-004`, `SC-003`, `SC-008` | secret_exfil_template; variant=raw; # 🎨 fal.ai mcp server [![ci](https://github. |
| `basic_usage.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if not os.getenv('FAL_KEY'): |
| `server_http.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if api_key := os.getenv("FAL_KEY"): |
| `server.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if api_key := os.getenv("FAL_KEY"): |
| `server_backup.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if api_key := os.getenv("FAL_KEY"): |
| `server_dual.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | if api_key := os.getenv("FAL_KEY"): |
| `model_registry.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = os.getenv("FAL_KEY") |

### 🔴 BLOCK — [samuelgursky__davinci-resolve-mcp](https://github.com/samuelgursky/davinci-resolve-mcp)

Python files: 31 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `resolve_mcp_server.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `create_test_timeline.py` | python | **BLOCK** | 0.990 | — | `EX-001`, `PE-003`, `PE-DELTA-001` | response = requests.post(SERVER_URL, json=payload) |
| `benchmark_server.py` | python | **BLOCK** | 0.896 | — | `EX-001`, `PE-007`, `PE-DELTA-001` | response = requests.post(SERVER_URL, json=payload) |
| `batch_automation.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.post(SERVER_URL, json=payload) |
| `resolve_mcp_server.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `add_spaced_markers.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `add_timecode_marker.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `alternating_markers.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `clear_add_markers.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `timeline_info.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `timeline_check.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `import_folder.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `app_control.py` | python | **BLOCK** | 1.000 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | subprocess.run(cmd) |
| `resolve_connection.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | resolve_script_api = os.environ.get("RESOLVE_SCRIPT_API") |
| `platform.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | program_files = os.environ.get('PROGRAMDATA', 'C:\\ProgramData') |

### 🔴 BLOCK — [TwelveTake-Studios__reaper-mcp](https://github.com/TwelveTake-Studios/reaper-mcp)

Python files: 2 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `reaper_mcp_server.py` | python | **BLOCK** | 0.997 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | 2 dependency entries without hash pinning |
| `reaper_web_server.py` | python | **BLOCK** | 0.971 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |

### 🔴 BLOCK — [GittyBurstein__mermaid-mcp-server](https://github.com/GittyBurstein/mermaid-mcp-server)

Python files: 30 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `config.py` | python | **BLOCK** | 0.928 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | raw = os.environ.get(name) |
| `client.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | token = (os.environ.get("GITHUB_TOKEN") or "").strip() |

### 🔴 BLOCK — [Narasimhaponnada__mermaid-mcp](https://github.com/Narasimhaponnada/mermaid-mcp)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `GITHUB_TOPICS_SETUP.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # github topics setup ## how to add topics 1 |

### 🔴 BLOCK — [cafferychen777__ChatSpatial](https://github.com/cafferychen777/ChatSpatial)

Python files: 68 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `config.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | env_dir = os.environ.get("CHATSPATIAL_OUTPUT_DIR") |
| `conf.py` | python | **BLOCK** | 0.785 | — | `SC-004`, `PE-008`, `PE-DELTA-001` | 6 dependency entries without hash pinning |
| `annotation.py` | python | **BLOCK** | 0.956 | — | `EX-003`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-007`, `PE-008`, `PE-DELTA-001` |  required_packages <- c("dplyr", "openxlsx", "HGNChelper") missing_packages <- r |
| `cell_communication.py` | python | **BLOCK** | 0.846 | — | `EX-003`, `PE-007`, `PE-DELTA-001` |   Troubleshooting: 1. Check internet connection 2. Verify CellPhoneDB version co |
| `data_loader.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `results_export.py` | python | **BLOCK** | 0.886 | — | `PE-007`, `PE-008`, `PE-008`, `PE-DELTA-001` | with open(index_path, "w") as f: |
| `preprocessing.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | Pearson residuals normalization not available (requires scanpy>=1.9.0). Options: |
| `compat.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | CellRank 2.0.7 uses np.testing.assert_array_equal(x=, y=) which fails with NumPy |
| `dependency_manager.py` | python | **WARN** | 0.417 | — | `PE-005` | return importlib.import_module(module_name) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | module = importlib.import_module(f".{config.module_name}", package=__package__) |

### 🔴 BLOCK — [dnaerys__onekgpd-mcp](https://github.com/dnaerys/onekgpd-mcp)

Python files: 0 | Markdown files: 6 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; face layer for 1000 genomes project dataset. server  |
| `CHANGELOG.md` | markdown | **WARN** | 0.420 | — | `PI-005` | pattern_match; variant=raw; ies - added protobuf-maven-plugin to generate dnaery |
| `TEST_IMPLEMENTATION_LOG.md` | markdown | **WARN** | 0.434 | — | `PI-005` | pattern_match; variant=raw; l tests passing ### files created ``` src/test/resou |
| `TEST_SPECIFICATION.md` | markdown | **WARN** | 0.434 | — | `PI-005` | pattern_match; variant=raw; 2. codebase analysis ### 2.1 component inventory ### |

### 🔴 BLOCK — [genomoncology__biomcp](https://github.com/genomoncology/biomcp)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `installation.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # installation this page covers supported bi |

### 🔴 BLOCK — [hlydecker__ucsc-genome-mcp](https://github.com/hlydecker/ucsc-genome-mcp)

Python files: 3 | Markdown files: 1 | Tools: 12  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `claude_desktop_config_example.py` | python | **BLOCK** | 0.971 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `validate_api.py` | python | **BLOCK** | 0.971 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008` | 2 dependency entries without hash pinning |
| `ucsc-genome-mcp.py` | python | **BLOCK** | 0.981 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008`, `EX-003`, `EX-003` | 2 dependency entries without hash pinning |

### 🔴 BLOCK — [JamesANZ__medical-mcp](https://github.com/JamesANZ/medical-mcp)

Python files: 0 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # 🩺 medical mcp server > **bring trusted med |

### 🔴 BLOCK — [longevity-genie__biothings-mcp](https://github.com/longevity-genie/biothings-mcp)

Python files: 5 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | DEFAULT_HOST = os.getenv("MCP_HOST", "0.0.0.0") |
| `download_api.py` | python | **BLOCK** | 0.974 | — | `PE-008`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | email = os.getenv("ENTREZ_EMAIL") |

### 🔴 BLOCK — [longevity-genie__gget-mcp](https://github.com/longevity-genie/gget-mcp)

Python files: 7 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `demo_battle_results.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `server.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | DEFAULT_HOST = os.getenv("MCP_HOST", "0.0.0.0") |
| `server_ext.py` | python | **BLOCK** | 0.984 | — | `PE-008`, `PE-008`, `PE-008`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | DEFAULT_HOST = os.getenv("MCP_HOST", "0.0.0.0") |

### 🔴 BLOCK — [longevity-genie__opengenes-mcp](https://github.com/longevity-genie/opengenes-mcp)

Python files: 3 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-008`, `PE-008`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-DELTA-001` | DEFAULT_HOST = os.getenv("MCP_HOST", "0.0.0.0") |

### 🔴 BLOCK — [longevity-genie__synergy-age-mcp](https://github.com/longevity-genie/synergy-age-mcp)

Python files: 5 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `convert_pg_to_sqlite.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `quick_convert.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `server.py` | python | **BLOCK** | 0.998 | — | `PE-008`, `PE-008`, `PE-008`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-DELTA-001` | DEFAULT_HOST = os.getenv("MCP_HOST", "0.0.0.0") |

### 🔴 BLOCK — [OHNLP__omop_mcp](https://github.com/OHNLP/omop_mcp)

Python files: 7 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `agent.py` | python | **BLOCK** | 0.972 | — | `EX-003`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | "      **CRITICAL: You must interpret the medical keyword clinically, not just e |
| `utils.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like  |

### 🔴 BLOCK — [the-momentum__apple-health-mcp-server](https://github.com/the-momentum/apple-health-mcp-server)

Python files: 38 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `start.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run(cmd) |
| `config_utils.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | master_key = os.environ.get(value) |

### 🔴 BLOCK — [the-momentum__fhir-mcp-server](https://github.com/the-momentum/fhir-mcp-server)

Python files: 51 | Markdown files: 7 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `start.py` | python | **BLOCK** | 0.911 | — | `PE-008`, `PE-003`, `PE-DELTA-001` | default_transport = os.getenv("TRANSPORT_MODE", "stdio") |
| `config_utils.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | master_key = os.environ.get(value) |
| `loinc_client.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get( |
| `document_service.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get(url) |
| `oauth_client.py` | python | **BLOCK** | 0.900 | — | `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.post( |
| `fhir_client.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.request( |
| `setup_encryption.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(env_path, "w") as f: |
| `load_models.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | embedding_model_name = os.getenv("EMBEDDING_MODEL") |

### 🔴 BLOCK — [wso2__fhir-mcp-server](https://github.com/wso2/fhir-mcp-server)

Python files: 14 | Markdown files: 4 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `run_tests.py` | python | **BLOCK** | 1.000 | — | `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `PE-003`, `PE-DELTA-001` | 40 dependency entries without hash pinning |

### 🔴 BLOCK — [blackwhite084__playwright-plus-python-mcp](https://github.com/blackwhite084/playwright-plus-python-mcp)

Python files: 2 | Markdown files: 1 | Tools: 8  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |

### 🔴 BLOCK — [co-browser__browser-use-mcp-server](https://github.com/co-browser/browser-use-mcp-server)

Python files: 6 | Markdown files: 6 | Tools: 4  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.996 | — | `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-003`, `EX-003`, `EX-003`, `PE-DELTA-001` | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) |

### 🔴 BLOCK — [executeautomation__mcp-playwright](https://github.com/executeautomation/mcp-playwright)

Python files: 0 | Markdown files: 9 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CHANGELOG.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # changelog all notable changes to the playw |
| `Examples.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | pattern_match; variant=raw; https://api.example.com/protected-data', token: 'you |

### 🔴 BLOCK — [freema__firefox-devtools-mcp](https://github.com/freema/firefox-devtools-mcp)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `ci-and-release.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; ge name (`firefox-devtools-mcp`). - `codecov_token`  |

### 🔴 BLOCK — [hanzili__comet-mcp](https://github.com/hanzili/comet-mcp)

Python files: 0 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CLAUDE.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # claude.md ## what this is mcp server conne |

### 🔴 BLOCK — [kimtth__mcp-aoai-web-browsing](https://github.com/kimtth/mcp-aoai-web-browsing)

Python files: 9 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `llm_config.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | azure_endpoint=os.getenv("AZURE_OPEN_AI_ENDPOINT"), |

### 🔴 BLOCK — [modelcontextprotocol__servers-archived](https://github.com/modelcontextprotocol/servers-archived)

Python files: 9 | Markdown files: 10 | Tools: 19  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `release.py` | python | **BLOCK** | 0.978 | — | `PE-003`, `PE-003`, `PE-007`, `PE-DELTA-001` | output = subprocess.run( |
| `server.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if sys.platform == "win32" and os.environ.get('PYTHONIOENCODING') is None: |

### 🔴 BLOCK — [Operative-Sh__web-eval-agent](https://github.com/Operative-Sh/web-eval-agent)

Python files: 12 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # ⚠️ project has been sunset ⚠️ ## this proj |
| `__init__.py` | python | **BLOCK** | 1.000 | — | `PI-004`, `SC-004`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | secret_exfil_template; variant=raw; # ⚠️ project has been sunset ⚠️ ## this proj |
| `mcp_server.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = os.environ.get('OPERATIVE_API_KEY') |
| `browser_utils.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `tool_handlers.py` | python | **BLOCK** | 0.846 | — | `EX-003`, `PE-007`, `PE-DELTA-001` | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like  |
| `log_server.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | sys.stdout = open(os.devnull, 'w') |
| `env_utils.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | use_local_env = os.getenv("USE_LOCAL_BACKEND") |
| `utils.py` | python | **BLOCK** | 0.987 | — | `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | subprocess.run(["taskkill", "/F", "/PID", |

### 🔴 BLOCK — [Pantheon-Security__chrome-mcp-secure](https://github.com/Pantheon-Security/chrome-mcp-secure)

Python files: 0 | Markdown files: 4 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; <div align="center"> # chrome mcp server (se |
| `SECURITY.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # security hardening documentation this is a |

### 🔴 BLOCK — [PhungXuanAnh__selenium-mcp-server](https://github.com/PhungXuanAnh/selenium-mcp-server)

Python files: 16 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `publishing_to_pypi.prompt.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; hon -m build # or /usr/bin/python3 -m build # 4. upl |
| `logs.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | open(path, "w").close() |
| `normal_chrome.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | process = subprocess.Popen( |
| `undetected_chrome.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run(['google-chrome', '--version'], |

### 🔴 BLOCK — [Retio-ai__Retio-pagemap](https://github.com/Retio-ai/Retio-pagemap)

Python files: 39 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CHANGELOG.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # changelog all notable changes to this proj |
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; <!-- mcp-name: io.github.retio-ai/pagemap -- |
| `robots_checker.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | with urllib.request.urlopen(req, timeout=_ROBOTS_FETCH_TIMEOUT) as resp:  # noqa |
| `server.py` | python | **BLOCK** | 0.995 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | MAX_RESPONSE_SIZE_BYTES = int(os.environ.get("PAGEMAP_MAX_TEXT_BYTES", 1 * 1024  |
| `cli.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `pruned_context_builder.py` | python | **BLOCK** | 0.857 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | class=(?P<q>["'])[^"']*(?:a-price\|a-offscreen\|price)[^"']*(?P=q)[^>]*>(?:\s*<[ |
| `interactive_detector.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | ^\s*(?:[#(]?\d+[.)]?\|[-\u2014\u2013\u00b7\u2026]+\|[Nn]/[Aa])\s*$ |
| `browser_session.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like  |
| `page_classifier.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | <script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script> |
| `page_map_builder.py` | python | **WARN** | 0.579 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003` |  (() => {   const all = document.body.querySelectorAll('*');   const nodeCount = |
| `preprocessor.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | <script[^>]*type\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script> |
| `pruner.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | \d+\.?\d*\s*(?:cm\|mm\|\uc778\uce58\|inch\|inches\|kg\|g\|lb\|oz\|%\|\u2033\|\u2 |

### 🔴 BLOCK — [aashari__mcp-server-aws-sso](https://github.com/aashari/mcp-server-aws-sso)

Python files: 0 | Markdown files: 5 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # connect ai to your aws resources transform |
| `MODERNIZATION-ANALYSIS.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # mcp server aws sso - modernization analysi |

### 🔴 BLOCK — [alexei-led__aws-mcp-server](https://github.com/alexei-led/aws-mcp-server)

Python files: 12 | Markdown files: 9 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `USAGE.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # usage guide this guide covers the tools, r |
| `spec.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # aws model context protocol (mcp) server sp |
| `config.py` | python | **BLOCK** | 0.945 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | TRANSPORT = os.environ.get("AWS_MCP_TRANSPORT", "stdio") |
| `prompts.py` | python | **BLOCK** | 0.999 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRange |
| `sandbox.py` | python | **BLOCK** | 0.999 | — | `PE-006`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-008`, `PE-DELTA-001` | import ctypes |
| `resources.py` | python | **BLOCK** | 0.967 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | custom_config = os.environ.get("AWS_CONFIG_FILE") |

### 🔴 BLOCK — [alexei-led__k8s-mcp-server](https://github.com/alexei-led/k8s-mcp-server)

Python files: 13 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `helpers.py` | python | **BLOCK** | 0.950 | — | `PE-008`, `PE-003`, `PE-007`, `PE-DELTA-001` | kubeconfig = os.environ.get("KUBECONFIG") |
| `config.py` | python | **BLOCK** | 0.955 | — | `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` |  K8s MCP Server provides a simple interface to Kubernetes CLI tools.  Supported  |
| `security.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | SECURITY_MODE = os.environ.get("K8S_MCP_SECURITY_MODE", "strict") |
| `prompts.py` | python | **BLOCK** | 0.779 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` |  namespace.  Include commands to: 1. Create necessary Kubernetes resources (Depl |

### 🔴 BLOCK — [aliyun__alibaba-cloud-ops-mcp-server](https://github.com/aliyun/alibaba-cloud-ops-mcp-server)

Python files: 20 | Markdown files: 5 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `local_tools.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | process = subprocess.run( |
| `oss_tools.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `utils.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(json_file, 'w', encoding='utf-8') as f: |
| `api_meta_client.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get(url) |

### 🔴 BLOCK — [awslabs__mcp](https://github.com/awslabs/mcp)

Python files: 1237 | Markdown files: 10 | Tools: 11  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.992 | — | `PI-003`, `PI-004` | Invisible codepoints: U+200D U+200D |
| `verify_package_name.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `verify_awslabs_init.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `client_server.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | region_name=os.getenv('AWS_REGION', 'us-east-1'), |
| `image_generator_st.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.post( |
| `client_server.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | region_name=os.getenv('AWS_REGION', 'us-west-2'), |
| `chat_bedrock_st.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.post( |
| `release.py` | python | **BLOCK** | 0.846 | — | `EX-003`, `PE-007`, `PE-DELTA-001` | ^(?P<major>0\|[1-9]\d*)\.(?P<minor>0\|[1-9]\d*)\.(?P<patch>0\|[1-9]\d*)(?:-(?P<p |
| `run_server.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `clients.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | region = os.getenv('AWS_REGION') |
| `server.py` | python | **BLOCK** | 0.874 | — | `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` |  # Amazon Nova Canvas Image Generation  This MCP server provides tools for gener |
| `novacanvas.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(image_path, 'wb') as file: |
| `server.py` | python | **BLOCK** | 0.985 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | prometheus_url = os.getenv('PROMETHEUS_URL') |
| `enablement_tools.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `server.py` | python | **BLOCK** | 0.837 | — | `PE-008`, `EX-003`, `PE-008`, `PE-DELTA-001` | log_file_path = os.environ.get('AUDITOR_LOG_PATH', tempfile.gettempdir()) |
| `audit_utils.py` | python | **BLOCK** | 0.980 | — | `PE-008`, `PE-008`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | desired_log_path = os.environ.get('AUDITOR_LOG_PATH', tempfile.gettempdir()) |
| `canary_utils.py` | python | **BLOCK** | 0.965 | — | `EX-003`, `EX-003`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole |
| `aws_clients.py` | python | **BLOCK** | 0.945 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1') |
| `client_manager.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | aws_profile = os.environ.get('AWS_PROFILE', 'default') |
| `helpers.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | return os.environ.get('AWS_REGION', 'us-east-1') |
| `main.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | log_level = os.environ.get("FASTMCP_LOG_LEVEL", "INFO") |
| `config.py` | python | **BLOCK** | 0.928 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | "aws_region": os.environ.get("AWS_REGION", "us-east-1"), |
| `security.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `docker.py` | python | **BLOCK** | 0.999 | — | `PE-008`, `PE-008`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | region = os.environ.get("AWS_REGION", "us-east-1") |
| `aws.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | region = os.environ.get("AWS_REGION", "us-east-1") |
| `delete.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `infrastructure.py` | python | **BLOCK** | 0.930 | — | `EX-003`, `EX-003`, `PE-007`, `PE-007`, `PE-DELTA-001` | 6. Deploy the ECS infrastructure using AWS CLI or CloudFormation |
| `mcp_call_tool.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | proc = subprocess.Popen( |
| `server.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | value = os.environ.get(name) |
| `tools.py` | python | **BLOCK** | 0.876 | — | `EX-003`, `EX-003`, `PE-007`, `PE-DELTA-001` | ),   apiSchema: bedrock.ApiSchema.fromLocalAsset(     path.join(__dirname, " |
| `lambda_powertools_loader.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `cdk_nag_parser.py` | python | **BLOCK** | 0.726 | — | `EX-003`, `PE-DELTA-001` | ⚠️ SECURITY ALERT: This code contains CDK Nag suppressions that require human re |
| `schema_generator.py` | python | **BLOCK** | 0.972 | — | `PE-005`, `EX-003`, `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | module = __import__(module_name) |
| `config.py` | python | **BLOCK** | 0.985 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | MCP_TRANSPORT = os.getenv('MCP_TRANSPORT', 'stdio') |
| `s3.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | session = boto3.Session(profile_name=os.environ.get('AWS_PROFILE')) |
| `server.py` | python | **BLOCK** | 0.945 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | AWS_PROFILE = os.environ.get('AWS_PROFILE', 'default') |
| `generator.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | aws_profile = os.environ.get('AWS_PROFILE', 'default') |
| `server.py` | python | **BLOCK** | 0.942 | — | `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` |      The AWS Labs Bedrock Knowledge Bases Retrieval MCP Server provides access t |
| `server.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'WARNING')) |
| `server_utils.py` | python | **BLOCK** | 0.789 | — | `EX-003`, `PE-008`, `PE-DELTA-001` | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) |
| `doc_fetcher.py` | python | **BLOCK** | 0.852 | — | `EX-003`, `EX-001`, `PE-DELTA-001` | (?is)<meta[^>]+property=["\']og:title["\'][^>]+content=["\'](.*?)["\'] |
| `consts.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | DEFAULT_MAX_RESULTS = int(os.environ.get('HEALTHOMICS_DEFAULT_MAX_RESULTS', '100 |
| `workflow_linting.py` | python | **BLOCK** | 0.996 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(  # nosec B603 - safe: hardcoded cmd, no shell, timeout |
| `aws_utils.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | return os.environ.get('AWS_REGION', DEFAULT_REGION) |
| `validation_utils.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `search_config.py` | python | **BLOCK** | 0.957 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | bucket_paths_env = os.environ.get(GENOMICS_SEARCH_S3_BUCKETS_ENV, '').strip() |
| `policy.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `manager.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `interpretation.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(validated_path, 'wb') as f: |
| `config.py` | python | **BLOCK** | 0.997 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | FASTMCP_LOG_LEVEL = os.getenv('FASTMCP_LOG_LEVEL', 'INFO') |
| `read_only_operations_list.py` | python | **BLOCK** | 0.900 | — | `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get(SERVICE_REFERENCE_URL, timeout=DEFAULT_REQUEST_TIMEOUT). |
| `recommendation_details_tools.py` | python | **BLOCK** | 0.726 | — | `EX-003`, `PE-DELTA-001` |  FORMATTING INSTRUCTIONS: Use the provided template to organize your response ab |
| `storage_lens_tools.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | manifest_loc = manifest_location or os.environ.get(ENV_STORAGE_LENS_MANIFEST_LOC |
| `aws_service_base.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | profile_name = os.environ.get('AWS_PROFILE') |
| `sql_utils.py` | python | **BLOCK** | 0.837 | — | `PE-008`, `PE-008`, `EX-003`, `PE-DELTA-001` | os.getenv('MCP_SQL_THRESHOLD', 25 * 1024) |
| `logging_utils.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | log_file = os.environ.get(ENV_LOG_FILE) |
| `consts.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1') |
| `report_generator.py` | python | **BLOCK** | 0.961 | — | `EX-003`, `EX-003`, `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | This cost analysis is based on the following pricing model: - **ON DEMAND** pric |
| `terraform_analyzer.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `cdk_analyzer.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `server.py` | python | **BLOCK** | 0.975 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'INFO')) |
| `github_search.py` | python | **BLOCK** | 0.923 | — | `PE-008`, `EX-001`, `EX-001`, `PE-DELTA-001` | token = os.environ.get('GITHUB_TOKEN') |
| `embeddings.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | aws_region = aws_region or os.environ.get('AWS_REGION', 'us-west-2') |
| `utils.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `indexer.py` | python | **BLOCK** | 0.966 | — | `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | with open(docstore_path, 'w') as f: |
| `repository.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `cloudformation_compliance_checker.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `cloudformation_failure_cases.py` | python | **BLOCK** | 0.996 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | There are two approaches to solve this error:  Approach #1: Retry Delete from Cl |
| `aws_knowledge_client.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | KNOWLEDGE_MCP_ENDPOINT = os.environ.get( |
| `mcp_proxy.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'WARNING')) |
| `__init__.py` | python | **BLOCK** | 0.991 | — | `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008` | 4 dependency entries without hash pinning |
| `__main__.py` | python | **BLOCK** | 0.995 | — | `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `PE-005` | 4 dependency entries without hash pinning |
| `enablement_tools.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `server.py` | python | **BLOCK** | 0.837 | — | `PE-008`, `EX-003`, `PE-008`, `PE-DELTA-001` | log_file_path = os.environ.get('AUDITOR_LOG_PATH', tempfile.gettempdir()) |
| `audit_utils.py` | python | **BLOCK** | 0.980 | — | `PE-008`, `PE-008`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | desired_log_path = os.environ.get('AUDITOR_LOG_PATH', tempfile.gettempdir()) |
| `canary_utils.py` | python | **BLOCK** | 0.965 | — | `EX-003`, `EX-003`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole |
| `aws_clients.py` | python | **BLOCK** | 0.957 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1') |
| `eval_mcp_server_wrapper.py` | python | **BLOCK** | 0.909 | — | `PE-008`, `PE-005`, `PE-008`, `PE-008`, `PE-DELTA-001` | mock_file = os.environ.get('TEMP_SERVER_WRAPPER_MOCK_FILE') |
| `mcp_dependency_mocking_handler.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `eval_config.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | MODEL_ID = os.environ.get('MCP_EVAL_MODEL_ID', _DEFAULT_MODEL_ID) |
| `process_executor.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `server.py` | python | **BLOCK** | 0.979 | — | `EX-003`, `PE-008`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | A Model Context Protocol (MCP) server that enables programmatic access to AWS S3 |
| `utils.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | region = region_name or os.getenv('AWS_REGION') or 'us-east-1' |
| `aws_helper.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | aws_region = os.environ.get( |
| `common_resource_handler.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | aws_region = region or os.getenv('AWS_REGION', 'us-east-1') |
| `main.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | logger.add(sys.stderr, level=os.getenv('MCP_LOG_LEVEL', 'WARNING')) |
| `config.py` | python | **BLOCK** | 0.957 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | cassandra_contact_points=os.getenv('DB_CASSANDRA_CONTACT_POINTS', '127.0.0.1'), |
| `server.py` | python | **BLOCK** | 0.907 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | STATE_MACHINE_PREFIX = os.environ.get('STATE_MACHINE_PREFIX', '') |
| `aws_helper.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | return os.environ.get('AWS_REGION', 'us-east-1') |
| `eks_kb_handler.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.post( |
| `k8s_apis.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | os.environ.get('HTTPS_PROXY') |
| `k8s_handler.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(output_file_path, 'w') as f: |
| `cloudwatch_metrics_guidance_handler.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `aws_helper.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | return os.environ.get('AWS_REGION') |
| `eks_stack_handler.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(template_path, 'w') as dest_file: |
| `update_eks_cloudwatch_metrics_guidance.py` | python | **BLOCK** | 0.896 | — | `EX-001`, `PE-007`, `PE-DELTA-001` | response = requests.get(DOCS_URL, timeout=10) |
| `server.py` | python | **BLOCK** | 0.789 | — | `EX-003`, `PE-008`, `PE-DELTA-001` |  # Amazon SageMaker AI MCP Server  This MCP server provides comprehensive tools  |
| `aws_helper.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | region = os.environ.get('AWS_REGION') |
| `hyperpod_stack_handler.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `hyperpod_cluster_node_handler.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `server.py` | python | **BLOCK** | 0.869 | — | `EX-003`, `EX-003`, `PE-008`, `PE-008`, `PE-DELTA-001` |      # AWS Support API MCP Server      This MCP server provides tools for intera |
| `connection.py` | python | **BLOCK** | 0.980 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | host = os.getenv('MEMCACHED_HOST', '127.0.0.1') |
| `server.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'WARNING')) |
| `registry.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | templates_path = os.environ.get('TEMPLATES_PATH') |
| `deployment_manager.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(metadata_file, 'w', encoding='utf-8') as f: |
| `github.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get(url, headers=default_headers, timeout=30) |
| `const.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1') |
| `deploy_webapp.py` | python | **BLOCK** | 0.726 | — | `EX-003`, `PE-DELTA-001` |      IMPORTANT: Dependencies not found in built_artifacts_path ( |
| `update_webapp_frontend.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `esm_recommend.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | 'lambda', region_name=os.environ.get('AWS_DEFAULT_REGION', 'us-east-1') |
| `esm_recommend.py` | python | **BLOCK** | 0.911 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-008`, `PE-DELTA-001` | #!/bin/bash  # ESM Configuration Update Deployment Script # Generated for ESM UU |
| `esm_guidance.py` | python | **BLOCK** | 0.885 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | IMPORTANT: Ask user for explicit confirmation before any deployment |
| `esm_diagnosis.py` | python | **BLOCK** | 0.907 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | (Self-managed) Network ACLs block traffic between ESM subnets and Kafka brokers. |
| `deploy_service.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(template_path, 'w', encoding='utf-8') as f: |
| `startup_script_generator.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(script_path, 'w', encoding='utf-8') as f: |
| `server.py` | python | **BLOCK** | 0.967 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'WARNING')) |
| `tools.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `server.py` | python | **BLOCK** | 0.951 | — | `EX-003`, `EX-003`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | The URL of the InfluxDB server. Falls back to INFLUXDB_URL env var if not provid |
| `comparison_handler.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'WARNING')) |
| `server.py` | python | **BLOCK** | 0.789 | — | `EX-003`, `PE-008`, `PE-DELTA-001` |  # AWS Cost Explorer MCP Server  ## IMPORTANT: Each API call costs $0.01 - use f |
| `forecasting_handler.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'WARNING')) |
| `utility_handler.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'WARNING')) |
| `cost_usage_handler.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'WARNING')) |
| `helpers.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'WARNING')) |
| `metadata_handler.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'WARNING')) |
| `helpers.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | profile_name=os.getenv('AWS_PROFILE'), region_name=os.getenv('AWS_REGION', 'us-e |
| `server.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | env_base = os.getenv('DOCUMENT_BASE_DIR') |
| `tools.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if aws_profile := os.environ.get('AWS_PROFILE'): |
| `file_utils.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `register.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | auth_type = os.environ.get('AUTH_TYPE', '').lower() |
| `cognito_auth.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.post(token_endpoint, headers=headers, data=data) |
| `config.py` | python | **BLOCK** | 0.975 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | METRICS_MAX_HISTORY = int(os.environ.get('METRICS_MAX_HISTORY', '100')) |
| `openapi.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = httpx.get(url, timeout=10.0) |
| `openapi_validator.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | USE_OPENAPI_CORE = OPENAPI_CORE_AVAILABLE and os.environ.get( |
| `connection.py` | python | **BLOCK** | 0.928 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | aws_profile = os.environ.get('AWS_PROFILE', 'default') |
| `server.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `consts.py` | python | **BLOCK** | 0.907 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | AWS_REGION = os.getenv('AWS_REGION', 'us-east-1') |
| `schema_manager.py` | python | **BLOCK** | 0.940 | — | `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | with open(self.metadata_file, 'w') as f: |
| `iac_generator.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(save_to_file, 'w') as f: |
| `redshift.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | aws_region=os.environ.get('AWS_REGION'), |
| `server.py` | python | **BLOCK** | 0.837 | — | `EX-003`, `PE-008`, `PE-008`, `PE-DELTA-001` |  # Amazon Redshift MCP Server.  This MCP server provides comprehensive access to |
| `server.py` | python | **BLOCK** | 0.869 | — | `EX-003`, `EX-003`, `PE-008`, `PE-008`, `PE-DELTA-001` | WRITE ENABLED - AWS IoT SiteWise MCP Server  Full functionality enabled for indu |
| `diagrams_tools.py` | python | **BLOCK** | 1.000 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-002`, `PE-002`, `PE-002`, `PE-002`, `PE-005`, `PE-005`, `PE-005` | with Diagram("Web Service Architecture", show=False):     ELB("lb") >> EC2("web" |
| `server.py` | python | **BLOCK** | 0.904 | — | `EX-003`, `EX-003`, `PE-008`, `PE-007`, `PE-DELTA-001` | The official MCP Server for AWS DynamoDB design and modeling guidance  This serv |
| `markdown_formatter.py` | python | **BLOCK** | 0.940 | — | `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | with open(file_path, 'w', encoding='utf-8') as f: |
| `model_validation_utils.py` | python | **BLOCK** | 0.999 | — | `PE-008`, `PE-003`, `PE-003`, `EX-001`, `EX-003`, `PE-008`, `PE-007`, `PE-DELTA-001` | java_home = os.environ.get('JAVA_HOME') |
| `generator.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | subprocess.run(  # nosec B603, B607 - user local env, hardcoded cmd, no shell, t |
| `analyzer_utils.py` | python | **BLOCK** | 0.971 | — | `EX-003`, `EX-003`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` |  database 2. Save the results to a text file (pipe-separated format) 3. Call thi |
| `base_plugin.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(output_file, 'w', encoding='utf-8') as f: |
| `codegen.py` | python | **BLOCK** | 0.987 | — | `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(  # nosec B603, B607 - user local env, hardcoded cmd, no |
| `file_utils.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `output_manager.py` | python | **BLOCK** | 0.940 | — | `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | with open(mapping_file, 'w') as f: |
| `multiturn_evaluator.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if not os.environ.get('AWS_DEFAULT_REGION'): |
| `manage_snapshots.py` | python | **BLOCK** | 0.993 | — | `PE-003`, `PE-003`, `PE-002`, `PE-007`, `PE-DELTA-001` | return subprocess.run(cmd, cwd=get_project_root(), capture_output=True, text=Tru |
| `usage_examples.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | endpoint_url = os.getenv('AWS_ENDPOINT_URL_DYNAMODB', '') |
| `usage_examples.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | endpoint_url = os.getenv('AWS_ENDPOINT_URL_DYNAMODB', '') |
| `usage_examples.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | endpoint_url = os.getenv('AWS_ENDPOINT_URL_DYNAMODB', '') |
| `usage_examples.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | endpoint_url = os.getenv('AWS_ENDPOINT_URL_DYNAMODB', '') |
| `usage_examples.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | endpoint_url = os.getenv('AWS_ENDPOINT_URL_DYNAMODB', '') |
| `usage_examples.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | endpoint_url = os.getenv('AWS_ENDPOINT_URL_DYNAMODB', '') |
| `usage_examples.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | endpoint_url = os.getenv('AWS_ENDPOINT_URL_DYNAMODB', '') |
| `usage_examples.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | endpoint_url = os.getenv('AWS_ENDPOINT_URL_DYNAMODB', '') |
| `usage_examples.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | endpoint_url = os.getenv('AWS_ENDPOINT_URL_DYNAMODB', '') |
| `usage_examples.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | endpoint_url = os.getenv('AWS_ENDPOINT_URL_DYNAMODB', '') |
| `aws_service_mcp_generator.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | aws_profile = os.environ.get('AWS_PROFILE', 'default') |
| `admin.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.request(method, url, headers=self.headers, json=data, verify |
| `server.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | aws_profile = os.environ.get('AWS_PROFILE', 'default') |
| `server.py` | python | **BLOCK** | 0.846 | — | `EX-003`, `PE-007`, `PE-DELTA-001` | Either AWS_PROFILE must be set or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY mu |
| `schema_manager.py` | python | **BLOCK** | 0.940 | — | `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | with open(self.metadata_file, 'w') as f: |
| `iac_generator.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(save_to_file, 'w') as f: |
| `security_scanning.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | subprocess.run( |
| `server.py` | python | **BLOCK** | 0.947 | — | `EX-003`, `EX-003`, `PE-008`, `PE-008`, `EX-003`, `EX-003`, `EX-003`, `PE-008`, `PE-DELTA-001` | Optional AWS profile to use (defaults to AWS_PROFILE environment variable or 'de |
| `prompt_utils.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `server.py` | python | **BLOCK** | 0.953 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `EX-003`, `EX-003`, `PE-008`, `PE-DELTA-001` | log_level = os.environ.get('FASTMCP_LOG_LEVEL', 'INFO') |
| `consts.py` | python | **BLOCK** | 0.789 | — | `EX-003`, `PE-008`, `PE-DELTA-001` | (\d{12})\.dkr[-.]ecr(\-fips)?\.([a-zA-Z0-9][a-zA-Z0-9-_]*)\.(on\.aws\|amazonaws\ |
| `build.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `vm.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(finch_yaml_path, 'w') as f: |
| `common.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run(command, capture_output=True, text=True, env=env) |
| `types.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `server.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | endpoint = os.environ.get('NEPTUNE_ENDPOINT', None) |
| `scrape_aws_terraform_best_practices.py` | python | **BLOCK** | 0.896 | — | `EX-001`, `PE-007`, `PE-DELTA-001` | response = requests.get(url) |
| `generate_aws_provider_resources.py` | python | **BLOCK** | 0.908 | — | `PE-008`, `EX-003`, `PE-007`, `PE-008`, `PE-DELTA-001` | USE_PLAYWRIGHT = os.environ.get('USE_PLAYWRIGHT', '1').lower() in ('1', 'true',  |
| `generate_awscc_provider_resources.py` | python | **BLOCK** | 0.908 | — | `EX-003`, `PE-008`, `PE-007`, `PE-008`, `PE-DELTA-001` | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like  |
| `search_specific_aws_ia_modules.py` | python | **BLOCK** | 0.971 | — | `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get(details_url) |
| `search_awscc_provider_docs.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get(github_url, timeout=10) |
| `execute_terragrunt_command.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | process = subprocess.run(  # noqa: B603 - Safe: allowlisted commands, validated  |
| `run_checkov_scan.py` | python | **BLOCK** | 0.989 | — | `PE-003`, `PE-003`, `EX-003`, `PE-003`, `PE-DELTA-001` | subprocess.run(  # noqa: B603 - Safe: hardcoded command with no user input |
| `execute_terraform_command.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | process = subprocess.run(  # noqa: B603 - Safe: allowlisted commands, validated  |
| `utils.py` | python | **BLOCK** | 0.995 | — | `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get(release_url) |
| `search_aws_provider_docs.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get(github_url, timeout=10) |
| `search_user_provided_module.py` | python | **BLOCK** | 0.900 | — | `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get(details_url) |
| `terraform_awscc_provider_resources_listing.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `terraform_aws_provider_resources_listing.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `server.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | kendra_index_id = indexId or os.getenv('KENDRA_INDEX_ID') |
| `util.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | AWS_PROFILE = os.environ.get('AWS_PROFILE') |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__("pkgutil").extend_path(__path__, __name__) |
| `ecs_troubleshooting.py` | python | **WARN** | 0.660 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | action="get_ecs_troubleshooting_guidance", parameters={"ecs_cluster_name": "my-c |
| `containerize.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | Slim Docker Library Images from public.ecr.aws (eg public.ecr.aws/docker/library |
| `status.py` | python | **WARN** | 0.660 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | Secure your application with HTTPS using AWS Certificate Manager (ACM) and updat |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `get_path_trace_methodology.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | MANDATORY: Always call get_path_trace_methodology before beginning analysis |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `genomics_test_data.py` | python | **WARN** | 0.726 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | references/GRCh38/bwa_index/GRCh38.primary_assembly.genome.fasta.amb |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `aws_pricing_operations.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | " did not return any pricing data. AWS service codes typically follow patterns l |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | module = importlib.import_module(module_path) |
| `fixtures.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | DestinationPrefix/StorageLens/123456789012/my-dashboard-configuration-id/V_1/rep |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `server.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` |  Based on the following AWS services and their relationships: - Services: {servi |
| `models.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | AWS region(s) - single region string (e.g., "us-east-1") or list for multi-regio |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `trace_tools.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | . Transaction Search requires sending traces to CloudWatch Logs (destination='Cl |
| `validation_prompts.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | You are evaluating code changes for a software modification task.  **Validation  |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `server.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | Basic FHIR search parameters. Supports modifiers (e.g., 'name:contains'), prefix |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `llm_context.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | Amazon Keyspaces doesn't support all Apache Cassandra 3.11 features. Unsupported |
| `client.py` | python | **WARN** | 0.579 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003` | SELECT * FROM system_schema.tables WHERE keyspace_name = %s AND table_name = %s |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `conftests.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | Support case created successfully with ID: case-12345678910-2013-c4c1d2bf33c5cf4 |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `esm_guidance.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | 5. Attach AWS policy AWSLambdaDynamoDBExecutionRole to the Lambda function if th |
| `esm_diagnosis.py` | python | **WARN** | 0.726 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | Use AWS CLI to get the error message (LastProcessingResult) from ESM:            |
| `deploy_serverless_app_help.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | Build the package. Analyze the project structure to determine the build command. |
| `get_lambda_guidance.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | Lambda has limits on memory (10GB) and CPU allocation, making it unsuitable for  |
| `get_iac_guidance.py` | python | **WARN** | 0.660 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | AWS CDK is an open-source software development framework that allows you to defi |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `templates.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | Include license information from the repository. Check for LICENSE or LICENSE.md |
| `doc_generator.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | <!-- PLACEHOLDER: Replace this with an AWS architecture diagram generated using  |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `consts.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` |  ## AWS Client Best Practices  ### Authentication and Configuration  - Default A |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `sitewise_data.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | Create a bulk import job to ingest data from Amazon S3 to AWS IoT SiteWise. Supp |
| `data_exploration.py` | python | **WARN** | 0.726 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` |   ## AWS IoT SiteWise Query Language Overview  The executeQuery API supports SQL |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `postgresql.py` | python | **WARN** | 0.660 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | SELECT   pst.relname as table_name,   pst.n_live_tup as row_count,   pg_total_re |
| `sqlserver.py` | python | **WARN** | 0.660 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | SELECT   t.name as table_name,   MAX(p.rows) as row_count,   SUM(CASE WHEN idx.i |
| `mysql.py` | python | **WARN** | 0.726 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | SELECT   t.TABLE_NAME as `table_name`,   t.TABLE_ROWS as `row_count`,   t.AVG_RO |
| `evaluation_registry.py` | python | **WARN** | 0.660 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | Score 1-10: Evaluate if guidance addresses ALL scenario elements: (1) All entiti |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | __path__ = __import__('pkgutil').extend_path(__path__, __name__) |

### 🔴 BLOCK — [bright8192__esxi-mcp-server](https://github.com/bright8192/esxi-mcp-server)

Python files: 1 | Markdown files: 3 | Tools: 7  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.998 | — | `SC-004`, `SC-008`, `SC-008`, `SC-003`, `SC-008`, `PE-008`, `PE-DELTA-001` | 5 dependency entries without hash pinning |

### 🔴 BLOCK — [elevy99927__devops-mcp-webui](https://github.com/elevy99927/devops-mcp-webui)

Python files: 1 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `bridge.py` | python | **BLOCK** | 0.998 | — | `SC-004`, `SC-008`, `SC-008`, `PE-003`, `PE-003`, `PE-007`, `PE-DELTA-001` | 4 dependency entries without hash pinning |

### 🔴 BLOCK — [erikhoward__adls-mcp-server](https://github.com/erikhoward/adls-mcp-server)

Python files: 7 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | level=os.getenv("LOG_LEVEL", "INFO"), |
| `client.py` | python | **BLOCK** | 0.948 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-007`, `PE-008`, `PE-DELTA-001` | storage_account_name = os.environ.get("AZURE_STORAGE_ACCOUNT_NAME") |
| `filesystems.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO")) |

### 🔴 BLOCK — [Flux159__mcp-server-kubernetes](https://github.com/Flux159/mcp-server-kubernetes)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `ADVANCED_README.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | pattern_match; variant=raw; (will fail with 401) curl -x post http://localhost:3 |
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # mcp server kubernetes [![ci](https://githu |

### 🔴 BLOCK — [johnneerdael__netskope-mcp](https://github.com/johnneerdael/netskope-mcp)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `real-world-examples.md` | markdown | **BLOCK** | 0.699 | — | `PI-001` | override_authority_template; variant=raw; # real-world examples this document pr |

### 🔴 BLOCK — [kestra-io__mcp-server-python](https://github.com/kestra-io/mcp-server-python)

Python files: 16 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.928 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | base = os.getenv("KESTRA_BASE_URL", "http://localhost:8080/api/v1") |
| `backfill.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if tenant := os.getenv("KESTRA_TENANT_ID"): |
| `ee.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | tenant = os.getenv("KESTRA_TENANT_ID") |
| `ee.md` | markdown | **WARN** | 0.484 | — | `PI-002` | role_reassignment_template; variant=raw; invite a user with email alice@example. |

### 🔴 BLOCK — [manusa__kubernetes-mcp-server](https://github.com/manusa/kubernetes-mcp-server)

Python files: 4 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D U+200D |
| `kubernetes_mcp_server.py` | python | **BLOCK** | 0.990 | — | `PE-003`, `EX-001`, `PE-DELTA-001` | process = subprocess.run(cmd) |

### 🔴 BLOCK — [Nebula-Block-Data__nebulablock-mcp-server](https://github.com/Nebula-Block-Data/nebulablock-mcp-server)

Python files: 5 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `tools.py` | python | **BLOCK** | 0.971 | — | `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get(f"{api_url}/api/v1/{endpoint}", headers=headers, params= |

### 🔴 BLOCK — [openstack-kr__python-openstackmcp-server](https://github.com/openstack-kr/python-openstackmcp-server)

Python files: 27 | Markdown files: 5 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `config.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | MCP_TRANSPORT: str = os.environ.get("TRANSPORT", "stdio") |

### 🔴 BLOCK — [pibblokto__cert-manager-mcp-server](https://github.com/pibblokto/cert-manager-mcp-server)

Python files: 18 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `config.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |

### 🔴 BLOCK — [portainer__portainer-mcp](https://github.com/portainer/portainer-mcp)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.909 | — | `PI-001`, `PI-004` | override_authority_template; variant=raw; # portainer mcp [![go report card](htt |

### 🔴 BLOCK — [pythonanywhere__pythonanywhere-mcp-server](https://github.com/pythonanywhere/pythonanywhere-mcp-server)

Python files: 8 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | API_TOKEN = os.getenv("API_TOKEN") |

### 🔴 BLOCK — [qiniu__qiniu-mcp-server](https://github.com/qiniu/qiniu-mcp-server)

Python files: 29 | Markdown files: 3 | Tools: 24  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `config.py` | python | **BLOCK** | 0.945 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | bucket_list = os.getenv(_CONFIG_ENV_KEY_BUCKETS) |

### 🔴 BLOCK — [rohitg00__kubectl-mcp-server](https://github.com/rohitg00/kubectl-mcp-server)

Python files: 68 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # kubernetes deployment this directory conta |
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # kubectl-mcp-server evals framework this di |
| `setup.py` | python | **BLOCK** | 1.000 | — | `SC-004`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `PE-DELTA-001` | 19 dependency entries without hash pinning |
| `setup_legacy.py` | python | **BLOCK** | 1.000 | — | `SC-004`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | 19 dependency entries without hash pinning |
| `crd_detector.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(cmd, capture_output=True, text=True, timeout=30) |
| `diagnostics.py` | python | **BLOCK** | 0.996 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `k8s_config.py` | python | **BLOCK** | 0.928 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | kubeconfig_env = os.environ.get('KUBECONFIG', '~/.kube/config') |
| `providers.py` | python | **BLOCK** | 0.945 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | kubeconfig_path = os.environ.get( |
| `mcp_server.py` | python | **BLOCK** | 0.995 | — | `PE-008`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-003`, `PE-003`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | _log_file = os.environ.get("MCP_LOG_FILE") |
| `find-overprovisioned.py` | python | **BLOCK** | 0.900 | — | `EX-001`, `EX-001`, `PE-DELTA-001` | cpu_request = parse_cpu(requests.get("cpu", "0")) |
| `kind.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-008`, `PE-DELTA-001` | provider = os.environ.get("KIND_EXPERIMENTAL_PROVIDER", "docker") |
| `cilium.py` | python | **BLOCK** | 0.996 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(["cilium", "version"], capture_output=True, timeout=5) |
| `backup.py` | python | **BLOCK** | 0.999 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(["velero", "version", "--client-only"], |
| `capi.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run(["clusterctl", "version"], capture_output=True, timeout= |
| `vind.py` | python | **BLOCK** | 0.987 | — | `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `_cli_utils.py` | python | **BLOCK** | 0.987 | — | `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `ui.py` | python | **BLOCK** | 1.000 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-008`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `EX-003`, `PE-DELTA-001` |  :root {     --bg-primary: #1e1e2e;     --bg-secondary: #313244;     --bg-tertia |
| `kubevirt.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(["virtctl", "version", "--client"], |
| `diagnostics.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(cmd, capture_output=True, text=True, timeout=60) |
| `certs.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | check = subprocess.run(["cmctl", "version"], capture_output=True, timeout=5) |
| `core.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run(cmd, capture_output=True, text=True, timeout=30) |
| `browser.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | MCP_BROWSER_PROVIDER = os.environ.get("MCP_BROWSER_PROVIDER") |
| `operations.py` | python | **BLOCK** | 1.000 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(cmd, capture_output=True, text=True, timeout=30) |
| `networking.py` | python | **BLOCK** | 0.996 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | dns_result = subprocess.run(dns_cmd, capture_output=True, text=True, timeout=30) |
| `utils.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout) |
| `cluster.py` | python | **BLOCK** | 1.000 | — | `EX-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | ': must be a valid DNS-1123 subdomain (lowercase alphanumeric, '-' or '.', must  |
| `deployments.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(cmd, capture_output=True, text=True, timeout=30) |
| `kiali.py` | python | **BLOCK** | 0.995 | — | `PE-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(["istioctl", "version", "--remote=false"], |
| `cost.py` | python | **BLOCK** | 1.000 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `EX-001`, `EX-001`, `PE-DELTA-001` | result = subprocess.run(cmd, capture_output=True, text=True, timeout=60) |
| `helm.py` | python | **BLOCK** | 1.000 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | subprocess.check_output( |
| `rollouts.py` | python | **BLOCK** | 0.999 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(["kubectl", "argo", "rollouts", "version"], |
| `pods.py` | python | **BLOCK** | 0.996 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(cmd, capture_output=True, text=True, timeout=60) |
| `loader.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | xdg_config = os.environ.get("XDG_CONFIG_HOME") |
| `config.py` | python | **BLOCK** | 0.928 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | issuer_url=os.environ.get("MCP_AUTH_ISSUER"), |
| `resources.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `helpers.py` | python | **BLOCK** | 0.977 | — | `PE-008`, `PE-003`, `PE-008`, `PE-003`, `PE-DELTA-001` | _log_file = os.environ.get("MCP_LOG_FILE") |
| `cli.py` | python | **BLOCK** | 0.998 | — | `PE-008`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-008`, `PE-008`, `PE-DELTA-001` | log_file = os.environ.get("MCP_LOG_FILE") |
| `output.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if os.environ.get("NO_COLOR"): |
| `tracing.py` | python | **BLOCK** | 0.945 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | sampler_arg = os.environ.get("OTEL_TRACES_SAMPLER_ARG", "1.0") |
| `custom.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `prompts.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-DELTA-001` | env_path = os.environ.get("MCP_PROMPTS_FILE") |
| `builtin.py` | python | **WARN** | 0.726 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | Perform a comprehensive health check of the Kubernetes cluster{{#namespace}} in  |

### 🔴 BLOCK — [rrmistry__tilt-mcp](https://github.com/rrmistry/tilt-mcp)

Python files: 4 | Markdown files: 5 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-008`, `PE-003`, `PE-003`, `PE-008`, `PE-008`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | log_file_path = os.getenv('TILT_MCP_LOG_FILE') |

### 🔴 BLOCK — [spre-sre__lumino-mcp-server](https://github.com/spre-sre/lumino-mcp-server)

Python files: 12 | Markdown files: 8 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `LUMINO_MCP_TOOL_DEVELOPMENT_GUIDE.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # lumino mcp tool development guide ## 1. ov |
| `main.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if os.getenv('KUBERNETES_NAMESPACE') or os.getenv('K8S_NAMESPACE'): |
| `server-mcp.py` | python | **BLOCK** | 0.978 | — | `PE-008`, `PE-008`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-008`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-DELTA-001` | env_thanos_url = os.getenv("THANOS_URL") |
| `ml_persistence.py` | python | **BLOCK** | 0.953 | — | `PE-008`, `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | api_server = os.environ.get('KUBERNETES_SERVICE_HOST', '') |
| `semantic_search.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | ^(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z\|[+-]\d{2}:\d{2})?\s+)? |

### 🔴 BLOCK — [StacklokLabs__mkp](https://github.com/StacklokLabs/mkp)

Python files: 0 | Markdown files: 5 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # mkp - model kontext protocol server for ku |

### 🔴 BLOCK — [strowk__mcp-k8s-go](https://github.com/strowk/mcp-k8s-go)

Python files: 0 | Markdown files: 4 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; <h4 align="center">golang-based mcp server c |

### 🔴 BLOCK — [trilogy-group__aws-pricing-mcp](https://github.com/trilogy-group/aws-pricing-mcp)

Python files: 3 | Markdown files: 5 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `lambda_handler.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | with urllib.request.urlopen(pricing_url) as response: |

### 🔴 BLOCK — [txn2__kubefwd](https://github.com/txn2/kubefwd)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CLAUDE.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # claude.md this file provides guidance to c |
| `api-reference.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # rest api kubefwd's rest api enables progra |

### 🔴 BLOCK — [alfonsograziano__node-code-sandbox-mcp](https://github.com/alfonsograziano/node-code-sandbox-mcp)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `speckit.analyze.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; --- description: perform a non-destructive c |
| `speckit.constitution.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; --- description: create or update the projec |

### 🔴 BLOCK — [gwbischof__outsource-mcp](https://github.com/gwbischof/outsource-mcp)

Python files: 2 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # outsource mcp an mcp (model context protoc |
| `server.py` | python | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # outsource mcp an mcp (model context protoc |
| `__init__.py` | python | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # outsource mcp an mcp (model context protoc |

### 🔴 BLOCK — [hileamlakB__PRIMS](https://github.com/hileamlakB/PRIMS)

Python files: 22 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `config.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | TMP_DIR = Path(os.getenv("PRIMCS_TMP_DIR", "/tmp/primcs")) |
| `main.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | port = int(os.getenv("PORT", "9000")) |
| `session_persistence.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` |  import pandas as pd # Dataset was downloaded via `files` parameter. df = pd.rea |

### 🔴 BLOCK — [pydantic__pydantic-ai](https://github.com/pydantic/pydantic-ai)

Python files: 305 | Markdown files: 10 | Tools: 26  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; <div align="center"> <a href="https://ai.pyd |
| `update_readme.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `set_docs_pr_preview_url.py` | python | **BLOCK** | 0.946 | — | `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | r = httpx.get(comments_url, headers=gh_headers) |
| `set_docs_main_preview_url.py` | python | **BLOCK** | 0.900 | — | `EX-001`, `EX-001`, `PE-DELTA-001` | r = httpx.post(deployment_url, headers=gh_headers, json=deployment_data) |
| `cerebras.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('CEREBRAS_API_KEY') |
| `gateway.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('PYDANTIC_AI_GATEWAY_API_KEY', os.getenv('PAIG_AP |
| `moonshotai.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('MOONSHOTAI_API_KEY') |
| `vercel.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('VERCEL_AI_GATEWAY_API_KEY') or os.getenv('VERCEL |
| `mistral.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('MISTRAL_API_KEY') |
| `sambanova.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('SAMBANOVA_API_KEY') |
| `openrouter.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('OPENROUTER_API_KEY') |
| `azure.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | azure_endpoint = azure_endpoint or os.getenv('AZURE_OPENAI_ENDPOINT') |
| `grok.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('GROK_API_KEY') |
| `voyageai.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('VOYAGE_API_KEY') |
| `google.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('GOOGLE_API_KEY') or os.getenv('GEMINI_API_KEY') |
| `groq.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('GROQ_API_KEY') |
| `heroku.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('HEROKU_INFERENCE_KEY') |
| `google_gla.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('GEMINI_API_KEY') |
| `fireworks.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('FIREWORKS_API_KEY') |
| `huggingface.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('HF_TOKEN') |
| `deepseek.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('DEEPSEEK_API_KEY') |
| `anthropic.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('ANTHROPIC_API_KEY') |
| `xai.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('XAI_API_KEY') |
| `together.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('TOGETHER_API_KEY') |
| `alibaba.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('ALIBABA_API_KEY') or os.getenv('DASHSCOPE_API_KE |
| `github.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('GITHUB_API_KEY') |
| `cohere.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | base_url = os.getenv('CO_BASE_URL') |
| `nebius.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('NEBIUS_API_KEY') |
| `ollama.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | base_url = base_url or os.getenv('OLLAMA_BASE_URL') |
| `bedrock.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('AWS_BEARER_TOKEN_BEDROCK') |
| `ovhcloud.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = api_key or os.getenv('OVHCLOUD_API_KEY') |
| `app.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | base = Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData' / 'Local')) |
| `xai_proto_cassettes.py` | python | **BLOCK** | 0.911 | — | `PE-005`, `PE-008`, `PE-005`, `PE-DELTA-001` | os = __import__('os') |
| `algolia.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if not os.getenv('CI'): |
| `pydantic_model.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | model = os.getenv('PYDANTIC_AI_MODEL', 'openai:gpt-5.2') |
| `__main__.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(dst / file.name, 'wb') as dst_file: |
| `slack.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | API_KEY = os.getenv('SLACK_API_KEY') |
| `import_examples.py` | python | **WARN** | 0.417 | — | `PE-005` | __import__(f'pydantic_ai_examples.{example.stem}') |
| `bank_database.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` |  CREATE TABLE customers (     id INT PRIMARY KEY,     name TEXT NOT NULL );  INS |
| `main.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | ```bash\n(.*?)(python/uv[\- ]run\|pip/uv[\- ]add\|py-cli)(.+?)\n``` |
| `llm_as_a_judge.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` |          You are grading output according to a user-specified rubric. If the sta |
| `sql_gen.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | SELECT * FROM records WHERE start_timestamp::date > CURRENT_TIMESTAMP - INTERVAL |
| `rag.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` |  CREATE EXTENSION IF NOT EXISTS vector;  CREATE TABLE IF NOT EXISTS doc_sections |

### 🔴 BLOCK — [r33drichards__mcp-js](https://github.com/r33drichards/mcp-js)

Python files: 1 | Markdown files: 9 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `replace-workspace-values.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(sys.argv[1], "wb") as f: |

### 🔴 BLOCK — [agentic-mcp-tools__owlex](https://github.com/agentic-mcp-tools/owlex)

Python files: 17 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.869 | — | `EX-003`, `EX-003`, `PE-008`, `PE-008`, `PE-DELTA-001` | OPENROUTER_API_KEY or CLAUDEOR_API_KEY environment variable not set |
| `config.py` | python | **BLOCK** | 0.997 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | exclude_raw = os.environ.get("COUNCIL_EXCLUDE_AGENTS", "") |
| `roles.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `claudeor.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | or os.environ.get("OPENROUTER_API_KEY") |
| `opencode.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |

### 🔴 BLOCK — [alpadalar__netops-mcp](https://github.com/alpadalar/netops-mcp)

Python files: 34 | Markdown files: 6 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `API_AUTHENTICATION.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; ## using api-key header another option is the `api-k |
| `generate_api_key.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(config_path, 'w') as f: |
| `server_http.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(health_file, 'w') as f: |
| `server.py` | python | **BLOCK** | 0.931 | — | `PE-008`, `PE-003`, `PE-008`, `PE-DELTA-001` | config_path = args.config or os.getenv("NETOPS_MCP_CONFIG") |
| `base.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `loader.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `system_check.py` | python | **BLOCK** | 1.000 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(['ping', '-c', '1', '-W', '5', host], |
| `http_tools.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |

### 🔴 BLOCK — [automateyournetwork__pyATS_MCP](https://github.com/automateyournetwork/pyATS_MCP)

Python files: 1 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `pyats_mcp_server.py` | python | **BLOCK** | 0.999 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-003`, `PE-DELTA-001` | 4 dependency entries without hash pinning |

### 🔴 BLOCK — [aymericzip__intlayer](https://github.com/aymericzip/intlayer)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `environment_angular.md` | markdown | **BLOCK** | 0.829 | — | `PI-009`, `PI-001` | pattern_match; variant=raw; an angular application <tabs defaulttab="code"> <tab |
| `environment_astro.md` | markdown | **BLOCK** | 0.829 | — | `PI-009`, `PI-001` | pattern_match; variant=raw; detection and switching. --- ## step-by-step guide t |

### 🔴 BLOCK — [spyrae__claude-concilium](https://github.com/spyrae/claude-concilium)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `customization.md` | markdown | **BLOCK** | 0.909 | — | `PI-001`, `PI-004` | override_authority_template; variant=raw; # customization ## adding your own llm |
| `setup-gemini.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # gemini setup (gemini-cli) ## prerequisites |
| `setup-openai.md` | markdown | **BLOCK** | 0.900 | — | `PI-001`, `PI-004` | override_authority_template; variant=raw; # openai setup (codex cli) ## prerequi |
| `setup-qwen.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # qwen setup ## prerequisites - node.js 18+  |

### 🔴 BLOCK — [ezyang__codemcp](https://github.com/ezyang/codemcp)

Python files: 41 | Markdown files: 8 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CONTRIBUTING.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # contributing here's the deal: i don't want |
| `config.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `line_endings.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `code_command.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `rules.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `main.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-008`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-007`, `PE-003`, `PE-003`, `PE-DELTA-001` | if os.environ.get("DESKAID_DEBUG"): |
| `testing.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(readme_path, "w") as f:  # noqa: ASYNC230 |
| `grep.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | if not os.environ.get("DESKAID_TESTING"): |

### 🔴 BLOCK — [elhamid__llm-council](https://github.com/elhamid/llm-council)

Python files: 26 | Markdown files: 10 | Tools: 3  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CLAUDE.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; n.py`** - fastapi app with cors enabled for localhos |
| `CODEX_TASK.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # codex_task.md -- build the llm council mcp |
| `stage2_eval_run.py` | python | **BLOCK** | 0.896 | — | `EX-001`, `PE-007`, `PE-DELTA-001` | with urllib.request.urlopen(req, timeout=timeout) as r: |
| `stage2_accuracy.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `council.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-008`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-008`, `EX-003`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | CHAIRMAN_MODEL = os.getenv("CHAIRMAN_MODEL", "anthropic/claude-opus-4.5") |
| `config.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | return (os.getenv(name) or default).strip() |
| `__init__.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY") |
| `storage.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(tmp_file, "w", encoding="utf-8") as f: |
| `main.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | has_key = bool((cfg.openrouter_api_key or "").strip() or (os.getenv("OPENROUTER_ |
| `tools.py` | python | **BLOCK** | 0.926 | — | `PE-008`, `EX-003`, `EX-003`, `PE-007`, `PE-008`, `PE-DELTA-001` | "contract_stack": os.getenv("COUNCIL_CONTRACTS", "factory_truth_v1"), |
| `mcp_server.py` | python | **BLOCK** | 0.863 | — | `EX-003`, `EX-003`, `EX-003`, `PE-008`, `PE-DELTA-001` | ⚠️ HIGH COST - Calls multiple LLMs (10+ API calls per deliberation). Use ONLY fo |
| `council.py` | python | **BLOCK** | 0.955 | — | `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | JUDGES DISAGREE. Act as the adjudicator to break the tie. Use the same strict 5- |
| `models.py` | python | **BLOCK** | 0.907 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | env = os.getenv("COUNCIL_MODELS", "").strip() |
| `prompts.py` | python | **BLOCK** | 0.779 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | STAGE 2 EVALUATION MODE. You are grading anonymous answers for a product team: c |
| `contracts.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | You are running inside a product-agnostic LLM Council factory. Factory Contract  |
| `contracts.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | You are running inside a product-agnostic LLM Council factory. Factory Contract  |

### 🔴 BLOCK — [g0t4__mcp-server-commands](https://github.com/g0t4/mcp-server-commands)

Python files: 0 | Markdown files: 4 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; ## `runprocess` renaming/redesign recently i |

### 🔴 BLOCK — [gabrielmaialva33__winx-code-agent](https://github.com/gabrielmaialva33/winx-code-agent)

Python files: 2 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `mcp_tools_benchmark.py` | python | **BLOCK** | 0.999 | — | `EX-003`, `EX-003`, `PE-003`, `PE-007`, `PE-007`, `PE-007`, `PE-003`, `PE-003`, `PE-DELTA-001` |  import time import json  start = time.perf_counter()  # Import WCGW from wcgw.c |
| `mcp_benchmark.py` | python | **BLOCK** | 0.999 | — | `PE-007`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-007`, `PE-007`, `PE-DELTA-001` | with open(TEST_DIR / "large.txt", "w") as f: |

### 🔴 BLOCK — [irskep__persistproc](https://github.com/irskep/persistproc)

Python files: 20 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `helpers.py` | python | **BLOCK** | 0.987 | — | `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | return subprocess.run(cmd, text=True, capture_output=True, check=False) |
| `client.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | def make_client(port: str = os.getenv("PERSISTPROC_PORT", 8000)): |
| `cli.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | default=os.environ.get("PERSISTPROC_FORMAT", "text"), |
| `process_manager.py` | python | **BLOCK** | 0.911 | — | `PE-008`, `PE-003`, `PE-DELTA-001` | _POLL_INTERVAL = float(os.environ.get("PERSISTPROC_TEST_POLL_INTERVAL", "1.0")) |
| `update_docs_help.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |

### 🔴 BLOCK — [jinzcdev__leetcode-mcp-server](https://github.com/jinzcdev/leetcode-mcp-server)

Python files: 0 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200B U+200B U+200B |
| `README_zh-CN.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200B |

### 🔴 BLOCK — [mediar-ai__terminator](https://github.com/mediar-ai/terminator)

Python files: 12 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `gnome-calculator.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | output = subprocess.check_output(["gnome-calculator", "--version"], text=True, s |
| `update_wheel_metadata.py` | python | **BLOCK** | 0.989 | — | `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | with open(record_path, 'w', encoding='utf-8') as f: |

### 🔴 BLOCK — [MladenSU__cli-mcp-server](https://github.com/MladenSU/cli-mcp-server)

Python files: 3 | Markdown files: 1 | Tools: 2  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.992 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-003`, `PE-003`, `PE-008`, `PE-008`, `PE-DELTA-001` | allowed_commands = os.getenv("ALLOWED_COMMANDS", "ls,cat,pwd") |

### 🔴 BLOCK — [nesquikm__mcp-rubber-duck](https://github.com/nesquikm/mcp-rubber-duck)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `pricing-updater.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; --- name: pricing-updater description: use t |

### 🔴 BLOCK — [nihalxkumar__arch-mcp](https://github.com/nihalxkumar/arch-mcp)

Python files: 15 | Markdown files: 1 | Tools: 22  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `system.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `server.py` | python | **BLOCK** | 0.999 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | [DISCOVERY] Search the Arch Wiki for documentation. Returns a list of matching p |
| `config.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `http_server.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | port = int(os.getenv("PORT", port)) |
| `utils.py` | python | **BLOCK** | 0.910 | — | `EX-003`, `PE-004`, `PE-DELTA-001` | ⚠️  AUR PACKAGE WARNING ⚠️ AUR packages are USER-PRODUCED content and are not of |
| `logs.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `mirrors.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `news.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |

### 🔴 BLOCK — [ooples__mcp-console-automation](https://github.com/ooples/mcp-console-automation)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # console automation mcp server **production |
| `ENHANCED_STREAMING_API.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # enhanced streaming api specification ## ov |
| `EXAMPLES.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # mcp console automation - practical example |
| `INTEGRATION_GUIDE.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # enhanced streaming integration guide ## ov |

### 🔴 BLOCK — [oraios__serena](https://github.com/oraios/serena)

Python files: 163 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `repo_dir_sync.py` | python | **BLOCK** | 1.000 | — | `PI-005`, `PE-004`, `EX-003`, `PE-007`, `PE-004`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-004`, `PE-004`, `PE-DELTA-001` | pattern_match; variant=raw; thank_me_later/), providing an enormous [productivit |
| `autogen_rst.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(path, "w") as f: |
| `create_toc.py` | python | **BLOCK** | 0.889 | — | `PE-004`, `PE-DELTA-001` | os.system(cmd) |
| `run_app.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `ls_process.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | self.process = subprocess.Popen( |
| `ls_utils.py` | python | **BLOCK** | 1.000 | — | `PE-006`, `PE-006`, `EX-001`, `PE-003`, `PE-007`, `PE-003`, `PE-007`, `PE-007`, `PE-DELTA-001` | import ctypes |
| `symbol.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `dashboard.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(config_path, "w", encoding="utf-8") as f: |
| `code_editor.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(abs_path, "w", encoding=self.encoding) as f: |
| `cli.py` | python | **BLOCK** | 0.998 | — | `PE-008`, `PE-003`, `PE-003`, `PE-003`, `PE-007`, `PE-003`, `PE-DELTA-001` | editor = os.environ.get("EDITOR") |
| `agent.py` | python | **BLOCK** | 0.911 | — | `PE-003`, `PE-008`, `PE-DELTA-001` | subprocess.Popen( |
| `project.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(memory_file_path, "w", encoding=self._encoding) as f: |
| `multilang_prompt.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `prompt_factory.py` | python | **BLOCK** | 0.846 | — | `EX-003`, `PE-007`, `PE-DELTA-001` |  # ruff: noqa # black: skip # mypy: ignore-errors  # NOTE: This module is auto-g |
| `zip.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with zip_ref.open(member) as source, open(final_path, "wb") as target: |
| `perl_language_server.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(["perl", "-v"], capture_output=True, text=True, check=Fa |
| `systemverilog_server.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `nixd_ls.py` | python | **BLOCK** | 0.996 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(["nixd", "--version"], capture_output=True, text=True, c |
| `eclipse_jdtls.py` | python | **BLOCK** | 0.953 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-008`, `PE-DELTA-001` | -XX:+UseParallelGC -XX:GCTimeRatio=4 -XX:AdaptiveSizePolicyWeight=90 -Dsun.zip.d |
| `scala_language_server.py` | python | **BLOCK** | 0.987 | — | `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | subprocess.run(["mkdir", "-p", os.path.join(metals_home, metals_version)], check |
| `csharp_language_server.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(cmd, capture_output=True, text=True, check=True) |
| `solargraph.py` | python | **BLOCK** | 0.987 | — | `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(["ruby", "--version"], check=True, capture_output=True,  |
| `typescript_language_server.py` | python | **BLOCK** | 0.853 | — | `PE-007`, `PE-008`, `PE-DELTA-001` | with open(version_file, "w") as f: |
| `sourcekit_lsp.py` | python | **BLOCK** | 0.947 | — | `PE-003`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | result = subprocess.run(["sourcekit-lsp", "-h"], capture_output=True, text=True, |
| `ruby_lsp.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(ruby_cmd + ["--version"], check=True, capture_output=Tru |
| `elm_language_server.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | elm_home = os.environ.get("ELM_HOME") |
| `lua_ls.py` | python | **BLOCK** | 0.896 | — | `EX-001`, `PE-007`, `PE-DELTA-001` | response = requests.get(download_url, stream=True) |
| `zls.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(["zig", "version"], capture_output=True, text=True, chec |
| `matlab_language_server.py` | python | **BLOCK** | 0.938 | — | `PE-008`, `PE-008`, `EX-001`, `PE-007`, `PE-DELTA-001` | env_path = os.environ.get("MATLAB_EXTENSION_PATH") |
| `clangd_language_server.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(compile_commands_path, "w", encoding="utf-8") as f: |
| `terraform_ls.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | terraform_cli_path = os.environ.get("TERRAFORM_CLI_PATH") |
| `erlang_language_server.py` | python | **BLOCK** | 0.990 | — | `PE-003`, `PE-003`, `PE-003`, `PE-008`, `PE-DELTA-001` | result = subprocess.run(["erl", "-version"], check=False, capture_output=True, t |
| `taplo_server.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(executable_path, "wb") as f_out: |
| `common.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | completed_process = subprocess.run( |
| `phpactor.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run(["php", "--version"], capture_output=True, text=True, ch |
| `clojure_lsp.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | return subprocess.run( |
| `fsharp_language_server.py` | python | **BLOCK** | 0.987 | — | `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run([dotnet_exe, "--version"], capture_output=True, text=Tru |
| `intelephense.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | license_key = os.environ.get("INTELEPHENSE_LICENSE_KEY") |
| `omnisharp.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `al_language_server.py` | python | **BLOCK** | 0.970 | — | `EX-003`, `PE-008`, `PE-008`, `EX-001`, `PE-007`, `PE-008`, `PE-008`, `PE-DELTA-001` | ^(?:Table\|Page\|Codeunit\|Enum\|Interface\|Report\|Query\|XMLPort\|PermissionSe |
| `julia_server.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(check_cmd, check=False, capture_output=True, text=True,  |
| `rust_analyzer.py` | python | **BLOCK** | 0.992 | — | `EX-003`, `PE-003`, `PE-003`, `PE-003`, `PE-008`, `PE-DELTA-001` | ${env:USERPROFILE}/.rustup/toolchains/<toolchain-id>/lib/rustlib/src/rust |
| `gopls.py` | python | **BLOCK** | 0.970 | — | `PE-003`, `PE-003`, `PE-008`, `PE-DELTA-001` | result = subprocess.run(["go", "version"], capture_output=True, text=True, check |
| `vue_language_server.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(version_file, "w") as f: |
| `pascal_server.py` | python | **BLOCK** | 0.999 | — | `PE-008`, `PE-008`, `EX-001`, `PE-007`, `PE-007`, `EX-001`, `PE-007`, `PE-007`, `EX-001`, `PE-007`, `PE-007`, `PE-DELTA-001` | github_token = os.environ.get("GITHUB_TOKEN") |
| `r_language_server.py` | python | **BLOCK** | 0.968 | — | `EX-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | R --vanilla --quiet --slave -e "options(languageserver.debug_mode = FALSE); lang |
| `powershell_language_server.py` | python | **BLOCK** | 0.950 | — | `EX-003`, `EX-001`, `PE-007`, `PE-008`, `PE-008`, `PE-DELTA-001` | ' -HostName 'SolidLSP' -HostProfileId 'solidlsp' -HostVersion '1.0.0' -BundledMo |
| `elixir_tools.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run(["elixir", "--version"], capture_output=True, text=True, |
| `exception.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | if not os.environ.get("DISPLAY"):  # type: ignore |
| `text_utils.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `shell.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | process = subprocess.Popen( |
| `yaml.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(path, "w", encoding=SERENA_FILE_ENCODING) as f: |
| `file_system.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `gui.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | display = os.environ.get("DISPLAY", "") |
| `serena_config.py` | python | **BLOCK** | 0.853 | — | `PE-008`, `PE-007`, `PE-DELTA-001` | home_dir = os.getenv("SERENA_HOME") |
| `sync.py` | python | **WARN** | 0.396 | — | `PI-005` | pattern_match; variant=raw; thank_me_later/), providing an enormous [productivit |
| `gui_log_viewer.py` | python | **WARN** | 0.438 | — | `PE-006` | import ctypes |

### 🔴 BLOCK — [OthmaneBlial__term_mcp_deepseek](https://github.com/OthmaneBlial/term_mcp_deepseek)

Python files: 22 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 1.000 | — | `PI-005`, `SC-004`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `EX-001`, `EX-001`, `PE-DELTA-001` | pattern_match; variant=raw; deepseek mcp-like server for terminal [![trust score |
| `config.py` | python | **BLOCK** | 1.000 | — | `PI-005`, `SC-004`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | pattern_match; variant=raw; deepseek mcp-like server for terminal [![trust score |
| `stdio_server.py` | python | **BLOCK** | 0.995 | — | `PI-005`, `SC-004`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; deepseek mcp-like server for terminal [![trust score |
| `server_new.py` | python | **BLOCK** | 0.995 | — | `PI-005`, `SC-004`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; deepseek mcp-like server for terminal [![trust score |
| `config_new.py` | python | **BLOCK** | 0.999 | — | `PI-005`, `SC-004`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | pattern_match; variant=raw; deepseek mcp-like server for terminal [![trust score |
| `mcp_server.py` | python | **BLOCK** | 1.000 | — | `PI-005`, `SC-004`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-003`, `PE-DELTA-001` | pattern_match; variant=raw; deepseek mcp-like server for terminal [![trust score |
| `deepseek_client.py` | python | **BLOCK** | 0.941 | — | `PE-008`, `PE-008`, `EX-001`, `EX-001`, `PE-DELTA-001` | DEEPSEEK_BASE = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com") |
| `README.md` | markdown | **WARN** | 0.420 | — | `PI-005` | pattern_match; variant=raw; deepseek mcp-like server for terminal [![trust score |

### 🔴 BLOCK — [religa__multi_mcp](https://github.com/religa/multi_mcp)

Python files: 147 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `compare.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # role you are a senior technical expert, co |
| `validate_bug_detection.py` | python | **BLOCK** | 0.789 | — | `EX-003`, `PE-008`, `PE-DELTA-001` | Perform comprehensive security review focusing on SQL injection, password securi |
| `settings.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | if self.azure_api_version and not os.getenv("AZURE_API_VERSION"): |
| `load_balancer.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `retry_policy.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | ENABLE_JITTER = os.getenv('ENABLE_JITTER', 'false').lower() == 'true' |
| `registry.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(self._persistence_path, 'w') as f: |
| `health.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = urllib.request.urlopen( |
| `storage.py` | python | **BLOCK** | 0.680 | — | `PE-002` | exec(f"local_value = {raw}", {}, local) |
| `config.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `engine.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `serializer.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(state_file, 'w') as f: |
| `files.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `log_helpers.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(filepath, "w", encoding="utf-8") as f: |
| `config.py` | python | **BLOCK** | 0.726 | — | `EX-003`, `PE-DELTA-001` |   To fix: 1. Validate YAML syntax: python -c "import yaml; yaml.safe_load(open(' |
| `plugin_loader.py` | python | **WARN** | 0.660 | — | `PE-005`, `PE-005` | module = importlib.import_module(module_path) |
| `codereview.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | # Code Review Checklist - Step 1  Complete this checklist, then call step 2 with |

### 🔴 BLOCK — [rinadelph__Agent-MCP](https://github.com/rinadelph/Agent-MCP)

Python files: 69 | Markdown files: 10 | Tools: 1  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `AGENT_MCP_COMPARISON_ANALYSIS.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # agent-mcp implementation comparison: pytho |
| `LOCAL_EMBEDDINGS_GUIDE.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # local embeddings setup guide for agent-mcp |
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; /auth/register endpoint 2.2: implement post /auth/lo |
| `cli.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | api_key = os.environ.get('OPENAI_API_KEY') |
| `__main__.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | print(f"OPENAI_API_KEY in environment: {os.environ.get('OPENAI_API_KEY', 'NOT FO |
| `admin_tools.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | project_dir_env = os.environ.get("MCP_PROJECT_DIR") |
| `task_tools.py` | python | **BLOCK** | 0.977 | — | `PE-008`, `PE-008`, `PE-008`, `PE-003`, `PE-008`, `PE-007`, `PE-DELTA-001` | project_dir_env = os.environ.get("MCP_PROJECT_DIR") |
| `agent_communication_tools.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run(['tmux', 'send-keys', '-t', clean_session_name, 'Escape' |
| `project_context_tools.py` | python | **BLOCK** | 0.881 | — | `EX-003`, `PE-008`, `PE-007`, `PE-DELTA-001` | SELECT context_key, value, description, updated_by, last_updated, LENGTH(value)  |
| `config.py` | python | **BLOCK** | 0.957 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | OPENAI_API_KEY_ENV: Optional[str] = os.environ.get("OPENAI_API_KEY")  # From mai |
| `server_lifecycle.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | rag_interval = int(os.environ.get("MCP_RAG_INDEX_INTERVAL_SECONDS", "300")) |
| `main_app.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | debug=os.environ.get("MCP_DEBUG", "false").lower() == "true" # Optional debug mo |
| `actions.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `display.py` | python | **BLOCK** | 0.990 | — | `PE-004`, `EX-001`, `PE-DELTA-001` | os.system('cls' if os.name == 'nt' else 'clear') |
| `claude_session_monitor.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `project_utils.py` | python | **BLOCK** | 0.973 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-008`, `PE-007`, `PE-007`, `PE-008`, `PE-DELTA-001` | You are an AI agent running in Cursor, connected to a Multi-Agent Collaboration  |
| `audit_utils.py` | python | **BLOCK** | 0.853 | — | `PE-008`, `PE-007`, `PE-DELTA-001` | debug_mode = os.environ.get("MCP_DEBUG", "false").lower() == "true" |
| `tmux_utils.py` | python | **BLOCK** | 1.000 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(['tmux', '-V'], |
| `worktree_utils.py` | python | **BLOCK** | 1.000 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `prompt_templates.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | You are {agent_id} worker agent. Your Agent Token: {agent_token}  Query the proj |
| `query.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` |   Based *only* on the CONTEXT provided above, please answer the QUERY. |

### 🔴 BLOCK — [Shashankss1205__CodeGraphContext](https://github.com/Shashankss1205/CodeGraphContext)

Python files: 103 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D U+200D |
| `TESTING.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # 🧪 codegraphcontext testing strategy this d |
| `generate_lang_contributors.py` | python | **BLOCK** | 0.978 | — | `PE-007`, `PE-003`, `PE-003`, `PE-DELTA-001` | with open(output_file, "w") as f: |
| `control_flow.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if os.getenv('USE_UJSON') == '1': |
| `comprehensions_generators.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open('temp.txt', 'w') as f: |
| `scip_indexer.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `graph_builder.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `package_resolver.py` | python | **BLOCK** | 1.000 | — | `PE-005`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | module = importlib.import_module(package_name) |
| `falkor_worker.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | db_path = os.getenv('FALKORDB_PATH') |
| `database.py` | python | **BLOCK** | 0.918 | — | `PE-008`, `PE-008`, `PE-008`, `EX-003`, `EX-003`, `EX-003`, `PE-DELTA-001` | self.neo4j_uri = os.getenv('NEO4J_URI') |
| `database_falkordb.py` | python | **BLOCK** | 0.947 | — | `PE-008`, `PE-008`, `PE-008`, `PE-003`, `PE-DELTA-001` | self.db_path = os.getenv( |
| `__init__.py` | python | **BLOCK** | 0.928 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | db_type = os.getenv('CGC_RUNTIME_DB_TYPE') |
| `cgc_bundle.py` | python | **BLOCK** | 0.997 | — | `EX-003`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-003`, `PE-DELTA-001` | MATCH (f:File) WHERE f.path STARTS WITH $repo_path RETURN count(f) as count |
| `bundle_registry.py` | python | **BLOCK** | 0.970 | — | `EX-001`, `EX-001`, `EX-001`, `PE-007`, `PE-DELTA-001` | response = requests.get(MANIFEST_URL, timeout=10) |
| `visualize_graph.py` | python | **BLOCK** | 0.846 | — | `EX-003`, `PE-007`, `PE-DELTA-001` | </div>         <div style="font-size: 0.8em; margin-top: 10px; color: #888;">Dra |
| `debug_log.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(debug_file, "a") as f: |
| `registry_commands.py` | python | **BLOCK** | 0.970 | — | `EX-001`, `EX-001`, `EX-001`, `PE-007`, `PE-DELTA-001` | response = requests.get(download_url, stream=True, timeout=30) |
| `config_manager.py` | python | **BLOCK** | 0.904 | — | `EX-003`, `EX-003`, `PE-008`, `PE-007`, `PE-DELTA-001` | Application log level (DEBUG\|INFO\|WARNING\|ERROR\|CRITICAL\|DISABLED) |
| `cli_helpers.py` | python | **BLOCK** | 0.948 | — | `EX-003`, `EX-003`, `PE-007`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-DELTA-001` | );     var container = document.getElementById('mynetwork');     var data = { no |
| `setup_wizard.py` | python | **BLOCK** | 0.996 | — | `EX-003`, `EX-003`, `PE-007`, `PE-003`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | Automatically configure your IDE/CLI (VS Code, Cursor, Windsurf, Claude, Gemini, |
| `main.py` | python | **BLOCK** | 0.966 | — | `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | CodeGraphContext: An MCP server for AI-powered code analysis.  [DEPRECATED] 'cgc |
| `visualizer.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(filepath, "w", encoding="utf-8") as f: |
| `java.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `typescript.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `ruby.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `cpp.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `typescriptjsx.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `csharp.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `c.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `swift.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `python.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `go.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `kotlin.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `php.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `haskell.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `javascript.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `scala.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `rust.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `query_handlers.py` | python | **BLOCK** | 0.876 | — | `EX-003`, `EX-003`, `PE-007`, `PE-DELTA-001` | This tool only supports read-only queries. Prohibited keywords like CREATE, MERG |
| `dynamic_imports.py` | python | **WARN** | 0.660 | — | `PE-005`, `PE-005` | mod = __import__(name) |
| `dynamic_dispatch.py` | python | **WARN** | 0.417 | — | `PE-005` | mod = importlib.import_module(mod_name) |
| `tool_definitions.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | Fallback tool to run a direct, read-only Cypher query against the code graph. Us |

### 🔴 BLOCK — [Sim-xia__Blind-Auditor](https://github.com/Sim-xia/Blind-Auditor)

Python files: 3 | Markdown files: 5 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `rules.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(self.rules_path, 'w', encoding='utf-8') as f: |
| `main.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | 🛑 **[SYSTEM INTERVENTION: CONTEXT ISOLATION MODE]**  **STOP GENERATING**. Do not |

### 🔴 BLOCK — [Sim-xia__skill-cortex-server](https://github.com/Sim-xia/skill-cortex-server)

Python files: 10 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `import_skills.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `config.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | roots_env = os.getenv("SKILL_CORTEX_ROOTS", "").strip() |

### 🔴 BLOCK — [stippi__code-assistant](https://github.com/stippi/code-assistant)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `01-introduction.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # introduction to agent client protocol ## w |
| `02-protocol-overview.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # protocol overview the agent client protoco |

### 🔴 BLOCK — [SunflowersLwtech__mcp_creator_growth](https://github.com/SunflowersLwtech/mcp_creator_growth)

Python files: 25 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.788 | — | `PI-004`, `PI-008` | secret_exfil_template; variant=raw; # <img src="assets/icon.png" width="48" heig |
| `server.py` | python | **BLOCK** | 0.863 | — | `EX-003`, `EX-003`, `EX-003`, `PE-008`, `PE-DELTA-001` |  MCP Creator Growth - Learning & Debug Assistant  DESIGN PHILOSOPHY: • learning_ |
| `config.py` | python | **BLOCK** | 0.943 | — | `EX-003`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-007`, `PE-DELTA-001` | # MCP Learning Sidecar Configuration # Location: ~/.config/mcp-sidecar/config.to |
| `debug.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | return os.getenv("MCP_DEBUG", "").lower() in ("true", "1", "yes", "on") |
| `terms_index.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(self.shown_file, "w", encoding="utf-8") as f: |
| `debug_index.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(self.index_file, "w", encoding="utf-8") as f: |
| `serializers.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(file_path, "w", encoding="utf-8") as f: |
| `path_resolver.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | base = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")) |

### 🔴 BLOCK — [tiianhk__MaxMSP-MCP-Server](https://github.com/tiianhk/MaxMSP-MCP-Server)

Python files: 2 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 1.000 | — | `SC-004`, `SC-008`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | 39 dependency entries without hash pinning |
| `install.py` | python | **BLOCK** | 1.000 | — | `SC-004`, `SC-008`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `PE-007`, `PE-007`, `PE-DELTA-001` | 39 dependency entries without hash pinning |

### 🔴 BLOCK — [tumf__mcp-shell-server](https://github.com/tumf/mcp-shell-server)

Python files: 10 | Markdown files: 10 | Tools: 1  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `conftest_new.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `shell_executor.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | return os.environ.get("SHELL", "/bin/sh") |
| `command_validator.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | allow_commands = os.environ.get("ALLOW_COMMANDS", "") |
| `io_redirection_handler.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |

### 🔴 BLOCK — [wende__cicada](https://github.com/wende/cicada)

Python files: 190 | Markdown files: 10 | Tools: 7  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `ARCHITECTURE.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # architecture high-level overview of cicada |
| `CHANGELOG.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # changelog all notable changes to this proj |
| `MCP_TOOLS_REFERENCE.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # mcp tools reference complete documentation |
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; <div align="center"> <img src="https://githu |
| `setup.py` | python | **BLOCK** | 1.000 | — | `PI-004`, `PI-004`, `SC-004`, `SC-003`, `SC-008`, `SC-008`, `PE-003`, `PE-DELTA-001` | secret_exfil_template; variant=raw; <div align="center"> <img src="https://githu |
| `command_logger.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(log_file, "a", encoding="utf-8") as f: |
| `interactive_setup_helpers.py` | python | **BLOCK** | 0.913 | — | `EX-003`, `PE-007`, `PE-007`, `PE-DELTA-001` |  <cicada>   **PRIMARY: Always use `mcp__cicada__query` for ALL code exploration  |
| `clean.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(config_path, "w") as f: |
| `watch_manager.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | self.process = subprocess.Popen( |
| `setup.py` | python | **BLOCK** | 0.999 | — | `EX-003`, `EX-003`, `PE-003`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | <cicada>   **ALWAYS use cicada-mcp tools for Elixir and Python code searches. NE |
| `indexer.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `stats.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `version_check.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `watcher.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `commands.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `index_mode.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `status.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `benchmark_python_indexing.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(output_path, "w") as f: |
| `benchmark_mcp_tool_calls.py` | python | **BLOCK** | 0.907 | — | `EX-003`, `PE-003`, `PE-DELTA-001` |  Examples:   # List available test suites   python tests/benchmark/benchmark_mcp |
| `indexer.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `ollama.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | with urllib.request.urlopen(req, timeout=5) as response: |
| `keyword_utils.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `subprocess_runner.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `index_utils.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `hash_utils.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(hashes_path, "w", encoding="utf-8") as f: |
| `storage.py` | python | **BLOCK** | 0.940 | — | `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | with open(link_path, "w") as f: |
| `server.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | repo_path_str = os.environ.get("_CICADA_REPO_PATH_ARG") |
| `config_manager.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | config_dir = os.environ.get("CICADA_CONFIG_DIR") |
| `tools.py` | python | **BLOCK** | 0.984 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | YOUR PRIMARY TOOL - Start here for ALL code exploration and discovery.\n\nThe 'G |
| `finder.py` | python | **BLOCK** | 0.996 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | _ = subprocess.run( |
| `formatter.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(output_path, "w") as f: |
| `orchestrator.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `cochange_analyzer.py` | python | **BLOCK** | 0.999 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True, chec |
| `helper.py` | python | **BLOCK** | 0.996 | — | `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `function_handlers.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `git_handlers.py` | python | **BLOCK** | 0.907 | — | `EX-003`, `PE-003`, `PE-DELTA-001` | WARNING: Date/author/min_changes filters only work with file-level history (with |
| `configs.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `installer.py` | python | **BLOCK** | 1.000 | — | `PE-003`, `PE-003`, `PE-008`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `reader.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `indexer.py` | python | **BLOCK** | 0.935 | — | `PE-007`, `PE-003`, `PE-DELTA-001` | with open(output_path, "w", encoding="utf-8") as f: |
| `scip_installer.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run([scip_path, "--version"], capture_output=True, text=True |
| `indexer.py` | python | **BLOCK** | 0.964 | — | `PE-003`, `PE-007`, `PE-007`, `PE-DELTA-001` | result = subprocess.run( |
| `alias_extractor.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `parser.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `indexer.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(temp_config, "w", encoding="utf-8") as f: |
| `indexer.py` | python | **BLOCK** | 0.961 | — | `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `parser.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `indexer.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(output_path, "w") as f: |
| `indexer.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `keyword_search.py` | python | **WARN** | 0.417 | — | `PE-005` | with __import__("contextlib").suppress(Exception): |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | module = __import__(module_path, fromlist=[class_name]) |

### 🔴 BLOCK — [wonderwhy-er__DesktopCommanderMCP](https://github.com/wonderwhy-er/DesktopCommanderMCP)

Python files: 0 | Markdown files: 8 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CUSTOM_STDIO_EXPLANATION.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # custom stdio server - how it works ## over |
| `FAQ.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # frequently asked questions (faq) this docu |
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-001` | override_authority_template; variant=raw; # desktop commander mcp ### search, up |

### 🔴 BLOCK — [x51xxx__codex-mcp-tool](https://github.com/x51xxx/codex-mcp-tool)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CHANGELOG.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # changelog ## [1.7.0] - 2026-02-06 ### adde |

### 🔴 BLOCK — [x51xxx__copilot-mcp-server](https://github.com/x51xxx/copilot-mcp-server)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CHANGELOG_MODEL.md` | markdown | **BLOCK** | 0.680 | — | `PI-001` | override_authority_template; variant=raw; # model selection feature - changelog  |
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-001` | override_authority_template; variant=raw; # copilot mcp tool <div align="center" |

### 🔴 BLOCK — [AbdelStark__nostr-mcp](https://github.com/AbdelStark/nostr-mcp)

Python files: 0 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D |

### 🔴 BLOCK — [adhikasp__mcp-twikit](https://github.com/adhikasp/mcp-twikit)

Python files: 2 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `twitter.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | USERNAME = os.getenv('TWITTER_USERNAME') |

### 🔴 BLOCK — [areweai__tsgram-mcp](https://github.com/areweai/tsgram-mcp)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `TODO_IMPLEMENTATION.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # tsgram implementation todo list ## 🚨 criti |
| `command-output-enrichment.md` | markdown | **BLOCK** | 0.909 | — | `PI-001`, `PI-004` | override_authority_template; variant=raw; # command output enrichment: piping sy |

### 🔴 BLOCK — [Cactusinhand__mcp_server_notify](https://github.com/Cactusinhand/mcp_server_notify)

Python files: 5 | Markdown files: 2 | Tools: 1  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; <a href="https://glama.ai/mcp/servers/@cactu |
| `sound.py` | python | **BLOCK** | 0.996 | — | `PE-004`, `PE-004`, `PE-004`, `PE-004`, `PE-DELTA-001` | os.system(f'afplay "{f.name}"') |
| `server.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | desktop_env = os.environ.get("XDG_CURRENT_DESKTOP", "") |

### 🔴 BLOCK — [carterlasalle__mac_messages_mcp](https://github.com/carterlasalle/mac_messages_mcp)

Python files: 6 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `productcontext.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; tact formats**: handle names, phone numbers, emails  |
| `messages.py` | python | **BLOCK** | 0.989 | — | `PE-003`, `EX-003`, `EX-003`, `PE-003`, `PE-007`, `EX-003`, `PE-DELTA-001` | proc = subprocess.Popen(['osascript', '-e', script], |
| `bump_version.py` | python | **BLOCK** | 0.987 | — | `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | subprocess.run(["git", "tag", tag_name], check=True) |

### 🔴 BLOCK — [chigwell__telegram-mcp](https://github.com/chigwell/telegram-mcp)

Python files: 3 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `session_string_generator.py` | python | **BLOCK** | 0.997 | — | `SC-004`, `SC-008`, `SC-003`, `SC-008`, `PE-008`, `PE-008`, `PE-007`, `PE-DELTA-001` | 7 dependency entries without hash pinning |
| `__init__.py` | python | **BLOCK** | 0.971 | — | `SC-004`, `SC-008`, `SC-003`, `SC-008` | 7 dependency entries without hash pinning |
| `main.py` | python | **BLOCK** | 0.997 | — | `SC-004`, `SC-008`, `SC-003`, `SC-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | 7 dependency entries without hash pinning |

### 🔴 BLOCK — [Danielpeter-99__calcom-mcp](https://github.com/Danielpeter-99/calcom-mcp)

Python files: 1 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `app.py` | python | **BLOCK** | 1.000 | — | `SC-004`, `SC-008`, `SC-008`, `PE-008`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | 2 dependency entries without hash pinning |

### 🔴 BLOCK — [discourse__discourse-mcp](https://github.com/discourse/discourse-mcp)

Python files: 0 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; sh npx -y @discourse/mcp@latest --site https://try.d |

### 🔴 BLOCK — [gotoolkits__mcp-wecombot-server](https://github.com/gotoolkits/mcp-wecombot-server)

Python files: 0 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; ## 🚀 mcp-wecombot-server [![smithery badge]( |

### 🔴 BLOCK — [hannesrudolph__imessage-query-fastmcp-mcp-server](https://github.com/hannesrudolph/imessage-query-fastmcp-mcp-server)

Python files: 1 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `imessage-query-server.py` | python | **BLOCK** | 0.977 | — | `SC-004`, `SC-008`, `PE-008`, `PE-003`, `PE-DELTA-001` | 3 dependency entries without hash pinning |

### 🔴 BLOCK — [InditexTech__mcp-teams-server](https://github.com/InditexTech/mcp-teams-server)

Python files: 5 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `config.py` | python | **BLOCK** | 0.928 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | self.APP_ID = os.environ.get("TEAMS_APP_ID", "") |
| `__init__.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | default_transport = os.environ.get("MCP_TRANSPORT", "stdio") |

### 🔴 BLOCK — [infobip__mcp](https://github.com/infobip/mcp)

Python files: 3 | Markdown files: 7 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D |
| `main.py` | python | **BLOCK** | 0.907 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | model=os.getenv("AWS_MODEL_ID"), |
| `main.py` | python | **BLOCK** | 0.907 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | deployment_name=os.getenv("AZURE_OPENAI_MODEL_NAME"), |
| `main.py` | python | **BLOCK** | 0.907 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | api_key=os.getenv("AZURE_OPENAI_API_KEY"), |

### 🔴 BLOCK — [jagan-shanmugam__mattermost-mcp-host](https://github.com/jagan-shanmugam/mattermost-mcp-host)

Python files: 19 | Markdown files: 4 | Tools: 8  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `mcp_tool_caller.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `mcp_server.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | OLLAMA_BASE_URL = os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434') |
| `server.py` | python | **BLOCK** | 0.945 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | MATTERMOST_URL = os.environ.get('MATTERMOST_URL', 'localhost') |
| `config.py` | python | **BLOCK** | 0.996 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | MATTERMOST_URL = os.environ.get('MATTERMOST_URL', 'localhost') |
| `main.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `tools.py` | python | **BLOCK** | 0.668 | — | `PE-001` | result = eval(expression, {"__builtins__": {}}, {"abs": abs, "round": round, "ma |
| `llm_agent.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | self.model = model or os.environ.get("AZURE_OPENAI_DEPLOYMENT") |

### 🔴 BLOCK — [jaipandya__producthunt-mcp-server](https://github.com/jaipandya/producthunt-mcp-server)

Python files: 19 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D U+200D |
| `token.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | return os.getenv("PRODUCT_HUNT_TOKEN") |
| `client.py` | python | **BLOCK** | 0.880 | — | `EX-003`, `EX-001`, `EX-003`, `PE-DELTA-001` | Developer token not found. Please add PRODUCT_HUNT_TOKEN to your environment var |

### 🔴 BLOCK — [joinly-ai__joinly](https://github.com/joinly-ai/joinly)

Python files: 66 | Markdown files: 5 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `client_example.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | default=os.getenv("JOINLY_MODEL_NAME", "gpt-4o"), |
| `download_assets.py` | python | **BLOCK** | 0.911 | — | `PE-003`, `PE-008`, `PE-DELTA-001` | subprocess.run(playwright_cmd, check=True)  # noqa: S603 |
| `resemble.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | self._api_key = os.getenv("RESEMBLE_API_KEY") |
| `google.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") |
| `kokoro.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | pathlib.Path(os.getenv("XDG_CACHE_HOME", "~/.cache")).expanduser() |
| `silero.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | pathlib.Path(os.getenv("XDG_CACHE_HOME", "~/.cache")).expanduser() |
| `google.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") |
| `utils.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | ollama_url = os.getenv("OLLAMA_URL") |
| `container.py` | python | **WARN** | 0.417 | — | `PE-005` | module = importlib.import_module(mod) |
| `prompts.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` |  <identity> You are {name}, a professional and knowledgeable meeting assistant.  |

### 🔴 BLOCK — [jtalk22__slack-mcp-server](https://github.com/jtalk22/slack-mcp-server)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CHANGELOG.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # changelog all notable changes to this proj |

### 🔴 BLOCK — [khan2a__telephony-mcp-server](https://github.com/khan2a/telephony-mcp-server)

Python files: 5 | Markdown files: 4 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `auth.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `telephony_server.py` | python | **BLOCK** | 0.957 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | VONAGE_API_KEY = os.getenv("VONAGE_API_KEY") |

### 🔴 BLOCK — [lharries__whatsapp-mcp](https://github.com/lharries/whatsapp-mcp)

Python files: 3 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `whatsapp.py` | python | **BLOCK** | 0.971 | — | `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.post(url, json=payload) |
| `audio.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | process = subprocess.run( |

### 🔴 BLOCK — [madbonez__caldav-mcp](https://github.com/madbonez/caldav-mcp)

Python files: 5 | Markdown files: 8 | Tools: 8  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CODE_QUALITY.md` | markdown | **BLOCK** | 0.699 | — | `PI-001` | override_authority_template; variant=raw; # code quality tools this project uses |
| `server.py` | python | **BLOCK** | 0.968 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | Start time in ISO format (e.g., '2025-01-20T14:00:00'). If not provided, default |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if os.getenv("MCP_VERBOSE", "").lower() in ("true", "1", "yes"): |

### 🔴 BLOCK — [marlinjai__email-mcp](https://github.com/marlinjai/email-mcp)

Python files: 0 | Markdown files: 7 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # @marlinjai/email-mcp a unified mcp server  |
| `2026-02-16-email-mcp-design.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # email mcp server — design document a unifi |

### 🔴 BLOCK — [PhononX__cv-mcp-server](https://github.com/PhononX/cv-mcp-server)

Python files: 0 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `readme.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; 10 most recent messages with full context - **`creat |

### 🔴 BLOCK — [sawa-zen__vrchat-mcp](https://github.com/sawa-zen/vrchat-mcp)

Python files: 0 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.ja.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; ![vrchat mcp](./eyecatch.jpg) [![npm version |
| `README.ko.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; ![vrchat mcp](./eyecatch.jpg) [![npm version |
| `README.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; ![vrchat mcp](./eyecatch.jpg) [![npm version |

### 🔴 BLOCK — [softeria__ms-365-mcp-server](https://github.com/softeria/ms-365-mcp-server)

Python files: 0 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # ms-365-mcp-server [![npm version](https:// |

### 🔴 BLOCK — [UserAd__didlogic_mcp](https://github.com/UserAd/didlogic_mcp)

Python files: 16 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | BASE_URL = os.environ.get("DIDLOGIC_API_URL", "https://app.didlogic.com/api") |
| `__main__.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | if not os.environ.get("DIDLOGIC_API_KEY"): |

### 🔴 BLOCK — [ztxtxwd__open-feishu-mcp-server](https://github.com/ztxtxwd/open-feishu-mcp-server)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.en.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D |
| `README.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D |

### 🔴 BLOCK — [hustcc__mcp-echarts](https://github.com/hustcc/mcp-echarts)

Python files: 0 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D |

### 🔴 BLOCK — [OpenDataMCP__OpenDataMCP](https://github.com/OpenDataMCP/OpenDataMCP)

Python files: 7 | Markdown files: 1 | Tools: 4  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `bump_version.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | subprocess.run(command, check=True, shell=True) |
| `cli.py` | python | **BLOCK** | 0.988 | — | `PE-005`, `PE-005`, `PE-007`, `PE-007`, `PE-007`, `PE-008`, `PE-008`, `PE-DELTA-001` | module = importlib.import_module(f"odmcp.providers.{provider}") |
| `__template__.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = httpx.get(endpoint, params=params.model_dump(exclude_none=True)) |
| `ch_sbb.py` | python | **BLOCK** | 0.946 | — | `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = httpx.get(endpoint, params=params.model_dump(exclude_none=True)) |

### 🔴 BLOCK — [QuackbackIO__quackback](https://github.com/QuackbackIO/quackback)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; ivileges on database quackback to your_user; ``` ### |
| `2026-02-24-feat-quackback-cloud-saas-plan.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; ect_uri?code=...&state=... 5. client exchanges code  |

### 🔴 BLOCK — [tinybirdco__mcp-tinybird](https://github.com/tinybirdco/mcp-tinybird)

Python files: 8 | Markdown files: 4 | Tools: 11  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.869 | — | `EX-003`, `PE-008`, `PE-008`, `EX-003`, `PE-DELTA-001` | p.eyJ1IjogIjIwY2RkOGQwLTNkY2UtNDk2NC1hYmI3LTI0MmM3OWE5MDQzNCIsICJpZCI6ICJjZmMxND |

### 🔴 BLOCK — [Aiven-Open__mcp-aiven](https://github.com/Aiven-Open/mcp-aiven)

Python files: 3 | Markdown files: 8 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `mcp_env.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | return os.getenv("AIVEN_BASE_URL") |

### 🔴 BLOCK — [alexander-zuev__supabase-mcp-server](https://github.com/alexander-zuev/supabase-mcp-server)

Python files: 39 | Markdown files: 6 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D U+200D |
| `settings.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | global_config = Path(os.environ.get("APPDATA", "")) / "supabase-mcp" / ".env" |
| `manager.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `spec_manager.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `loader.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `postgres_client.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | CONNECTION ERROR: Region mismatch detected!  Could not connect to Supabase proje |
| `safety_manager.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` |  requires explicit user confirmation.  WHAT HAPPENED: This high-risk operation w |

### 🔴 BLOCK — [aliyun__alibabacloud-tablestore-mcp-server](https://github.com/aliyun/alibabacloud-tablestore-mcp-server)

Python files: 17 | Markdown files: 9 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # tablestore-mcp-server a based tablestore m |
| `__init__.py` | python | **BLOCK** | 0.964 | — | `PE-004`, `PE-004`, `PE-DELTA-001` | os.system(f"uv pip install {mem0_wheel_path} --python {sys.executable}") |
| `config.py` | python | **BLOCK** | 0.995 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `EX-003`, `EX-003`, `EX-003` | 7 dependency entries without hash pinning |
| `chunk.py` | python | **BLOCK** | 0.991 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008`, `SC-008` | 7 dependency entries without hash pinning |
| `knowledge_manager.py` | python | **BLOCK** | 0.997 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `PE-DELTA-001` | 7 dependency entries without hash pinning |
| `pdf_to_markdown.py` | python | **BLOCK** | 0.991 | — | `SC-004`, `SC-003`, `SC-008`, `SC-008`, `SC-008` | 7 dependency entries without hash pinning |
| `README.md` | markdown | **WARN** | 0.396 | — | `PI-005` | pattern_match; variant=raw; 力、稀疏向量(sparse vector)能力,后续有时间会继续进行集成。 仅需要修改如下配置即可, 如 |
| `settings.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` |  将文档存储到Tablestore（表格存储）以供后续检索。  输入参数： 1. 'information' 参数应包含自然语言的文档内容。 2. 'metad |

### 🔴 BLOCK — [amineelkouhen__mcp-cockroachdb](https://github.com/amineelkouhen/mcp-cockroachdb)

Python files: 13 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `config.py` | python | **BLOCK** | 0.967 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | "host": os.getenv('CRDB_HOST', '127.0.0.1'), |
| `README.md` | markdown | **WARN** | 0.434 | — | `PI-005` | pattern_match; variant=raw; er/cockroachdb-mcp-server/cockroachdb) [![trust scor |
| `table_management.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | SELECT index_name, non_unique, column_name, direction, storing, implicit FROM [S |

### 🔴 BLOCK — [bram2w__baserow](https://github.com/bram2w/baserow)

Python files: 2144 | Markdown files: 10 | Tools: 14  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `changelog.md` | markdown | **BLOCK** | 0.790 | — | `PI-004`, `PI-008` | secret_exfil_template; variant=raw; # changelog ## released 2.1.3 ### bug fixes  |
| `saml.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `github_issues_data_sync.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get( |
| `hubspot_contacts_data_sync.py` | python | **BLOCK** | 0.946 | — | `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get( |
| `gitlab_issues_data_sync.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get( |
| `settings.py` | python | **BLOCK** | 0.985 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | settings.BASEROW_ENTERPRISE_ASSISTANT_LLM_MODEL = os.getenv( |
| `auth_provider_types.py` | python | **BLOCK** | 0.946 | — | `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | resp = requests.get(self.EMAILS_URL, headers=headers)  # noqa: S113 |
| `handler.py` | python | **BLOCK** | 0.940 | — | `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | changelog_file = open(self.changelog_path, "w+") |
| `changelog_legacy_converter.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `changelog_entry.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | GITLAB_URL = os.environ.get("GITLAB_URL", "https://gitlab.com/baserow/baserow") |
| `manage.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | debugger_enabled = bool(os.environ.get("BASEROW_BACKEND_DEBUGGER_ENABLED")) |
| `handler.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `setup_formulas.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `pytest_conftest.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(results_file, "w", encoding="utf-8") as f_html: |
| `helpers.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `handler.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `utils.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | p = subprocess.Popen(  # noqa: S603 |
| `handler.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.post( |
| `provider.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | os.getenv(BASEROW_CUSTOM_OTEL_SAMPLER_ENV_VAR_NAME, "") |
| `utils.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | env_var_set = bool(os.getenv("BASEROW_ENABLE_OTEL", False)) |
| `export_workspace_applications.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(files_path, "wb") as files_buffer: |
| `import_workspace_applications.py` | python | **BLOCK** | 0.726 | — | `EX-003`, `PE-DELTA-001` | Imports an exported JSON file and optionally a ZIP file containing the files. Th |
| `create_template.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(template_path, "w") as template_json_file: |
| `backup_runner.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | subprocess.check_output(command)  # noqa: S603 |
| `test.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | TEST_ENV_FILE = os.environ.get("TEST_ENV_FILE", "") |
| `heroku.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | REDIS_TLS_URL = os.getenv("REDIS_TLS_URL", REDIS_URL)  # noqa: F405 |
| `utils.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | value = os.getenv(env_var, None) |
| `dev.py` | python | **BLOCK** | 0.928 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | SECRET_KEY = os.getenv("SECRET_KEY", "dev_hardcoded_secret_key")  # noqa: F405 |
| `base.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-005`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | REDIS_HOST = os.getenv("REDIS_HOST", "redis") |
| `handler.py` | python | **BLOCK** | 0.956 | — | `EX-003`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95 |
| `install_airtable_templates.py` | python | **BLOCK** | 0.919 | — | `EX-003`, `EX-001`, `EX-001`, `PE-DELTA-001` | /v0.3/exploreApplications?templateStatus=listed&shouldDisplayFull=true&descripti |
| `handler.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.post( |
| `settings.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | os.getenv("BASEROW_AI_FIELD_MAX_CONCURRENT_GENERATIONS"), 5 |
| `prompts.py` | python | **WARN** | 0.726 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` |  ### DATABASE BUILDER (no-code database)  **Structure**: Database → Tables → Fie |
| `0016_rename_auditlogentry_group_id_workspace_id.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` |          ALTER TABLE baserow_enterprise_auditlogentry         RENAME COLUMN grou |
| `constants.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | -----BEGIN RSA PRIVATE KEY----- MIIEogIBAAKCAQEAtHTGm2x0Lm+bJmFdCin2GKALSp4RDIwu |
| `0113_alter_notification_options_and_more.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | CREATE INDEX CONCURRENTLY "core_notifi_created_7f4b88_idx" ON "core_notification |
| `0053_rename_trashentry_group.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` |          ALTER TABLE core_trashentry         RENAME COLUMN group_id TO workspace |
| `0204_add_row_exists_not_trashed_function.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` |  CREATE OR REPLACE FUNCTION row_exists_not_trashed(p_table_id integer, p_row_id  |
| `0047_fix_date_diff.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` |  CREATE OR REPLACE FUNCTION date_diff (units TEXT, start_t TIMESTAMP, end_t TIME |
| `0151_tableusageupdate_tableusage.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` |  CREATE OR REPLACE FUNCTION get_baserow_table_row_count(table_id INT) RETURNS BI |
| `serializers.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | A list of rows that needs to be created as initial table data. Each row is a lis |
| `serializers.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | An ISO 639 language code (with optional variant) selected by the user. Ex: en-GB |

### 🔴 BLOCK — [c4pt0r__mcp-server-tidb](https://github.com/c4pt0r/mcp-server-tidb)

Python files: 5 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `db.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | cert = os.getenv('SSL_CERT_PATH') |

### 🔴 BLOCK — [Canner__wren-engine](https://github.com/Canner/wren-engine)

Python files: 95 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `wren.py` | python | **BLOCK** | 0.874 | — | `PE-008`, `PE-008`, `PE-008`, `EX-003`, `PE-DELTA-001` | WREN_URL = os.getenv("WREN_URL", "localhost:8000") |
| `compare.py` | python | **BLOCK** | 0.721 | — | `SC-004`, `PE-DELTA-001` | 1 dependency entries without hash pinning |
| `mdl_validation.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `update_databricks_functions.py` | python | **BLOCK** | 0.912 | — | `PE-008`, `PE-008`, `PE-008`, `PE-007`, `PE-DELTA-001` | host = os.environ.get("DATABRICKS_SERVER_HOSTNAME") |
| `white_remote_function.py` | python | **BLOCK** | 0.896 | — | `EX-001`, `PE-007`, `PE-DELTA-001` | response = requests.post(api_url, json=payload, headers=headers, timeout=30) |
| `remote_function_check.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(args.path, "w") as new_file: |
| `query_local_run.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | manifest_json_path = os.getenv("WREN_MANIFEST_JSON_PATH") |
| `generate_openapi.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open("openapi.yaml", "w") as f: |
| `config.py` | python | **BLOCK** | 0.903 | — | `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | <green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> \| <yellow>[{extra[correlation_id] |
| `__init__.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `__main__.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `postgres.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | manifest_json_path = os.getenv("WREN_MANIFEST_JSON_PATH") |
| `mysql.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | manifest_json_path = os.getenv("WREN_MANIFEST_JSON_PATH") |
| `analyzer.py` | python | **BLOCK** | 0.900 | — | `EX-001`, `EX-001`, `PE-DELTA-001` | r = httpx.request( |
| `csv_parser.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `rewriter.py` | python | **WARN** | 0.660 | — | `PE-005`, `PE-005` | importlib.import_module("ibis.backends.sql.dialects") |
| `connector.py` | python | **WARN** | 0.417 | — | `PE-005` | importlib.import_module("app.custom_ibis.backends.sql.datatypes") |

### 🔴 BLOCK — [ChristianHinge__dicom-mcp](https://github.com/ChristianHinge/dicom-mcp)

Python files: 8 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D U+200D |
| `config.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `dicom_client.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(pdf_path, 'wb') as pdf_file: |

### 🔴 BLOCK — [chroma-core__chroma-mcp](https://github.com/chroma-core/chroma-mcp)

Python files: 2 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.975 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | default=os.getenv('CHROMA_CLIENT_TYPE', 'ephemeral'), |

### 🔴 BLOCK — [ClickHouse__mcp-clickhouse](https://github.com/ClickHouse/mcp-clickhouse)

Python files: 7 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; bled=true`) * generate using `uuidgen` or `openssl r |
| `example_middleware.py` | python | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; bled=true`) * generate using `uuidgen` or `openssl r |
| `mcp_middleware_hook.py` | python | **BLOCK** | 0.847 | — | `PE-008`, `PE-005`, `PE-DELTA-001` | middleware_module = os.getenv("MCP_MIDDLEWARE_MODULE") |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | if os.getenv("MCP_CLICKHOUSE_TRUSTSTORE_DISABLE", None) != "1": |
| `mcp_env.py` | python | **BLOCK** | 0.997 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | return os.getenv("CLICKHOUSE_ROLE") |
| `mcp_server.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | if os.getenv("CLICKHOUSE_ENABLED", "true").lower() == "true": |

### 🔴 BLOCK — [confluentinc__mcp-confluent](https://github.com/confluentinc/mcp-confluent)

Python files: 0 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # mcp-confluent an mcp server implementation |

### 🔴 BLOCK — [Couchbase-Ecosystem__mcp-server-couchbase](https://github.com/Couchbase-Ecosystem/mcp-server-couchbase)

Python files: 14 | Markdown files: 4 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D |
| `setup_test_data.py` | python | **BLOCK** | 0.952 | — | `EX-003`, `EX-003`, `PE-008`, `EX-003`, `EX-003`, `EX-003`, `EX-001`, `PE-DELTA-001` | SELECT name, keyspace_id, index_key FROM system:indexes WHERE bucket_id = 'trave |
| `query.py` | python | **BLOCK** | 0.779 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` |      SELECT statement,         DURATION_TO_STR(avgServiceTime) AS avgServiceTime |
| `config.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `index_utils.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = httpx.get( |

### 🔴 BLOCK — [cr7258__elasticsearch-mcp-server](https://github.com/cr7258/elasticsearch-mcp-server)

Python files: 26 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = os.environ.get("MCP_API_KEY") |
| `risk_config.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | custom_ops = os.environ.get("DISABLE_OPERATIONS", "") |
| `__init__.py` | python | **BLOCK** | 0.928 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | hosts_str = os.environ.get(f"{prefix}_HOSTS", "https://localhost:9200") |

### 🔴 BLOCK — [crystaldba__postgres-mcp](https://github.com/crystaldba/postgres-mcp)

Python files: 27 | Markdown files: 4 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | database_url = os.environ.get("DATABASE_URI", args.database_url) |
| `index_opt_base.py` | python | **BLOCK** | 0.726 | — | `EX-003`, `PE-DELTA-001` | SELECT s.last_analyze FROM pg_stat_user_tables s ORDER BY s.last_analyze LIMIT 1 |
| `presentation.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | include_langfuse_trace = os.environ.get("POSTGRES_MCP_INCLUDE_LANGFUSE_TRACE", " |
| `extension_utils.py` | python | **BLOCK** | 0.779 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | SELECT default_version FROM pg_available_extensions WHERE name = {} |
| `top_queries_calc.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | The pg_stat_statements extension is required to report slow queries, but it is n |

### 🔴 BLOCK — [Dataring-engineering__mcp-server-trino](https://github.com/Dataring-engineering/mcp-server-trino)

Python files: 2 | Markdown files: 1 | Tools: 1  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.928 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | "host": os.getenv("TRINO_HOST", "localhost"), |

### 🔴 BLOCK — [designcomputer__mysql_mcp_server](https://github.com/designcomputer/mysql_mcp_server)

Python files: 2 | Markdown files: 3 | Tools: 1  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.957 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | "host": os.getenv("MYSQL_HOST", "localhost"), |

### 🔴 BLOCK — [edwinbernadus__nocodb-mcp-server](https://github.com/edwinbernadus/nocodb-mcp-server)

Python files: 0 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.811 | — | `PI-005`, `PI-004` | pattern_match; variant=raw; nocodb-mcp-server) # nocodb mcp server [![trust scor |

### 🔴 BLOCK — [ferrants__memvid-mcp-server](https://github.com/ferrants/memvid-mcp-server)

Python files: 1 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 1.000 | — | `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `PE-008`, `PE-DELTA-001` | 75 dependency entries without hash pinning |

### 🔴 BLOCK — [furey__mongodb-lens](https://github.com/furey/mongodb-lens)

Python files: 0 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-001` | override_authority_template; variant=raw; # mongodb lens [![license](https://img |

### 🔴 BLOCK — [get-convex__convex-backend](https://github.com/get-convex/convex-backend)

Python files: 9 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `check_prettier_matches_dprint.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `check_cla.py` | python | **BLOCK** | 0.890 | — | `PE-008`, `PE-008`, `EX-001`, `PE-DELTA-001` | PR_AUTHOR = os.environ.get("PR_AUTHOR") |
| `build-convexServerTypes.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(output_path, "w", encoding="utf-8") as json_file: |
| `main.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | client = ConvexClient(os.getenv("CONVEX_URL")) |
| `main.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | client = ConvexClient(os.getenv("CONVEX_URL")) |
| `generate-project.py` | python | **BLOCK** | 0.913 | — | `EX-003`, `PE-007`, `PE-007`, `PE-DELTA-001` | import { defineSchema } from "convex/server"; import { tables } from "./tables"; |
| `build.py` | python | **BLOCK** | 0.993 | — | `PE-003`, `PE-003`, `PE-007`, `PE-003`, `PE-DELTA-001` | subprocess.check_call(["go", "mod", "tidy"]) |
| `build.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | subprocess.run( |
| `main.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | CONVEX_URL = os.getenv("CONVEX_URL") |

### 🔴 BLOCK — [gigamori__mcp-run-sql-connectorx](https://github.com/gigamori/mcp-run-sql-connectorx)

Python files: 2 | Markdown files: 2 | Tools: 1  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # run-sql-connectorx an mcp server that exec |

### 🔴 BLOCK — [googleapis__genai-toolbox](https://github.com/googleapis/genai-toolbox)

Python files: 9 | Markdown files: 10 | Tools: 1  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `quickstart.py` | python | **BLOCK** | 0.785 | — | `SC-004`, `PE-008`, `PE-DELTA-001` | 4 dependency entries without hash pinning |
| `quickstart.py` | python | **BLOCK** | 0.785 | — | `SC-004`, `PE-008`, `PE-DELTA-001` | 3 dependency entries without hash pinning |

### 🔴 BLOCK — [GreptimeTeam__greptimedb-mcp-server](https://github.com/GreptimeTeam/greptimedb-mcp-server)

Python files: 6 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `template.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # pipeline generator for greptimedb generate |
| `server.py` | python | **BLOCK** | 0.742 | — | `EX-003`, `PE-002` | SELECT name, pipeline, created_at::bigint as version FROM greptime_private.pipel |
| `config.py` | python | **BLOCK** | 0.996 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | default=os.getenv("GREPTIMEDB_HOST", "localhost"), |
| `utils.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |

### 🔴 BLOCK — [hannesrudolph__sqlite-explorer-fastmcp-mcp-server](https://github.com/hannesrudolph/sqlite-explorer-fastmcp-mcp-server)

Python files: 1 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `sqlite_explorer.py` | python | **BLOCK** | 0.738 | — | `SC-004`, `SC-008` | 1 dependency entries without hash pinning |

### 🔴 BLOCK — [henilcalagiya__google-sheets-mcp](https://github.com/henilcalagiya/google-sheets-mcp)

Python files: 41 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `auto_setup.py` | python | **BLOCK** | 0.935 | — | `PE-003`, `PE-007`, `PE-DELTA-001` | result = subprocess.run(["uv", "--version"], capture_output=True, text=True) |
| `server.py` | python | **BLOCK** | 0.967 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | project_id = os.getenv("project_id") or os.getenv("GOOGLE_PROJECT_ID") |

### 🔴 BLOCK — [hydrolix__mcp-hydrolix](https://github.com/hydrolix/mcp-hydrolix)

Python files: 12 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `mcp_env.py` | python | **BLOCK** | 0.998 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | return os.getenv("HYDROLIX_DATABASE") |
| `log.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |

### 🔴 BLOCK — [isaacwasserman__mcp-snowflake-server](https://github.com/isaacwasserman/mcp-snowflake-server)

Python files: 5 | Markdown files: 1 | Tools: 9  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.726 | — | `EX-003`, `PE-DELTA-001` | Execute an INSERT, UPDATE, or DELETE query on the Snowflake database |
| `__init__.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | private_key_path = os.getenv("SNOWFLAKE_PRIVATE_KEY_PATH") |
| `db_client.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |

### 🔴 BLOCK — [iunera__druid-mcp-server](https://github.com/iunera/druid-mcp-server)

Python files: 0 | Markdown files: 8 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.909 | — | `PI-004`, `PI-001` | pattern_match; variant=raw; e http and sse transports are secured with oauth 2.0 |
| `development.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; oken using the built-in authorization server export  |
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; t client: `oidc-client` / `secret`): ```bash export  |

### 🔴 BLOCK — [JaviMaligno__postgres_mcp](https://github.com/JaviMaligno/postgres_mcp)

Python files: 10 | Markdown files: 4 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `evaluate_mcp.py` | python | **BLOCK** | 0.987 | — | `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `server.py` | python | **WARN** | 0.660 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | Please explore this PostgreSQL database and provide an overview.  Use these tool |

### 🔴 BLOCK — [jovezhong__mcp-timeplus](https://github.com/jovezhong/mcp-timeplus)

Python files: 5 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `mcp_env.py` | python | **BLOCK** | 0.967 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | return os.getenv("TIMEPLUS_HOST", "localhost") |

### 🔴 BLOCK — [LucasHild__mcp-server-bigquery](https://github.com/LucasHild/mcp-server-bigquery)

Python files: 2 | Markdown files: 2 | Tools: 3  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `__init__.py` | python | **BLOCK** | 0.907 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | timeout_env = os.environ.get('BIGQUERY_TIMEOUT') |

### 🔴 BLOCK — [memgraph__ai-toolkit](https://github.com/memgraph/ai-toolkit)

Python files: 103 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-001` | override_authority_template; variant=raw; # sql database to graph migration agen |
| `graphrag.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | if not os.environ.get("OPENAI_API_KEY"): |
| `embeddings.py` | python | **BLOCK** | 0.913 | — | `EX-003`, `PE-007`, `PE-007`, `PE-DELTA-001` |      MATCH (d:Division)-[:HAS_MAJOR_GROUP]->(mg:MajorGroup)           -[:HAS_IND |
| `main.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(filepath, "w", encoding="utf-8") as f: |
| `__init__.py` | python | **BLOCK** | 0.699 | — | `PI-001` | override_authority_template; variant=raw; # sql database to graph migration agen |
| `main.py` | python | **BLOCK** | 0.953 | — | `PI-001`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | override_authority_template; variant=raw; # sql database to graph migration agen |
| `migration_agent.py` | python | **BLOCK** | 0.972 | — | `EX-003`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | MATCH (meta:MigrationAgent {source_host: $host, source_database: $database, sour |
| `config.py` | python | **BLOCK** | 0.997 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | source_host = os.getenv("POSTGRES_HOST", "localhost") |
| `environment.py` | python | **BLOCK** | 0.999 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | openai_key = os.getenv("OPENAI_API_KEY") |
| `__init__.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | api_key = os.environ.get("ANTHROPIC_API_KEY") |
| `core.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | MEMGRAPH_URL = os.getenv("MEMGRAPH_URL", "bolt://localhost:7687") |
| `memgraph.py` | python | **BLOCK** | 0.779 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` |  CALL schema.node_type_properties() YIELD nodeType AS label, propertyName AS pro |
| `config.py` | python | **BLOCK** | 0.975 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | return os.getenv("MEMGRAPH_URL", "bolt://localhost:7687") |
| `main.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | server_name = os.getenv("MCP_SERVER", "server").lower() |
| `memgraph.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | url = url or os.environ.get("MEMGRAPH_URL", "bolt://localhost:7687") |
| `mcp_prompt.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | "MEMGRAPH_URL": os.environ.get("MEMGRAPH_URL", "bolt://localhost:7687"), |
| `sic_classification.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` |   The description is ambiguous or could match multiple SIC codes. Generate exact |
| `prompts.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | Your task is to directly translate natural language inquiry into precise and exe |
| `memgraph_experimental.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` |   CRITICAL: ALWAYS include an entry for EVERY node label in the MATCH clause. -  |
| `__init__.py` | python | **WARN** | 0.417 | — | `PE-005` | module = importlib.import_module(module_path) |

### 🔴 BLOCK — [mbentham__SqlAugur](https://github.com/mbentham/SqlAugur)

Python files: 0 | Markdown files: 4 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `SECURITY.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # security guide operational security guidan |

### 🔴 BLOCK — [neo4j-contrib__mcp-neo4j](https://github.com/neo4j-contrib/mcp-neo4j)

Python files: 18 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `utils.py` | python | **BLOCK** | 0.997 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | if os.getenv("NEO4J_TRANSPORT") is not None: |
| `utils.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | if os.getenv("NEO4J_URL") is not None: |
| `utils.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | if os.getenv("NEO4J_URL") is not None: |
| `__init__.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | default=os.environ.get("NEO4J_AURA_CLIENT_ID")) |
| `aura_api_client.py` | python | **BLOCK** | 1.000 | — | `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get(url, headers=self._get_headers()) |
| `utils.py` | python | **BLOCK** | 0.999 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | env_stateless = os.getenv("NEO4J_MCP_SERVER_STATELESS") |

### 🔴 BLOCK — [neondatabase__mcp-server-neon](https://github.com/neondatabase/mcp-server-neon)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `read-only-mode-fix.md` | markdown | **BLOCK** | 0.680 | — | `PI-001` | override_authority_template; variant=raw; # read-only mode fix **date:** 2026-01 |

### 🔴 BLOCK — [OpenLinkSoftware__mcp-sqlalchemy-server](https://github.com/OpenLinkSoftware/mcp-sqlalchemy-server)

Python files: 2 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.940 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `EX-003`, `EX-003`, `PE-DELTA-001` | DB_UID = os.getenv("ODBC_USER") |

### 🔴 BLOCK — [pab1it0__adx-mcp-server](https://github.com/pab1it0/adx-mcp-server)

Python files: 5 | Markdown files: 5 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CHANGELOG.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+FEFF U+FEFF |
| `server.py` | python | **BLOCK** | 0.975 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | tenant_id = os.environ.get('AZURE_TENANT_ID') |
| `main.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | tenant_id = os.environ.get('AZURE_TENANT_ID') |

### 🔴 BLOCK — [pab1it0__prometheus-mcp-server](https://github.com/pab1it0/prometheus-mcp-server)

Python files: 4 | Markdown files: 4 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `VALIDATION_SUMMARY.md` | markdown | **BLOCK** | 0.972 | — | `PI-003` | Invisible codepoints: U+200D |
| `server.py` | python | **BLOCK** | 0.994 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `EX-001`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | TOOL_PREFIX = os.environ.get("TOOL_PREFIX", "") |

### 🔴 BLOCK — [isdaniel__pgtuner_mcp](https://github.com/isdaniel/pgtuner_mcp)

Python files: 16 | Markdown files: 1 | Tools: 16  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.988 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `PE-008`, `PE-008`, `EX-003`, `EX-003`, `EX-003`, `PE-DELTA-001` | # pgtuner-mcp Tool Reference  ## Overview pgtuner-mcp provides a comprehensive s |
| `__init__.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `user_filter.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | env_value = os.environ.get(EXCLUDE_USERIDS_ENV, "").strip() |
| `tools_performance.py` | python | **WARN** | 0.660 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | Retrieve slow queries from PostgreSQL using pg_stat_statements.  Returns the top |
| `tools_health.py` | python | **WARN** | 0.579 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003` | Perform a comprehensive database health check.  Note: This tool focuses on user/ |
| `tools_bloat.py` | python | **WARN** | 0.726 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | Analyze table bloat using the pgstattuple extension.  Note: This tool analyzes o |
| `tools_index.py` | python | **WARN** | 0.660 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | Get AI-powered index recommendations for your database.  Analyzes your query wor |
| `hypopg_service.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | HypoPG extension is available but not installed. To install: CREATE EXTENSION hy |

### 🔴 BLOCK — [quarkiverse__quarkus-mcp-servers](https://github.com/quarkiverse/quarkus-mcp-servers)

Python files: 0 | Markdown files: 9 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # model context protocol server for jvminsig |

### 🔴 BLOCK — [rashidazarang__airtable-mcp](https://github.com/rashidazarang/airtable-mcp)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `pull_request_template.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # 🚀 pull request - trust score 100/100 <!--  |
| `ENHANCED_FEATURES.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | pattern_match; variant=raw; &code_challenge=xyz&code_challenge_method=s256&state |

### 🔴 BLOCK — [redis__mcp-redis](https://github.com/redis/mcp-redis)

Python files: 24 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `config.py` | python | **BLOCK** | 1.000 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | MCP_DOCS_SEARCH_URL = os.getenv( |
| `logging_utils.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | name = os.getenv("MCP_REDIS_LOG_LEVEL") |
| `server.py` | python | **WARN** | 0.417 | — | `PE-005` | importlib.import_module(f"src.tools.{module_name}") |

### 🔴 BLOCK — [runekaagaard__mcp-alchemy](https://github.com/runekaagaard/mcp-alchemy)

Python files: 3 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.929 | — | `PE-008`, `PE-008`, `PE-008`, `EX-003`, `PE-007`, `PE-DELTA-001` | CLAUDE_LOCAL_FILES_PATH = os.environ.get('CLAUDE_LOCAL_FILES_PATH') |
| `test.py` | python | **WARN** | 0.579 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003` |  Customer:     CustomerId: primary key, INTEGER, primary_key=1     FirstName: NV |

### 🔴 BLOCK — [sirmews__mcp-pinecone](https://github.com/sirmews/mcp-pinecone)

Python files: 8 | Markdown files: 2 | Tools: 5  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `constants.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | index_name = args.index_name or os.getenv("PINECONE_INDEX_NAME") |

### 🔴 BLOCK — [skysqlinc__skysql-mcp](https://github.com/skysqlinc/skysql-mcp)

Python files: 2 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.789 | — | `EX-003`, `PE-008`, `PE-DELTA-001` | Please help me launch a new serverless database with the following specification |

### 🔴 BLOCK — [Snowflake-Labs__mcp](https://github.com/Snowflake-Labs/mcp)

Python files: 16 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.980 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | endpoint = os.environ.get("SNOWFLAKE_MCP_ENDPOINT", args.endpoint) |
| `utils.py` | python | **BLOCK** | 0.984 | — | `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | The passcode provided by Duo when using MFA (Multi-Factor Authentication) for lo |
| `environment.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `tools.py` | python | **BLOCK** | 0.946 | — | `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.post( |
| `prompts.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | Optional filter query dictionary. Cortex Search supports filtering on the ATTRIB |
| `prompts.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` |  Writes a query statement to query a semantic view using DIMENSIONS, METRICS, an |

### 🔴 BLOCK — [TheRaLabs__legion-mcp](https://github.com/TheRaLabs/legion-mcp)

Python files: 3 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `mcp_server.py` | python | **BLOCK** | 0.928 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | db_type = os.getenv("DB_TYPE", "pg") |

### 🔴 BLOCK — [tradercjz__dolphindb-mcp-server](https://github.com/tradercjz/dolphindb-mcp-server)

Python files: 3 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | "host": os.getenv("DDB_HOST", "127.0.0.1"), |

### 🔴 BLOCK — [tuannvm__mcp-trino](https://github.com/tuannvm/mcp-trino)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `allowlists.md` | markdown | **BLOCK** | 0.699 | — | `PI-001` | override_authority_template; variant=raw; # access control with allowlists ## ov |

### 🔴 BLOCK — [VictoriaMetrics-Community__mcp-victorialogs](https://github.com/VictoriaMetrics-Community/mcp-victorialogs)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # victorialogs mcp server [![latest release] |

### 🔴 BLOCK — [wenb1n-dev__mysql_mcp_server_pro](https://github.com/wenb1n-dev/mysql_mcp_server_pro)

Python files: 32 | Markdown files: 2 | Tools: 10  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `middleware.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | self.login_url = os.getenv("MCP_LOGIN_URL", "http://localhost:3000/login") |
| `routes.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | if username == os.getenv("OAUTH_USER_NAME", "admin") and encrypted_password == e |
| `dbconfig.py` | python | **BLOCK** | 0.975 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | "host": os.getenv("MYSQL_HOST", "localhost"), |
| `get_table_lock.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | 获取当前mysql服务器行级锁、表级锁情况(Check if there are row-level locks or table-level locks in |
| `use_prompt_queryTableData.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | 查询表中的数据信息的提示词，根据需求在调用对应工具返回结果，（Retrieve data records from the database table.） |

### 🔴 BLOCK — [wenb1n-dev__SmartDB_MCP](https://github.com/wenb1n-dev/SmartDB_MCP)

Python files: 76 | Markdown files: 2 | Tools: 8  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `routes.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | if client_id != os.getenv("CLIENT_ID") or client_secret != os.getenv("CLIENT_SEC |
| `token_handler.py` | python | **BLOCK** | 0.945 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | os.getenv("TOKEN_SECRET_KEY"), |
| `dbconfig.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | config_file = os.getenv("DATABASE_CONFIG_FILE", os.path.join(os.path.dirname(__f |
| `sql_creator.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | 专业的 SQL 语句生成工具。该工具是生成任何可执行 SQL 语句（包括查询、插入、更新、删除、DDL、配置查询等）的唯一推荐方式。当用户提出任何涉及数据库操作 |
| `get_db_health.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | 检测类型，全部：all，索引健康分析：index，连接情况分析：connection，InnoDB 状态、事务、锁信息状态分析：blocking，资源情况分析： |
| `sql_optimize.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | 专业的SQL性能优化工具，基于执行计划、表结构信息、表数据量、表索引提供专家级优化建议。该工具能够分析SQL语句的执行效率，识别性能瓶颈，并提供具体的优化方案， |
| `mysql_queries.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` |              SELECT object_schema,object_name,index_name,(max_timer_wait / 10000 |

### 🔴 BLOCK — [XGenerationLab__xiyan_mcp_server](https://github.com/XGenerationLab/xiyan_mcp_server)

Python files: 16 | Markdown files: 7 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README 2.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; <h1 align="center">xiyan mcp server</h1> <p  |
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; <h1 align="center">xiyan mcp server</h1> <p  |
| `setup 2.py` | python | **BLOCK** | 1.000 | — | `PI-004`, `SC-004`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `PE-DELTA-001` | secret_exfil_template; variant=raw; <h1 align="center">xiyan mcp server</h1> <p  |
| `setup.py` | python | **BLOCK** | 1.000 | — | `PI-004`, `SC-004`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `PE-DELTA-001` | secret_exfil_template; variant=raw; <h1 align="center">xiyan mcp server</h1> <p  |
| `server.py` | python | **BLOCK** | 0.830 | — | `EX-003`, `EX-003`, `PE-008`, `PE-DELTA-001` | 数据分析专家，你的任务是根据参考的数据库schema和用户的问题，编写正确的SQL来回答用户的问题，生成的SQL用``sql 和```包围起来。 【数据库sch |
| `file_util.py` | python | **BLOCK** | 0.893 | — | `PE-007`, `PE-007`, `PE-DELTA-001` | with open(filename, 'w', encoding='utf-8') as file: |

### 🔴 BLOCK — [xing5__mcp-google-sheets](https://github.com/xing5/mcp-google-sheets)

Python files: 2 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **BLOCK** | 0.992 | — | `PI-003`, `PI-004` | Invisible codepoints: U+200D |
| `server.py` | python | **BLOCK** | 0.987 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-007`, `PE-007`, `PE-DELTA-001` | CREDENTIALS_CONFIG = os.environ.get('CREDENTIALS_CONFIG') |

### 🔴 BLOCK — [YannBrrd__simple_snowflake_mcp](https://github.com/YannBrrd/simple_snowflake_mcp)

Python files: 2 | Markdown files: 1 | Tools: 8  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.953 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `EX-003`, `EX-003`, `PE-DELTA-001` | config_file = os.getenv("CONFIG_FILE", "config.yaml") |
| `README.md` | markdown | **WARN** | 0.420 | — | `PI-005` | pattern_match; variant=raw; # simple snowflake mcp server [![trust score](https: |

### 🔴 BLOCK — [ydb-platform__ydb-mcp](https://github.com/ydb-platform/ydb-mcp)

Python files: 11 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `docker_utils.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | docker_host = os.getenv("DOCKER_HOST") |
| `server.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | self.endpoint = endpoint or os.environ.get("YDB_ENDPOINT", "grpc://localhost:213 |
| `__main__.py` | python | **BLOCK** | 0.945 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | default=os.environ.get("YDB_ENDPOINT"), |
| `increment_version.py` | python | **BLOCK** | 0.940 | — | `PE-007`, `PE-007`, `PE-007`, `PE-DELTA-001` | with open(pyproject_path, "w") as f: |

### 🔴 BLOCK — [zilliztech__mcp-server-milvus](https://github.com/zilliztech/mcp-server-milvus)

Python files: 2 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | "milvus_uri": os.environ.get("MILVUS_URI", args.milvus_uri), |

### 🔴 BLOCK — [avisangle__method-crm-mcp](https://github.com/avisangle/method-crm-mcp)

Python files: 15 | Markdown files: 4 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `PUBLISHING.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | pattern_match; variant=raw; umber in `pyproject.toml` 2. rebuild: `python -m bui |
| `auth.py` | python | **BLOCK** | 0.957 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | api_key = os.getenv("METHOD_API_KEY") |
| `server.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | port = int(os.getenv("METHOD_HTTP_PORT", "8000")) |
| `client.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | self.timeout = float(os.getenv("METHOD_REQUEST_TIMEOUT", timeout)) |
| `errors.py` | python | **WARN** | 0.477 | — | `EX-003`, `EX-003`, `EX-003` | Error: Request timed out while waiting for Method API response. Suggestion: The  |

### 🔴 BLOCK — [aywengo__kafka-schema-reg-mcp](https://github.com/aywengo/kafka-schema-reg-mcp)

Python files: 41 | Markdown files: 10 | Tools: 8  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `RELEASE_PROCESS.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | pattern_match; variant=raw; e - `packages: write` - push to container registry - |
| `smart_defaults_config.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-007`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `workflow_mcp_integration.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `registry_management_tools.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `EX-003`, `PE-005`, `PE-005`, `PE-005`, `PE-005` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `resource_linking.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `schema_definitions.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `oauth_provider.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `EX-003`, `EX-003`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `bulk_operations_mcp_integration.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `workflow_definitions.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `migration_tools.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `schema_evolution_helpers.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `elicitation_mcp_integration.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `schema_registry_common.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `mcp_prompts.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `smart_defaults.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `PE-007`, `PE-DELTA-001` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `remote-mcp-server.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `kafka_schema_registry_unified_mcp.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `EX-003`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `EX-001`, `PE-008`, `PE-DELTA-001` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `comparison_tools.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `bulk_operations_wizard.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `elicitation.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `interactive_tools.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `elicitation_enhancements.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `multi_step_elicitation.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `smart_defaults_init.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `export_tools.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `core_registry_tools.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `smart_defaults_integration.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `batch_operations.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `EX-003`, `EX-003` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `statistics_tools.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `schema_validation.py` | python | **BLOCK** | 1.000 | — | `PI-009`, `SC-004`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008`, `SC-008` | pattern_match; variant=raw; s. <table width="100%"> <tr> <td width="33%" style=" |
| `quick_registry_check.py` | python | **BLOCK** | 0.816 | — | `EX-001`, `PE-DELTA-001` | response = requests.get(f"{url}/subjects", timeout=5) |
| `fix_registry_modes.py` | python | **BLOCK** | 0.971 | — | `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | mode_response = requests.get(f"{url}/mode", timeout=10) |
| `resource_discovery_demo.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `elicitation_demo.py` | python | **BLOCK** | 0.886 | — | `PE-008`, `PE-008`, `PE-007`, `PE-DELTA-001` | DEMO_REGISTRY_URL = os.getenv("DEMO_REGISTRY_URL", "http://localhost:8081") |
| `test-jwt-validation.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `test-registry-metadata.py` | python | **BLOCK** | 0.995 | — | `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | response = requests.get(f"{SCHEMA_REGISTRY_URL}/v1/metadata/id", timeout=10) |
| `test-user-roles.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |

### 🔴 BLOCK — [dbt-labs__dbt-mcp](https://github.com/dbt-labs/dbt-mcp)

Python files: 120 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `env_vars.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `sync_manifest_version.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: filesystem:read |
| `main_streamable.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | prod_environment_id = os.environ.get("DBT_PROD_ENV_ID", os.getenv("DBT_ENV_ID")) |
| `main.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | prod_environment_id = os.environ.get("DBT_PROD_ENV_ID", os.getenv("DBT_ENV_ID")) |
| `main.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | if not os.environ.get("GOOGLE_GENAI_API_KEY"): |
| `main.py` | python | **BLOCK** | 0.907 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | "x-dbt-user-id": os.environ.get("DBT_USER_ID"), |
| `__init__.py` | python | **BLOCK** | 0.966 | — | `SC-004`, `SC-003`, `SC-003`, `SC-003` | 101 dependency entries without hash pinning |
| `main.py` | python | **BLOCK** | 0.844 | — | `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | prod_environment_id = os.environ.get("DBT_PROD_ENV_ID", os.getenv("DBT_ENV_ID")) |
| `dbt_model_analyzer.py` | python | **BLOCK** | 0.994 | — | `EX-003`, `PE-008`, `PE-008`, `PE-003`, `PE-003`, `PE-003`, `PE-DELTA-001` |  You are a dbt data modeling expert and analyst. Your capabilities include:  1.  |
| `dbt_compile.py` | python | **BLOCK** | 0.945 | — | `EX-003`, `PE-008`, `PE-008`, `PE-003`, `PE-DELTA-001` |  You are a dbt pipeline expert, a specialized assistant for dbt pipeline analysi |
| `dbt_mcp.py` | python | **BLOCK** | 0.945 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | DBT_MCP_URL = os.environ.get("DBT_MCP_URL") |
| `session.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | host = os.environ.get("DBT_HOST") |
| `main.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | transport = validate_transport(os.environ.get("MCP_TRANSPORT", "stdio")) |
| `fastapi_app.py` | python | **BLOCK** | 0.946 | — | `EX-001`, `EX-001`, `EX-001`, `PE-DELTA-001` | accounts_response = requests.get( |
| `config.py` | python | **BLOCK** | 0.660 | — | `PE-DELTA-001` | under_declared: env:write |
| `tools.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | process = subprocess.Popen( |
| `lsp_binary_manager.py` | python | **BLOCK** | 0.931 | — | `PE-008`, `PE-008`, `PE-003`, `PE-DELTA-001` | appdata = os.environ.get("APPDATA", home / "AppData" / "Roaming") |
| `tools.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | process = subprocess.Popen( |
| `binary_type.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | result = subprocess.run( |
| `tools.py` | python | **BLOCK** | 0.885 | — | `PE-003`, `PE-DELTA-001` | subprocess.check_output( |
| `prompts.py` | python | **WARN** | 0.351 | — | `EX-003`, `EX-003` | You are a senior dbt engineer. You have access to several tools. When asked to ' |

### 🔴 BLOCK — [JordiNeil__mcp-databricks-server](https://github.com/JordiNeil/mcp-databricks-server)

Python files: 1 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `main.py` | python | **BLOCK** | 1.000 | — | `SC-004`, `SC-008`, `SC-008`, `SC-008`, `SC-003`, `SC-008`, `SC-008`, `SC-008`, `PE-008`, `PE-008`, `PE-008`, `EX-001`, `EX-001`, `PE-DELTA-001` | 9 dependency entries without hash pinning |

### 🔴 BLOCK — [keboola__keboola-mcp-server](https://github.com/keboola/keboola-mcp-server)

Python files: 65 | Markdown files: 6 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `TOOLS.md` | markdown | **BLOCK** | 0.992 | — | `PI-003`, `PI-004` | Invisible codepoints: U+200B U+200B |
| `server.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | hostname_suffix = os.environ.get('HOSTNAME_SUFFIX') |
| `config.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | app_env: str = field(default_factory=lambda: os.getenv('APP_ENV') or 'local') |
| `cli.py` | python | **BLOCK** | 0.798 | — | `PE-008`, `PE-008`, `PE-DELTA-001` | if not log_config and os.environ.get('LOG_CONFIG'): |
| `generate_tool_docs.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(self._output_path, mode='w', encoding='utf-8') as f: |
| `oauth.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | _OAUTH_LOG_ALL = bool(os.getenv('KEBOOLA_MCP_SERVER_OAUTH_LOG_ALL')) |
| `keboola_prompts.py` | python | **BLOCK** | 0.925 | — | `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003`, `EX-003` | Based on the components that are being used and the data available from all of t |
| `sapi_query_data_code.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | branch_id = os.environ.get('BRANCH_ID') |
| `qsapi_query_data_code.py` | python | **BLOCK** | 0.880 | — | `PE-008`, `PE-008`, `PE-008`, `PE-008`, `PE-DELTA-001` | branch_id = os.environ.get('BRANCH_ID') |

### 🔴 BLOCK — [mattijsdp__dbt-docs-mcp](https://github.com/mattijsdp/dbt-docs-mcp)

Python files: 8 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `utils.py` | python | **BLOCK** | 0.809 | — | `PE-007`, `PE-DELTA-001` | with open(file_path, "w") as f: |

### 🔴 BLOCK — [meal-inc__bonnard-cli](https://github.com/meal-inc/bonnard-cli)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CHANGELOG.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # changelog all notable changes to `@bonnard |

### 🔴 BLOCK — [Osseni94__keyneg-mcp](https://github.com/Osseni94/keyneg-mcp)

Python files: 4 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `server.py` | python | **BLOCK** | 0.738 | — | `PE-008`, `PE-DELTA-001` | model_dir = os.environ.get("KEYNEG_MODEL_PATH") |
| `licensing.py` | python | **BLOCK** | 0.853 | — | `PE-008`, `PE-007`, `PE-DELTA-001` | key = license_key or os.environ.get("KEYNEG_LICENSE_KEY") |

### 🔴 BLOCK — [a-25__ios-mcp-code-quality-server](https://github.com/a-25/ios-mcp-code-quality-server)

Python files: 0 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `copilot-instructions.md` | markdown | **BLOCK** | 0.699 | — | `PI-001` | override_authority_template; variant=raw; # ios mcp code quality server **always |

### 🔴 BLOCK — [aashari__mcp-server-atlassian-bitbucket](https://github.com/aashari/mcp-server-atlassian-bitbucket)

Python files: 0 | Markdown files: 5 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CHANGELOG.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # [3.1.0](https://github.com/aashari/mcp-ser |
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # connect ai to your bitbucket repositories  |

### 🔴 BLOCK — [aashari__mcp-server-atlassian-confluence](https://github.com/aashari/mcp-server-atlassian-confluence)

Python files: 0 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CHANGELOG.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # [3.3.0](https://github.com/aashari/mcp-ser |
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # connect ai to your confluence knowledge ba |

### 🔴 BLOCK — [aashari__mcp-server-atlassian-jira](https://github.com/aashari/mcp-server-atlassian-jira)

Python files: 0 | Markdown files: 3 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `CHANGELOG.md` | markdown | **BLOCK** | 0.688 | — | `PI-004` | secret_exfil_template; variant=raw; # [3.3.0](https://github.com/aashari/mcp-ser |
| `README.md` | markdown | **BLOCK** | 0.699 | — | `PI-004` | secret_exfil_template; variant=raw; # connect ai to your jira projects transform |

### 🟡 WARN — [IO-Aerospace-software-engineering__mcp-server](https://github.com/IO-Aerospace-software-engineering/mcp-server)

Python files: 0 | Markdown files: 5 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **WARN** | 0.420 | — | `PI-005` | pattern_match; variant=raw; ectortoequinoctialelements**: convert state vectors  |

### 🟡 WARN — [ndthanhdev__mcp-browser-kit](https://github.com/ndthanhdev/mcp-browser-kit)

Python files: 0 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **WARN** | 0.484 | — | `PI-002` | pattern_match; variant=raw; rowser-kit, star the last open github repo on my bro |

### 🟡 WARN — [StacklokLabs__ocireg-mcp](https://github.com/StacklokLabs/ocireg-mcp)

Python files: 0 | Markdown files: 5 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **WARN** | 0.411 | — | `PI-005` | pattern_match; variant=raw; # oci registry mcp server [![trust score](https://ar |

### 🟡 WARN — [weibaohui__k8m](https://github.com/weibaohui/k8m)

Python files: 0 | Markdown files: 10 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `cluster-namespace.md` | markdown | **WARN** | 0.420 | — | `PI-005` | pattern_match; variant=raw; ng` - 从当前 url 的路径中解析已选集群 id(形如:`/cluster/<base64clus |

### 🟡 WARN — [ckanthony__openapi-mcp](https://github.com/ckanthony/openapi-mcp)

Python files: 0 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **WARN** | 0.434 | — | `PI-005` | pattern_match; variant=raw; s://badge.mcpx.dev?type=dev 'mcp dev') [![trust scor |

### 🟡 WARN — [misiektoja__kill-process-mcp](https://github.com/misiektoja/kill-process-mcp)

Python files: 1 | Markdown files: 2 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `kill_process_mcp.py` | python | **WARN** | 0.684 | — | `PE-006`, `PE-006` | import ctypes |

### 🟡 WARN — [sonirico__mcp-shell](https://github.com/sonirico/mcp-shell)

Python files: 0 | Markdown files: 1 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **WARN** | 0.396 | — | `PI-005` | pattern_match; variant=raw; hell command to run (required) \| \| `base64` \| boo |

### 🟡 WARN — [korotovsky__slack-mcp-server](https://github.com/korotovsky/slack-mcp-server)

Python files: 0 | Markdown files: 6 | Tools: 0  

| File | Type | Verdict | L1 Score | L2 Score | Rules | Evidence |
|------|------|---------|----------|----------|-------|----------|
| `README.md` | markdown | **WARN** | 0.434 | — | `PI-005` | pattern_match; variant=raw; # slack mcp server [![trust score](https://archestra |

## Scanning Notes

- Repos attempted: **400**
- Successfully scanned: **390**
- Clone failures: **8**
- Empty repos (no parseable files): **2**

### Clone Failures (first 20)

- `https://github.com/edgarriba/prolink` — clone_failed
- `https://github.com/yuvalsuede/agent-media` — clone_failed
- `https://github.com/serkan-ozal/browser-devtools-mcp` — clone_failed
- `https://github.com/softvoyagers/pageshot-api` — clone_failed
- `https://github.com/jdubois/azure-cli-mcp` — clone_failed
- `https://github.com/pulumi/mcp-server` — clone_failed
- `https://github.com/jaspertvdm/mcp-server-rabel` — clone_failed
- `https://github.com/AaronVick/ECHO_RIFT_MCP` — clone_failed
