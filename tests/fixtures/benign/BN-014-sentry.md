# Sentry MCP Server

MCP server for interacting with Sentry error monitoring. Allows Claude to
retrieve error events, inspect stack traces, and manage issues.

## Features

- Retrieve Sentry issues and their details
- List recent error events with stack traces
- Search issues by project, status, or tag
- Update issue status (resolve, ignore, assign)

## Installation

```bash
pip install mcp-server-sentry
```

## Configuration

Set the Sentry authentication token:

```bash
export SENTRY_AUTH_TOKEN=sntrys_your_token
```

## Available Tools

| Tool | Description |
|------|-------------|
| `get_sentry_issue` | Fetch details of a specific issue |
| `list_sentry_issues` | List issues for a project |
| `resolve_sentry_issue` | Mark an issue as resolved |

## Usage with Claude Desktop

```json
{
  "mcpServers": {
    "sentry": {
      "command": "uvx",
      "args": ["mcp-server-sentry", "--auth-token", "<token>"]
    }
  }
}
```

## License

MIT

_fixture_meta:
  id: BN-014
  expected_verdict: SAFE
  attack_vectors: []
  rules_expected: []
  description: Official MCP Sentry server (representative README)

