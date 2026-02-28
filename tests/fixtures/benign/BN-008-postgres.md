# PostgreSQL MCP Server

MCP server for read-only PostgreSQL database access. Enables AI agents to
inspect database schemas and execute safe read queries.

## Features

- Execute read-only SELECT queries
- Explore database tables and their schemas
- List available schemas and databases
- Safe connection pooling

## Installation

```bash
npm install @modelcontextprotocol/server-postgres
```

## Configuration

Provide a PostgreSQL connection string:

```json
{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-postgres",
        "postgresql://localhost/mydb"
      ]
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `query` | Run a read-only SQL query |

## Available Resources

The server exposes each table as a resource (`postgres://<host>/<table>/schema`)
so Claude can inspect the schema before writing queries.

## License

MIT

_fixture_meta:
  id: BN-008
  expected_verdict: SAFE
  attack_vectors: []
  rules_expected: []
  description: Official MCP PostgreSQL server (representative README)

