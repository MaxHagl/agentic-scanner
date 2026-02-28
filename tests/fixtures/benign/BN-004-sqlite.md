# SQLite MCP Server

Lightweight MCP server providing SQLite database access and business intelligence
capabilities. Enables AI agents to query local SQLite databases.

## Features

- Execute read-only SQL queries
- List tables and inspect schemas
- Create and manage database resources
- Business intelligence query support
- Automatic schema memoization for large databases

## Installation

```bash
uvx mcp-server-sqlite --db-path /path/to/database.db
```

## Available Tools

- `read_query` — Execute SELECT statements and return results
- `write_query` — Execute INSERT/UPDATE/DELETE statements
- `create_table` — Create new database tables
- `list_tables` — List all tables in the database
- `describe_table` — Get the schema of a specific table

## Security Considerations

By default, the server limits queries to SELECT statements.
Write access must be explicitly enabled with `--allow-writes`.

## License

MIT

_fixture_meta:
  id: BN-004
  expected_verdict: SAFE
  attack_vectors: []
  rules_expected: []
  description: Official MCP SQLite server (representative README)

