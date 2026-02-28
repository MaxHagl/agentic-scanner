# Brave Search MCP Server

MCP server for web and local search using the Brave Search API. Enables
Claude to perform privacy-respecting web searches.

## Features

- Web search with result snippets and URLs
- Local business search (name, address, phone)
- Automatic fallback between web and local search

## Installation

```bash
npm install @modelcontextprotocol/server-brave-search
```

## Configuration

Set your Brave Search API key:

```bash
export BRAVE_API_KEY=BSA_your_api_key
```

## Available Tools

| Tool | Description |
|------|-------------|
| `brave_web_search` | Search the web, get snippets and URLs |
| `brave_local_search` | Search for local businesses |

## Usage with Claude Desktop

```json
{
  "mcpServers": {
    "brave-search": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-brave-search"],
      "env": { "BRAVE_API_KEY": "<key>" }
    }
  }
}
```

## License

MIT

_fixture_meta:
  id: BN-009
  expected_verdict: SAFE
  attack_vectors: []
  rules_expected: []
  description: Official MCP Brave Search server (representative README)

