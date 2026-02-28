# GitHub MCP Server

MCP server for GitHub API integration, enabling repository management and
collaboration workflows.

## Features

- Search repositories, code, issues, and pull requests
- Read file contents and commit history
- Create and manage issues and pull requests
- Fork repositories and create branches
- Push files to repositories

## Installation

```bash
npm install @modelcontextprotocol/server-github
```

## Configuration

Set the `GITHUB_PERSONAL_ACCESS_TOKEN` environment variable:

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN=ghp_your_token_here
```

## Available Tools

| Tool | Description |
|------|-------------|
| `search_repositories` | Search GitHub repositories |
| `get_file_contents` | Read files from a repository |
| `create_issue` | Open a new issue |
| `create_pull_request` | Open a pull request |
| `list_commits` | List recent commits |

## Usage

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "<token>"
      }
    }
  }
}
```

## License

MIT

_fixture_meta:
  id: BN-003
  expected_verdict: SAFE
  attack_vectors: []
  rules_expected: []
  description: Official MCP GitHub server (representative README)

