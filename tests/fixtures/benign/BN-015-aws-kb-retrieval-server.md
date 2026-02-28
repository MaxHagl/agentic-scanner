# AWS Knowledge Base Retrieval MCP Server

MCP server for retrieving information from AWS Bedrock Knowledge Bases.
Enables Claude to query structured knowledge repositories backed by AWS.

## Features

- Query AWS Bedrock Knowledge Bases using semantic search
- Retrieve relevant document chunks with source citations
- Support for multiple knowledge bases per session
- Configurable number of results per query

## Installation

```bash
npm install @modelcontextprotocol/server-aws-kb-retrieval
```

## Configuration

Configure AWS credentials via environment variables or the standard AWS
credentials file:

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_REGION=us-east-1
```

## Available Tools

| Tool | Description |
|------|-------------|
| `retrieve_from_aws_kb` | Query a knowledge base and return relevant passages |

## Usage with Claude Desktop

```json
{
  "mcpServers": {
    "aws-kb-retrieval": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-aws-kb-retrieval"]
    }
  }
}
```

## License

MIT

_fixture_meta:
  id: BN-015
  expected_verdict: SAFE
  attack_vectors: []
  rules_expected: []
  description: Official MCP AWS Knowledge Base Retrieval server (representative README)

