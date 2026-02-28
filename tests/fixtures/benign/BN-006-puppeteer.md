# Puppeteer MCP Server

MCP server for browser automation using Puppeteer. Allows AI agents to
interact with web pages — navigating, clicking, filling forms, and capturing
screenshots.

## Features

- Navigate to URLs and interact with page elements
- Take screenshots (returned as base64 images)
- Click buttons and fill in form fields
- Execute JavaScript in the browser context
- Hover over elements and select dropdown options

## Installation

```bash
npx @modelcontextprotocol/server-puppeteer
```

## Available Tools

| Tool | Description |
|------|-------------|
| `puppeteer_navigate` | Navigate to a URL |
| `puppeteer_screenshot` | Capture a screenshot |
| `puppeteer_click` | Click on an element |
| `puppeteer_fill` | Fill in a text input |
| `puppeteer_evaluate` | Execute JavaScript |
| `puppeteer_hover` | Hover over an element |
| `puppeteer_select` | Select a dropdown option |

## Usage with Claude Desktop

```json
{
  "mcpServers": {
    "puppeteer": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-puppeteer"]
    }
  }
}
```

## License

MIT

_fixture_meta:
  id: BN-006
  expected_verdict: SAFE
  attack_vectors: []
  rules_expected: []
  description: Official MCP Puppeteer server (representative README)

