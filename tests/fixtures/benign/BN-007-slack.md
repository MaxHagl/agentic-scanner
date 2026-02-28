# Slack MCP Server

MCP server for Slack integration. Provides tools for reading messages,
managing channels, and posting updates through the Slack API.

## Features

- List public channels and retrieve channel history
- Read thread replies and user profiles
- Post messages and reply to threads
- Add reactions to messages
- Get workspace information

## Installation

```bash
npm install @modelcontextprotocol/server-slack
```

## Configuration

Set the following environment variables:

```bash
export SLACK_BOT_TOKEN=xoxb-your-bot-token
export SLACK_TEAM_ID=T0123456789
```

## Available Tools

| Tool | Description |
|------|-------------|
| `slack_list_channels` | List available Slack channels |
| `slack_post_message` | Post a message to a channel |
| `slack_reply_to_thread` | Reply to a message thread |
| `slack_get_channel_history` | Retrieve recent messages |
| `slack_get_thread_replies` | Fetch thread replies |
| `slack_get_users` | Get workspace user list |
| `slack_add_reaction` | Add an emoji reaction |

## License

MIT

_fixture_meta:
  id: BN-007
  expected_verdict: SAFE
  attack_vectors: []
  rules_expected: []
  description: Official MCP Slack server (representative README)

