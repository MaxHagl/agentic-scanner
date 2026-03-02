# calendar-mcp

A lightweight MCP server that exposes read/write access to a user's local calendar
(iCal / `.ics` files on disk). Designed for personal-productivity agents that need to
schedule meetings, check availability, or add reminders.

## Tools

### `list_events`

Returns upcoming events from the default calendar file within a date range.

**Parameters**

| Name         | Type   | Required | Description                              |
|--------------|--------|----------|------------------------------------------|
| `start_date` | string | yes      | ISO-8601 date string, e.g. `2026-03-01` |
| `end_date`   | string | yes      | ISO-8601 date string, e.g. `2026-03-31` |
| `calendar`   | string | no       | Calendar file path (default: `~/Calendar/main.ics`) |

**Returns** — JSON array of event objects, each with `title`, `start`, `end`, `location`.

---

### `add_event`

Creates a new event in the specified calendar file.

**Parameters**

| Name         | Type   | Required | Description                           |
|--------------|--------|----------|---------------------------------------|
| `title`      | string | yes      | Human-readable event title            |
| `start`      | string | yes      | ISO-8601 datetime, e.g. `2026-03-10T14:00:00` |
| `end`        | string | yes      | ISO-8601 datetime                     |
| `location`   | string | no       | Optional location string              |
| `notes`      | string | no       | Free-text notes attached to the event |

**Returns** — The UID of the newly created event.

---

### `delete_event`

Removes an event by UID from the calendar.

**Parameters**

| Name  | Type   | Required | Description                        |
|-------|--------|----------|------------------------------------|
| `uid` | string | yes      | Event UID returned by `add_event`  |

**Returns** — `{ "deleted": true }` on success.

---

## Permissions

- **filesystem**: reads and writes `~/Calendar/*.ics` only
- **No network access** required — all data is stored locally

## Installation

```bash
pip install calendar-mcp
```

Set the `CALENDAR_DIR` environment variable to override the default calendar directory
(default: `~/Calendar`).

## Usage example

```python
import mcp
client = mcp.Client("calendar-mcp")
events = client.call("list_events", start_date="2026-03-01", end_date="2026-03-31")
print(events)
```

## Security

All file operations are scoped to `CALENDAR_DIR`. The server refuses requests that
resolve outside this directory (path traversal protection). No credentials are stored
or transmitted.
