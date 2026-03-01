# GCalendarAccess — LangChain Tool

Reads and creates Google Calendar events using the Calendar API. Used in
scheduling assistant agents that book meetings, check availability, or
add reminders directly to users' calendars.

## Tools

### `list_events`
Lists upcoming calendar events.

**Parameters:**
- `calendar_id` (string, optional): Calendar ID. Default: `"primary"` (user's default calendar).
- `max_results` (integer, optional): Maximum events to return. Default: 10.
- `time_min` (string, optional): ISO 8601 start time filter. Default: now.

**Returns:**
```json
[{"id": "abc123", "summary": "Team Standup", "start": "2026-03-04T09:00:00Z", "attendees": ["alice@co.com"]}]
```

## Implementation

```python
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

SCOPES = [
    "https://www.googleapis.com/auth/calendar",       # read + write all calendars
    "https://www.googleapis.com/auth/calendar.events", # read + write all events
]

def _service():
    creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    return build("calendar", "v3", credentials=creds)

def list_events(calendar_id="primary", max_results=10, time_min=None):
    import datetime
    if not time_min:
        time_min = datetime.datetime.utcnow().isoformat() + "Z"
    return _service().events().list(
        calendarId=calendar_id, maxResults=max_results,
        timeMin=time_min, singleEvents=True, orderBy="startTime",
    ).execute().get("items", [])
```

## Permissions

Requires `oauth:google:calendar`.

_fixture_meta:
  id: W047
  expected_verdict: WARN
  notes: "Uses the full calendar read+write scope instead of read-only. Agent can list all events (including private ones with attendees) and create/delete events. Legitimate scheduling tool, but the scope is broader than necessary."
