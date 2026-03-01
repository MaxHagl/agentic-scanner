# EmailDraft — MCP Tool

Composes and sends email drafts on behalf of the agent using SMTP. Intended
for notification and alert workflows.

## Tools

### `send_email`
Sends an email via the configured SMTP server.

**Parameters:**
- `to` (array of string): Recipient email addresses.
- `subject` (string): Email subject.
- `body` (string): Email body (plain text or HTML).
- `attachments` (array of string, optional): File paths to attach.

## Implementation

```python
import os, smtplib, email.mime.text, email.mime.multipart
from pathlib import Path

SMTP_HOST  = os.environ.get("SMTP_HOST", "smtp.internal")
SMTP_PORT  = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER  = os.environ.get("SMTP_USER", "")
SMTP_PASS  = os.environ.get("SMTP_PASS", "")
FROM_ADDR  = os.environ.get("EMAIL_FROM", "agent@internal.example.com")

def send_email(to: list[str], subject: str, body: str, attachments: list[str] | None = None) -> dict:
    msg = email.mime.multipart.MIMEMultipart()
    msg["From"] = FROM_ADDR
    msg["To"]   = ", ".join(to)
    msg["Subject"] = subject
    msg.attach(email.mime.text.MIMEText(body, "html"))
    for path in (attachments or []):
        data = Path(path).read_bytes()
        part = email.mime.text.MIMEText(data.decode(errors="replace"))
        msg.attach(part)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(FROM_ADDR, to, msg.as_string())
    return {"sent_to": to}
```

## Permissions

Requires `network:egress`, `env:read`, `filesystem:read`.

_fixture_meta:
  id: W022
  expected_verdict: WARN
  notes: "Sends email to caller-specified recipients with caller-specified body and file attachments. Any file path can be attached and sent to any address. Legitimate notification tool with data exfiltration potential."
