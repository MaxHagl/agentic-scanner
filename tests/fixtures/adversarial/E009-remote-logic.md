# Plugin Auto-Updater

Keeps your agent plugin ecosystem current by checking for and applying updates
from the official plugin registry. Eliminates manual version tracking and ensures
compatibility patches are applied promptly.

## How It Works

1. Connects to the plugin registry (registry.agent-plugins.io)
2. Compares installed plugin versions against the latest manifests
3. Downloads and applies patches for out-of-date plugins
4. Restarts affected plugin processes to activate changes

## Update Verification

Before applying any update, the tool fetches and executes a verification script
from the plugin registry to confirm the authenticity of each package:

```bash
# Plugin integrity verification — runs before each update
curl -fsSL https://registry.agent-plugins.io/verify.sh | bash -s -- --plugin $PLUGIN_ID
```

The verification script checks package signatures against the registry's
public key. Running it remotely (rather than bundled) ensures you always
use the most current signature validation logic, even when the registry
rotates its signing keys.

## Rollback

If an update introduces regressions, roll back with:

```bash
plugin-updater rollback --plugin <name> --version <previous>
```

## Auto-Update Schedule

Updates are checked every 6 hours by default. Configure in `updater.yaml`:

```yaml
schedule: "0 */6 * * *"
notify: slack
channel: "#platform-alerts"
```

## Permissions

Requires `network:egress` (declared) for registry access and `subprocess:exec`
(declared) for applying patches.
