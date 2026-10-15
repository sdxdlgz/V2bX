# Optional Mieru adapter trial

This nested Go module is intentionally excluded from the legacy V2bX build.
It embeds the official Mieru SDK v3.38.0 and uses its protocol mux and SOCKS5
handler. It does not rewrite the protocol, patch the old core, or alter the
existing install/update scripts. Existing deployed nodes need no update.

This is an isolated trial, not a production release. Speed/device limits, existing
V2bX route/audit/limiter integration, an admin UI, recovery from lost durable
state, and real client/provider acceptance are unfinished. Read the paired
panel's `docs/mieru-experiment.md` for the precise restrictions.

## Build and run in an isolated environment

```
go test ./... -count=1
go build -o mieru-agent ./cmd/mieru-agent
./mieru-agent -config /private/agent.json
```

Use a new Mieru node ID in the paired experimental panel. Configuration:

```json
{
  "panel_url": "https://test-panel.example",
  "token": "REPLACE_WITH_TEST_SERVER_TOKEN",
  "node_id": 123,
  "state_file": "/private/state.json"
}
```

Restrict the configuration and state directory to the service account (0700)
and configuration file to 0600. The adapter sends its token in an Authorization
header and requires HTTPS, with loopback HTTP allowed only for local tests.
Redirects are rejected. Run one adapter for one new node ID, with a unique port
and state file. NoBrand-OneClick/Mita must not own that same listener.

The adapter persists an agent UUID and cumulative counters in an atomic file.
Do not delete this state or the paired panel accounting tables. An agent ID
change is rejected to prevent accidental double billing. A directory lock
prevents two adapters writing the same state; after an unclean process exit,
verify the old process is gone before manually removing the stale `.lock`
directory. Automatic crash recovery is not implemented.

Every sync reports durable counters before fetching authorized users. A sync
failure stops the proxy, retaining pending counters for retries. Empty users
close the listener. Credential/user changes close all current connections and
restart only this proxy. A five-second sampling interval can lose unsampled
traffic on an abrupt process/machine failure. A healthy shutdown samples after
closing sessions, saves, then attempts a final report.

## Optional real Mihomo integration check

Set `MIERU_TEST_MIHOMO` to a local Mihomo executable before `go test -v ./agent`.
Optionally set `MIERU_TEST_PROFILE` to a JSON proxy object emitted by the paired
panel's Mieru formatter. The test replaces only its host/port with local
ephemeral values, starts Mihomo in a temporary directory, and proxies a local
HTTP payload through the real Mieru runtime. TCP, application UDP, directional
counters, and revocation of an established session are also exercised through
the official client SDK. External VPS credentials and Internet endpoints are
not used.
