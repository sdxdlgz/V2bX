# Server-side upstream gateway

This optional Linux service binds one existing V2bX ingress to one upstream subscription. Users keep their ordinary Trojan/VLESS credentials and original panel subscription. Authentication, package accounting, speed/device limits and revocation remain in the existing ingress. No old-node reinstall or core/control-loop change is required.

The panel companion feature is on `sdxdlgz/v2board` branch `feat/upstream-gateway`. The earlier direct-Mieru experiment is archived; this module does not depend on it.

## Data path

Client -> dedicated V2bX/Xray ingress -> loopback SOCKS relay -> private Mihomo -> upstream -> destination.

The gateway service has no public listener. Provision a separate ingress that can reach the upstream. Provider IP/province restrictions apply to this server's exit address. The server bears all forwarded bandwidth; upstream aggregate quota still applies.

## Supported inputs

- HTTPS subscription URL returning a Mihomo/Clash `proxies` YAML/JSON object, a URI list, or base64 URI list parsed by **Mihomo v1.19.32**.
- Single `vless://`, `vmess://`, `trojan://`, `ss://`, `ssr://`, `hysteria://`, `hysteria2://`, `hy2://`, `tuic://`, `anytls://`, or `mierus://` URI.
- VLESS Reality requires all original parameters, including the correct public key, SNI, short ID, flow and supported transport. Parser support does not establish reachability.
- First version permits VLESS, VMess, Trojan, Shadowsocks/R, Hysteria1/2, TUIC, AnyTLS, Mieru, Snell, SOCKS5, HTTP, WireGuard and SSH proxy types recognized by that pinned core. Other types are rejected. Arbitrary proprietary protocols are not promised.
- Subscription global rules, DNS, listeners and controller settings are ignored. Only its provider nodes are used. DIRECT/COMPATIBLE and nested selectors cannot be the upstream.
- A single node auto-selects. For multiple nodes, enter its exact name in the admin page. Unsupported Sing-box full JSON or encrypted proprietary formats require a compatible export; no external conversion service receives your secrets.

## One-time installation

1. Build this independent module: `go build -trimpath -o v2bx-upstream .` (Go1.25+). The legacy V2bX build is unchanged.
2. Install the trusted **v1.19.32** Mihomo Linux binary as `/usr/local/bin/mihomo` and this binary as `/usr/local/bin/v2bx-upstream`. Check the release checksum. No automatic binary upgrades.
3. Create a dedicated system account `v2bx-upstream` and private directories `/etc/v2bx-upstream` and `/var/lib/v2bx-upstream`. The account needs read access to its JSON configuration and write access only to its state directory.
4. Create a separate ordinary Trojan or VLESS node in the panel. Install/configure its normal V2bX service and certificate/Reality settings. Keep it hidden until validation passes.
5. In the new **上游订阅** page, select that ingress, paste the upstream URL/URI, and save. Download the one-time agent JSON. Install it as `/etc/v2bx-upstream/ID.json`, mode0640 root:v2bx-upstream. Its token is scoped to that binding; it is not the panel-wide server token.
6. If hosting multiple gateways, assign a different loopback `listen` port to each downloaded JSON. Create its `state_dir` mode0700 owned by v2bx-upstream.
7. Install `v2bx-upstream@.service` and start only `v2bx-upstream@ID`. No existing service must be restarted.

The downloaded JSON names the binary, state directory and `https://www.gstatic.com/generate_204` probe. `allow_private_sources` defaults false; it permits internal subscription hosts only when an operator explicitly enables it. HTTPS certificate verification remains enabled. Use HTTP panel URLs only for loopback tests.

## Dedicated V2bX routing

For this **dedicated** Xray core only, set `OutboundConfigPath` to a JSON array containing:

```json
[
  {"tag":"upstream","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":19090}]}},
  {"tag":"blocked","protocol":"blackhole","settings":{}}
]
```

Set `RouteConfigPath` to:

```json
{"domainStrategy":"AsIs","rules":[{"type":"field","network":"tcp,udp","outboundTag":"upstream"}]}
```

Keep these files separate from old node configuration. Do not attach this catch-all route to a shared core carrying existing direct nodes. If the relay/upstream stops, connections must fail; do not add a DIRECT fallback. Verify actual routing before publishing the node.

## Updates and failures

- Poll panel authorization every 5 seconds while idle. Downloads/probes can delay the next poll by their bounded timeouts. Explicit disable, deletion/token revocation and missing ingress revoke forwarding and active sessions when observed. A panel network outage allows a 60 second lease plus in-flight bounded work before revocation; recovery requires fresh authorization and a successful probe.
- Fetch sources directly from the gateway, with public-address DNS validation on each connection/redirect, HTTPS verification,15second timeout and2MiB decompressed limit. Local proxy environment variables are not used to fetch subscriptions.
- Stage a private candidate core, require a valid selected proxy and an actual HTTP204 through it, then switch the loopback relay. Failed updates keep the last active valid configuration and report a generic error. Credentials never enter reports/logs.
- Unchanged node content does not restart the core. Changed content switches new connections and closes old core sessions; applications may reconnect. This is not seamless connection migration.
- Only one process may own a state directory. OS lock releases on crash; child cores receive a Linux parent-death signal, and systemd kills the whole control group. Restart requires fresh panel authorization and a successful probe; no stale credential snapshot authorizes forwarding.
- UDP availability depends on both protocols and upstream. SOCKS UDP associations use the selected core's loopback port. Do not equate the TCP health probe with successful UDP/game/video testing.

## Verification and rollback

Run `go test ./...` and `go vet ./...`. On Linux set `MIHOMO_BINARY` to the pinned core path to include real parsing/selection/failure tests.

For full acceptance, `tests/acceptance.py` needs Python3, OpenSSL, curl, the pinned Mihomo, this gateway and a V2bX binary with Xray. Set absolute environment paths `UPSTREAM_REVIEW_ROOT` (an empty private test directory), `MIHOMO_BINARY`, `UPSTREAM_BINARY`, and `V2BX_BINARY`, then run `python3 tests/acceptance.py`. Run as an unprivileged user; it owns its subprocesses, synthetic accounts and loopback listeners, and never loads installed client or production panel configuration. Private fixture files remain below the test directory for diagnosis. Do not publish them.

The 2026-10-16 isolated Linux acceptance passed HTTPS/Mieru and base64/VLESS Reality TCP/UDP, real V2bX ingress UDP, two-user counters, individual revocation, 1 Mbps limiting, invalid/unchanged updates, disable, restart, duplicate-instance locking, authorization loss/recovery and upstream failure without DIRECT fallback. These are functional checks, not a capacity or provider-network benchmark.

To withdraw a binding: disable it in the admin page, verify `已停用`, hide the ordinary ingress, stop that new gateway and ingress service. Keep configuration/private state backups. Existing nodes and panel subscription URLs remain unchanged. Do not change your installed clients to manage this service.

## Accounting boundary

Package quota and speed limits are enforced by V2bX using the existing panel report/pull cycle. The relay/Mihomo does not bill users. Ordinary reporting has its existing crash/network-loss semantics; this feature does not add byte-exact durable metering or separate per-user-per-node allowances. Capacity and simultaneous-user behavior must be measured on the intended gateway before production deployment.
