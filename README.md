# OpenEye

OpenEye is a local AI activity monitor for developers and power users. The MVP in this repository implements the event model, AI-process filter, default alert rules, temporal correlation engine, CLI demo, JSON-lines ingestion path, and a small MCP manifest auditor.

The long-term product needs privileged macOS Endpoint Security and Network Extension collectors. Those require Apple entitlements, so this first build creates the runnable spine first: collectors can emit events into `openeye ingest`, and the core engine will classify and alert locally.

## Quick Start

```sh
npm run app
```

Then open `http://127.0.0.1:3737`.

The dashboard monitors real macOS process, file, and network snapshots using `ps` and `lsof`. It shows a live feed, alert inbox, active process activity, and plain-English explanations for selected items.

For the synthetic rules demo:

```sh
npm run demo
```

You should see a live stream of synthetic AI-agent activity, including warnings for `.env` access and critical alerts for SSH key, wallet, clipboard, and exfiltration patterns.

The Rust workspace mirrors the intended production core. If your shell does not see `cargo`, use `/Users/dawn/.cargo/bin/cargo`.

## Ingest Events

`openeye ingest` reads tab-separated `key=value` events from stdin:

```sh
printf 'kind=FILE_READ\tpid=42\tprocess=cursor\tcommand=cursor-agent\ttarget=/Users/me/.ssh/id_ed25519\nkind=NETWORK_SEND\tpid=42\tprocess=cursor\ttarget=https://203.0.113.10/upload\tbytes=120000\n' | node src/openeye.mjs ingest
```

Supported event kinds:

- `FILE_READ`
- `FILE_WRITE`
- `NETWORK_CONNECT`
- `NETWORK_SEND`
- `CLIPBOARD_READ`
- `PROCESS_EXEC`
- `MCP_MANIFEST_CHANGE`

## Default Rules

Critical:

- `SSH_KEY_READ`
- `SSH_KEY_EXFIL`
- `ENV_PLUS_NET`
- `WALLET_FILE_READ`
- `BLIND_CLIPBOARD`
- `MCP_MANIFEST_CHANGE`

Warning:

- `ENV_FILE_READ`
- `BROWSER_PROFILE_READ`
- `CHILD_PROCESS_SPAWN`
- `LARGE_FILE_EXFIL`

## MCP Auditor Prototype

```sh
node auditors/mcp-auditor/src/index.js --demo
```

The first run saves a baseline to `~/.openeye/mcp-baseline.json`. If that path is not writable, the auditor falls back to `.openeye/mcp-baseline.json` in the current workspace. Later runs diff the current manifest against that baseline and print `MCP_MANIFEST_CHANGE` when tool drift is detected.

## Architecture

```text
crates/openeye-core       Event model, process filter, alert rules
apps/openeye-cli          Demo, ingestion, and local explanations
src/                      Runnable Node MVP with matching rules
auditors/mcp-auditor      Manifest baseline and diff prototype
```

## macOS Collector Roadmap

The production collector should use Apple's Endpoint Security Framework for file and process events and Network Extension or PF-backed process tagging for network events. Development builds must be signed with `com.apple.developer.endpoint-security.client`; distribution requires Apple approval.

Until that entitlement is available, external probes can feed normalized events into `openeye ingest`.

Current best-effort collector limits:

- `lsof` snapshots show files and sockets open at scan time, not every read/write syscall.
- Some system or other-user process details may be hidden unless OpenEye is run with elevated permissions.
- Clipboard owner detection and complete per-packet payload inspection require native macOS APIs that are not available to a plain Node process.
