# Persistent collector and agent services

This is a source implementation for Windows SCM and Linux systemd. Validation used isolated temporary data directories and ephemeral loopback ports. No machine service was installed, started, stopped, or removed, and the running SIEM on port 9710 was not restarted.

## Lifecycle modes

The desktop default remains portable: it starts its own sidecar with a randomly generated local API token. It authenticates the sidecar's process identity and requests a graceful shutdown on exit. A forced termination fallback applies only to the child handle created by that desktop.

Persistent collector entry points:

```text
redtrace --persistent --config ABSOLUTE_PRIVATE_JSON
redtrace --windows-service --persistent --config ABSOLUTE_PRIVATE_JSON
```

Foreground environment mode is also supported:

```text
REDTRACE_SERVICE_MODE=persistent
REDTRACE_DATA_DIR=ABSOLUTE_PRIVATE_DIRECTORY
REDTRACE_API_BIND=127.0.0.1:9710
```

`REDTRACE_API_BIND` defaults to `127.0.0.1:9710`. It accepts literal loopback IP socket addresses, including `127.0.0.1:0` and `[::1]:0` for isolated process tests. Hostnames, wildcard listeners, and non-loopback IPs are rejected before opening storage. An occupied port causes startup failure; its owner is never terminated.

Persistent agents use the existing `AgentRuntime` and durable disk spool:

```text
redtrace-service-agent --persistent --config ABSOLUTE_PRIVATE_JSON
redtrace-service-agent --windows-service --persistent --config ABSOLUTE_PRIVATE_JSON
```

SCM callbacks handle STOP and SHUTDOWN. Linux foreground processes handle SIGTERM and Ctrl-C. The collector shares a level-triggered shutdown signal between API, ingest, SSE, ingestion, and retention. Accepted queued events drain to the WAL. A failed WAL batch stays bounded in memory and is retried with backpressure; it does not advance checkpoints or receive a durable ACK. Failure to persist during shutdown produces a non-success exit for service-manager recovery. Agent shutdown preserves unacknowledged spool records for the next start.

## Private configuration

Collector example, with concrete paths chosen for the service account:

```json
{
  "data_dir": "C:\\Users\\Alice\\AppData\\Local\\REDTRACE-Service",
  "api_bind": "127.0.0.1:9710",
  "environment": {
    "REDTRACE_RETENTION_DAYS": "7",
    "REDTRACE_MAX_STORAGE_MB": "512"
  }
}
```

Linux agent example:

```json
{
  "data_dir": "/home/alice/.local/share/redtrace-agent-service",
  "environment": {
    "REDTRACE_AGENT_SERVER": "https://siem.example:9711",
    "REDTRACE_AGENT_TOKEN_FILE": "/home/alice/.config/redtrace-private/agent.token",
    "REDTRACE_AGENT_CA": "/opt/redtrace/ingest-ca.pem",
    "REDTRACE_AGENT_NAME": "alice-host",
    "REDTRACE_AGENT_POLL_SECONDS": "5",
    "REDTRACE_AGENT_HEARTBEAT_SECONDS": "30"
  }
}
```

Only bounded `REDTRACE_` environment entries are accepted. API/agent tokens cannot be embedded in the configuration environment. Agent credentials come from a private token file. TLS private keys and agent token files must be private; certificates and CA files must be protected. Loading a configuration clears inherited `REDTRACE_` variables before applying its settings, so configuration-driven boot is deterministic.

All paths are absolute, reject parent traversal, redirections/reparse points, control characters, quotes, and expansion characters. No provisioning command executes a shell. Binary files and their immediate directories must have protected ownership and deny untrusted writes.

On Linux, private files and their directories must belong to the running UID, without group/other access (`0600`/`0700` for generated state). Protected binaries may belong to that UID or root and cannot be group/other writable. On Windows, generated state uses an owner-specific protected DACL allowing only the service account and SYSTEM. Reading existing private files validates the owner and effective access instead of silently repairing permissive ACLs.

The configuration file's parent must itself be private. Provision it as the service identity. On Windows, the built-in provisioning tool validates files as its current logon identity; using it elevated as the same account is supported. A separate administrator provisioning a different dedicated account must arrange account-owned configuration/state and register the documented absolute SCM command using an account-aware deployment procedure. This cross-account installation workflow has not been exercised.

`REDTRACE_COLLECT_LOCAL=0` explicitly disables local collection for a remote-only collector or isolated lifecycle fixtures. It also disables collection in the service-agent wrapper, while retaining delivery of its existing spool. Normal collection is enabled by default.

## GUI attachment and credentials

Set these variables before launching the desktop:

```text
REDTRACE_DESKTOP_MODE=persistent
REDTRACE_SERVICE_DATA_DIR=ABSOLUTE_PRIVATE_DIRECTORY
REDTRACE_SERVICE_BINARY=ABSOLUTE_PROTECTED_COLLECTOR_BINARY
```

`REDTRACE_SERVICE_BINARY` defaults to the bundled `redtrace` binary beside the desktop. `REDTRACE_SESSION_FILE` can override the default `DATA_DIR/session.json` directory, while retaining the reserved `session.json` filename. The current frontend requires `127.0.0.1:9710`; other API binds are available to foreground cores and process tests.

The desktop reads the private session file, verifies the expected executable and data directory, checks owner/PID/process creation identity, confirms that the loopback listener belongs to that process, and authenticates `/api/session`. It requires matching protocol, package version, and per-process instance identity. Windows uses IP Helper and process/token APIs; Linux uses `/proc` listener inodes, executable identity, UID, and process start time. Attachment is same-account; a GUI running as a different identity cannot read the session capability. Cross-account GUI access needs a separately designed authenticated broker.

The local API capability is generated into private `DATA_DIR/session.key` after WAL ownership is acquired. It survives collector restarts, allowing the existing frontend's cached token to keep working when the service returns. `session.json` is atomically replaced on each start with a fresh instance identity, PID, and listener address. Neither credential is passed in a URL or command argument, and neither appears in health/diagnostics. Portable desktop credentials remain per-launch environment capabilities.

Graceful shutdown removes only that process's published `session.json`, and leaves `session.key`. A crash leaves a stale session publication; the next owner replaces it after recovery. The publication lock, WAL lock, and catalog lock prevent duplicate owners. A process never removes a replacement publication belonging to a different instance. Offline local-capability rotation requires stopping the collector, replacing/removing its private `session.key`, then restarting the collector and GUI. This local-owner capability is separate from remote-agent credential TTL/rotation.

Closing an attached desktop does not stop or kill the persistent collector. Persistent mode does not spawn a fallback portable collector when attachment fails.

## Provisioning commands

Commands validate the explicit protected binary and private configuration. `validate` and template generation are read-only:

```text
redtrace-service validate --binary ABSOLUTE_BINARY --config ABSOLUTE_PRIVATE_JSON
redtrace-service systemd-template --binary ABSOLUTE_BINARY --config ABSOLUTE_PRIVATE_JSON --identity alice
redtrace-service systemd-user-template --binary ABSOLUTE_BINARY --config ABSOLUTE_PRIVATE_JSON --identity alice
```

Add `--agent` and use the `redtrace-service-agent` binary for agent units. The system template has explicit `User=alice`; the user template runs as the user manager's identity. There is no root default. Templates use quoted absolute `ExecStart`, `Restart=on-failure`, bounded restart delays, a 45-second stop timeout, `UMask=0077`, and filesystem hardening. Session publication must stay inside the writable data directory for these templates. User-manager filesystem sandboxing depends on host user-namespace support.

After reviewing the emitted unit, an operator can place it under `/etc/systemd/system/` or `~/.config/systemd/user/`, reload the corresponding manager, and enable/start it. Boot availability for a user manager requires an explicit linger decision by the operator. Systemd installation, boot, sandbox behavior, and crash-restart policy have not been tested against a live manager.

Windows provisioning commands are implemented and require a deliberate privileged invocation:

```text
redtrace-service install --binary ABSOLUTE_BINARY --config ABSOLUTE_PRIVATE_JSON --identity DOMAIN\Alice --password-file ABSOLUTE_PRIVATE_PASSWORD_FILE
redtrace-service start --binary ABSOLUTE_BINARY --config ABSOLUTE_PRIVATE_JSON
redtrace-service stop --binary ABSOLUTE_BINARY --config ABSOLUTE_PRIVATE_JSON
redtrace-service remove --binary ABSOLUTE_BINARY --config ABSOLUTE_PRIVATE_JSON
```

Use `--agent` for `REDTRACEAgent`; the collector is `REDTRACE`. Installation requires an explicit non-System identity and never starts the service automatically. Passwords are optional for accounts whose service logon supports that, are read from private files, and are not supplied as process arguments. The registered SCM command is a quoted absolute binary/config invocation. Management checks the registered command against those expected paths before acting. Installation configures delayed automatic startup and recovery restart delays of 5/15/60 seconds, including non-crash failures.

The service identity needs **Log on as a service**, read/execute on the protected binaries, ownership/access to its private configuration and data, and only the telemetry-read permissions needed for its collection sources. Windows Security/Sysmon channel access and Linux journal membership are deployment-specific. These commands do not grant audit policy, Sysmon, channel ACL, firewall, or account rights. LocalSystem/root is not chosen as a default. Actual SCM install/logon/start/stop/recovery remains an operator validation gate.

## APIs and main integration

- `GET /api/session`: authenticated instance identity, `Cache-Control: no-store`.
- `POST /api/session/stop`: requires the local API token and exact `x-redtrace-instance`; returns 202, or 409 for a different instance.
- `POST /api/agents/{id}/rotate`: `ingest::RotateAgentParams` (`ttl_seconds`, `overlap_seconds`), returns `IssuedAgentCredential` with `Cache-Control: no-store`; 400 for invalid policy, 404 for unknown/revoked agents, generic 500 for persistence failure.
- All `/api/agents` management routes require a configured local API token, even with `REDTRACE_ALLOW_UNAUTHENTICATED=1`.
- Agent creation credentials also use `Cache-Control: no-store`; persistence errors omit internal paths.
- `/api/health` exposes `remote_ingest.budget` from `AgentRegistry::budget_health_with_known` and `storage.retention` counters. `/api/diagnostics` exposes `remote_ingest_budget`, `retention`, and non-secret lifecycle mode/protocol.
- Retention runs at startup and every 60 seconds while idle or active, under the shared query-snapshot write gate with blocking storage work isolated from async workers. Retention failures and storage-cap failures are counted. Startup UID state is rebuilt after WAL migration/cap eviction. Existing query concurrency, cancellation, and rotation gates are preserved.

## Verification and remaining gates

Windows and Linux isolated process tests cover private file validation, loopback-only bind validation, unknown listeners, bad auth/PID/version, session publication ownership, agent credential rotation, unauthenticated management rejection, graceful collector stop, preserved fixture search results, restart, and stale-publication crash recovery. Main tests cover a 512-event drain, WAL-write failure/recovery without re-enqueueing, and retention/query snapshot coordination. Linux additionally verifies SIGTERM for collector and service-agent foreground processes with pending spool preservation.

Validation on 2026-10-12:

| Check | Result |
| --- | --- |
| Windows library | 137 passed; 3 read-only native collector tests left ignored |
| Windows main | 10 passed |
| Windows service process integration | 6 passed |
| Windows spool / ingest / ingest limits / TLS | 25 / 7 / 10 / 1 passed |
| Windows core clippy, all library/binary/test targets | Passed with `-D warnings` |
| Windows desktop clippy, all targets | Passed with `-D warnings` |
| Core and desktop fmt checks | Passed |
| Windows desktop test harness | Passed; 0 existing test cases |
| Isolated Kali WSL library / main / service processes | 124 / 10 / 7 passed |
| Kali WSL clippy | Unavailable: toolchain has no `cargo-clippy`; no component was installed |
| Shared hardening integration | 3 passed, 3 failed as described below |

Core commands used `cargo test --lib --bins --test service_mode` plus explicitly selected spool/ingest/TLS integration targets. Final focused checks reran the main/service/ingest/TLS targets and the service library tests after relevant edits. Desktop used `cargo test --manifest-path src-tauri/Cargo.toml --all-targets`. Linux validation copied the current source into an isolated temporary workspace and used a separate `/tmp/redtrace-service-validation-target` build directory. Fixed-9710 `query_api`, `windows_tls_process`, and `wal_recovery` process tests were skipped; the new service process suite used ephemeral ports.

Live SCM/systemd integration, boot/logon rights, GUI attachment to an actually installed persistent service, service restart with the actual GUI open, signed/package delivery, cross-account brokering, and power-loss guarantees remain platform gates. No release/installer build or long-load run was performed.

Update 2026-10-13: the shared hardening suite passes 6/6 on Windows and macOS after independent durable receipts, explicit definitive consumer rejection feedback, and checkpoint sequencing. Main retains/retries WAL failures. macOS listener ownership/creation identity validation is implemented through libproc/lsof; source process tests pass. Installation instructions and current beta scope: `BETA_INSTALL.md`; evidence: `BETA_VALIDATION_20261013.md`.
