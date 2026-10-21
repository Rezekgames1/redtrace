# macOS telemetry — 21 October 2026

REDTRACE 0.2.0 remains a controlled pilot. Transport, durable storage, search and
the desktop event explorer exist; useful endpoint coverage and validated product
quality are separate requirements. A working connection does not establish full
macOS security coverage.

## Observed issue

The running Basic collector was collecting Unified Log activity records as if
they were security messages. A bounded native sample contained 83
`activityCreateEvent` records and 14 `logEvent` records. Examples of activity
messages were `Retrieve User by ID` and `Retrieve Group by ID`. These represent
directory lookups inside sudo, not execution of the user's command.

The authd messages contained the requested authorization right and the executable
and PID of the requesting client. The old parser retained these facts only in
the raw message, classified the record as `system`, and displayed authd's own
command line as row context. That obscured which application requested a right.

## Change

- Backfill and streaming select `logEvent`. The parser also rejects explicit
  non-log event types. Legacy input without `eventType` remains compatible.
- The parser assigns authentication category, dataset, parser version and the
  recorded executable path. An executable path is available even if a short-lived
  process has exited; historical command lines and parent PIDs are not invented.
- Sudo records expose the invoking and target users, terminal, working directory
  and requested command. `sudo.command` is distinct from the command line of the
  sudo PID. The complete command tail is retained, including embedded semicolons.
- Authorization records expose `authorization.right`, `client.process.*` and
  `authorization.creator.process.*`. The requesting client's PID does not replace
  the PID of authd.
- Rows explain the authorization decision and show the requesting application or
  requested sudo command. The original message remains searchable, in the event's
  fields and raw JSON. Existing database records are not rewritten.
- Sources explains that Basic macOS collection covers selected sudo, SSH and
  authd messages. Additional investigation fields are selectable as columns and
  appear in event details.

An allowed sudo request is not evidence of a zero exit code or of a completed
command. Redacted and missing identities remain unavailable. Existing historical
activity records remain in the database; the filter affects new collection.

## Coverage boundary

The inspected running configuration had `macos_endpoint_security: false`.
Unified Log does not establish a complete process execution, file operation or
network connection audit trail. REDTRACE has native Endpoint Security helper and
normalization code, but enabling native collection requires the appropriate
Apple entitlement, privilege and Full Disk Access. The eslogger compatibility
backend is explicit and experimental, not an interchangeable production API.
See [Apple Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
and the local `eslogger(1)` manual.

This change does not grant those permissions or claim that the ES helper has
passed native coverage validation. Signing/notarization and the agreed native
lifecycle and reliability gates remain open.

## Verification

The new predicate was checked against the native Unified Log for a bounded
15-minute window: it returned two `logEvent` records and no activity records.
Focused parser tests cover activity exclusion, authd client/daemon separation,
sudo command preservation, privacy redaction, malformed input, and remote ingest
field preservation. UI tests cover informative summaries, original-message
fallback and request-versus-process context.

Source change: `c964365`. Verification passed: 257 Rust tests, 20 UI tests,
TypeScript checking, targeted UI ESLint, `cargo fmt --check` and Clippy with
warnings denied. The complete Rust run used process-local
`NO_PROXY=localhost,127.0.0.1,::1`: the first attempt exposed existing localhost
test clients using the configured proxy and stalling. All ten ingest-limit tests
and the complete suite passed with localhost isolated from that proxy. System
proxy configuration was not changed.

The release desktop bundle built successfully and was installed at
`/Applications/REDTRACE.app`. All seven installed binaries match the signed local
release bundle. Local ad-hoc signature verification passed; this is not a
Developer ID/notarization result. The original bundle and a private 57,416,324-byte
database backup are retained locally. Existing collector and sender launchd jobs
were restarted with their existing data and configuration.

After installation, the native API returned seven new real authd authorization
records with `parser.version=2`, a requested right, and a client PID separate from
authd's PID. The source was streaming; WAL and segment error and corruption
counters were zero. The native Tauri window showed eight live rows, including
those authorization records. Visual inspection confirmed readable right/client
summaries and the client executable/PID as context. Opening a row exposed the
right, client path/PID and outcome in details. Sources displayed the Basic macOS
coverage explanation. The window was left on the event stream.

A separate harmless `sudo -n /usr/bin/true` probe exited with code 1 and produced
no matching command record in the inspected native search window. That probe
remains **PENDING**, not PASS. Sudo parsing is covered by fixtures and remote
normalization tests, but native sudo-command coverage is not established by this
session. This reinforces the coverage boundary above; field extraction cannot
recover command telemetry that the source did not provide.

Private native evidence remains under `outputs/macos-telemetry-20261021/`,
including the installed binary manifest and native authd verification. Raw logs,
credentials, backups and screenshots are not committed to Git.

The previously configured Windows WinRM endpoint was unreachable during this
session; the owner confirmed that the Windows laptop was switched off. No new
Windows GUI or two-direction delivery PASS is claimed. The
earlier Windows-to-Mac evidence and outstanding reverse GUI check retain their
original scope.
