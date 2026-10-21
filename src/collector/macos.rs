#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use super::{BoundedLine, BoundedLines, CollectionBatch, SourceStatus};
use crate::model::Event;
use crate::storage::CheckpointStore;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::BufReader;
use tokio::sync::{RwLock, mpsc};

const PREDICATE: &str = r#"eventType == "logEvent" AND (process == "sshd" OR process == "sshd-session" OR process == "sudo" OR (process == "authd" AND (eventMessage CONTAINS[c] "succeeded" OR eventMessage CONTAINS[c] "failed" OR eventMessage CONTAINS[c] "login")))"#;
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
const SNAPSHOT_REFRESH: Duration = Duration::from_secs(30);
const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnifiedLogRecord {
    #[serde(default)]
    event_type: String,
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    event_message: String,
    #[serde(default, rename = "processID")]
    process_id: u64,
    #[serde(default)]
    process_image_path: String,
    #[serde(default)]
    subsystem: String,
    #[serde(default)]
    category: String,
    #[serde(default, rename = "bootUUID")]
    boot_uuid: String,
    #[serde(default)]
    mach_timestamp: u64,
    #[serde(default, rename = "traceID")]
    trace_id: u64,
}

#[derive(Clone, Debug)]
struct ProcessInfo {
    parent_pid: String,
    command_line: String,
}

pub fn collect(checkpoints: &CheckpointStore) -> CollectionBatch {
    let lookback = configured_lookback();
    let mut command = Command::new("/usr/bin/log");
    command.args(["show", "--style", "ndjson", "--info", "--no-pager"]);
    if let Some(checkpoint) = checkpoints.newest_with_prefix("macos.") {
        let start = chrono::DateTime::parse_from_rfc3339(&checkpoint.timestamp)
            .map(|at| at.format("%Y-%m-%d %H:%M:%S%z").to_string())
            .unwrap_or(checkpoint.timestamp);
        command.args(["--start", &start]);
    } else {
        command.args(["--last", &lookback]);
    }
    command.args(["--predicate", PREDICATE]);
    let processes = process_snapshot();
    let mut seen = BTreeSet::new();
    let mut events = Vec::new();
    let mut child = match command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return failed_batch(lookback, error.to_string()),
    };
    let stderr = child.stderr.take();
    let diagnostics = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(stderr) = stderr {
            use std::io::Read;
            let _ = stderr.take(4096).read_to_end(&mut bytes);
        }
        String::from_utf8_lossy(&bytes).into_owned()
    });
    let mut error = None;
    let mut capped = false;
    let mut bytes = 0;
    if let Some(stdout) = child.stdout.take() {
        let mut lines = BoundedLines::new(std::io::BufReader::new(stdout), MAX_RECORD_BYTES);
        loop {
            match lines.read_line() {
                Ok(BoundedLine::End) => break,
                Ok(BoundedLine::Complete(line)) => {
                    bytes += line.len();
                    match parse_line(&line, &processes) {
                        Ok(Some(event)) => {
                            if seen.insert(event.uid.clone()) {
                                events.push(event);
                            }
                        }
                        Ok(None) => {}
                        Err(reason) => {
                            error = Some(reason);
                            break;
                        }
                    }
                    if events.len() >= 4096 || bytes >= MAX_BATCH_BYTES {
                        capped = true;
                        break;
                    }
                }
                Ok(_) => {
                    error =
                        Some("Unified Log record oversized or incomplete; checkpoint held".into());
                    break;
                }
                Err(reason) => {
                    error = Some(reason.to_string());
                    break;
                }
            }
        }
    }
    if capped || error.is_some() {
        let _ = child.kill();
    }
    let exit = child.wait();
    let diagnostic = diagnostics.join().unwrap_or_default();
    if !capped && !exit.is_ok_and(|exit| exit.success()) {
        error.get_or_insert(format!("Unified Log failed: {diagnostic}"));
    }
    if events.is_empty()
        && let Some(reason) = &error
    {
        return failed_batch(lookback, reason.clone());
    }
    events.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));
    for (index, event) in events.iter_mut().enumerate() {
        event.id = (index + 1) as u64;
    }

    CollectionBatch {
        status: SourceStatus {
            name: "macos.unified_log".into(),
            platform: "macos".into(),
            state: if error.is_some() { "degraded" } else { "ready" }.into(),
            events_collected: events.len(),
            lookback,
            last_error: error,
        },
        events,
    }
}

pub async fn stream_unified_log(
    tx: mpsc::Sender<Event>,
    status: Arc<RwLock<SourceStatus>>,
    _checkpoints: Arc<CheckpointStore>,
) {
    let mut backoff = Duration::from_secs(1);
    let mut snapshot = HashMap::new();
    let mut snapshot_at: Option<Instant> = None;
    loop {
        let spawned = tokio::process::Command::new("/usr/bin/log")
            .args([
                "stream",
                "--style",
                "ndjson",
                "--info",
                "--predicate",
                PREDICATE,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(error) => {
                set_state(
                    &status,
                    "error",
                    Some(format!("log stream failed to start: {error}")),
                )
                .await;
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RESTART_BACKOFF_MAX);
                continue;
            }
        };
        let Some(stdout) = child.stdout.take() else {
            set_state(
                &status,
                "error",
                Some("log stream produced no stdout".into()),
            )
            .await;
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(RESTART_BACKOFF_MAX);
            continue;
        };
        backoff = Duration::from_secs(1);
        set_state(&status, "streaming", None).await;
        tracing::info!("Unified Log stream started");

        let mut lines = BoundedLines::new(BufReader::new(stdout), MAX_RECORD_BYTES);
        loop {
            let line =
                tokio::select! { _ = tx.closed() => return, line = lines.next_line() => line };
            let Ok(BoundedLine::Complete(line)) = line else {
                break;
            };
            if snapshot_at.is_none_or(|at| at.elapsed() >= SNAPSHOT_REFRESH) {
                snapshot = tokio::task::spawn_blocking(process_snapshot)
                    .await
                    .unwrap_or_default();
                snapshot_at = Some(Instant::now());
            }
            let event = match parse_line(&line, &snapshot) {
                Ok(Some(event)) => event,
                Ok(None) => continue,
                Err(error) => {
                    set_state(&status, "error", Some(error)).await;
                    break;
                }
            };
            if tx.send(event).await.is_err() {
                return;
            }
        }

        set_state(
            &status,
            "error",
            Some("log stream exited unexpectedly; restarting".into()),
        )
        .await;
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RESTART_BACKOFF_MAX);
    }
}

fn build_event(record: UnifiedLogRecord, processes: &HashMap<u64, ProcessInfo>) -> Event {
    let timestamp = chrono::DateTime::parse_from_rfc3339(&record.timestamp)
        .or_else(|_| chrono::DateTime::parse_from_str(&record.timestamp, "%Y-%m-%d %H:%M:%S%.f%z"))
        .map(|timestamp| {
            timestamp
                .to_utc()
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
        })
        .unwrap_or_else(|_| record.timestamp.clone());
    let identity = format!(
        "{}:{}:{}:{}:{}:{}",
        record.boot_uuid,
        record.mach_timestamp,
        record.process_id,
        record.trace_id,
        record.subsystem,
        record.category
    );
    let process_name = record
        .process_image_path
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("unknown")
        .to_string();
    let source = format!("macos.{process_name}");
    let (event_id, level, outcome) = classify(&process_name, &record.event_message);
    let mut fields = BTreeMap::from([
        ("event.id".into(), event_id.into()),
        ("event.outcome".into(), outcome.into()),
        ("event.category".into(), "authentication".into()),
        ("event.dataset".into(), "macos.unified_log".into()),
        ("parser.version".into(), "2".into()),
        ("process.name".into(), process_name.clone()),
        ("process.executable".into(), record.process_image_path),
        ("process.pid".into(), record.process_id.to_string()),
        ("log.subsystem".into(), record.subsystem),
        ("log.category".into(), record.category),
        ("collector.cursor".into(), timestamp.clone()),
        ("event.original_timestamp".into(), record.timestamp.clone()),
    ]);
    if chrono::DateTime::parse_from_rfc3339(&timestamp)
        .is_ok_and(|at| chrono::Utc::now().timestamp().abs_diff(at.timestamp()) <= 5)
        && let Some(process) = processes.get(&record.process_id)
    {
        fields.insert("process.parent.pid".into(), process.parent_pid.clone());
        fields.insert("process.command_line".into(), process.command_line.clone());
    }
    match process_name.as_str() {
        "sshd" | "sshd-session" => {
            fields.insert(
                "event.action".into(),
                if event_id.starts_with("ssh.login.") {
                    "ssh-login"
                } else {
                    "ssh-session"
                }
                .into(),
            );
            enrich_ssh_fields(&record.event_message, &mut fields);
        }
        "sudo" => enrich_sudo_fields(&record.event_message, &mut fields),
        "authd" => enrich_authorization_fields(&record.event_message, &mut fields),
        _ => {}
    }

    let mut event = Event::normalized(
        0,
        timestamp,
        source,
        level.into(),
        record.event_message,
        fields,
    );
    if record.mach_timestamp != 0 && !record.boot_uuid.is_empty() {
        let identity = format!("{identity}:{}", event.uid);
        event
            .fields
            .insert("event.record_id".into(), identity.clone());
        event.identify(&identity);
    }
    event
}

fn parse_line(
    bytes: &[u8],
    processes: &HashMap<u64, ProcessInfo>,
) -> Result<Option<Event>, String> {
    let bytes = bytes.trim_ascii();
    if bytes.is_empty() || bytes.starts_with(b"Filtering the log data using ") {
        return Ok(None);
    }
    let record: UnifiedLogRecord = serde_json::from_slice(bytes)
        .map_err(|_| "invalid Unified Log JSON; checkpoint held".to_owned())?;
    if (!record.event_type.is_empty() && record.event_type != "logEvent")
        || record.timestamp.is_empty()
        || record.event_message.is_empty()
    {
        return Ok(None);
    }
    let event = build_event(record, processes);
    if chrono::DateTime::parse_from_rfc3339(&event.timestamp).is_err() {
        return Err("invalid Unified Log timestamp; checkpoint held".into());
    }
    Ok(Some(event))
}

async fn set_state(status: &Arc<RwLock<SourceStatus>>, state: &str, error: Option<String>) {
    let mut guard = status.write().await;
    guard.state = state.into();
    if state == "streaming" {
        guard.last_error = None;
    } else if let Some(error) = error {
        guard.last_error = Some(error);
    }
}

pub fn configured_lookback() -> String {
    let value = std::env::var("REDTRACE_LOOKBACK").unwrap_or_else(|_| "15m".into());
    let valid = value.strip_suffix(['m', 'h', 'd']).is_some_and(|amount| {
        amount
            .parse::<u32>()
            .is_ok_and(|amount| amount > 0 && amount <= 10080)
    });
    if valid { value } else { "15m".into() }
}

fn failed_batch(lookback: String, error: String) -> CollectionBatch {
    CollectionBatch {
        events: Vec::new(),
        status: SourceStatus {
            name: "macos.unified_log".into(),
            platform: "macos".into(),
            state: "error".into(),
            events_collected: 0,
            lookback,
            last_error: Some(error),
        },
    }
}

fn classify<'a>(process: &str, message: &str) -> (&'a str, &'a str, &'a str) {
    let classification = if process == "sudo" {
        message
            .split_once(" ; COMMAND=")
            .map_or(message, |(metadata, _)| metadata)
    } else {
        message
    };
    let lower = classification.to_ascii_lowercase();
    if matches!(process, "sshd" | "sshd-session") && lower.contains("failed") {
        ("ssh.login.failure", "medium", "failure")
    } else if matches!(process, "sshd" | "sshd-session") && lower.contains("accepted") {
        ("ssh.login.success", "low", "success")
    } else if matches!(process, "sshd" | "sshd-session") {
        ("ssh.event", "low", "unknown")
    } else if process == "sudo"
        && [
            "denied",
            "incorrect",
            "a password is required",
            "not in the sudoers",
            "not allowed to execute",
            "authentication failure",
            "command not allowed",
        ]
        .iter()
        .any(|reason| lower.contains(reason))
    {
        ("sudo.command.failure", "high", "failure")
    } else if process == "sudo"
        && message
            .split(" ; ")
            .any(|part| part.starts_with("COMMAND="))
    {
        ("sudo.command.allowed", "medium", "success")
    } else if process == "sudo" {
        ("sudo.event", "medium", "unknown")
    } else if lower.starts_with("failed ") {
        ("authentication.failure", "medium", "failure")
    } else if lower.starts_with("succeeded ") {
        ("authentication.success", "low", "success")
    } else {
        ("authentication.event", "low", "unknown")
    }
}

fn enrich_ssh_fields(message: &str, fields: &mut BTreeMap<String, String>) {
    let words: Vec<&str> = message.split_whitespace().collect();
    if let Some(index) = words
        .iter()
        .position(|word| word.eq_ignore_ascii_case("from"))
    {
        if let Some(address) = words.get(index + 1).and_then(|address| {
            address
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
        }) {
            fields.insert("source.ip".into(), address.to_string());
        }
        let user_start = words
            .iter()
            .position(|word| word.eq_ignore_ascii_case("for"));
        if let Some(start) = user_start.filter(|start| *start < index) {
            let candidate = words[start + 1..index]
                .iter()
                .rfind(|word| !matches!(word.to_ascii_lowercase().as_str(), "invalid" | "user"));
            if let Some(user) = candidate.filter(|user| **user != "<private>") {
                fields.insert("user.name".into(), user.trim_matches(':').into());
            }
        }
    }
    if let Some(index) = words
        .iter()
        .position(|word| word.eq_ignore_ascii_case("port"))
        && let Some(port) = words.get(index + 1)
        && let Ok(port) = port.trim_matches(':').parse::<u16>()
        && port > 0
    {
        fields.insert("source.port".into(), port.to_string());
    }
}

fn enrich_sudo_fields(message: &str, fields: &mut BTreeMap<String, String>) {
    fields.insert("event.action".into(), "sudo-command".into());
    if let Some((user, _)) = message.split_once(" : ")
        && !user.trim().is_empty()
        && !user.trim().contains(char::is_whitespace)
        && user.trim() != "<private>"
    {
        fields.insert("user.name".into(), user.trim().into());
    }
    // COMMAND is the requested command, not the command line of the sudo PID.
    // It may itself contain semicolons and keys; preserve its complete tail.
    let (metadata, command) = message
        .split_once(" ; COMMAND=")
        .map_or((message, None), |(metadata, command)| {
            (metadata, Some(command))
        });
    if let Some(command) = command.filter(|command| !command.is_empty() && *command != "<private>")
    {
        fields.insert("sudo.command".into(), command.into());
    }
    for (key, field) in [
        ("TTY=", "terminal.name"),
        ("PWD=", "process.working_directory"),
        ("USER=", "user.target.name"),
    ] {
        if let Some(value) = metadata
            .split(" ; ")
            .find_map(|part| {
                part.trim().strip_prefix(key).or_else(|| {
                    part.split_once(" : ")
                        .and_then(|(_, rest)| rest.strip_prefix(key))
                })
            })
            .filter(|value| !value.is_empty() && *value != "<private>")
        {
            fields.insert(field.into(), value.into());
        }
    }
}

fn enrich_authorization_fields(message: &str, fields: &mut BTreeMap<String, String>) {
    fields.insert("event.action".into(), "authorization".into());
    if let Some((_, tail)) = message.split_once("right '")
        && let Some((right, _)) = tail.split_once('\'')
        && !right.is_empty()
        && right != "<private>"
    {
        fields.insert("authorization.right".into(), right.into());
    }
    for (marker, prefix) in [
        ("by client '", "client.process"),
        ("created by '", "authorization.creator.process"),
    ] {
        if let Some((_, tail)) = message.split_once(marker)
            && let Some((path, tail)) = tail.split_once("' [")
        {
            if path.starts_with('/') {
                fields.insert(format!("{prefix}.executable"), path.into());
                fields.insert(
                    format!("{prefix}.name"),
                    path.rsplit('/').next().unwrap_or(path).into(),
                );
            }
            if let Some((pid, _)) = tail.split_once(']')
                && pid.parse::<u32>().is_ok()
            {
                fields.insert(format!("{prefix}.pid"), pid.into());
            }
        }
    }
}

fn process_snapshot() -> HashMap<u64, ProcessInfo> {
    let Ok(output) = Command::new("/bin/ps")
        .args(["-axo", "pid=,ppid=,command="])
        .output()
    else {
        return HashMap::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let pid = parts.next()?.parse().ok()?;
            let parent_pid = parts.next()?.to_string();
            let command_line = parts.collect::<Vec<_>>().join(" ");
            Some((
                pid,
                ProcessInfo {
                    parent_pid,
                    command_line,
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_log_command_preamble_but_refuses_other_non_json_records() {
        let processes = HashMap::new();
        assert!(
            parse_line(
                b"Filtering the log data using \"process == sshd\"\n",
                &processes
            )
            .unwrap()
            .is_none()
        );
        assert!(parse_line(b" \n", &processes).unwrap().is_none());
        assert!(parse_line(b"unrecognized malformed record\n", &processes).is_err());
    }

    #[test]
    fn extracts_ssh_identity_and_origin() {
        let mut fields = BTreeMap::new();
        enrich_ssh_fields(
            "Failed password for invalid user admin from 10.0.0.8 port 51422 ssh2",
            &mut fields,
        );
        assert_eq!(fields.get("user.name").map(String::as_str), Some("admin"));
        assert_eq!(
            fields.get("source.ip").map(String::as_str),
            Some("10.0.0.8")
        );
        assert_eq!(fields.get("source.port").map(String::as_str), Some("51422"));
    }

    #[test]
    fn builds_normalized_event_from_stream_record() {
        let record = UnifiedLogRecord {
            event_type: "logEvent".into(),
            timestamp: "2026-09-20T12:00:00Z".into(),
            event_message: "Failed password for invalid user admin from 10.0.0.8 port 51422 ssh2"
                .into(),
            process_id: 42,
            process_image_path: "/usr/sbin/sshd".into(),
            subsystem: "com.openssh.sshd".into(),
            category: "auth".into(),
            boot_uuid: "fixture-boot".into(),
            mach_timestamp: 1,
            trace_id: 1,
        };
        let event = build_event(record, &HashMap::new());
        assert_eq!(event.source, "macos.sshd");
        assert_eq!(event.fields["event.id"], "ssh.login.failure");
        assert_eq!(event.fields["source.ip"], "10.0.0.8");
        assert_eq!(event.fields["user.name"], "admin");
        assert_eq!(event.level, "medium");
    }

    fn log_event(process: &str, message: &str) -> Event {
        let raw = serde_json::json!({
            "eventType": "logEvent", "timestamp": "2026-10-21T10:00:00Z",
            "eventMessage": message, "processID": 42,
            "processImagePath": format!("/usr/bin/{process}"),
            "bootUUID": "fixture", "machTimestamp": 123, "traceID": 456,
        });
        parse_line(&serde_json::to_vec(&raw).unwrap(), &HashMap::new())
            .unwrap()
            .unwrap()
    }

    #[test]
    fn activities_are_not_security_log_messages() {
        let raw = br#"{"eventType":"activityCreateEvent","timestamp":"2026-10-21T10:00:00Z","eventMessage":"Retrieve Group by ID","processID":42,"processImagePath":"/usr/bin/sudo"}"#;
        assert!(parse_line(raw, &HashMap::new()).unwrap().is_none());
        let event = log_event("sudo", "Too many groups requested");
        assert_eq!(event.message, "Too many groups requested");
        assert_eq!(event.fields["event.outcome"], "unknown");
    }

    #[test]
    fn sudo_extracts_request_without_inventing_a_process_command_line() {
        let message = "fixture : a password is required ; TTY=unknown ; PWD=/Users/fixture ; USER=root ; COMMAND=/usr/bin/printf 'hello ; USER=somebody'";
        let event = log_event("sudo", message);
        assert_eq!(event.message, message);
        assert_eq!(event.fields["event.id"], "sudo.command.failure");
        assert_eq!(event.fields["event.category"], "authentication");
        assert_eq!(event.fields["event.outcome"], "failure");
        assert_eq!(event.fields["user.name"], "fixture");
        assert_eq!(event.fields["user.target.name"], "root");
        assert_eq!(event.fields["process.working_directory"], "/Users/fixture");
        assert_eq!(event.fields["terminal.name"], "unknown");
        assert_eq!(
            event.fields["sudo.command"],
            "/usr/bin/printf 'hello ; USER=somebody'"
        );
        assert_eq!(event.fields["process.executable"], "/usr/bin/sudo");
        assert!(!event.fields.contains_key("process.command_line"));
        assert!(!event.fields.contains_key("process.parent.pid"));
        let allowed = log_event(
            "sudo",
            "fixture : TTY=ttys001 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/echo denied incorrect failed",
        );
        assert_eq!(allowed.fields["event.id"], "sudo.command.allowed");
        assert_eq!(allowed.fields["event.outcome"], "success");
        assert!(!allowed.fields.contains_key("process.exit_code"));
    }

    #[test]
    fn authd_separates_the_authorizing_daemon_from_the_requesting_process() {
        let event = log_event(
            "authd",
            "Succeeded authorizing right 'com.apple.ServiceManagement.daemons.modify' by client '/usr/libexec/fixture-client' [123] for authorization created by '/usr/bin/fixture-origin' [456] (2,0) (engine 1)",
        );
        assert_eq!(event.fields["event.category"], "authentication");
        assert_eq!(event.fields["event.action"], "authorization");
        assert_eq!(event.fields["process.pid"], "42");
        assert_eq!(event.fields["process.executable"], "/usr/bin/authd");
        assert_eq!(
            event.fields["authorization.right"],
            "com.apple.ServiceManagement.daemons.modify"
        );
        assert_eq!(
            event.fields["client.process.executable"],
            "/usr/libexec/fixture-client"
        );
        assert_eq!(event.fields["client.process.pid"], "123");
        assert_eq!(event.fields["authorization.creator.process.pid"], "456");
        assert_eq!(event.fields["event.outcome"], "success");
        assert!(!event.fields.contains_key("user.name"));
        let remote = crate::ingest::normalize_event(
            &crate::ingest::AuthenticatedAgent {
                id: "1111111111111111".into(),
                name: "fixture".into(),
            },
            None,
            crate::ingest::IngestEvent::from(&event),
        )
        .unwrap();
        assert_eq!(remote.fields["client.process.pid"], "123");
        assert_eq!(
            remote.fields["authorization.right"],
            event.fields["authorization.right"]
        );
        let misleading = log_event(
            "authd",
            "Succeeded authorizing right 'fixture.failed' by client '/tmp/failed' [123]",
        );
        assert_eq!(misleading.fields["event.outcome"], "success");
    }

    #[test]
    fn redacted_and_malformed_values_do_not_become_asserted_identities() {
        let sudo = log_event(
            "sudo",
            "<private> : TTY=<private> ; PWD=<private> ; USER=<private> ; COMMAND=<private>",
        );
        for field in [
            "user.name",
            "user.target.name",
            "sudo.command",
            "terminal.name",
            "process.working_directory",
        ] {
            assert!(!sudo.fields.contains_key(field), "{field}");
        }
        let authd = log_event(
            "authd",
            "Failed authorizing right '<private>' by client '<private>' [not-a-pid]",
        );
        assert!(!authd.fields.contains_key("client.process.executable"));
        assert!(!authd.fields.contains_key("client.process.pid"));
        assert!(!authd.fields.contains_key("authorization.right"));
        assert_eq!(authd.fields["event.outcome"], "failure");
        let ssh = log_event(
            "sshd",
            "Failed password for fixture from [2001:db8::1] port 2222 ssh2",
        );
        assert_eq!(ssh.fields["source.ip"], "2001:db8::1");
        assert_eq!(ssh.fields["source.port"], "2222");
        let invalid = log_event("sshd", "from cache for user port nope");
        assert!(!invalid.fields.contains_key("source.ip"));
        assert!(!invalid.fields.contains_key("source.port"));
    }

    #[test]
    fn rejects_invalid_lookback_from_environment_contract() {
        let valid = |value: &str| {
            value.len() >= 2
                && value[..value.len() - 1]
                    .chars()
                    .all(|char| char.is_ascii_digit())
                && matches!(value.chars().last(), Some('m' | 'h' | 'd'))
        };
        assert!(valid("30m"));
        assert!(valid("24h"));
        assert!(!valid("--predicate"));
    }

    #[test]
    fn actual_unified_timestamp_and_record_identity_are_remote_compatible() {
        let line = br#"{"timestamp":"2026-10-13 09:44:36.055416+0300","eventMessage":"Accepted publickey for fixture from 192.0.2.5 port 43210 ssh2","processID":42,"processImagePath":"/usr/libexec/sshd-session","bootUUID":"fixture-boot","machTimestamp":123,"traceID":456}"#;
        let event = parse_line(line, &HashMap::new()).unwrap().unwrap();
        assert_eq!(event.timestamp, "2026-10-13T06:44:36.055416Z");
        assert_eq!(event.fields["event.id"], "ssh.login.success");
        let raw = String::from_utf8(line.to_vec())
            .unwrap()
            .replace("123", "124");
        let other = parse_line(raw.as_bytes(), &HashMap::new())
            .unwrap()
            .unwrap();
        assert_ne!(event.uid, other.uid);
        crate::ingest::normalize_event(
            &crate::ingest::AuthenticatedAgent {
                id: "1111111111111111".into(),
                name: "fixture".into(),
            },
            None,
            crate::ingest::IngestEvent::from(&event),
        )
        .unwrap();
    }

    #[test]
    fn malformed_ssh_word_order_and_invalid_timestamp_do_not_panic_or_advance() {
        enrich_ssh_fields("from cache for user", &mut BTreeMap::new());
        assert!(
            parse_line(
                br#"{"timestamp":"invalid","eventMessage":"message"}"#,
                &HashMap::new()
            )
            .is_err()
        );
    }
}
