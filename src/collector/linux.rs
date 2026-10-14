#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use super::{BoundedLine, BoundedLines, CollectionBatch, SourceStatus};
use crate::model::Event;
use crate::storage::CheckpointStore;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::BufReader,
    sync::{RwLock, mpsc},
};

const MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_DIAGNOSTIC_LINE_BYTES: usize = 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 4096;

const JOURNAL_ARGS: &[&str] = &["--all", "--output=json", "--no-pager"];

pub fn configured_lookback() -> String {
    let value = std::env::var("REDTRACE_LOOKBACK").unwrap_or_else(|_| "15m".into());
    if valid_lookback(&value) {
        value
    } else {
        "15m".into()
    }
}

pub fn collect(checkpoints: &CheckpointStore) -> CollectionBatch {
    let lookback = configured_lookback();
    let since = format!("-{lookback}");
    let mut command = Command::new("journalctl");
    command.args(JOURNAL_ARGS);
    let checkpoint = checkpoints.newest_with_prefix("linux.");
    if let Some(checkpoint) = &checkpoint {
        command.arg(format!("--after-cursor={}", checkpoint.cursor));
    } else {
        command.args(["--since", &since]);
    }
    let mut output = read_backfill(&mut command);
    if output
        .as_ref()
        .is_err_and(|error| error.to_ascii_lowercase().contains("cursor"))
        && let Some(checkpoint) = &checkpoint
    {
        output = read_backfill(
            Command::new("journalctl")
                .args(JOURNAL_ARGS)
                .args(["--since", &checkpoint.timestamp]),
        );
    }
    match output {
        Ok((events, diagnostic)) => CollectionBatch {
            status: SourceStatus {
                name: "linux.journald".into(),
                platform: "linux".into(),
                state: if diagnostic.is_empty() {
                    "ready"
                } else {
                    "degraded"
                }
                .into(),
                events_collected: events.len(),
                lookback,
                last_error: (!diagnostic.is_empty()).then_some(diagnostic),
            },
            events,
        },
        Err(error) => failed(lookback, error),
    }
}

#[derive(Default)]
struct JournalDiagnostics {
    message: String,
    oversized_lines: usize,
}

impl JournalDiagnostics {
    fn append(&mut self, text: &str) {
        let remaining = MAX_DIAGNOSTIC_BYTES.saturating_sub(self.message.len());
        if remaining == 0 {
            return;
        }
        let mut end = text.len().min(remaining.saturating_sub(1));
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.message.push_str(&text[..end]);
        self.message.push('\n');
    }

    fn observe(&mut self, line: BoundedLine) -> bool {
        match line {
            BoundedLine::End => false,
            BoundedLine::Complete(bytes) => {
                self.append(String::from_utf8_lossy(&bytes).trim());
                true
            }
            BoundedLine::Oversized => {
                self.oversized_lines = self.oversized_lines.saturating_add(1);
                true
            }
            BoundedLine::Incomplete => {
                self.append("journal diagnostic line is incomplete");
                false
            }
        }
    }

    fn summary(&self) -> String {
        if self.oversized_lines == 0 {
            self.message.trim().into()
        } else {
            format!(
                "{}; oversized_stderr_lines={}",
                self.message.trim(),
                self.oversized_lines
            )
        }
    }
}

fn journal_event(line: BoundedLine) -> Result<Option<Event>, String> {
    match line {
        BoundedLine::End => Ok(None),
        BoundedLine::Oversized => Err(format!(
            "journald record exceeds {MAX_RECORD_BYTES} bytes; checkpoint held before unconfirmed record"
        )),
        BoundedLine::Incomplete => {
            Err("journald record is incomplete; checkpoint held before unconfirmed record".into())
        }
        BoundedLine::Complete(bytes) => {
            let line = std::str::from_utf8(&bytes).map_err(|_| {
                "journald record is not UTF-8; checkpoint held before unconfirmed record"
                    .to_string()
            })?;
            let event = parse_record(line)
                .filter(|event| {
                    event.fields.get("collector.cursor").is_some_and(|cursor| !cursor.is_empty())
                })
                .ok_or_else(|| {
                    "journald record cannot be normalized or has no cursor; checkpoint held before unconfirmed record".to_string()
                })?;
            Ok(Some(event))
        }
    }
}

fn read_backfill(command: &mut Command) -> Result<(Vec<Event>, String), String> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let stderr = child.stderr.take();
    let diagnostics = std::thread::spawn(move || {
        let mut diagnostic = JournalDiagnostics::default();
        if let Some(stderr) = stderr {
            let mut lines =
                BoundedLines::new(std::io::BufReader::new(stderr), MAX_DIAGNOSTIC_LINE_BYTES);
            loop {
                match lines.read_line() {
                    Ok(line) => {
                        if !diagnostic.observe(line) {
                            break;
                        }
                    }
                    Err(error) => {
                        diagnostic.append(&format!("journal diagnostic read failed: {error}"));
                        break;
                    }
                }
            }
        }
        diagnostic.summary()
    });
    let mut events = Vec::new();
    let mut bytes = 0;
    let mut capped = false;
    let mut read_error = None;
    if let Some(stdout) = child.stdout.take() {
        let mut lines = BoundedLines::new(std::io::BufReader::new(stdout), MAX_RECORD_BYTES);
        loop {
            let line = match lines.read_line() {
                Ok(line) => line,
                Err(error) => {
                    read_error = Some(format!("journal stdout read failed: {error}"));
                    break;
                }
            };
            if let BoundedLine::Complete(record) = &line {
                bytes += record.len();
            }
            let oversized = line == BoundedLine::Oversized;
            match journal_event(line) {
                Ok(Some(event)) => events.push(event),
                Ok(None) => break,
                Err(error) => {
                    read_error = Some(if oversized {
                        tracing::warn!(
                            oversized_records = 1,
                            "journald oversized backfill record; holding checkpoint"
                        );
                        format!("{error}; oversized_records=1")
                    } else {
                        error
                    });
                    break;
                }
            }
            if events.len() >= 4096 || bytes >= 8 * 1024 * 1024 {
                capped = true;
                break;
            }
        }
    } else {
        read_error = Some("journalctl produced no stdout".into());
    }
    if capped || read_error.is_some() {
        let _ = child.kill();
    }
    let exit = child.wait().map_err(|error| error.to_string());
    let diagnostic = diagnostics
        .join()
        .unwrap_or_else(|_| "journal diagnostic reader failed".into());
    if let Some(error) = read_error {
        return Ok((
            events,
            format!("{error}; {diagnostic}")
                .trim_end_matches("; ")
                .into(),
        ));
    }
    let exit = exit?;
    if !exit.success() && !capped {
        let error = format!("journalctl exited with {exit}: {}", diagnostic.trim());
        if events.is_empty() {
            return Err(error);
        }
        return Ok((events, error));
    }
    Ok((events, diagnostic))
}

async fn read_diagnostics<R: tokio::io::AsyncBufRead + Unpin>(
    reader: R,
    status: Arc<RwLock<SourceStatus>>,
    warned: Arc<AtomicBool>,
) -> String {
    let mut diagnostic = JournalDiagnostics::default();
    let mut lines = BoundedLines::new(reader, MAX_DIAGNOSTIC_LINE_BYTES);
    loop {
        match lines.next_line().await {
            Ok(line) => {
                if !diagnostic.observe(line) {
                    break;
                }
            }
            Err(error) => {
                diagnostic.append(&format!("journal diagnostic read failed: {error}"));
                break;
            }
        }
        let mut current = status.write().await;
        warned.store(true, Ordering::Relaxed);
        current.state = "degraded".into();
        current.last_error = Some(diagnostic.summary());
    }
    let summary = diagnostic.summary();
    if !summary.is_empty() {
        let mut current = status.write().await;
        warned.store(true, Ordering::Relaxed);
        current.state = "degraded".into();
        current.last_error = Some(summary.clone());
    }
    summary
}

async fn forward_journal<R: tokio::io::AsyncBufRead + Unpin>(
    reader: R,
    tx: &mpsc::Sender<Event>,
    status: &Arc<RwLock<SourceStatus>>,
    warned: &AtomicBool,
    oversized_records: &mut usize,
) -> Result<bool, String> {
    let mut lines = BoundedLines::new(reader, MAX_RECORD_BYTES);
    loop {
        let line = tokio::select! {
            _ = tx.closed() => return Ok(true),
            line = lines.next_line() => line.map_err(|error| format!("journal stdout read failed: {error}"))?,
        };
        if line == BoundedLine::Oversized {
            *oversized_records = oversized_records.saturating_add(1);
            tracing::warn!(
                oversized_records = *oversized_records,
                "journald oversized record; holding checkpoint"
            );
        }
        let Some(event) = journal_event(line)
            .map_err(|error| format!("{error}; oversized_records={oversized_records}"))?
        else {
            return Ok(false);
        };
        if tx.send(event).await.is_err() {
            return Ok(true);
        }
        let mut current = status.write().await;
        if !warned.load(Ordering::Relaxed) {
            current.state = "streaming".into();
            current.last_error = None;
        }
    }
}

pub async fn stream_journal(
    tx: mpsc::Sender<Event>,
    status: Arc<RwLock<SourceStatus>>,
    checkpoints: Arc<CheckpointStore>,
) {
    let mut backoff = Duration::from_secs(1);
    let mut recover_cursor = false;
    let mut oversized_records = 0;
    let lookback = configured_lookback();
    let amount = lookback[..lookback.len() - 1].parse::<i64>().unwrap_or(15);
    let minutes = match lookback.chars().last() {
        Some('d') => amount * 1440,
        Some('h') => amount * 60,
        _ => amount,
    };
    let initial_since = (Utc::now() - chrono::Duration::minutes(minutes))
        .to_rfc3339_opts(SecondsFormat::Micros, true);
    loop {
        if tx.is_closed() {
            return;
        }
        let mut command = tokio::process::Command::new("journalctl");
        command.args(JOURNAL_ARGS).args(["--follow", "--no-tail"]);
        if let Some(checkpoint) = checkpoints.newest_with_prefix("linux.") {
            if recover_cursor {
                command.args(["--since", &checkpoint.timestamp]);
            } else {
                command.arg(format!("--after-cursor={}", checkpoint.cursor));
            }
        } else {
            command.args(["--since", &initial_since]);
        }
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                set_state(&status, "error", Some(error.to_string())).await;
                tokio::select! {
                    _ = tx.closed() => return,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        let stderr = child.stderr.take();
        let diagnostic_status = status.clone();
        let warned = Arc::new(AtomicBool::new(false));
        let diagnostic_warned = warned.clone();
        let diagnostics = tokio::spawn(async move {
            if let Some(stderr) = stderr {
                read_diagnostics(BufReader::new(stderr), diagnostic_status, diagnostic_warned).await
            } else {
                "journalctl produced no stderr".into()
            }
        });
        let started = std::time::Instant::now();
        let result = if let Some(stdout) = child.stdout.take() {
            forward_journal(
                BufReader::new(stdout),
                &tx,
                &status,
                &warned,
                &mut oversized_records,
            )
            .await
        } else {
            Err("journalctl produced no stdout".into())
        };
        let _ = child.kill().await;
        let exit = child.wait().await;
        let diagnostic = diagnostics
            .await
            .unwrap_or_else(|error| format!("journal diagnostic reader failed: {error}"));
        if tx.is_closed() || matches!(result, Ok(true)) {
            return;
        }
        if result.is_ok() {
            recover_cursor = !recover_cursor && diagnostic.to_lowercase().contains("cursor");
        }
        let error = match result {
            Err(error) => format!("{error}; restarting from durable checkpoint. {diagnostic}"),
            Ok(_) => format!("journal stream exited ({exit:?}); restarting. {diagnostic}"),
        };
        set_state(&status, "error", Some(error)).await;
        if started.elapsed() >= Duration::from_secs(30) {
            backoff = Duration::from_secs(1);
        }
        tokio::select! {
            _ = tx.closed() => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

fn parse_record(line: &str) -> Option<Event> {
    let value: Value = serde_json::from_str(line).ok()?;
    let mut message = json_string(&value, "MESSAGE")?;
    let process = json_string(&value, "SYSLOG_IDENTIFIER")
        .or_else(|| json_string(&value, "_COMM"))
        .unwrap_or_else(|| "journal".into());
    let micros = json_string(&value, "__REALTIME_TIMESTAMP")?
        .parse::<i64>()
        .ok()?;
    let timestamp = DateTime::<Utc>::from_timestamp_micros(micros)?
        .to_rfc3339_opts(SecondsFormat::Micros, true);
    let lower = message.to_ascii_lowercase();
    let (event_id, level, outcome) = classify(&process, &lower);
    let mut fields = BTreeMap::from([
        ("event.id".into(), event_id.into()),
        ("event.outcome".into(), outcome.into()),
        ("process.name".into(), process.clone()),
    ]);
    if message.trim().is_empty() {
        fields.insert("event.original_message".into(), message);
        fields.insert("event.message_state".into(), "empty".into());
        message = format!("{process}: journald record with an empty MESSAGE");
    }
    copy_field(&value, "_PID", "process.pid", &mut fields);
    copy_field(&value, "_CMDLINE", "process.command_line", &mut fields);
    copy_field(&value, "_EXE", "process.executable", &mut fields);
    copy_field(&value, "_UID", "user.id", &mut fields);
    copy_field(&value, "_GID", "group.id", &mut fields);
    copy_field(&value, "_HOSTNAME", "host.name", &mut fields);
    copy_field(&value, "_BOOT_ID", "host.boot.id", &mut fields);
    copy_field(&value, "_TRANSPORT", "log.transport", &mut fields);
    copy_field(&value, "PRIORITY", "log.syslog.priority", &mut fields);
    copy_field(&value, "_AUDIT_LOGINUID", "user.audit.id", &mut fields);
    copy_field(&value, "_AUDIT_SESSION", "session.id", &mut fields);
    copy_field(&value, "_SYSTEMD_UNIT", "service.name", &mut fields);
    copy_field(&value, "__CURSOR", "collector.cursor", &mut fields);
    copy_field(&value, "__CURSOR", "event.record_id", &mut fields);
    if process.contains("sshd") {
        enrich_ssh(&message, &mut fields);
    }
    if process.contains("sudo") {
        enrich_sudo(&message, &mut fields);
    }
    if process.contains("audit") || json_string(&value, "_TRANSPORT").as_deref() == Some("audit") {
        enrich_audit(&message, &mut fields);
    }
    if let Some(pid) = fields.get("process.pid")
        && pid.chars().all(|c| c.is_ascii_digit())
        && Utc::now().timestamp_micros().abs_diff(micros) < 5_000_000
        && !fields.contains_key("process.parent.pid")
        && let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status"))
        && let Some(ppid) = status.lines().find_map(|line| line.strip_prefix("PPid:"))
    {
        fields.insert("process.parent.pid".into(), ppid.trim().into());
    }
    let priority = json_string(&value, "PRIORITY").and_then(|value| value.parse::<u8>().ok());
    let level = match priority {
        Some(0..=2) => "critical",
        Some(3) => "high",
        Some(4) if level == "low" => "medium",
        _ => level,
    };
    let mut event = Event::normalized(
        0,
        timestamp,
        format!(
            "linux.{}",
            process
                .chars()
                .take(120)
                .map(
                    |c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                        c.to_ascii_lowercase()
                    } else {
                        '_'
                    }
                )
                .collect::<String>()
        ),
        level.into(),
        message,
        fields,
    );
    if let Some(cursor) = event.fields.get("collector.cursor").cloned() {
        event.identify(&cursor);
    }
    Some(event)
}

fn enrich_sudo(message: &str, fields: &mut BTreeMap<String, String>) {
    if let Some((user, details)) = message.split_once(" : ") {
        fields.insert("user.name".into(), user.trim().into());
        for (key, target) in [
            ("TTY=", "terminal.name"),
            ("PWD=", "process.working_directory"),
            ("USER=", "user.target.name"),
            ("COMMAND=", "process.command_line"),
        ] {
            if let Some((_, value)) = details.split_once(key) {
                fields.insert(
                    target.into(),
                    if key == "COMMAND=" {
                        value.trim()
                    } else {
                        value.split(';').next().unwrap_or(value).trim()
                    }
                    .into(),
                );
            }
        }
    }
}

fn enrich_audit(message: &str, fields: &mut BTreeMap<String, String>) {
    for (key, target) in [
        ("pid", "process.pid"),
        ("ppid", "process.parent.pid"),
        ("uid", "user.id"),
        ("auid", "user.audit.id"),
        ("exe", "process.executable"),
        ("comm", "process.name"),
        ("syscall", "audit.syscall"),
        ("type", "audit.type"),
        ("success", "event.outcome"),
    ] {
        if let Some(value) = message
            .split_whitespace()
            .find_map(|word| word.strip_prefix(&format!("{key}=")))
        {
            let value = value.trim_matches('"');
            let value = if key == "success" {
                match value {
                    "yes" => "success",
                    "no" => "failure",
                    _ => "unknown",
                }
            } else {
                value
            };
            fields.insert(target.into(), value.into());
        }
    }
}

fn classify<'a>(process: &str, lower: &str) -> (&'a str, &'a str, &'a str) {
    if process.contains("sshd") && lower.contains("failed") {
        ("ssh.login.failure", "medium", "failure")
    } else if process.contains("sshd") && lower.contains("accepted") {
        ("ssh.login.success", "low", "success")
    } else if process.contains("sudo") && (lower.contains("denied") || lower.contains("incorrect"))
    {
        ("sudo.command.failure", "high", "failure")
    } else if process.contains("sudo") {
        ("sudo.command", "medium", "unknown")
    } else if process.contains("audit") {
        ("linux.audit", "medium", "unknown")
    } else if process.contains("systemd") {
        ("service.event", "low", "unknown")
    } else {
        ("linux.system", "low", "unknown")
    }
}

fn enrich_ssh(message: &str, fields: &mut BTreeMap<String, String>) {
    let words: Vec<_> = message.split_whitespace().collect();
    if let Some(from) = words
        .iter()
        .position(|word| word.eq_ignore_ascii_case("from"))
    {
        if let Some(ip) = words.get(from + 1) {
            fields.insert("source.ip".into(), ip.trim_matches(['[', ']']).into());
        }
        if let Some(start) = words
            .iter()
            .position(|word| word.eq_ignore_ascii_case("for"))
            && start < from
            && let Some(user) = words[start + 1..from]
                .iter()
                .rfind(|word| !matches!(word.to_ascii_lowercase().as_str(), "invalid" | "user"))
        {
            fields.insert("user.name".into(), user.trim_matches(':').into());
        }
    }
    if let Some(port) = words
        .iter()
        .position(|word| word.eq_ignore_ascii_case("port"))
        .and_then(|index| words.get(index + 1))
    {
        fields.insert("source.port".into(), port.trim_matches(':').into());
    }
}

fn json_string(value: &Value, key: &str) -> Option<String> {
    match value.get(key)? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Array(bytes) => {
            let bytes: Option<Vec<u8>> = bytes
                .iter()
                .map(|byte| byte.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                .collect();
            bytes.map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

fn copy_field(value: &Value, source: &str, target: &str, fields: &mut BTreeMap<String, String>) {
    if let Some(value) = json_string(value, source) {
        fields.insert(target.into(), value);
    }
}

fn valid_lookback(value: &str) -> bool {
    value.strip_suffix(['m', 'h', 'd']).is_some_and(|number| {
        number
            .parse::<u32>()
            .is_ok_and(|number| number > 0 && number <= 10080)
    })
}

fn failed(lookback: String, error: String) -> CollectionBatch {
    CollectionBatch {
        events: Vec::new(),
        status: SourceStatus {
            name: "linux.journald".into(),
            platform: "linux".into(),
            state: "error".into(),
            events_collected: 0,
            lookback,
            last_error: Some(error),
        },
    }
}

async fn set_state(status: &Arc<RwLock<SourceStatus>>, state: &str, error: Option<String>) {
    let mut status = status.write().await;
    status.state = state.into();
    status.last_error = error;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::tests::CheckpointFixture;

    fn fixture_record(cursor: &str) -> Vec<u8> {
        format!(
            "{}\n",
            serde_json::json!({
                "MESSAGE": "fixture event",
                "SYSLOG_IDENTIFIER": "collector-fixture",
                "__REALTIME_TIMESTAMP": "1760000000000000",
                "__CURSOR": cursor,
            })
        )
        .into_bytes()
    }

    fn fixture_status() -> Arc<RwLock<SourceStatus>> {
        Arc::new(RwLock::new(SourceStatus {
            name: "linux.journald".into(),
            platform: "linux".into(),
            state: "degraded".into(),
            events_collected: 0,
            lookback: "15m".into(),
            last_error: Some("old stream error".into()),
        }))
    }

    #[tokio::test]
    async fn live_oversized_record_stops_before_later_cursor_and_preserves_durable_prefix() {
        let fixture = CheckpointFixture::new();
        let status = fixture_status();
        let (tx, mut rx) = mpsc::channel(8);
        let mut input = fixture_record("confirmed-prefix");
        input.extend(std::iter::repeat_n(b'x', MAX_RECORD_BYTES + 1));
        input.push(b'\n');
        input.extend(fixture_record("must-not-be-confirmed"));
        let mut oversized = 0;
        let error = forward_journal(
            BufReader::with_capacity(7, input.as_slice()),
            &tx,
            &status,
            &AtomicBool::new(false),
            &mut oversized,
        )
        .await
        .unwrap_err();
        assert_eq!(oversized, 1);
        assert!(error.contains("oversized_records=1"));
        assert!(error.contains("checkpoint held"));
        let event = rx.try_recv().unwrap();
        assert_eq!(event.fields["collector.cursor"], "confirmed-prefix");
        assert!(rx.try_recv().is_err());
        assert!(fixture.store.is_empty());
        let wal = crate::storage::Wal::open(fixture.directory.join("fixture.wal")).unwrap();
        wal.append(std::slice::from_ref(&event)).unwrap();
        fixture.store.update_events(&[event]).unwrap();
        assert_eq!(
            fixture.store.newest_with_prefix("linux.").unwrap().cursor,
            "confirmed-prefix"
        );
        assert_eq!(wal.recover().unwrap().events.len(), 1);
    }

    #[tokio::test]
    async fn live_invalid_and_incomplete_records_are_checkpoint_barriers() {
        for barrier in [
            b"not-json\n".to_vec(),
            b"{\"MESSAGE\":\"no cursor\",\"__REALTIME_TIMESTAMP\":\"1760000000000000\"}\n".to_vec(),
            vec![255, b'\n'],
            fixture_record("partial")[..fixture_record("partial").len() - 1].to_vec(),
        ] {
            let status = fixture_status();
            let (tx, mut rx) = mpsc::channel(8);
            let mut input = fixture_record("prefix");
            input.extend(barrier);
            let mut oversized = 0;
            assert!(
                forward_journal(
                    BufReader::new(input.as_slice()),
                    &tx,
                    &status,
                    &AtomicBool::new(false),
                    &mut oversized
                )
                .await
                .is_err()
            );
            assert_eq!(rx.try_recv().unwrap().fields["collector.cursor"], "prefix");
            assert!(rx.try_recv().is_err());
            assert_eq!(oversized, 0);
        }
    }

    #[tokio::test]
    async fn live_clean_record_clears_old_error_but_not_current_stderr_warning() {
        for warned in [false, true] {
            let status = fixture_status();
            let (tx, mut rx) = mpsc::channel(8);
            let input = fixture_record("record");
            let mut oversized = 0;
            assert!(
                !forward_journal(
                    BufReader::new(input.as_slice()),
                    &tx,
                    &status,
                    &AtomicBool::new(warned),
                    &mut oversized
                )
                .await
                .unwrap()
            );
            assert!(rx.try_recv().is_ok());
            let current = status.read().await;
            assert_eq!(current.state, if warned { "degraded" } else { "streaming" });
            assert_eq!(current.last_error.is_some(), warned);
        }
    }

    #[tokio::test]
    async fn live_reader_stops_when_receiver_closes_even_without_stdout() {
        let status = fixture_status();
        let (tx, rx) = mpsc::channel(8);
        let (_writer, reader) = tokio::io::duplex(8);
        drop(rx);
        let mut oversized = 0;
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                forward_journal(
                    BufReader::new(reader),
                    &tx,
                    &status,
                    &AtomicBool::new(false),
                    &mut oversized,
                )
            )
            .await
            .unwrap()
            .unwrap()
        );
    }

    #[tokio::test]
    async fn diagnostics_are_bounded_and_count_each_oversized_line_once() {
        let status = fixture_status();
        let warned = Arc::new(AtomicBool::new(false));
        let mut input = vec![b'x'; 2 * 1024 * 1024];
        input.extend_from_slice(b"\nnormal diagnostic\n");
        input.extend("multibyte diagnostic: ".repeat(1000).as_bytes());
        input.push(b'\n');
        let summary = read_diagnostics(
            BufReader::with_capacity(31, input.as_slice()),
            status.clone(),
            warned.clone(),
        )
        .await;
        assert!(summary.contains("oversized_stderr_lines=2"));
        assert!(summary.contains("normal diagnostic"));
        assert!(summary.len() <= MAX_DIAGNOSTIC_BYTES + 64);
        assert!(warned.load(Ordering::Relaxed));
        assert_eq!(status.read().await.state, "degraded");
        let mut diagnostic = JournalDiagnostics::default();
        for _ in 0..10000 {
            diagnostic.append(&"\u{20ac}".repeat(512));
        }
        assert!(diagnostic.message.len() <= MAX_DIAGNOSTIC_BYTES);
        assert!(std::str::from_utf8(diagnostic.message.as_bytes()).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn backfill_process_retains_only_the_prefix_before_an_oversized_record() {
        let prefix = String::from_utf8(fixture_record("prefix")).unwrap();
        let suffix = String::from_utf8(fixture_record("suffix")).unwrap();
        let script = "import sys; sys.stdout.write(sys.argv[1]); sys.stdout.write('x' * (1024 * 1024 + 1) + '\\n'); sys.stdout.write(sys.argv[2]); sys.stdout.flush()";
        let (events, diagnostic) =
            read_backfill(Command::new("python3").args(["-c", script, &prefix, &suffix])).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].fields["collector.cursor"], "prefix");
        assert!(diagnostic.contains("oversized_records=1"));
    }

    #[test]
    fn parses_sshd_journal_record() {
        let line = r#"{"MESSAGE":"Failed password for invalid user root from 10.0.0.4 port 52211 ssh2","SYSLOG_IDENTIFIER":"sshd","__REALTIME_TIMESTAMP":"1760000000000000","_PID":"42"}"#;
        let event = parse_record(line).unwrap();
        assert_eq!(event.fields["event.id"], "ssh.login.failure");
        assert_eq!(event.fields["source.ip"], "10.0.0.4");
        assert_eq!(event.fields["user.name"], "root");
    }

    #[test]
    fn parses_sudo_context_and_journal_identity() {
        let line = r#"{"MESSAGE":"alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id -u","SYSLOG_IDENTIFIER":"sudo","__REALTIME_TIMESTAMP":"1760000000000000","__CURSOR":"s=one","_HOSTNAME":"linux-host","_CMDLINE":"sudo id -u"}"#;
        let event = parse_record(line).unwrap();
        assert_eq!(event.fields["user.name"], "alice");
        assert_eq!(event.fields["user.target.name"], "root");
        assert_eq!(event.fields["process.command_line"], "/usr/bin/id -u");
        assert_eq!(event.fields["host.name"], "linux-host");
        let other = parse_record(&line.replace("s=one", "s=two")).unwrap();
        assert_ne!(event.uid, other.uid);
    }

    #[test]
    fn parses_audit_context_and_binary_message() {
        let event = parse_record(r#"{"MESSAGE":"type=SYSCALL pid=42 ppid=7 uid=1000 auid=1000 exe=\"/usr/bin/id\" success=no syscall=59","SYSLOG_IDENTIFIER":"audit","__REALTIME_TIMESTAMP":1760000000000000,"PRIORITY":"3"}"#).unwrap();
        assert_eq!(event.fields["process.parent.pid"], "7");
        assert_eq!(event.fields["event.outcome"], "failure");
        assert_eq!(event.level, "high");
        let binary = parse_record(
            r#"{"MESSAGE":[104,105],"__REALTIME_TIMESTAMP":"1760000000000000","_COMM":"app"}"#,
        )
        .unwrap();
        assert_eq!(binary.message, "hi");
        assert!(parse_record(r#"{"MESSAGE":"missing timestamp"}"#).is_none());
    }

    #[test]
    fn validates_unicode_and_bounded_lookback() {
        for invalid in ["é", "0m", "999999d", "-1h", "1h;id", "m"] {
            assert!(!valid_lookback(invalid));
        }
        assert!(valid_lookback("15m"));
    }

    #[test]
    fn ignores_ssh_like_words_in_other_services() {
        let event = parse_record(r#"{"MESSAGE":"route from cache for service","_COMM":"app","__REALTIME_TIMESTAMP":"1760000000000000"}"#).unwrap();
        assert!(!event.fields.contains_key("source.ip"));
    }
    #[test]
    fn empty_journal_messages_preserve_identity_and_can_be_ingested_remotely() {
        for message in ["", " \t\n"] {
            let record = serde_json::json!({
                "MESSAGE": message,
                "__REALTIME_TIMESTAMP": "1791489011347067",
                "__CURSOR": "empty-message-cursor",
                "SYSLOG_IDENTIFIER": "systemd",
            });
            let event = parse_record(&record.to_string()).unwrap();
            assert_eq!(
                event.message,
                "systemd: journald record with an empty MESSAGE"
            );
            assert_eq!(event.fields["event.original_message"], message);
            assert_eq!(event.fields["event.message_state"], "empty");
            assert_eq!(event.fields["event.record_id"], "empty-message-cursor");
            let agent = crate::ingest::AuthenticatedAgent {
                id: "linux-fixture".into(),
                name: "linux-fixture".into(),
            };
            let remote = crate::ingest::normalize_event(
                &agent,
                None,
                crate::ingest::IngestEvent::from(&event),
            )
            .unwrap();
            assert_eq!(remote.fields["event.original_message"], message);
            assert_eq!(remote.fields["event.record_id"], "empty-message-cursor");
        }
    }
}
