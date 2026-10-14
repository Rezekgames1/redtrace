//! Native Endpoint Security helper transport, with an explicit eslogger compatibility backend.
use super::{BoundedLine, BoundedLines};
use crate::{model::Event, modules::ModuleHealth};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, TryRecvError},
};

pub fn parse_record(raw: &[u8]) -> io::Result<Event> {
    if raw.len() > 256 * 1024 {
        return Err(io::Error::other("ES record cap exceeded"));
    }
    let value: Value = serde_json::from_slice(raw).map_err(io::Error::other)?;
    let native = value.get("redtrace_es").and_then(Value::as_u64) == Some(1);
    let timestamp = value
        .get("timestamp")
        .or_else(|| value.get("time"))
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .ok_or_else(|| io::Error::other("Endpoint Security timestamp/schema unsupported"))?
        .with_timezone(&chrono::Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let action = if native {
        value
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other("missing ES action"))?
    } else {
        value
            .get("event")
            .and_then(Value::as_object)
            .filter(|m| m.len() == 1)
            .and_then(|m| m.keys().next())
            .map(String::as_str)
            .ok_or_else(|| io::Error::other("eslogger event schema unsupported"))?
    };
    let action = match action {
        "ssh_login" => "openssh_login",
        "ssh_logout" => "openssh_logout",
        other => other,
    };
    if !matches!(
        action,
        "exec"
            | "fork"
            | "exit"
            | "create"
            | "rename"
            | "unlink"
            | "open"
            | "close"
            | "authentication"
            | "login_login"
            | "login_logout"
            | "openssh_login"
            | "openssh_logout"
    ) {
        return Err(io::Error::other("unsupported ES event type"));
    }
    let mut fields = BTreeMap::new();
    if native {
        let map = value
            .get("fields")
            .and_then(Value::as_object)
            .ok_or_else(|| io::Error::other("missing ES fields"))?;
        if map.len() > 48 {
            return Err(io::Error::other("ES field cap exceeded"));
        }
        for (k, v) in map {
            let v = v
                .as_str()
                .filter(|s| s.len() <= 60 * 1024)
                .ok_or_else(|| io::Error::other("invalid native ES field"))?;
            if !valid_field_name(k)
                || k.starts_with("collector.")
                || k.starts_with("agent.")
                || k == "event.filtered"
            {
                return Err(io::Error::other("invalid native ES field name"));
            }
            fields.insert(k.clone(), v.into());
        }
    } else {
        let event = value
            .get("event")
            .and_then(|v| {
                v.get(action).or_else(|| {
                    v.get(match action {
                        "openssh_login" => "ssh_login",
                        "openssh_logout" => "ssh_logout",
                        other => other,
                    })
                })
            })
            .unwrap_or(&Value::Null);
        if !event.is_object() {
            return Err(io::Error::other(
                "eslogger event payload schema unsupported",
            ));
        }
        let process = if action == "exec" {
            event.get("target")
        } else if action == "fork" {
            event.get("child")
        } else {
            value.get("process")
        };
        if let Some(p) = process {
            for (pointer, field) in [
                ("/audit_token/pid", "process.pid"),
                ("/audit_token/ruid", "user.id"),
                ("/audit_token/euid", "user.effective.id"),
                ("/audit_token/pidversion", "process.pidversion"),
                ("/ppid", "process.parent.pid"),
                ("/executable/path", "process.executable"),
                ("/signing_id", "process.code_signature.signing_id"),
                ("/team_id", "process.code_signature.team_id"),
                ("/start_time", "process.start"),
            ] {
                if let Some(v) = p.pointer(pointer).and_then(scalar) {
                    fields.insert(field.into(), v);
                }
            }
        }
        if let Some(args) = event.get("args").and_then(Value::as_array) {
            if args.len() > 256 || args.iter().any(|a| !a.is_string()) {
                return Err(io::Error::other("invalid ES argument list"));
            }
            let args: Vec<_> = args.iter().filter_map(Value::as_str).collect();
            fields.insert(
                "process.args".into(),
                serde_json::to_string(&args).map_err(io::Error::other)?,
            );
        }
        for (pointer, field) in [
            ("/target/path", "file.path"),
            ("/file/path", "file.path"),
            ("/source/path", "file.path"),
            (
                "/destination/existing_file/path",
                if action == "create" {
                    "file.path"
                } else {
                    "file.target.path"
                },
            ),
            (
                "/destination/new_path/dir/path",
                if action == "create" {
                    "file.directory"
                } else {
                    "file.target.directory"
                },
            ),
            (
                "/destination/new_path/filename",
                if action == "create" {
                    "file.name"
                } else {
                    "file.target.name"
                },
            ),
            ("/cwd/path", "process.working_directory"),
            ("/stat", "process.exit_status"),
            ("/username", "user.name"),
            ("/source_address", "source.address"),
            ("/failure_message", "event.reason"),
            ("/result_type", "event.code"),
            ("/data/od/record_name", "user.name"),
            ("/data/od/node_name", "authentication.node"),
            ("/data/auto_unlock/username", "user.name"),
        ] {
            if let Some(v) = event.pointer(pointer).and_then(scalar) {
                fields.insert(field.into(), v);
            }
        }
        if let Some(success) = event.get("success").and_then(Value::as_bool) {
            fields.insert(
                "event.outcome".into(),
                if success { "success" } else { "failure" }.into(),
            );
        }
        if event.get("has_uid").and_then(Value::as_bool) != Some(false)
            && let Some(uid) = event
                .pointer("/uid/uid")
                .or_else(|| event.get("uid"))
                .and_then(scalar)
        {
            fields.insert("user.id".into(), uid);
        }
        fields.insert(
            "es.schema_version".into(),
            value
                .get("schema_version")
                .map(Value::to_string)
                .unwrap_or_else(|| "unknown".into()),
        );
    }
    if let Some(address) = fields.get("source.address")
        && let Ok(ip) = address.parse::<std::net::IpAddr>()
    {
        fields.insert("source.ip".into(), ip.to_string());
    }
    if action == "exit"
        && let Some(status) = fields
            .get("process.exit_status")
            .and_then(|v| v.parse::<u32>().ok())
    {
        // Darwin's wait status stores a normal exit code in the high byte, and a
        // terminating signal in the low seven bits (the core flag is bit seven).
        let signal = status & 0x7f;
        if signal == 0 {
            fields
                .entry("process.exit_code".into())
                .or_insert_with(|| ((status >> 8) & 0xff).to_string());
        } else if signal != 0x7f {
            fields
                .entry("process.exit_signal".into())
                .or_insert_with(|| signal.to_string());
        }
    }
    for (directory, name, path) in [
        ("file.directory", "file.name", "file.path"),
        (
            "file.target.directory",
            "file.target.name",
            "file.target.path",
        ),
    ] {
        if let (Some(directory), Some(name)) = (fields.get(directory), fields.get(name)) {
            let path_value = format!("{}/{name}", directory.trim_end_matches('/'));
            fields.entry(path.into()).or_insert(path_value);
        }
    }
    let category = if matches!(action, "exec" | "fork" | "exit") {
        "process"
    } else if matches!(action, "create" | "rename" | "unlink" | "open" | "close") {
        "file"
    } else {
        "authentication"
    };
    if let Some(encoded) = fields.get("process.args") {
        let args = serde_json::from_str::<Vec<String>>(encoded).map_err(io::Error::other)?;
        if args.len() > 256 {
            return Err(io::Error::other("ES argument cap exceeded"));
        }
        fields
            .entry("process.command_line".into())
            .or_insert_with(|| {
                args.into_iter()
                    .map(|v| {
                        if v.contains(char::is_whitespace) {
                            format!("{v:?}")
                        } else {
                            v
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            });
    }
    if let (Some(pid), Some(version)) =
        (fields.get("process.pid"), fields.get("process.pidversion"))
    {
        let identity = format!(
            "{}:{pid}:{version}:{}",
            value
                .get("session")
                .and_then(Value::as_str)
                .unwrap_or("eslogger"),
            fields
                .get("process.start")
                .map(String::as_str)
                .unwrap_or("")
        );
        fields.insert(
            "process.entity_id".into(),
            crate::ingest::hex(&crate::ingest::sha256(identity.as_bytes())),
        );
    }
    fields.insert("event.id".into(), format!("{category}.{action}"));
    fields.insert("event.action".into(), action.into());
    fields.insert("event.category".into(), category.into());
    fields.insert("parser.version".into(), "1".into());
    let seq = value
        .get("global_seq_num")
        .or_else(|| value.get("seq_num"))
        .map(Value::to_string)
        .unwrap_or_default();
    fields.insert("es.sequence".into(), seq.clone());
    let session = value
        .get("session")
        .and_then(Value::as_str)
        .unwrap_or("eslogger");
    let description = format!(
        "{action}: {}",
        fields
            .get("process.executable")
            .or_else(|| fields.get("file.path"))
            .map(String::as_str)
            .unwrap_or("Endpoint Security")
    );
    let mut event = Event::normalized(
        0,
        timestamp,
        "macos.endpoint_security".into(),
        "low".into(),
        description,
        fields,
    );
    let mach_time = value
        .get("mach_time")
        .map(Value::to_string)
        .unwrap_or_default();
    let identity = if seq.is_empty() && mach_time.is_empty() {
        crate::ingest::hex(&crate::ingest::sha256(raw))
    } else {
        format!("{session}:{seq}:{mach_time}")
    };
    event.identify(&identity);
    crate::modules::normalize(&mut event);
    if event.fields.len() > crate::ingest::MAX_FIELDS_PER_EVENT
        || event
            .fields
            .values()
            .any(|v| v.len() > crate::ingest::MAX_EVENT_FIELD_BYTES)
    {
        return Err(io::Error::other("normalized ES event exceeds field limits"));
    }
    Ok(event)
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(_) | Value::Bool(_) => Some(value.to_string()),
        _ => None,
    }
}

fn valid_field_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub struct EsSession {
    child: Child,
    receiver: Receiver<io::Result<Event>>,
    pending: Option<Event>,
    pub health: ModuleHealth,
}
impl EsSession {
    pub fn start(events: &[String], record_cap: usize) -> io::Result<Self> {
        if !cfg!(target_os = "macos") {
            return Err(io::Error::other(
                "Endpoint Security is available on macOS only",
            ));
        }
        let native = std::env::current_exe()?
            .parent()
            .ok_or_else(|| io::Error::other("executable directory unavailable"))?
            .join("redtrace-es-helper");
        let backend = std::env::var("REDTRACE_ES_BACKEND").unwrap_or_else(|_| "native".into());
        if !matches!(backend.as_str(), "native" | "eslogger") {
            return Err(io::Error::other(
                "REDTRACE_ES_BACKEND must be native or eslogger",
            ));
        }
        let events: Vec<_> = events
            .iter()
            .map(|event| match event.as_str() {
                "ssh_login" => "openssh_login",
                "ssh_logout" => "openssh_logout",
                other => other,
            })
            .collect();
        let binary: PathBuf = if backend == "eslogger" {
            "/usr/bin/eslogger".into()
        } else {
            native
        };
        let mut child = Command::new(binary)
            .args(&events)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("ES stdout missing"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("ES stderr missing"))?;
        let (sender, receiver) = mpsc::sync_channel(32);
        let errors = sender.clone();
        std::thread::spawn(move || {
            let mut lines = BoundedLines::new(std::io::BufReader::new(stdout), record_cap);
            loop {
                let result = match lines.read_line() {
                    Ok(BoundedLine::Complete(raw)) => parse_record(&raw),
                    Ok(BoundedLine::End) => break,
                    Ok(_) => Err(io::Error::other(
                        "ES record exceeds limit or stream is incomplete",
                    )),
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        break;
                    }
                };
                if sender.send(result).is_err() {
                    break;
                }
            }
        });
        std::thread::spawn(move || {
            let mut lines = BoundedLines::new(std::io::BufReader::new(stderr), 1024);
            while let Ok(BoundedLine::Complete(raw)) = lines.read_line() {
                if errors
                    .send(Err(io::Error::other(
                        String::from_utf8_lossy(&raw).trim().to_owned(),
                    )))
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            receiver,
            pending: None,
            health: ModuleHealth {
                id: "macos.endpoint_security".into(),
                state: "starting".into(),
                permissions: "root + Full Disk Access; native backend also requires ES entitlement"
                    .into(),
                ..ModuleHealth::default()
            },
        })
    }
    pub fn drain(&mut self, maximum: usize) -> Vec<Event> {
        self.drain_bounded(maximum, usize::MAX)
    }
    pub fn drain_bounded(&mut self, maximum: usize, maximum_bytes: usize) -> Vec<Event> {
        let mut events = Vec::new();
        let mut bytes = 0;
        let mut disconnected = false;
        for _ in 0..maximum {
            let next = self
                .pending
                .take()
                .map(|event| Ok(Ok(event)))
                .unwrap_or_else(|| self.receiver.try_recv());
            match next {
                Ok(Ok(event)) => {
                    let size = serde_json::to_vec(&event)
                        .map(|v| v.len())
                        .unwrap_or(usize::MAX);
                    if size > maximum_bytes.saturating_sub(bytes) {
                        self.pending = Some(event);
                        if events.is_empty() {
                            self.health.state = "degraded".into();
                            self.health.error =
                                Some("ES event awaits a larger batch byte budget".into());
                        }
                        break;
                    }
                    bytes += size;
                    self.health.events += 1;
                    self.health.last_event_at = Some(event.timestamp.clone());
                    self.health.state = "streaming".into();
                    if event
                        .fields
                        .get("es.dropped_total")
                        .and_then(|v| v.parse::<u64>().ok())
                        .is_some_and(|d| d > 0)
                    {
                        self.health.state = "degraded".into();
                        self.health.error = Some(format!(
                            "ES helper dropped {} events at its record or queue limits",
                            event.fields["es.dropped_total"]
                        ));
                    }
                    events.push(event);
                }
                Ok(Err(error)) => {
                    self.health.errors += 1;
                    self.health.state = "degraded".into();
                    self.health.error = Some(error.to_string().chars().take(512).collect());
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    self.health.state = "error".into();
                    break;
                }
            }
        }
        // A helper can exit while its bounded transport still contains events. Consume
        // those records before exposing terminal health and letting the caller restart it.
        if let Ok(Some(exit)) = self.child.try_wait()
            && disconnected
        {
            self.health.state = "error".into();
            if self.health.error.is_none() {
                self.health.error = Some(format!(
                    "Endpoint Security helper exited {exit}; check entitlement, root and Full Disk Access"
                ));
            }
        }
        events
    }
}
impl Drop for EsSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ended_session(records: usize) -> EsSession {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.wait().unwrap();
        let (sender, receiver) = mpsc::sync_channel(records);
        for sequence in 0..records {
            let raw = serde_json::json!({"redtrace_es":1,"timestamp":"2026-10-13T10:00:00Z","action":"exec","session":"fixture","global_seq_num":sequence,"fields":{"process.pid":"12"}});
            sender
                .send(Ok(parse_record(&serde_json::to_vec(&raw).unwrap()).unwrap()))
                .unwrap();
        }
        drop(sender);
        EsSession {
            child,
            receiver,
            pending: None,
            health: ModuleHealth::default(),
        }
    }

    #[test]
    fn finished_helper_delivers_buffered_records_before_terminal_health() {
        let mut session = ended_session(3);
        let mut delivered = Vec::new();
        for _ in 0..3 {
            let batch = session.drain(1);
            assert_eq!(batch.len(), 1);
            assert_ne!(session.health.state, "error");
            delivered.extend(batch);
        }
        assert_eq!(delivered.len(), 3);
        assert!(session.drain(1).is_empty());
        assert_eq!(session.health.state, "error");
    }

    #[test]
    fn byte_limited_drain_retains_record_for_next_call() {
        let mut session = ended_session(1);
        assert!(session.drain_bounded(1, 1).is_empty());
        assert!(session.pending.is_some());
        assert_eq!(session.drain_bounded(1, 4096).len(), 1);
    }
    #[test]
    fn native_exec_preserves_identity_and_common_fields() {
        let raw=br#"{"redtrace_es":1,"timestamp":"2026-10-13T10:00:00Z","action":"exec","session":"boot-a","global_seq_num":7,"mach_time":77,"fields":{"process.pid":"12","process.executable":"/bin/sh","process.args":"[\"/bin/sh\",\"-c\",\"true\"]"}}"#;
        let a = parse_record(raw).unwrap();
        assert_eq!(a.fields["event.id"], "process.exec");
        assert_eq!(a.uid, parse_record(raw).unwrap().uid);
        assert!(parse_record(br#"{"timestamp":"invalid"}"#).is_err());
    }
}
