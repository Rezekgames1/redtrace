use super::{CollectionBatch, SourceStatus};
use crate::model::Event;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    process::Command,
};

const PREDICATE: &str = r#"process == "sshd" OR process == "sudo" OR (process == "authd" AND (eventMessage CONTAINS[c] "succeeded" OR eventMessage CONTAINS[c] "failed" OR eventMessage CONTAINS[c] "login"))"#;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnifiedLogRecord {
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
}

#[derive(Clone, Debug)]
struct ProcessInfo {
    parent_pid: String,
    command_line: String,
}

pub fn collect() -> CollectionBatch {
    let lookback = configured_lookback();
    let output = Command::new("/usr/bin/log")
        .args([
            "show",
            "--style",
            "json",
            "--last",
            &lookback,
            "--predicate",
            PREDICATE,
        ])
        .output();

    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            return failed_batch(
                lookback,
                format!(
                    "Unified Log exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            );
        }
        Err(error) => return failed_batch(lookback, error.to_string()),
    };

    let records: Vec<UnifiedLogRecord> = match serde_json::from_slice(&output.stdout) {
        Ok(records) => records,
        Err(error) => return failed_batch(lookback, format!("invalid Unified Log JSON: {error}")),
    };

    let processes = process_snapshot();
    let mut seen = BTreeSet::new();
    let mut events = Vec::new();
    for record in records {
        if record.timestamp.is_empty() || record.event_message.is_empty() {
            continue;
        }
        let process_name = record
            .process_image_path
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or("unknown")
            .to_string();
        let source = format!("macos.{process_name}");
        if !seen.insert((
            record.timestamp.clone(),
            source.clone(),
            record.event_message.clone(),
        )) {
            continue;
        }

        let (event_id, level, outcome) = classify(&process_name, &record.event_message);
        let mut fields = BTreeMap::from([
            ("event.id".into(), event_id.into()),
            ("event.outcome".into(), outcome.into()),
            ("process.name".into(), process_name),
            ("process.pid".into(), record.process_id.to_string()),
            ("log.subsystem".into(), record.subsystem),
            ("log.category".into(), record.category),
        ]);
        if let Some(process) = processes.get(&record.process_id) {
            fields.insert("process.parent.pid".into(), process.parent_pid.clone());
            fields.insert("process.command_line".into(), process.command_line.clone());
        }
        enrich_ssh_fields(&record.event_message, &mut fields);

        events.push(Event::normalized(
            0,
            record.timestamp,
            source,
            level.into(),
            record.event_message,
            fields,
        ));
    }
    events.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));
    for (index, event) in events.iter_mut().enumerate() {
        event.id = (index + 1) as u64;
    }

    CollectionBatch {
        status: SourceStatus {
            name: "macos.unified_log".into(),
            platform: "macos".into(),
            state: "ready".into(),
            events_collected: events.len(),
            lookback,
            last_error: None,
        },
        events,
    }
}

fn configured_lookback() -> String {
    let value = std::env::var("REDTRACE_LOOKBACK").unwrap_or_else(|_| "15m".into());
    let valid = value.len() >= 2
        && value[..value.len() - 1]
            .chars()
            .all(|char| char.is_ascii_digit())
        && matches!(value.chars().last(), Some('m' | 'h' | 'd'));
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
    let lower = message.to_ascii_lowercase();
    if process == "sshd" && lower.contains("failed") {
        ("ssh.login.failure", "medium", "failure")
    } else if process == "sshd" && lower.contains("accepted") {
        ("ssh.login.success", "low", "success")
    } else if process == "sshd" {
        ("ssh.event", "low", "unknown")
    } else if process == "sudo" && (lower.contains("denied") || lower.contains("incorrect")) {
        ("sudo.command.failure", "high", "failure")
    } else if process == "sudo" {
        ("sudo.event", "medium", "unknown")
    } else if lower.contains("failed") {
        ("authentication.failure", "medium", "failure")
    } else if lower.contains("succeeded") {
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
        if let Some(address) = words.get(index + 1) {
            fields.insert("source.ip".into(), address.trim_matches(['[', ']']).into());
        }
        let user_start = words
            .iter()
            .position(|word| word.eq_ignore_ascii_case("for"));
        if let Some(start) = user_start {
            let candidate = words[start + 1..index]
                .iter()
                .filter(|word| !matches!(word.to_ascii_lowercase().as_str(), "invalid" | "user"))
                .last();
            if let Some(user) = candidate {
                fields.insert("user.name".into(), user.trim_matches(':').into());
            }
        }
    }
    if let Some(index) = words
        .iter()
        .position(|word| word.eq_ignore_ascii_case("port"))
        && let Some(port) = words.get(index + 1)
    {
        fields.insert("source.port".into(), port.trim_matches(':').into());
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
}
