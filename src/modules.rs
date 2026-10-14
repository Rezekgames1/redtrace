//! Stable input contract for independently installed telemetry modules, including NTA.
use crate::model::Event;
use serde::{Deserialize, Serialize};

pub const PROTOCOL: u16 = 1;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleEvent {
    pub protocol: u16,
    pub module: String,
    pub event: Event,
}

impl ModuleEvent {
    /// Validate the producer contract before assigning a local source and durable cursor.
    pub fn validate(&self, expected_module: &str) -> std::io::Result<()> {
        let event = &self.event;
        if self.protocol != PROTOCOL || self.module != expected_module {
            return Err(std::io::Error::other(
                "module protocol or identity mismatch",
            ));
        }
        if event.schema_version != 1
            || chrono::DateTime::parse_from_rfc3339(&event.timestamp).is_err()
            || event.message.trim().is_empty()
            || event.message.len() > crate::ingest::MAX_EVENT_FIELD_BYTES
            || event.level.is_empty()
            || event.level.len() > 16
            || !event
                .level
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || event.fields.len() > 48
            || event.fields.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 128
                    || !key.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
                    || value.len() > 60 * 1024
            })
        {
            return Err(std::io::Error::other("invalid module event"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ModuleHealth {
    pub id: String,
    pub state: String,
    pub permissions: String,
    pub events: u64,
    pub filtered: u64,
    pub errors: u64,
    pub last_event_at: Option<String>,
    pub error: Option<String>,
}

pub fn catalog(config: &crate::config::Config) -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({"id":"system", "enabled":config.sources.system,"platforms":["windows","linux","macos"],"kind":"native"}),
        serde_json::json!({"id":"linux.audit", "enabled":config.sources.linux_audit,"platforms":["linux"],"kind":"file","requires":"audit.log read access"}),
        serde_json::json!({"id":"macos.endpoint_security", "enabled":config.sources.macos_endpoint_security,"platforms":["macos"],"kind":"native ES helper (eslogger fallback opt-in)","requires":"root, Full Disk Access and native ES entitlement"}),
        serde_json::json!({"id":"external", "protocol":PROTOCOL,"inputs":config.sources.module_inputs,"kind":"ndjson","categories":["network","process","file","authentication"],"isolated":true}),
    ]
}

pub fn normalize(event: &mut Event) {
    event
        .fields
        .entry("observer.type".into())
        .or_insert_with(|| "redtrace".into());
    event
        .fields
        .entry("event.schema_version".into())
        .or_insert_with(|| "1".into());
    event.fields.entry("host.os".into()).or_insert_with(|| {
        if event.source.starts_with("linux.") {
            "linux"
        } else if event.source.starts_with("macos.") {
            "macos"
        } else if event.source.starts_with("windows.") {
            "windows"
        } else {
            std::env::consts::OS
        }
        .into()
    });
    if !event.fields.contains_key("event.category") {
        let id = event.field("event.id").unwrap_or_default();
        let category = match id {
            "1" | "4688" | "process.exec" | "process.fork" | "process.exit" => "process",
            "3" | "22" | "network.connect" | "network.dns" => "network",
            "4624"
            | "4625"
            | "4740"
            | "ssh.login.failure"
            | "ssh.login.success"
            | "sudo.command.failure" => "authentication",
            "11" | "23" | "26" | "file.create" | "file.rename" | "file.unlink" | "file.open"
            | "file.close" => "file",
            _ => "system",
        };
        event
            .fields
            .insert("event.category".into(), category.into());
    }
}
