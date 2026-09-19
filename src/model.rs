use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub id: u64,
    pub uid: String,
    pub schema_version: u16,
    pub timestamp: String,
    pub source: String,
    pub level: String,
    pub message: String,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
}

impl Event {
    pub fn normalized(
        id: u64,
        timestamp: String,
        source: String,
        level: String,
        message: String,
        fields: BTreeMap<String, String>,
    ) -> Self {
        let uid = stable_uid(&timestamp, &source, &message);
        Self {
            id,
            uid,
            schema_version: 1,
            timestamp,
            source,
            level,
            message,
            fields,
        }
    }

    pub fn field(&self, name: &str) -> Option<&str> {
        match name {
            "@timestamp" | "timestamp" => Some(&self.timestamp),
            "source" | "log.source" => Some(&self.source),
            "level" | "event.level" => Some(&self.level),
            "message" | "event.description" => Some(&self.message),
            _ => self.fields.get(name).map(String::as_str),
        }
    }
}

fn stable_uid(timestamp: &str, source: &str, message: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in timestamp
        .bytes()
        .chain([0xff])
        .chain(source.bytes())
        .chain([0xfe])
        .chain(message.bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_is_stable_and_sensitive_to_content() {
        let first = stable_uid("2026-01-01T00:00:00Z", "macos.sshd", "accepted");
        let second = stable_uid("2026-01-01T00:00:00Z", "macos.sshd", "accepted");
        let changed = stable_uid("2026-01-01T00:00:00Z", "macos.sshd", "failed");
        assert_eq!(first, second);
        assert_ne!(first, changed);
    }
}
