use crate::modules::ModuleHealth;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Report {
    pub pending_events: u64,
    pub spool_bytes: u64,
    pub spool_limit_bytes: u64,
    pub oldest_pending_at: Option<String>,
    pub last_event_at: Option<String>,
    pub retry_total: u64,
    pub quarantine_events: u64,
    pub quarantine_bytes: u64,
    pub enqueue_refused_total: u64,
    pub modules: Vec<ModuleHealth>,
    pub config_generation: u64,
    pub trust_sha256: String,
}
impl Report {
    pub fn validate(&self) -> Result<(), String> {
        if self.pending_events > 100_000
            || self.spool_bytes > 1024 * 1024 * 1024
            || self.spool_limit_bytes > 1024 * 1024 * 1024
            || self.quarantine_bytes > 1024 * 1024 * 1024
            || self.modules.len() > 16
            || self.trust_sha256.len() > 64
            || self.modules.iter().any(|m| {
                m.id.len() > 64
                    || m.state.len() > 32
                    || m.permissions.len() > 256
                    || m.error.as_ref().is_some_and(|e| e.len() > 1024)
            })
            || self
                .oldest_pending_at
                .iter()
                .chain(self.last_event_at.iter())
                .any(|s| s.len() > 64 || chrono::DateTime::parse_from_rfc3339(s).is_err())
        {
            return Err("invalid agent health report".into());
        }
        Ok(())
    }
}
pub fn liveness(
    last_seen: u64,
    last_event: u64,
    report: Option<&Report>,
    revoked: bool,
    expires: Option<u64>,
    now: u64,
) -> &'static str {
    if revoked {
        return "revoked";
    }
    if expires.is_some_and(|e| now >= e) {
        return "expired";
    }
    if last_seen == 0 {
        return "registered";
    }
    let age = now.saturating_sub(last_seen);
    if age >= 600 {
        return "offline";
    }
    if age >= 120 {
        return "stale";
    }
    if report.is_some_and(|r| {
        r.modules
            .iter()
            .any(|m| matches!(m.state.as_str(), "error" | "degraded"))
            || r.spool_limit_bytes > 0 && r.spool_bytes >= r.spool_limit_bytes
            || r.oldest_pending_at
                .as_ref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .is_some_and(|t| now.saturating_sub(t.timestamp().max(0) as u64) > 120)
    }) {
        return "degraded";
    }
    if last_event == 0 || now.saturating_sub(last_event) >= 60 {
        "idle"
    } else {
        "online"
    }
}
