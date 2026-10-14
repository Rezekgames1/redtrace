//! Versioned configuration shared by collector, desktop and agents.
use crate::service::{self, invalid};
use serde::{Deserialize, Serialize};
use std::{io, path::Path};

pub const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    #[default]
    Basic,
    Extended,
    Custom,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Sources {
    pub system: bool,
    pub linux_audit: bool,
    pub audit_path: String,
    pub macos_endpoint_security: bool,
    pub es_events: Vec<String>,
    pub module_inputs: Vec<ModuleInput>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModuleInput {
    pub id: String,
    pub path: String,
    pub query: String,
}

impl Default for Sources {
    fn default() -> Self {
        Self {
            system: true,
            linux_audit: false,
            audit_path: "/var/log/audit/audit.log".into(),
            macos_endpoint_security: false,
            es_events: vec![
                "exec".into(),
                "fork".into(),
                "exit".into(),
                "create".into(),
                "rename".into(),
                "unlink".into(),
            ],
            module_inputs: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Resources {
    pub poll_seconds: u64,
    pub heartbeat_seconds: u64,
    pub max_batch_events: usize,
    pub max_batch_bytes: usize,
    pub max_record_bytes: usize,
    pub max_aggregation_events: usize,
    pub max_aggregation_bytes: usize,
    pub spool_events: usize,
    pub spool_bytes: u64,
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            poll_seconds: 2,
            heartbeat_seconds: 30,
            max_batch_events: 512,
            max_batch_bytes: 4 * 1024 * 1024,
            max_record_bytes: 128 * 1024,
            max_aggregation_events: 256,
            max_aggregation_bytes: 2 * 1024 * 1024,
            spool_events: 20_000,
            spool_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub version: u16,
    pub profile: Profile,
    pub sources: Sources,
    pub resources: Resources,
    pub include: String,
    pub exclude: String,
    pub builtin_detections: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: VERSION,
            profile: Profile::Basic,
            sources: Sources::default(),
            resources: Resources::default(),
            include: "*".into(),
            exclude: String::new(),
            builtin_detections: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> io::Result<()> {
        if self.version != VERSION {
            return Err(invalid(
                "unsupported configuration version; upgrade REDTRACE before opening this configuration",
            ));
        }
        let r = &self.resources;
        if !(1..=60).contains(&r.poll_seconds)
            || !(5..=300).contains(&r.heartbeat_seconds)
            || !(1..=4096).contains(&r.max_batch_events)
            || !(1024..=8 * 1024 * 1024).contains(&r.max_batch_bytes)
            || !(1024..=256 * 1024).contains(&r.max_record_bytes)
            || r.max_record_bytes > r.max_batch_bytes
            || !(1..=1024).contains(&r.max_aggregation_events)
            || !(1024..=8 * 1024 * 1024).contains(&r.max_aggregation_bytes)
            || !(1..=100_000).contains(&r.spool_events)
            || !(1024..=1024 * 1024 * 1024).contains(&r.spool_bytes)
        {
            return Err(invalid("resource limits are outside supported bounds"));
        }
        // This is a Linux source path, including in enrollment packages created on Windows.
        if !self.sources.audit_path.starts_with('/')
            || self.sources.audit_path.len() > 4096
            || self.sources.audit_path.split('/').any(|part| part == "..")
            || self.sources.audit_path.chars().any(char::is_control)
        {
            return Err(invalid("audit path must be absolute"));
        }
        if self.sources.es_events.is_empty()
            || self.sources.es_events.len() > 16
            || self.sources.es_events.iter().any(|e| {
                !matches!(
                    e.as_str(),
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
                        | "ssh_login"
                        | "ssh_logout"
                        | "openssh_login"
                        | "openssh_logout"
                )
            })
        {
            return Err(invalid("unsupported Endpoint Security event selection"));
        }
        if self.sources.module_inputs.len() > 8 {
            return Err(invalid("at most eight module inputs are supported"));
        }
        let mut ids = std::collections::HashSet::new();
        for input in &self.sources.module_inputs {
            if input.id.is_empty()
                || input.id.len() > 32
                || !input
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                || !ids.insert(&input.id)
            {
                return Err(invalid("invalid or duplicate module ID"));
            }
            service::absolute_path(Path::new(&input.path))?;
            crate::query::parse(&input.query).map_err(|_| invalid("invalid module filter"))?;
        }
        crate::query::parse(&self.include).map_err(|_| invalid("invalid include filter"))?;
        if !self.exclude.is_empty() {
            crate::query::parse(&self.exclude).map_err(|_| invalid("invalid exclude filter"))?;
        }
        Ok(())
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let result: Self = serde_json::from_slice(&service::read_private(path, 64 * 1024)?)
            .map_err(|_| invalid("invalid configuration"))?;
        result.validate()?;
        Ok(result)
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        self.validate()?;
        service::write_private(
            path,
            &serde_json::to_vec_pretty(self).map_err(io::Error::other)?,
        )
    }

    pub fn for_profile(profile: Profile) -> Self {
        let mut c = Self {
            profile,
            ..Self::default()
        };
        if profile == Profile::Extended {
            c.sources.linux_audit = true;
            c.sources.macos_endpoint_security = true;
        }
        c
    }
}

/// Compiled once per configuration change; no index is constructed per event.
pub struct EventFilter {
    include: crate::query::Expr,
    exclude: Option<crate::query::Expr>,
}
impl EventFilter {
    pub fn new(config: &Config) -> io::Result<Self> {
        config.validate()?;
        Ok(Self {
            include: crate::query::parse(&config.include).map_err(io::Error::other)?,
            exclude: if config.exclude.is_empty() {
                None
            } else {
                Some(crate::query::parse(&config.exclude).map_err(io::Error::other)?)
            },
        })
    }
    pub fn accepts(&self, event: &crate::model::Event) -> bool {
        let mut budget = crate::index::QueryBudget::new(crate::index::ExecutionLimits::default());
        crate::index::matches_event(&self.include, event, &mut budget).unwrap_or(false)
            && !self.exclude.as_ref().is_some_and(|expr| {
                crate::index::matches_event(expr, event, &mut budget).unwrap_or(true)
            })
    }
}
