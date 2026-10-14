//! One-time enrollment capability. Packages contain a short-lived grant, not an agent token.
use crate::{
    config::Config,
    ingest::{AgentRegistry, hex, sha256},
    pki::now,
    service::{self, invalid},
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub version: u16,
    pub server: String,
    pub ca_pem: String,
    pub ca_sha256: String,
    pub enrollment: String,
    pub expires_unix: u64,
    pub name: String,
    pub config: Config,
}
#[derive(Clone, Serialize, Deserialize)]
struct Grant {
    hash: String,
    name: String,
    expires: u64,
    config: Config,
    #[serde(default)]
    agent_id: Option<String>,
}
pub struct Enrollment {
    path: PathBuf,
    grants: Mutex<Vec<Grant>>,
    registry: Arc<AgentRegistry>,
}
#[derive(Serialize, Deserialize)]
pub struct Enrolled {
    pub id: String,
    pub token: String,
    pub config: Config,
}
impl Enrollment {
    pub fn open(path: PathBuf, registry: Arc<AgentRegistry>) -> io::Result<Self> {
        let grants: Vec<Grant> = if path.exists() {
            serde_json::from_slice(&service::read_private(&path, 1024 * 1024)?)
                .map_err(io::Error::other)?
        } else {
            Vec::new()
        };
        if grants.len() > 128 {
            return Err(invalid("enrollment grant storage limit"));
        }
        Ok(Self {
            path,
            grants: Mutex::new(grants),
            registry,
        })
    }
    pub fn issue(
        &self,
        name: &str,
        server: &str,
        ca_pem: String,
        config: Config,
    ) -> io::Result<Package> {
        config.validate()?;
        crate::agent::parse_server(server).map_err(io::Error::other)?;
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(invalid("agent name must be hostname-like, 1–64 characters"));
        }
        let enrollment = service::random_secret()?;
        let expires = now() + 15 * 60;
        let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = grants.clone();
        next.retain(|g| g.expires > now());
        if next.len() >= 128 {
            return Err(invalid("too many pending enrollments"));
        }
        next.push(Grant {
            hash: hex(&sha256(enrollment.as_bytes())),
            name: name.into(),
            expires,
            config: config.clone(),
            agent_id: None,
        });
        self.persist(&next)?;
        *grants = next;
        Ok(Package {
            version: 1,
            server: server.into(),
            ca_sha256: hex(&sha256(ca_pem.as_bytes())),
            ca_pem,
            enrollment,
            expires_unix: expires,
            name: name.into(),
            config,
        })
    }
    pub fn redeem(&self, secret: &str) -> io::Result<Enrolled> {
        if secret.len() != 64 {
            return Err(invalid("invalid enrollment code"));
        }
        let hash = hex(&sha256(secret.as_bytes()));
        let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        let index = grants
            .iter()
            .position(|g| {
                g.expires > now()
                    && crate::ingest::constant_time_equal(hash.as_bytes(), g.hash.as_bytes())
            })
            .ok_or_else(|| invalid("enrollment expired or already used"))?;
        // Consume before issuing identity: no repeated redemption can create two agents.
        let mut next = grants.clone();
        let grant = next.remove(index);
        self.persist(&next)?;
        *grants = next;
        let (record, token) = self.registry.create(&grant.name)?;
        if let Err(error) = self
            .registry
            .configure_agent(&record.id, grant.config.clone())
        {
            let _ = self.registry.revoke(&record.id);
            return Err(error);
        }
        Ok(Enrolled {
            id: record.id,
            token,
            config: grant.config,
        })
    }
    fn persist(&self, grants: &[Grant]) -> io::Result<()> {
        service::write_private(
            &self.path,
            &serde_json::to_vec(grants).map_err(io::Error::other)?,
        )
    }
}

pub fn install_package(
    path: &std::path::Path,
    state_dir: &std::path::Path,
) -> io::Result<Enrolled> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > 128 * 1024 {
        return Err(invalid("invalid enrollment package"));
    }
    let bytes = std::fs::read(path)?;
    let package: Package =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid enrollment package JSON"))?;
    if package.version != 1
        || package.expires_unix <= now()
        || package.ca_pem.len() > 64 * 1024
        || hex(&sha256(package.ca_pem.as_bytes())) != package.ca_sha256
    {
        return Err(invalid(
            "enrollment package expired or trust fingerprint mismatch",
        ));
    }
    package.config.validate()?;
    crate::agent::validate_token(&package.enrollment)?;
    if package.enrollment.len() != 64 || package.name.is_empty() || package.name.len() > 64 {
        return Err(invalid("invalid enrollment capability or agent name"));
    }
    // A failed or duplicate redemption must never replace an existing agent's trust.
    for name in [
        "agent.token",
        "service.json",
        "config.json",
        "progress.json",
        "spool",
    ] {
        if std::fs::symlink_metadata(state_dir.join(name)).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "agent state already exists; use a new state directory",
            ));
        }
    }
    service::private_directory(state_dir)?;
    let ca = state_dir.join("ca.pem");
    service::write_private(&ca, package.ca_pem.as_bytes())?;
    let mut endpoint = crate::agent::parse_server(&package.server).map_err(io::Error::other)?;
    endpoint.ca_file = Some(ca);
    let body = serde_json::json!({"enrollment":package.enrollment}).to_string();
    let response = crate::agent::http_post(&endpoint, "/ingest/v1/enroll", "", &body)?;
    if response.status != 200 {
        return Err(io::Error::other(format!(
            "enrollment rejected: HTTP {}",
            response.status
        )));
    }
    let enrolled: Enrolled = serde_json::from_str(&response.body).map_err(io::Error::other)?;
    crate::agent::validate_token(&enrolled.token)?;
    service::write_private(&state_dir.join("agent.token"), enrolled.token.as_bytes())?;
    enrolled.config.save(&state_dir.join("config.json"))?;
    let config = serde_json::json!({"data_dir":state_dir,"environment":{"REDTRACE_AGENT_SERVER":package.server,"REDTRACE_AGENT_NAME":package.name,"REDTRACE_AGENT_TOKEN_FILE":state_dir.join("agent.token"),"REDTRACE_AGENT_CA":state_dir.join("ca.pem")}});
    service::write_private(
        &state_dir.join("service.json"),
        &serde_json::to_vec_pretty(&config).map_err(io::Error::other)?,
    )?;
    Ok(enrolled)
}
