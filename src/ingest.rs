use crate::model::Event;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{DefaultBodyLimit, Extension, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write as IoWrite},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{RwLock, mpsc};
use tokio::time::timeout;

pub const INGEST_TOKEN_HEADER: &str = "x-redtrace-ingest-token";
pub const MAX_EVENTS_PER_BATCH: usize = 1000;
pub const MAX_INGEST_BODY_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_EVENT_FIELD_BYTES: usize = 64 * 1024;
pub const MAX_FIELDS_PER_EVENT: usize = 64;
pub const DEFAULT_TOKEN_TTL_SECONDS: u64 = 90 * 24 * 60 * 60;
pub const MAX_TOKEN_TTL_SECONDS: u64 = 365 * 24 * 60 * 60;
pub const DEFAULT_TOKEN_OVERLAP_SECONDS: u64 = 300;
pub const MAX_TOKEN_OVERLAP_SECONDS: u64 = 24 * 60 * 60;
pub const MAX_REGISTERED_AGENTS: usize = 4096;
const MAX_REGISTRY_BYTES: u64 = 4 * 1024 * 1024;

#[path = "ingest_budget.rs"]
mod budget;
#[path = "ingest_receipts.rs"]
mod receipts;
pub use budget::{BudgetUsage, IngestBudgetHealth, IngestLimits};

const AGENTS_VERSION: u16 = 2;
const REGISTRY_PERSIST_INTERVAL: Duration = Duration::from_secs(30);

pub fn constant_time_equal(expected: &[u8], supplied: &[u8]) -> bool {
    let mut difference = expected.len() ^ supplied.len();
    let length = expected.len().max(supplied.len());
    for index in 0..length {
        difference |= usize::from(
            expected.get(index).copied().unwrap_or_default()
                ^ supplied.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = [
        0x6a09e667_u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = u64::try_from(data.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    for block in message.chunks_exact(64) {
        let mut w = [0_u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let mut h = state;
        for index in 0..64 {
            let s1 = h[4].rotate_right(6) ^ h[4].rotate_right(11) ^ h[4].rotate_right(25);
            let choose = (h[4] & h[5]) ^ ((!h[4]) & h[6]);
            let temp1 = h[7]
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(SHA256_K[index])
                .wrapping_add(w[index]);
            let s0 = h[0].rotate_right(2) ^ h[0].rotate_right(13) ^ h[0].rotate_right(22);
            let majority = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
            let temp2 = s0.wrapping_add(majority);
            h = [
                temp1.wrapping_add(temp2),
                h[0],
                h[1],
                h[2],
                h[3].wrapping_add(temp1),
                h[4],
                h[5],
                h[6],
            ];
        }
        for (index, value) in h.into_iter().enumerate() {
            state[index] = state[index].wrapping_add(value);
        }
    }
    let mut digest = [0_u8; 32];
    for (index, value) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    digest
}

pub fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRecord {
    pub id: String,
    pub name: String,
    pub token_hash: String,
    pub platform: Option<String>,
    pub created_unix: u64,
    pub last_seen_unix: u64,
    pub events_received: u64,
    pub revoked: bool,
    #[serde(default)]
    pub token_expires_unix: Option<u64>,
    #[serde(default)]
    pub token_generation: u64,
    #[serde(default)]
    pub previous_token: Option<PreviousAgentToken>,
    #[serde(default)]
    pub telemetry: Option<crate::fleet::Report>,
    #[serde(default)]
    pub last_event_received_unix: u64,
    #[serde(default)]
    pub last_event_at: Option<String>,
    #[serde(default)]
    pub desired_config: Option<crate::config::Config>,
    #[serde(default)]
    pub config_generation: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreviousAgentToken {
    pub token_hash: String,
    pub valid_until_unix: u64,
}

impl std::fmt::Debug for AgentRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentRecord")
            .field("id", &self.id)
            .field("revoked", &self.revoked)
            .field("token_expires_unix", &self.token_expires_unix)
            .field("token_generation", &self.token_generation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct RegistryFile {
    version: u16,
    agents: Vec<AgentRecord>,
}

impl Default for RegistryFile {
    fn default() -> Self {
        Self {
            version: AGENTS_VERSION,
            agents: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct AgentRegistry {
    pub maintenance: Arc<RwLock<()>>,
    path: PathBuf,
    state: Mutex<RegistryFile>,
    last_persist: Mutex<Instant>,
    budget: Arc<budget::IngestBudget>,
    receipts: Mutex<receipts::ReceiptStore>,
    rotation_key: Mutex<Option<RotationKey>>,
}

struct RotationKey(ring::hmac::Key);
impl std::fmt::Debug for RotationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RotationKey([redacted])")
    }
}

impl AgentRegistry {
    pub fn open_default() -> std::io::Result<Self> {
        Self::open(crate::storage::data_directory().join("agents.json"))
    }

    pub fn open(path: PathBuf) -> std::io::Result<Self> {
        let limits = IngestLimits::from_env()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        Self::open_with_limits(path, limits)
    }

    pub fn open_with_limits(path: PathBuf, limits: IngestLimits) -> std::io::Result<Self> {
        limits
            .validate()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut migrated = false;
        let state = if path.exists() {
            let file = private_registry_open(&path)?;
            if file.metadata()?.len() > MAX_REGISTRY_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "agent registry exceeds size limit",
                ));
            }
            let mut parsed: RegistryFile =
                serde_json::from_reader(file.take(MAX_REGISTRY_BYTES + 1)).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid agent registry")
                })?;
            if !matches!(parsed.version, 1 | AGENTS_VERSION) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unsupported agent registry version {}", parsed.version),
                ));
            }
            validate_registry(&parsed)?;
            if parsed.version == 1 {
                let expiry = now_unix().saturating_add(DEFAULT_TOKEN_TTL_SECONDS);
                for agent in &mut parsed.agents {
                    agent.token_expires_unix = Some(agent.token_expires_unix.unwrap_or(expiry));
                    agent.token_generation = agent.token_generation.max(1);
                }
                migrated = true;
            }
            parsed.version = AGENTS_VERSION;
            parsed
        } else {
            RegistryFile::default()
        };
        let registry = Self {
            maintenance: Arc::new(RwLock::new(())),
            rotation_key: Mutex::new(None),
            receipts: Mutex::new(receipts::ReceiptStore::open(
                path.with_extension("receipts"),
            )?),
            path,
            state: Mutex::new(state),
            last_persist: Mutex::new(Instant::now()),
            budget: Arc::new(budget::IngestBudget::new(limits)),
        };
        if migrated || !registry.path.exists() {
            let state = registry
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            registry.persist(&state)?;
        }
        Ok(registry)
    }

    pub fn create(&self, name: &str) -> std::io::Result<(AgentRecord, String)> {
        self.create_with_ttl(name, DEFAULT_TOKEN_TTL_SECONDS)
    }

    pub fn create_with_ttl(
        &self,
        name: &str,
        ttl_seconds: u64,
    ) -> std::io::Result<(AgentRecord, String)> {
        validate_token_policy(ttl_seconds, 0)?;
        let name = name.trim();
        if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "agent name must be 1-64 UTF-8 bytes without control characters",
            ));
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.agents.len() >= MAX_REGISTERED_AGENTS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "agent registry is full",
            ));
        }
        loop {
            let id = hex(&random_bytes(8)?);
            if state.agents.iter().all(|agent| agent.id != id) {
                let token = hex(&random_bytes(32)?);
                let record = AgentRecord {
                    id,
                    name: name.into(),
                    token_hash: hex(&sha256(token.as_bytes())),
                    platform: None,
                    created_unix: now_unix(),
                    last_seen_unix: 0,
                    events_received: 0,
                    revoked: false,
                    token_expires_unix: Some(now_unix().saturating_add(ttl_seconds)),
                    token_generation: 1,
                    previous_token: None,
                    telemetry: None,
                    last_event_received_unix: 0,
                    last_event_at: None,
                    desired_config: None,
                    config_generation: 0,
                };
                let mut candidate = state.clone();
                candidate.agents.push(record.clone());
                self.persist(&candidate)?;
                *state = candidate;
                return Ok((record, token));
            }
        }
    }

    pub fn verify(&self, token: &str) -> Option<AgentRecord> {
        self.verify_at(token, now_unix())
    }

    fn verify_at(&self, token: &str, now: u64) -> Option<AgentRecord> {
        if !valid_token_hex(token) {
            return None;
        }
        let digest = hex(&sha256(token.as_bytes()));
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state
            .agents
            .iter()
            .filter(|agent| !agent.revoked)
            .find(|agent| {
                let current = constant_time_equal(digest.as_bytes(), agent.token_hash.as_bytes())
                    & agent.token_expires_unix.is_none_or(|expires| now < expires);
                let previous = agent.previous_token.as_ref().is_some_and(|previous| {
                    constant_time_equal(digest.as_bytes(), previous.token_hash.as_bytes())
                        & (now < previous.valid_until_unix)
                });
                current | previous
            })
            .cloned()
    }

    pub fn rotate(
        &self,
        id: &str,
        ttl_seconds: u64,
        overlap_seconds: u64,
    ) -> std::io::Result<Option<IssuedAgentCredential>> {
        validate_token_policy(ttl_seconds, overlap_seconds)?;
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let mut candidate = state.clone();
        let Some(agent) = candidate
            .agents
            .iter_mut()
            .find(|agent| agent.id == id && !agent.revoked)
        else {
            return Ok(None);
        };
        let now = now_unix();
        let previous_valid_until_unix = now
            .saturating_add(overlap_seconds)
            .min(agent.token_expires_unix.unwrap_or(u64::MAX));
        agent.previous_token = (previous_valid_until_unix > now).then(|| PreviousAgentToken {
            token_hash: agent.token_hash.clone(),
            valid_until_unix: previous_valid_until_unix,
        });
        let token = hex(&random_bytes(32)?);
        agent.token_hash = hex(&sha256(token.as_bytes()));
        agent.token_generation = agent.token_generation.saturating_add(1);
        agent.token_expires_unix = Some(now.saturating_add(ttl_seconds));
        let issued = IssuedAgentCredential {
            id: agent.id.clone(),
            token,
            token_generation: agent.token_generation,
            issued_unix: now,
            token_expires_unix: agent.token_expires_unix.unwrap(),
            previous_valid_until_unix: agent
                .previous_token
                .as_ref()
                .map(|token| token.valid_until_unix),
        };
        self.persist(&candidate)?;
        *state = candidate;
        Ok(Some(issued))
    }

    fn automatic_token(&self, id: &str, generation: u64, expires: u64) -> std::io::Result<String> {
        let mut cached = self.rotation_key.lock().unwrap_or_else(|e| e.into_inner());
        if cached.is_none() {
            let path = self.path.with_extension("rotation-key");
            if !path.exists() {
                match private_registry_create(&path) {
                    Ok(mut file) => {
                        file.write_all(&random_bytes(32)?)?;
                        file.sync_all()?;
                        #[cfg(unix)]
                        File::open(self.data_dir())?.sync_all()?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
            }
            let mut bytes = Vec::new();
            private_registry_open(&path)?
                .take(33)
                .read_to_end(&mut bytes)?;
            if bytes.len() != 32 {
                return Err(std::io::Error::other("invalid automatic rotation key"));
            }
            *cached = Some(RotationKey(ring::hmac::Key::new(
                ring::hmac::HMAC_SHA256,
                &bytes,
            )));
        }
        let message = format!("REDTRACE automatic credential v1:{id}:{generation}:{expires}");
        Ok(hex(ring::hmac::sign(
            &cached
                .as_ref()
                .ok_or_else(|| std::io::Error::other("rotation key unavailable"))?
                .0,
            message.as_bytes(),
        )
        .as_ref()))
    }

    pub fn automatic_credential(
        &self,
        id: &str,
        supplied: &str,
    ) -> std::io::Result<Option<IssuedAgentCredential>> {
        let digest = hex(&sha256(supplied.as_bytes()));
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut candidate = state.clone();
        let Some(agent) = candidate
            .agents
            .iter_mut()
            .find(|a| a.id == id && !a.revoked)
        else {
            return Ok(None);
        };
        let now = now_unix();
        let Some(mut expires) = agent.token_expires_unix.filter(|e| *e > now) else {
            return Ok(None);
        };
        let current = constant_time_equal(digest.as_bytes(), agent.token_hash.as_bytes());
        let replay = agent.previous_token.as_ref().is_some_and(|p| {
            p.valid_until_unix > now
                && constant_time_equal(digest.as_bytes(), p.token_hash.as_bytes())
        });
        if !current && !replay || current && expires >= now.saturating_add(7 * 86400) {
            return Ok(None);
        }
        if current {
            agent.previous_token = Some(PreviousAgentToken {
                token_hash: agent.token_hash.clone(),
                valid_until_unix: expires.min(now.saturating_add(DEFAULT_TOKEN_OVERLAP_SECONDS)),
            });
            agent.token_generation = agent
                .token_generation
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("token generation exhausted"))?;
            expires = now.saturating_add(DEFAULT_TOKEN_TTL_SECONDS);
            agent.token_expires_unix = Some(expires);
        }
        let token = self.automatic_token(id, agent.token_generation, expires)?;
        if replay
            && !constant_time_equal(
                hex(&sha256(token.as_bytes())).as_bytes(),
                agent.token_hash.as_bytes(),
            )
        {
            return Ok(None);
        }
        agent.token_hash = hex(&sha256(token.as_bytes()));
        let issued = IssuedAgentCredential {
            id: id.into(),
            token,
            token_generation: agent.token_generation,
            issued_unix: expires.saturating_sub(DEFAULT_TOKEN_TTL_SECONDS),
            token_expires_unix: expires,
            previous_valid_until_unix: agent.previous_token.as_ref().map(|p| p.valid_until_unix),
        };
        if current {
            self.persist(&candidate)?;
            *state = candidate;
        }
        Ok(Some(issued))
    }

    pub fn budget_health(&self) -> IngestBudgetHealth {
        self.budget.snapshot()
    }

    pub fn confirm_durable(&self, events: &[Event]) -> std::io::Result<()> {
        let uids: Vec<_> = events
            .iter()
            .filter(|event| event.fields.contains_key("agent.id"))
            .map(|event| event.uid.clone())
            .collect();
        self.receipts
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .confirm(uids.iter().cloned())?;
        self.budget.reap(&uids.into_iter().collect());
        Ok(())
    }

    pub fn storage_rejected(&self, events: &[Event]) {
        self.budget
            .reap(&events.iter().map(|event| event.uid.clone()).collect());
    }

    fn has_receipt(&self, uid: &str) -> bool {
        self.receipts
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .contains(uid)
    }

    pub fn budget_health_with_known(&self, known_uids: &HashSet<String>) -> IngestBudgetHealth {
        self.budget.reap(known_uids);
        self.budget_health()
    }

    pub fn revoke(&self, id: &str) -> std::io::Result<bool> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let mut candidate = state.clone();
        match candidate.agents.iter_mut().find(|agent| agent.id == id) {
            Some(agent) if !agent.revoked => {
                agent.revoked = true;
                agent.previous_token = None;
                self.persist(&candidate)?;
                *state = candidate;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub fn list(&self) -> Vec<AgentRecord> {
        let mut agents = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .agents
            .clone();
        agents.sort_by_key(|agent| agent.created_unix);
        agents
    }

    pub fn touch(
        &self,
        id: &str,
        events_delta: u64,
        platform: Option<&str>,
    ) -> Option<AgentRecord> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let agent = state
            .agents
            .iter_mut()
            .find(|agent| agent.id == id && !agent.revoked)?;
        agent.last_seen_unix = now_unix();
        agent.events_received = agent.events_received.saturating_add(events_delta);
        if events_delta > 0 {
            agent.last_event_received_unix = now_unix();
        }
        if let Some(platform) = platform.filter(|platform| valid_os(platform)) {
            agent.platform = Some(platform.into());
        }
        let updated = agent.clone();
        let should_persist = {
            let mut last = self
                .last_persist
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if last.elapsed() >= REGISTRY_PERSIST_INTERVAL {
                *last = Instant::now();
                true
            } else {
                false
            }
        };
        if should_persist && self.persist(&state).is_err() {
            self.budget.log("registry_persist_failed");
        }
        Some(updated)
    }

    pub fn update_health(&self, id: &str, report: crate::fleet::Report) -> std::io::Result<()> {
        report.validate().map_err(std::io::Error::other)?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(agent) = state.agents.iter_mut().find(|a| a.id == id && !a.revoked) {
            agent.telemetry = Some(report);
        }
        Ok(())
    }
    pub fn update_event_time(&self, id: &str, timestamp: Option<String>) {
        if let Some(agent) = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .agents
            .iter_mut()
            .find(|a| a.id == id)
        {
            agent.last_event_at = timestamp;
        }
    }
    pub fn configure_agent(
        &self,
        id: &str,
        config: crate::config::Config,
    ) -> std::io::Result<bool> {
        config.validate()?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = state.clone();
        let Some(agent) = next.agents.iter_mut().find(|a| a.id == id && !a.revoked) else {
            return Ok(false);
        };
        agent.config_generation = agent.config_generation.saturating_add(1);
        agent.desired_config = Some(config);
        self.persist(&next)?;
        *state = next;
        Ok(true)
    }
    pub fn data_dir(&self) -> PathBuf {
        self.path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf()
    }

    fn persist(&self, state: &RegistryFile) -> std::io::Result<()> {
        let parent = self
            .path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let temp = parent.join(format!(".agents-{}.tmp", hex(&random_bytes(16)?)));
        let result = (|| {
            let mut file = private_registry_create(&temp)?;
            serde_json::to_writer_pretty(&mut file, state).map_err(std::io::Error::other)?;
            file.write_all(b"\n")?;
            file.flush()?;
            file.sync_all()?;
            if file.metadata()?.len() > MAX_REGISTRY_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "agent registry exceeds size limit",
                ));
            }
            drop(file);
            reject_registry_link(&self.path)?;
            private_registry_replace(&temp, &self.path)?;
            #[cfg(unix)]
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

fn valid_token_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_token_policy(ttl_seconds: u64, overlap_seconds: u64) -> std::io::Result<()> {
    if ttl_seconds == 0
        || ttl_seconds > MAX_TOKEN_TTL_SECONDS
        || overlap_seconds > MAX_TOKEN_OVERLAP_SECONDS
        || overlap_seconds > ttl_seconds
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid credential TTL or overlap",
        ));
    }
    Ok(())
}

fn validate_registry(state: &RegistryFile) -> std::io::Result<()> {
    let mut ids = HashSet::new();
    if state.agents.len() > MAX_REGISTERED_AGENTS
        || state.agents.iter().any(|agent| {
            agent.id.len() != 16
                || !agent.id.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !ids.insert(&agent.id)
                || agent.name.is_empty()
                || agent.name.len() > 64
                || agent.name.chars().any(char::is_control)
                || !valid_token_hex(&agent.token_hash)
                || (state.version == AGENTS_VERSION
                    && (agent.token_expires_unix.is_none() || agent.token_generation == 0))
                || agent
                    .platform
                    .as_deref()
                    .is_some_and(|platform| !valid_os(platform))
                || agent
                    .previous_token
                    .as_ref()
                    .is_some_and(|token| !valid_token_hex(&token.token_hash))
        })
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid agent registry records",
        ));
    }
    Ok(())
}

fn random_bytes(count: usize) -> std::io::Result<Vec<u8>> {
    let mut buffer = vec![0_u8; count];
    getrandom::fill(&mut buffer).map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(buffer)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn reject_registry_link(path: &std::path::Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(windows)]
            let redirected = {
                use std::os::windows::fs::MetadataExt;
                metadata.file_attributes() & 0x400 != 0
            };
            #[cfg(not(windows))]
            let redirected = metadata.file_type().is_symlink();
            if !metadata.is_file() || redirected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "agent registry must be a regular file",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "linked agent registry rejected",
                    ));
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn private_registry_open(path: &std::path::Path) -> std::io::Result<File> {
    reject_registry_link(path)?;
    #[cfg(windows)]
    {
        registry_windows::open(path)
    }
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(0x20000);
        }
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(0x100);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "agent registry must be a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if file.metadata()?.nlink() != 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "linked agent registry rejected",
                ));
            }
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        Ok(file)
    }
}

fn private_registry_replace(
    source: &std::path::Path,
    target: &std::path::Path,
) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let source: Vec<_> = source.as_os_str().encode_wide().chain([0]).collect();
        let target: Vec<_> = target.as_os_str().encode_wide().chain([0]).collect();
        if unsafe {
            MoveFileExW(
                source.as_ptr(),
                target.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    fs::rename(source, target)
}

fn private_registry_create(path: &std::path::Path) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        registry_windows::create(path)
    }
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)
    }
}

#[cfg(windows)]
mod registry_windows {
    use super::*;
    use std::{
        os::windows::{
            ffi::OsStrExt,
            fs::OpenOptionsExt,
            io::{AsRawHandle, FromRawHandle},
        },
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE, LocalFree},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SE_FILE_OBJECT, SetSecurityInfo,
            },
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
            PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
            TokenUser,
        },
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    struct Descriptor(*mut std::ffi::c_void);

    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    fn descriptor() -> std::io::Result<Descriptor> {
        let mut token = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut length = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut length);
        }
        let mut buffer = vec![0_usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
        let success = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        };
        let error = std::io::Error::last_os_error();
        unsafe {
            CloseHandle(token);
        }
        if success == 0 {
            return Err(error);
        }
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut text = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut size = 0;
        unsafe {
            while *text.add(size) != 0 {
                size += 1;
            }
        }
        let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, size) });
        unsafe {
            LocalFree(text.cast());
        }
        let sddl: Vec<_> = format!("D:P(A;;FA;;;SY)(A;;FA;;;{sid})")
            .encode_utf16()
            .chain([0])
            .collect();
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Descriptor(descriptor))
    }

    pub(super) fn create(path: &std::path::Path) -> std::io::Result<File> {
        let descriptor = descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let path: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                0x40000000,
                0,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    pub(super) fn open(path: &std::path::Path) -> std::io::Result<File> {
        let file = OpenOptions::new()
            .access_mode(0x80000000 | 0x00040000)
            .share_mode(1)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        use std::os::windows::fs::MetadataExt;
        if file.metadata()?.file_attributes() & 0x400 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "redirected agent registry rejected",
            ));
        }
        let descriptor = descriptor()?;
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = ptr::null_mut();
        if unsafe {
            GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted)
        } == 0
            || present == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let result = unsafe {
            SetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result as i32));
        }
        Ok(file)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentPublic {
    pub id: String,
    pub name: String,
    pub platform: Option<String>,
    pub created_unix: u64,
    pub last_seen_unix: u64,
    pub events_received: u64,
    pub revoked: bool,
    pub token_expires_unix: Option<u64>,
    pub token_generation: u64,
    pub previous_valid_until_unix: Option<u64>,
    pub credential_state: String,
    pub state: String,
    pub last_event_at: Option<String>,
    pub delivery_lag_seconds: Option<i64>,
    pub telemetry: Option<crate::fleet::Report>,
    pub config_generation: u64,
}

impl From<&AgentRecord> for AgentPublic {
    fn from(record: &AgentRecord) -> Self {
        Self {
            state: crate::fleet::liveness(
                record.last_seen_unix,
                record.last_event_received_unix,
                record.telemetry.as_ref(),
                record.revoked,
                record.token_expires_unix,
                now_unix(),
            )
            .into(),
            last_event_at: record.last_event_at.clone(),
            delivery_lag_seconds: record
                .last_event_at
                .as_ref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|t| record.last_event_received_unix as i64 - t.timestamp()),
            telemetry: record.telemetry.clone(),
            config_generation: record.config_generation,
            id: record.id.clone(),
            name: record.name.clone(),
            platform: record.platform.clone(),
            created_unix: record.created_unix,
            last_seen_unix: record.last_seen_unix,
            events_received: record.events_received,
            revoked: record.revoked,
            token_expires_unix: record.token_expires_unix,
            token_generation: record.token_generation,
            previous_valid_until_unix: record
                .previous_token
                .as_ref()
                .map(|token| token.valid_until_unix),
            credential_state: if record.revoked {
                "revoked"
            } else if record
                .token_expires_unix
                .is_some_and(|expires| now_unix() >= expires)
            {
                "expired"
            } else if record.token_expires_unix.is_none() {
                "legacy"
            } else {
                "active"
            }
            .into(),
        }
    }
}

#[derive(Serialize)]
pub struct CreatedAgent {
    pub id: String,
    pub name: String,
    pub token: String,
    pub created_unix: u64,
}

#[derive(Serialize)]
pub struct IssuedAgentCredential {
    pub id: String,
    pub token: String,
    pub token_generation: u64,
    pub issued_unix: u64,
    pub token_expires_unix: u64,
    pub previous_valid_until_unix: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateAgentParams {
    #[serde(default = "default_token_ttl")]
    pub ttl_seconds: u64,
    #[serde(default = "default_token_overlap")]
    pub overlap_seconds: u64,
}

fn default_token_ttl() -> u64 {
    DEFAULT_TOKEN_TTL_SECONDS
}

fn default_token_overlap() -> u64 {
    DEFAULT_TOKEN_OVERLAP_SECONDS
}

#[derive(Default, Serialize, Clone)]
pub struct IngestStats {
    pub remote_events_total: u64,
    pub duplicate_events_total: u64,
    pub rejected_batches: u64,
    pub heartbeats_total: u64,
    pub last_remote_event_at: Option<String>,
}

#[derive(Clone)]
pub struct IngestState {
    pub registry: Arc<AgentRegistry>,
    pub events: mpsc::Sender<Event>,
    pub known_uids: Arc<RwLock<HashSet<String>>>,
    pub stats: Arc<RwLock<IngestStats>>,
}

impl IngestState {
    pub async fn budget_health(&self) -> IngestBudgetHealth {
        self.registry
            .budget_health_with_known(&*self.known_uids.read().await)
    }
}

#[derive(Clone, Debug)]
pub struct AuthenticatedAgent {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct IngestHost {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default, alias = "architecture")]
    pub arch: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IngestEvent {
    pub timestamp: String,
    pub source: String,
    pub level: String,
    pub message: String,
    #[serde(default, deserialize_with = "deserialize_fields")]
    pub fields: BTreeMap<String, String>,
}

impl From<&Event> for IngestEvent {
    fn from(event: &Event) -> Self {
        Self {
            timestamp: event.timestamp.clone(),
            source: event.source.clone(),
            level: event.level.clone(),
            message: event.message.clone(),
            fields: event.fields.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct IngestRequest {
    #[serde(default)]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub host: Option<IngestHost>,
    #[serde(default, deserialize_with = "deserialize_events")]
    pub events: Vec<IngestEvent>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRequest {
    #[serde(default)]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub host: Option<IngestHost>,
    #[serde(default)]
    pub sent_total: u64,
    #[serde(default)]
    pub dropped_total: u64,
    #[serde(default)]
    pub telemetry: Option<crate::fleet::Report>,
}

pub fn normalize_event(
    agent: &AuthenticatedAgent,
    host: Option<&IngestHost>,
    raw: IngestEvent,
) -> Result<Event, String> {
    normalize_event_with_limit(agent, host, raw, IngestLimits::default().max_event_bytes)
}

fn normalize_event_with_limit(
    agent: &AuthenticatedAgent,
    host: Option<&IngestHost>,
    raw: IngestEvent,
    max_bytes: usize,
) -> Result<Event, String> {
    validate_metadata(host, None)?;
    if raw.timestamp.len() > 64 || chrono::DateTime::parse_from_rfc3339(&raw.timestamp).is_err() {
        return Err("invalid timestamp".into());
    }
    if !valid_identifier(&raw.source, 128) {
        return Err("invalid source".into());
    }
    let source = raw.source.to_ascii_lowercase();
    if raw.message.len() > MAX_EVENT_FIELD_BYTES {
        return Err("message exceeds 64 KiB".into());
    }
    if raw.message.trim().is_empty() {
        return Err("empty message".into());
    }
    if raw.level.len() > 64 {
        return Err("invalid level".into());
    }
    let mut level = raw.level.trim().to_ascii_lowercase();
    if level.is_empty() {
        level = "low".into();
    }
    if level.len() > 16
        || !level
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("invalid level".into());
    }
    if raw.fields.len() > MAX_FIELDS_PER_EVENT {
        return Err(format!("more than {MAX_FIELDS_PER_EVENT} fields"));
    }
    let mut fields = BTreeMap::new();
    let identity = raw.fields.get("event.record_id").cloned();
    for (key, value) in raw.fields {
        if !valid_identifier(&key, 128) || value.len() > MAX_EVENT_FIELD_BYTES {
            return Err("invalid or oversized event field".into());
        }
        if key == "collector.cursor"
            || key.starts_with("host.")
            || key.starts_with("agent.")
            || key.starts_with("observer.")
        {
            continue;
        }
        fields.insert(key, value);
    }
    fields.insert("agent.id".into(), agent.id.clone());
    fields.insert("agent.name".into(), agent.name.clone());
    if let Some(host) = host {
        for (key, value) in [
            ("host.name", &host.name),
            ("host.os", &host.os),
            ("host.architecture", &host.arch),
        ] {
            if let Some(value) = value {
                fields.insert(key.into(), value.clone());
            }
        }
    }
    if fields.len() > MAX_FIELDS_PER_EVENT {
        return Err("normalized event exceeds field count limit".into());
    }
    let mut event = Event::remote(&agent.id, raw.timestamp, source, level, raw.message, fields);
    if let Some(identity) = identity {
        event.identify(&format!("{}:{identity}", agent.id));
    }
    normalized_event_bytes(&event, max_bytes)?;
    Ok(event)
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_os(value: &str) -> bool {
    matches!(
        value,
        "linux"
            | "windows"
            | "macos"
            | "freebsd"
            | "openbsd"
            | "netbsd"
            | "dragonfly"
            | "android"
            | "ios"
            | "illumos"
            | "solaris"
            | "aix"
            | "haiku"
    )
}

pub fn validate_metadata(
    host: Option<&IngestHost>,
    agent_version: Option<&str>,
) -> Result<(), String> {
    if agent_version.is_some_and(|version| {
        version.is_empty()
            || version.len() > 64
            || !version.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
            })
    }) {
        return Err("invalid agent_version".into());
    }
    if let Some(host) = host {
        if host
            .name
            .as_deref()
            .is_some_and(|name| !valid_identifier(name, 128))
        {
            return Err("invalid host.name".into());
        }
        if host
            .os
            .as_deref()
            .is_some_and(|os| os.len() > 16 || !valid_os(os))
        {
            return Err("invalid host.os".into());
        }
        if host.arch.as_deref().is_some_and(|arch| {
            arch.len() > 16
                || !matches!(
                    arch,
                    "x86"
                        | "x86_64"
                        | "arm"
                        | "aarch64"
                        | "riscv32"
                        | "riscv64"
                        | "mips"
                        | "mips64"
                        | "powerpc"
                        | "powerpc64"
                        | "s390x"
                        | "sparc"
                        | "sparc64"
                        | "wasm32"
                        | "wasm64"
                        | "loongarch64"
                )
        }) {
            return Err("invalid host.arch".into());
        }
    }
    Ok(())
}

pub fn normalized_event_bytes(event: &Event, max_bytes: usize) -> Result<usize, String> {
    struct Counter {
        bytes: usize,
        limit: usize,
    }
    impl IoWrite for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes) {
                return Err(std::io::Error::other("normalized event exceeds byte limit"));
            }
            self.bytes += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter {
        bytes: 0,
        limit: max_bytes,
    };
    serde_json::to_writer(&mut counter, event)
        .map_err(|_| "normalized event exceeds byte limit".to_string())?;
    Ok(counter.bytes)
}

fn deserialize_fields<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Fields;
    impl<'de> serde::de::Visitor<'de> for Fields {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bounded event fields")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> Result<Self::Value, M::Error> {
            let mut fields = BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                if fields.len() >= MAX_FIELDS_PER_EVENT
                    || !valid_identifier(&key, 128)
                    || fields.contains_key(&key)
                {
                    return Err(serde::de::Error::custom("invalid event fields"));
                }
                let value = map.next_value::<String>()?;
                if value.len() > MAX_EVENT_FIELD_BYTES {
                    return Err(serde::de::Error::custom("oversized event field"));
                }
                fields.insert(key, value);
            }
            Ok(fields)
        }
    }
    deserializer.deserialize_map(Fields)
}

fn deserialize_events<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<IngestEvent>, D::Error> {
    struct Events;
    impl<'de> serde::de::Visitor<'de> for Events {
        type Value = Vec<IngestEvent>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bounded event batch")
        }
        fn visit_seq<S: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: S,
        ) -> Result<Self::Value, S::Error> {
            let mut events = Vec::new();
            while events.len() < MAX_EVENTS_PER_BATCH {
                match sequence.next_element()? {
                    Some(event) => events.push(event),
                    None => return Ok(events),
                }
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("too many events"));
            }
            Ok(events)
        }
    }
    deserializer.deserialize_seq(Events)
}

pub fn ingest_router(state: IngestState) -> Router {
    let protected = Router::new()
        .route("/ingest/v1/events", post(ingest_events))
        .route("/ingest/v1/heartbeat", post(ingest_heartbeat))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            authorize_ingest,
        ));
    protected
        .merge(Router::new().route("/ingest/v1/health", get(ingest_health)))
        .layer(DefaultBodyLimit::max(
            state.registry.budget.limits.max_body_bytes,
        ))
        .with_state(state)
}

async fn authorize_ingest(
    State(state): State<IngestState>,
    mut request: Request,
    next: Next,
) -> Response {
    let supplied = request
        .headers()
        .get(INGEST_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_token_hex(value))
        .unwrap_or_default()
        .to_owned();
    let Some(record) = state.registry.verify(&supplied).filter(|_| {
        request
            .headers()
            .get_all(INGEST_TOKEN_HEADER)
            .iter()
            .count()
            == 1
    }) else {
        state.registry.budget.log("unauthorized");
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid agent token" })),
        )
            .into_response();
    };
    let Ok(_permit) = state.registry.budget.acquire(&record.id).await else {
        return throttle_response(&state, "ingest request budget exhausted").await;
    };
    let deadline = Duration::from_millis(state.registry.budget.limits.request_timeout_ms);
    match timeout(deadline, async {
        if state.registry.verify(&supplied).is_none() {
            return unauthorized_response(&state);
        }
        if request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|length| length.to_str().ok())
            .and_then(|length| length.parse::<u64>().ok())
            .is_some_and(|length| length > state.registry.budget.limits.max_body_bytes as u64)
        {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({"error": "oversized ingest body"})),
            )
                .into_response();
        }
        let (mut parts, body) = request.into_parts();
        let bytes = match to_bytes(body, state.registry.budget.limits.max_body_bytes).await {
            Ok(bytes) => bytes,
            Err(_) => {
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(serde_json::json!({"error": "invalid or oversized ingest body"})),
                )
                    .into_response();
            }
        };
        if state.registry.verify(&supplied).is_none() {
            return unauthorized_response(&state);
        }
        state.registry.budget.reap(&*state.known_uids.read().await);
        parts.extensions.insert(AuthenticatedAgent {
            id: record.id,
            name: record.name,
        });
        request = Request::from_parts(parts, Body::from(bytes));
        next.run(request).await
    })
    .await
    {
        Ok(response) => response,
        Err(_) => {
            state.registry.budget.log("request_timeout");
            throttle_response(&state, "ingest request deadline exceeded; retry batch").await
        }
    }
}

fn unauthorized_response(state: &IngestState) -> Response {
    state.registry.budget.log("unauthorized");
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "invalid agent token"})),
    )
        .into_response()
}

async fn throttle_response(state: &IngestState, error: &'static str) -> Response {
    state.registry.budget.log("throttled");
    let mut stats = state.stats.write().await;
    stats.rejected_batches = stats.rejected_batches.saturating_add(1);
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(
            header::RETRY_AFTER,
            state.registry.budget.limits.retry_after_seconds.to_string(),
        )],
        Json(serde_json::json!({"error": error})),
    )
        .into_response()
}

async fn ingest_events(
    State(state): State<IngestState>,
    Extension(agent): Extension<AuthenticatedAgent>,
    payload: Result<Json<IngestRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(request)) = payload else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid ingest JSON"})),
        )
            .into_response();
    };
    if let Err(error) = validate_metadata(request.host.as_ref(), request.agent_version.as_deref()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error})),
        )
            .into_response();
    }
    if request.events.len() > MAX_EVENTS_PER_BATCH {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "error": "too many events in one batch",
                "max_events": MAX_EVENTS_PER_BATCH
            })),
        )
            .into_response();
    }
    let mut normalized = Vec::with_capacity(request.events.len());
    let mut batch_bytes = 0_usize;
    for (index, raw) in request.events.into_iter().enumerate() {
        match normalize_event_with_limit(
            &agent,
            request.host.as_ref(),
            raw,
            state.registry.budget.limits.max_event_bytes,
        ) {
            Ok(event) => {
                let bytes =
                    normalized_event_bytes(&event, state.registry.budget.limits.max_event_bytes)
                        .unwrap();
                batch_bytes += bytes;
                if batch_bytes > state.registry.budget.limits.max_batch_bytes {
                    return (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        Json(serde_json::json!({"error": "normalized batch exceeds byte limit"})),
                    )
                        .into_response();
                }
                normalized.push((event, bytes));
            }
            Err(error) => {
                return (
                    if error == "normalized event exceeds byte limit" {
                        StatusCode::PAYLOAD_TOO_LARGE
                    } else {
                        StatusCode::BAD_REQUEST
                    },
                    Json(serde_json::json!({ "error": error, "index": index })),
                )
                    .into_response();
            }
        }
    }
    let known = state.known_uids.read().await;
    let mut fresh = Vec::with_capacity(normalized.len());
    let mut duplicates = 0_usize;
    let mut batch_uids = HashSet::new();
    for (event, bytes) in normalized {
        if known.contains(&event.uid)
            || state.registry.has_receipt(&event.uid)
            || !batch_uids.insert(event.uid.clone())
        {
            duplicates += 1;
        } else {
            fresh.push((event, bytes));
        }
    }
    let pending_sizes: Vec<_> = fresh
        .iter()
        .map(|(event, bytes)| (event.uid.clone(), *bytes))
        .collect();
    let pending_uids: Vec<_> = pending_sizes.iter().map(|(uid, _)| uid.clone()).collect();
    let reservation = state
        .registry
        .budget
        .reserve_pending(&agent.id, &pending_sizes);
    drop(known);
    let Ok(mut pending) = reservation else {
        return throttle_response(&state, "ingest pending event budget exhausted").await;
    };
    let mut accepted = 0_usize;
    let mut last_event_at = None;
    for (event, _) in fresh {
        if !pending.owns(&event.uid) {
            duplicates += 1;
            continue;
        }
        last_event_at = Some(event.timestamp.clone());
        match timeout(
            Duration::from_millis(state.registry.budget.limits.queue_wait_ms),
            state.events.reserve(),
        )
        .await
        {
            Ok(Ok(permit)) => {
                pending.sent(&event.uid);
                permit.send(event);
                accepted += 1;
            }
            _ => {
                return throttle_response(&state, "ingest queue unavailable; retry batch").await;
            }
        }
    }
    let durable = timeout(Duration::from_secs(8), async {
        loop {
            if state.known_uids.try_read().is_ok_and(|known| {
                pending_uids
                    .iter()
                    .all(|uid| known.contains(uid) || state.registry.has_receipt(uid))
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if durable.is_err() {
        return throttle_response(
            &state,
            "durable storage acknowledgement unavailable; retry batch",
        )
        .await;
    }
    state.registry.budget.reap(&*state.known_uids.read().await);
    let _maintenance = state.registry.maintenance.read().await;
    let _ = state.registry.touch(
        &agent.id,
        accepted as u64,
        request.host.as_ref().and_then(|h| h.os.as_deref()),
    );
    {
        let mut stats = state.stats.write().await;
        stats.remote_events_total += accepted as u64;
        stats.duplicate_events_total += duplicates as u64;
        if accepted > 0 {
            state
                .registry
                .update_event_time(&agent.id, last_event_at.clone());
            stats.last_remote_event_at = last_event_at;
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "accepted": accepted, "duplicates": duplicates })),
    )
        .into_response()
}

async fn ingest_heartbeat(
    State(state): State<IngestState>,
    Extension(agent): Extension<AuthenticatedAgent>,
    headers: axum::http::HeaderMap,
    payload: Result<Json<HeartbeatRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let _maintenance = state.registry.maintenance.read().await;
    let Ok(Json(request)) = payload else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid heartbeat JSON"})),
        )
            .into_response();
    };
    if let Err(error) = validate_metadata(request.host.as_ref(), request.agent_version.as_deref()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error})),
        )
            .into_response();
    }
    if let Some(report) = request.telemetry
        && let Err(error) = state.registry.update_health(&agent.id, report)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":error.to_string()})),
        )
            .into_response();
    }
    let record = state.registry.touch(
        &agent.id,
        0,
        request.host.as_ref().and_then(|host| host.os.as_deref()),
    );
    state.stats.write().await.heartbeats_total += 1;
    let trust = crate::pki::Pki::new(state.registry.data_dir().join("pki"))
        .trust_bundle()
        .ok();
    let credential = headers
        .get(INGEST_TOKEN_HEADER)
        .and_then(|h| h.to_str().ok())
        .and_then(|token| {
            state
                .registry
                .automatic_credential(&agent.id, token)
                .ok()
                .flatten()
        });
    let mut response = (
        StatusCode::OK,
        Json(serde_json::json!({ "server_time": chrono::Utc::now().to_rfc3339(), "trust_pem":trust, "credential":credential, "config":record.as_ref().and_then(|r|r.desired_config.as_ref()), "config_generation":record.as_ref().map(|r|r.config_generation) })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

async fn ingest_health() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "service": "redtrace-ingest",
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
        })),
    )
}

pub fn agent_source_status(records: &[AgentRecord]) -> Vec<crate::collector::SourceStatus> {
    let now = now_unix();
    records
        .iter()
        .map(|record| {
            let state = if record.revoked {
                "revoked"
            } else if record
                .token_expires_unix
                .is_some_and(|expires| now >= expires)
            {
                "expired"
            } else if record.last_seen_unix > 0 && now.saturating_sub(record.last_seen_unix) < 120 {
                "streaming"
            } else if record.last_seen_unix > 0 && now.saturating_sub(record.last_seen_unix) < 600 {
                "idle"
            } else if record.last_seen_unix > 0 {
                "stale"
            } else {
                "registered"
            };
            crate::collector::SourceStatus {
                name: format!("agent.{}", record.name),
                platform: record.platform.clone().unwrap_or_else(|| "remote".into()),
                state: state.into(),
                events_collected: usize::try_from(record.events_received).unwrap_or(usize::MAX),
                lookback: "remote agent".into(),
                last_error: None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authenticated(name: &str) -> AuthenticatedAgent {
        AuthenticatedAgent {
            id: "a1b2c3d4e5f60718".into(),
            name: name.into(),
        }
    }

    fn raw_event() -> IngestEvent {
        IngestEvent {
            timestamp: "2026-10-03T10:00:00Z".into(),
            source: "Linux.SSHD".into(),
            level: "Medium".into(),
            message: "Failed password for root from 10.0.0.4 port 22 ssh2".into(),
            fields: BTreeMap::from([
                ("event.id".into(), "ssh.login.failure".into()),
                ("source.ip".into(), "10.0.0.4".into()),
                ("collector.cursor".into(), "s=abc;u=def".into()),
                ("agent.id".into(), "spoofed".into()),
            ]),
        }
    }

    #[test]
    fn sha256_matches_reference_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn constant_time_compare_rejects_mismatch() {
        assert!(constant_time_equal(b"token", b"token"));
        assert!(!constant_time_equal(b"token", b"tokem"));
        assert!(!constant_time_equal(b"token", b"tokens"));
    }

    #[test]
    fn normalize_event_validates_and_tags_agent_context() {
        let event = normalize_event(&authenticated("web-01"), None, raw_event()).unwrap();
        assert_eq!(event.source, "linux.sshd");
        assert_eq!(event.level, "medium");
        assert_eq!(event.fields["agent.id"], "a1b2c3d4e5f60718");
        assert_eq!(event.fields["agent.name"], "web-01");
        assert!(!event.fields.contains_key("collector.cursor"));
        assert!(!event.fields.contains_key("host.name"));
        assert_eq!(event.fields["source.ip"], "10.0.0.4");
        let host = IngestHost {
            name: Some("web-01.corp".into()),
            os: Some("linux".into()),
            arch: None,
        };
        let event = normalize_event(&authenticated("web-01"), Some(&host), raw_event()).unwrap();
        assert_eq!(event.fields["host.name"], "web-01.corp");
    }

    #[test]
    fn normalize_event_rejects_invalid_payloads() {
        let mut bad_timestamp = raw_event();
        bad_timestamp.timestamp = "not-a-timestamp".into();
        assert!(normalize_event(&authenticated("x"), None, bad_timestamp).is_err());

        let mut bad_source = raw_event();
        bad_source.source = "linux sshd".into();
        assert!(normalize_event(&authenticated("x"), None, bad_source).is_err());

        let mut empty_message = raw_event();
        empty_message.message = "   ".into();
        assert!(normalize_event(&authenticated("x"), None, empty_message).is_err());
    }

    #[test]
    fn registry_roundtrip_and_revocation() {
        let path = std::env::temp_dir().join(format!(
            "redtrace-agents-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_file(&path);
        let registry = AgentRegistry::open(path.clone()).unwrap();
        assert!(registry.verify("anything").is_none());
        let (record, token) = registry.create("kali-endpoint").unwrap();
        assert_eq!(registry.verify(&token).unwrap().id, record.id);
        assert!(registry.verify("wrong-token").is_none());
        assert!(registry.create(" ").is_err());

        let reopened = AgentRegistry::open(path.clone()).unwrap();
        assert_eq!(reopened.verify(&token).unwrap().id, record.id);
        assert!(reopened.list().len() == 1);

        assert!(reopened.revoke(&record.id).unwrap());
        assert!(reopened.verify(&token).is_none());
        assert!(!reopened.revoke(&record.id).unwrap());

        let reopened = AgentRegistry::open(path.clone()).unwrap();
        assert!(reopened.verify(&token).is_none());
        assert!(reopened.list()[0].revoked);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn touch_updates_counters() {
        let path = std::env::temp_dir().join(format!(
            "redtrace-agents-touch-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_file(&path);
        let registry = AgentRegistry::open(path.clone()).unwrap();
        let (record, _token) = registry.create("srv").unwrap();
        let updated = registry.touch(&record.id, 42, Some("linux")).unwrap();
        assert_eq!(updated.events_received, 42);
        assert_eq!(updated.platform.as_deref(), Some("linux"));
        assert!(updated.last_seen_unix > 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn agent_source_status_maps_liveness() {
        let records = vec![
            AgentRecord {
                id: "1".into(),
                name: "live".into(),
                token_hash: "aa".into(),
                platform: Some("linux".into()),
                created_unix: 1,
                last_seen_unix: now_unix() - 10,
                events_received: 5,
                revoked: false,
                token_expires_unix: None,
                token_generation: 0,
                previous_token: None,
                ..AgentRecord::default()
            },
            AgentRecord {
                id: "2".into(),
                name: "old".into(),
                token_hash: "bb".into(),
                platform: None,
                created_unix: 1,
                last_seen_unix: now_unix() - 999_999,
                events_received: 0,
                revoked: false,
                token_expires_unix: None,
                token_generation: 0,
                previous_token: None,
                ..AgentRecord::default()
            },
        ];
        let statuses = agent_source_status(&records);
        assert_eq!(statuses[0].state, "streaming");
        assert_eq!(statuses[0].name, "agent.live");
        assert_eq!(statuses[1].state, "stale");
    }

    fn registry_fixture() -> (AgentRegistry, PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "redtrace-credential-{}-{}.json",
            std::process::id(),
            hex(&random_bytes(16).unwrap())
        ));
        let registry =
            AgentRegistry::open_with_limits(path.clone(), IngestLimits::default()).unwrap();
        (registry, path)
    }

    #[test]
    fn credential_rotation_expiry_overlap_revocation_and_restart() {
        let (registry, path) = registry_fixture();
        let (record, old_token) = registry.create_with_ttl("endpoint", 60).unwrap();
        let created_expiry = record.token_expires_unix.unwrap();
        assert!(registry.verify_at(&old_token, created_expiry - 1).is_some());
        assert!(registry.verify_at(&old_token, created_expiry).is_none());
        let new = registry.rotate(&record.id, 120, 30).unwrap().unwrap();
        assert_eq!(new.id, record.id);
        assert_eq!(new.token_generation, 2);
        let overlap_end = new.previous_valid_until_unix.unwrap();
        assert!(registry.verify_at(&old_token, overlap_end - 1).is_some());
        assert!(registry.verify_at(&old_token, overlap_end).is_none());
        assert_eq!(registry.verify(&new.token).unwrap().id, record.id);
        assert!(
            registry
                .verify_at(&new.token, new.token_expires_unix)
                .is_none()
        );
        let reopened =
            AgentRegistry::open_with_limits(path.clone(), IngestLimits::default()).unwrap();
        assert_eq!(reopened.verify(&new.token).unwrap().id, record.id);
        assert!(reopened.verify(&old_token).is_some());
        assert!(reopened.revoke(&record.id).unwrap());
        assert!(reopened.verify(&old_token).is_none());
        assert!(reopened.verify(&new.token).is_none());
        assert!(reopened.rotate(&record.id, 60, 0).unwrap().is_none());
        let reopened =
            AgentRegistry::open_with_limits(path.clone(), IngestLimits::default()).unwrap();
        assert!(reopened.verify(&new.token).is_none());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rotation_drops_older_overlap_and_never_extends_old_expiry() {
        let (registry, path) = registry_fixture();
        let (record, original) = registry.create_with_ttl("endpoint", 10).unwrap();
        let next = registry.rotate(&record.id, 120, 60).unwrap().unwrap();
        assert_eq!(next.previous_valid_until_unix, record.token_expires_unix);
        let last = registry.rotate(&record.id, 120, 60).unwrap().unwrap();
        assert!(registry.verify(&original).is_none());
        assert!(registry.verify(&next.token).is_some());
        assert!(registry.verify(&last.token).is_some());
        let immediate = registry.rotate(&record.id, 60, 0).unwrap().unwrap();
        assert!(registry.verify(&last.token).is_none());
        assert!(immediate.previous_valid_until_unix.is_none());
        assert!(registry.create_with_ttl("bad", 0).is_err());
        assert!(registry.rotate(&record.id, 0, 0).is_err());
        assert!(registry.rotate(&record.id, 60, 61).is_err());
        assert!(
            registry
                .rotate(&record.id, MAX_TOKEN_TTL_SECONDS + 1, 0)
                .is_err()
        );
        assert!(
            registry
                .rotate(
                    &record.id,
                    MAX_TOKEN_TTL_SECONDS,
                    MAX_TOKEN_OVERLAP_SECONDS + 1
                )
                .is_err()
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_credential_persistence_does_not_change_live_authorization() {
        let (registry, path) = registry_fixture();
        let (record, token) = registry.create("endpoint").unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(registry.rotate(&record.id, 60, 0).is_err());
        assert!(registry.revoke(&record.id).is_err());
        assert!(registry.create("second").is_err());
        assert_eq!(registry.verify(&token).unwrap(), record);
        assert_eq!(registry.list().len(), 1);
        fs::remove_dir(path).unwrap();
    }

    #[test]
    fn legacy_registry_survives_migration_and_secrets_stay_out_of_public_output() {
        let (registry, path) = registry_fixture();
        let (record, token) = registry.create("legacy").unwrap();
        drop(registry);
        let mut stored: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        stored["version"] = serde_json::json!(1);
        let agent = stored["agents"][0].as_object_mut().unwrap();
        for key in ["token_expires_unix", "token_generation", "previous_token"] {
            agent.remove(key);
        }
        fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
        let registry =
            AgentRegistry::open_with_limits(path.clone(), IngestLimits::default()).unwrap();
        let legacy = registry.verify(&token).unwrap();
        assert_eq!(legacy.id, record.id);
        assert_eq!(AgentPublic::from(&legacy).credential_state, "active");
        let expiry = legacy.token_expires_unix.unwrap();
        let reopened =
            AgentRegistry::open_with_limits(path.clone(), IngestLimits::default()).unwrap();
        assert_eq!(
            reopened.verify(&token).unwrap().token_expires_unix,
            Some(expiry)
        );
        let issued = registry.rotate(&record.id, 60, 0).unwrap().unwrap();
        let public = serde_json::to_string(&AgentPublic::from(&registry.list()[0])).unwrap();
        let stored = fs::read_to_string(&path).unwrap();
        assert!(!stored.contains(&token));
        assert!(!stored.contains(&issued.token));
        assert!(!public.contains("token_hash"));
        assert!(!public.contains(&token));
        assert!(!public.contains(&issued.token));
        assert!(!format!("{:?}", registry).contains(&registry.list()[0].token_hash));
        assert!(registry.verify(&"x".repeat(65536)).is_none());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn metadata_and_normalized_bytes_cover_enrichment_and_json_escaping() {
        let mut host = IngestHost {
            name: Some("endpoint.local".into()),
            os: Some("linux".into()),
            arch: Some("x86_64".into()),
        };
        assert!(validate_metadata(Some(&host), Some("0.1.0+dev-1")).is_ok());
        for os in ["LINUX", "unknown", "", "linux\n"] {
            host.os = Some(os.into());
            assert!(validate_metadata(Some(&host), None).is_err());
        }
        host.os = Some("linux".into());
        host.name = Some("endpoint\nsecret".into());
        assert!(validate_metadata(Some(&host), None).is_err());
        host.name = Some("x".repeat(129));
        assert!(validate_metadata(Some(&host), None).is_err());
        host.name = Some("endpoint".into());
        host.arch = Some("x86_64\n".into());
        assert!(validate_metadata(Some(&host), None).is_err());
        assert!(validate_metadata(None, Some(&"x".repeat(65))).is_err());
        assert!(validate_metadata(None, Some("token\n")).is_err());
        let event = normalize_event(&authenticated("endpoint"), None, raw_event()).unwrap();
        let size = serde_json::to_vec(&event).unwrap().len();
        assert_eq!(normalized_event_bytes(&event, size).unwrap(), size);
        assert!(normalized_event_bytes(&event, size - 1).is_err());
        let mut escaped = raw_event();
        escaped.message = "\u{1}".repeat(50_000);
        assert!(normalize_event(&authenticated("endpoint"), None, escaped).is_err());
        let mut fields = raw_event();
        fields.fields = (0..MAX_FIELDS_PER_EVENT)
            .map(|index| (format!("field{index}"), "value".into()))
            .collect();
        assert!(normalize_event(&authenticated("endpoint"), None, fields).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn registry_privacy_rejects_links_and_repairs_existing_file_mode() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (registry, path) = registry_fixture();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let reopened =
            AgentRegistry::open_with_limits(path.clone(), IngestLimits::default()).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = path.with_extension("link");
        symlink(&path, &link).unwrap();
        assert!(AgentRegistry::open_with_limits(link.clone(), IngestLimits::default()).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&path, &link).unwrap();
        assert!(AgentRegistry::open_with_limits(path.clone(), IngestLimits::default()).is_err());
        fs::remove_file(link).unwrap();
        drop(registry);
        drop(reopened);
        fs::remove_file(path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn registry_privacy_uses_protected_system_and_current_user_dacl() {
        use std::{os::windows::io::AsRawHandle, ptr};
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::{
                Authorization::{
                    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo,
                    SE_FILE_OBJECT,
                },
                DACL_SECURITY_INFORMATION,
            },
        };
        let (registry, path) = registry_fixture();
        registry.create("privacy-fixture").unwrap();
        let reopened =
            AgentRegistry::open_with_limits(path.clone(), IngestLimits::default()).unwrap();
        let file = private_registry_open(&path).unwrap();
        let mut descriptor = ptr::null_mut();
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    file.as_raw_handle().cast(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut descriptor,
                )
            },
            0
        );
        let mut text = ptr::null_mut();
        let mut length = 0;
        assert_ne!(
            unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor,
                    1,
                    DACL_SECURITY_INFORMATION,
                    &mut text,
                    &mut length,
                )
            },
            0
        );
        let dacl = String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(text, length as usize - 1)
        });
        unsafe {
            LocalFree(text.cast());
            LocalFree(descriptor);
        }
        assert!(dacl.starts_with("D:P"));
        assert!(dacl.contains(";;;SY)"));
        assert_eq!(dacl.matches("(A;").count(), 2);
        for broad in [";;;WD)", ";;;BU)", ";;;AU)", ";;;BA)"] {
            assert!(!dacl.contains(broad));
        }
        drop(file);
        drop(registry);
        drop(reopened);
        fs::remove_file(path).unwrap();
    }
}
