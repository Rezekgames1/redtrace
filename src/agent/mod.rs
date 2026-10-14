mod files;
pub mod spool;

pub use spool::{DiskSpool, Enqueued, SpoolChunk, SpoolLimits};

use crate::ingest::{INGEST_TOKEN_HEADER, IngestEvent, IngestHost, IngestRequest};
use crate::model::Event;
use crate::storage::CheckpointStore;
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::PathBuf,
    time::Duration,
};

pub const DEFAULT_POLL: Duration = Duration::from_secs(5);
pub const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(30);
pub const DEFAULT_FLUSH_EVENTS: usize = 500;
pub const DEFAULT_OUTBOX_CAP: usize = 20_000;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct AgentConfig {
    pub server: String,
    pub token: String,
    pub name: String,
    pub state_dir: PathBuf,
    pub poll: Duration,
    pub heartbeat: Duration,
    pub flush_events: usize,
    pub outbox_cap: usize,
    pub lookback: Option<String>,
}

impl AgentConfig {
    pub fn state_path(&self) -> PathBuf {
        self.state_dir.join("checkpoints.json")
    }
}

pub fn default_state_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("REDTRACE_AGENT_STATE") {
        return PathBuf::from(path);
    }
    #[cfg(target_os = "windows")]
    if let Some(path) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(path).join("redtrace-agent");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".redtrace-agent");
    }
    PathBuf::from(".redtrace-agent")
}

pub fn default_agent_name() -> String {
    for variable in ["COMPUTERNAME", "HOSTNAME"] {
        if let Some(value) = std::env::var_os(variable)
            && let Some(value) = value.to_str()
            && !value.is_empty()
        {
            return value.into();
        }
    }
    "unknown".into()
}

pub fn read_token_file(path: &std::path::Path) -> std::io::Result<String> {
    files::regular(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "token file must not grant group or other access",
            ));
        }
    }
    let bytes = files::read_bounded(path, 4096)?;
    let token = String::from_utf8(bytes).map_err(|_| files::invalid("token file is not UTF-8"))?;
    let token = token.trim_end_matches(['\r', '\n']).to_owned();
    validate_token(&token)?;
    Ok(token)
}

pub fn validate_token(token: &str) -> std::io::Result<()> {
    if token.is_empty()
        || token.len() > 4096
        || !token.is_ascii()
        || token
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid agent token format",
        ));
    }
    Ok(())
}

pub struct ServerEndpoint {
    pub addr: String,
    pub host_header: String,
    pub url: String,
    pub ca_file: Option<PathBuf>,
    client: std::sync::Mutex<Option<(String, reqwest::blocking::Client)>>,
}

pub fn parse_server(server: &str) -> Result<ServerEndpoint, String> {
    let url = reqwest::Url::parse(server).map_err(|error| error.to_string())?;
    let host = url.host_str().ok_or("server host is missing")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("server must be an HTTP(S) origin without credentials or path".into());
    }
    if url.scheme() == "http" && !matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
        return Err("remote servers require HTTPS".into());
    }
    let port = url.port_or_known_default().ok_or("server port missing")?;
    let addr = format!("{host}:{port}");
    Ok(ServerEndpoint {
        host_header: addr.clone(),
        addr,
        url: url.to_string(),
        ca_file: std::env::var_os("REDTRACE_AGENT_CA").map(PathBuf::from),
        client: std::sync::Mutex::new(None),
    })
}

pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

pub fn http_post(
    endpoint: &ServerEndpoint,
    path: &str,
    token: &str,
    body: &str,
) -> std::io::Result<HttpResponse> {
    if endpoint.url.starts_with("https://") {
        let pem = if let Some(ca) = &endpoint.ca_file {
            let metadata = std::fs::metadata(ca)?;
            if metadata.len() > 64 * 1024 {
                return Err(std::io::Error::other("CA bundle exceeds limit"));
            }
            std::fs::read(ca)?
        } else {
            Vec::new()
        };
        let fingerprint = crate::ingest::hex(&crate::ingest::sha256(&pem));
        let mut cached = endpoint.client.lock().unwrap_or_else(|e| e.into_inner());
        if cached.as_ref().is_none_or(|(hash, _)| hash != &fingerprint) {
            let mut builder = reqwest::blocking::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy();
            if !pem.is_empty() {
                for certificate in
                    reqwest::Certificate::from_pem_bundle(&pem).map_err(std::io::Error::other)?
                {
                    builder = builder.add_root_certificate(certificate);
                }
            }
            *cached = Some((fingerprint, builder.build().map_err(std::io::Error::other)?));
        }
        let client = cached
            .as_ref()
            .ok_or_else(|| std::io::Error::other("TLS client unavailable"))?
            .1
            .clone();
        drop(cached);
        let response = client
            .post(format!("{}{path}", endpoint.url.trim_end_matches('/')))
            .header(INGEST_TOKEN_HEADER, token)
            .header("content-type", "application/json")
            .body(body.to_owned())
            .send()
            .map_err(std::io::Error::other)?;
        let status = response.status().as_u16();
        let mut body = Vec::new();
        response.take(1024 * 1024 + 1).read_to_end(&mut body)?;
        if body.len() > 1024 * 1024 {
            return Err(std::io::Error::other("response exceeds limit"));
        }
        return Ok(HttpResponse {
            status,
            body: String::from_utf8_lossy(&body).into_owned(),
        });
    }
    if token.chars().any(char::is_control) || endpoint.host_header.chars().any(char::is_control) {
        return Err(std::io::Error::other("invalid HTTP header value"));
    }
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: redtrace-agent/{version}\r\nContent-Type: application/json\r\n{token_header}: {token}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{body}",
        host = endpoint.host_header,
        version = env!("CARGO_PKG_VERSION"),
        token_header = INGEST_TOKEN_HEADER,
        length = body.len(),
    );
    let addresses: Vec<SocketAddr> = endpoint
        .addr
        .to_socket_addrs()
        .map_err(std::io::Error::other)?
        .collect();
    let mut stream = connect(&addresses)?;
    stream.set_read_timeout(Some(HTTP_TIMEOUT))?;
    stream.set_write_timeout(Some(HTTP_TIMEOUT))?;
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let mut raw = Vec::new();
    stream.take(1024 * 1024 + 1).read_to_end(&mut raw)?;
    if raw.len() > 1024 * 1024 {
        return Err(std::io::Error::other("server response exceeds limit"));
    }
    let response = String::from_utf8_lossy(&raw).into_owned();
    let status = response
        .lines()
        .next()
        .and_then(|status_line| status_line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "malformed HTTP response from server: {}",
                    response.chars().take(64).collect::<String>()
                ),
            )
        })?;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    Ok(HttpResponse { status, body })
}

fn connect(addresses: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(address, HTTP_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "server address did not resolve",
        )
    }))
}

pub fn build_events_body(agent_name: &str, events: &[Event]) -> String {
    let request = IngestRequest {
        agent_version: Some(env!("CARGO_PKG_VERSION").into()),
        host: Some(IngestHost {
            name: Some(agent_name.into()),
            os: Some(std::env::consts::OS.into()),
            arch: Some(std::env::consts::ARCH.into()),
        }),
        events: events.iter().map(IngestEvent::from).collect(),
    };
    serde_json::to_string(&request).unwrap_or_else(|_| "{}".into())
}

pub fn build_heartbeat_body(agent_name: &str, sent_total: u64, dropped_total: u64) -> String {
    serde_json::to_string(&serde_json::json!({
        "agent_version": env!("CARGO_PKG_VERSION"),
        "host": {
            "name": agent_name,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "sent_total": sent_total,
        "dropped_total": dropped_total,
    }))
    .unwrap_or_else(|_| "{}".into())
}

#[derive(Debug, PartialEq, Eq)]
pub enum Delivery {
    Accepted { accepted: usize, duplicates: usize },
    Rejected { reason: String },
    Unauthorized,
    Unreachable { reason: String },
}

pub fn deliver_chunk(
    endpoint: &ServerEndpoint,
    token: &str,
    agent_name: &str,
    chunk: &[Event],
) -> Delivery {
    let body = build_events_body(agent_name, chunk);
    match http_post(endpoint, "/ingest/v1/events", token, &body) {
        Ok(response) => match response.status {
            200 => {
                let parsed: Option<Value> = serde_json::from_str(&response.body).ok();
                let accepted = parsed
                    .as_ref()
                    .and_then(|value| value.get("accepted"))
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok());
                let duplicates = parsed
                    .as_ref()
                    .and_then(|value| value.get("duplicates"))
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok());
                let (Some(accepted), Some(duplicates)) = (accepted, duplicates) else {
                    return Delivery::Unreachable {
                        reason: "invalid batch acknowledgement".into(),
                    };
                };
                if accepted.checked_add(duplicates) != Some(chunk.len()) {
                    return Delivery::Unreachable {
                        reason: "invalid batch acknowledgement".into(),
                    };
                }
                Delivery::Accepted {
                    accepted,
                    duplicates,
                }
            }
            401 => Delivery::Unauthorized,
            400 | 413 => Delivery::Rejected {
                reason: response.body,
            },
            status => Delivery::Unreachable {
                reason: format!("server returned HTTP {status}"),
            },
        },
        Err(error) => Delivery::Unreachable {
            reason: error.to_string(),
        },
    }
}

pub fn send_heartbeat(
    endpoint: &ServerEndpoint,
    token: &str,
    agent_name: &str,
    sent_total: u64,
    dropped_total: u64,
) -> std::io::Result<u16> {
    let body = build_heartbeat_body(agent_name, sent_total, dropped_total);
    http_post(endpoint, "/ingest/v1/heartbeat", token, &body).map(|response| response.status)
}

pub struct AgentRuntime {
    pub config: AgentConfig,
    pub checkpoints: CheckpointStore,
    pub outbox: DiskSpool,
    pub sent_total: u64,
    pub dropped_total: u64,
    last_heartbeat: std::time::Instant,
    last_error: Option<String>,
    extended: crate::collector::extended::ExtendedCollectors,
    settings: crate::config::Config,
    filter: crate::config::EventFilter,
    retry_total: u64,
    enqueue_refused_total: u64,
    config_generation: u64,
    last_event_at: Option<String>,
    system_health: crate::modules::ModuleHealth,
    module_pending: std::collections::VecDeque<Event>,
}

impl AgentRuntime {
    pub fn new(config: AgentConfig) -> std::io::Result<Self> {
        let limits = SpoolLimits {
            max_events: config.outbox_cap,
            ..SpoolLimits::default()
        };
        Self::new_with_spool_limits(config, limits)
    }

    pub fn new_with_spool_limits(
        mut config: AgentConfig,
        limits: SpoolLimits,
    ) -> std::io::Result<Self> {
        let mut outbox = DiskSpool::open(config.state_dir.clone(), limits)?;
        let checkpoints = outbox.collector_checkpoints()?;
        let sent_total = outbox.sent_total();
        let dropped_total = outbox.rejected_total();
        let settings = crate::config::Config::load(&config.state_dir.join("config.json"))?;
        if config.state_dir.join("config.json").exists() {
            outbox.reconfigure_limits(SpoolLimits {
                max_events: settings.resources.spool_events,
                max_bytes: settings.resources.spool_bytes,
                ..limits
            })?;
            config.poll = Duration::from_secs(settings.resources.poll_seconds);
            config.heartbeat = Duration::from_secs(settings.resources.heartbeat_seconds);
            config.flush_events = settings.resources.max_batch_events.min(500);
        }
        let extended = crate::collector::extended::ExtendedCollectors::new(settings.clone())?;
        let filter = crate::config::EventFilter::new(&settings)?;
        Ok(Self {
            extended,
            settings,
            filter,
            retry_total: 0,
            enqueue_refused_total: 0,
            config_generation: 0,
            last_event_at: None,
            system_health: crate::modules::ModuleHealth {
                id: "system".into(),
                state: "starting".into(),
                ..crate::modules::ModuleHealth::default()
            },
            module_pending: std::collections::VecDeque::new(),
            checkpoints,
            outbox,
            config,
            sent_total,
            dropped_total,
            last_heartbeat: std::time::Instant::now()
                .checked_sub(DEFAULT_HEARTBEAT)
                .unwrap_or_else(std::time::Instant::now),
            last_error: None,
        })
    }

    pub fn collect(&mut self) {
        if self.module_pending.is_empty() && self.settings.sources.system {
            self.collect_with(crate::collector::collect_platform_events);
        }
        if self.module_pending.is_empty() {
            self.module_pending
                .extend(self.extended.collect(&self.checkpoints));
        }
        while let Some(event) = self.module_pending.front().cloned() {
            match self.enqueue_events([event]) {
                Ok(_) => {
                    self.module_pending.pop_front();
                }
                Err(error) => {
                    self.enqueue_refused_total += 1;
                    self.collection_error(format!(
                        "extended event retained while durable spool is unavailable: {error}"
                    ));
                    break;
                }
            }
        }
        if let Err(error) = self.refresh_checkpoints() {
            self.collection_error(error.to_string());
        }
    }

    pub fn collect_with(
        &mut self,
        collect: impl FnOnce(&CheckpointStore) -> crate::collector::CollectionBatch,
    ) {
        if let Err(error) = self.refresh_checkpoints() {
            self.collection_error(format!("spool collection checkpoint unavailable: {error}"));
            return;
        }
        let batch = collect(&self.checkpoints);
        self.system_health.state = batch.status.state.clone();
        self.system_health.error = batch.status.last_error.clone();
        self.system_health.permissions = if batch.status.state == "error" {
            "unavailable"
        } else {
            "read-only"
        }
        .into();
        self.system_health.events += batch.events.len() as u64;
        if batch.status.state == "error" {
            let error = batch.status.last_error.clone().unwrap_or_default();
            self.collection_error(format!("collector error: {error}"));
            return;
        }
        let mut bytes = 0;
        let max_bytes = self.settings.resources.max_batch_bytes;
        let events = batch
            .events
            .into_iter()
            .take(self.settings.resources.max_batch_events)
            .take_while(|e| {
                bytes += crate::index::event_memory_bytes(e);
                bytes <= max_bytes
            });
        if let Err(error) = self.enqueue_events(events) {
            self.collection_error(format!(
                "durable enqueue refused; remaining events and cursor retained: {error}"
            ));
            return;
        }
        self.last_error = None;
    }

    pub fn enqueue_events(
        &mut self,
        events: impl IntoIterator<Item = Event>,
    ) -> std::io::Result<usize> {
        let mut stored = 0;
        for mut event in events {
            crate::modules::normalize(&mut event);
            if !self.filter.accepts(&event) {
                event.fields.retain(|k, _| k.starts_with("collector."));
                event.fields.insert("event.filtered".into(), "true".into());
                event.message = "Event excluded by collection policy".into();
            }
            self.last_event_at = Some(event.timestamp.clone());
            match self.outbox.push(event) {
                Ok(Enqueued::Stored) => stored += 1,
                Ok(Enqueued::Duplicate) => {}
                Err(error) => {
                    self.enqueue_refused_total += 1;
                    if !self.outbox.is_failed() {
                        self.refresh_checkpoints()?;
                    }
                    return Err(error);
                }
            }
        }
        self.refresh_checkpoints()?;
        Ok(stored)
    }

    fn refresh_checkpoints(&mut self) -> std::io::Result<()> {
        self.checkpoints = self.outbox.collector_checkpoints()?;
        Ok(())
    }

    fn collection_error(&mut self, error: String) {
        if self.last_error.as_deref() != Some(error.as_str()) {
            log(&error);
            self.last_error = Some(error);
        }
    }

    pub fn flush(&mut self, endpoint: &ServerEndpoint) -> bool {
        self.reload_token();
        let mut delivered_any = false;
        for _ in 0..4 {
            if self.outbox.is_empty() {
                break;
            }
            let chunk = match self.outbox.peek_chunk(self.config.flush_events) {
                Ok(chunk) => chunk,
                Err(error) => {
                    log(&format!(
                        "spool read failed; pending records preserved: {error}"
                    ));
                    return delivered_any;
                }
            };
            match deliver_chunk(
                endpoint,
                &self.config.token,
                &self.config.name,
                chunk.events(),
            ) {
                Delivery::Accepted {
                    accepted,
                    duplicates,
                } => {
                    if let Err(error) = self.outbox.acknowledge(&chunk, accepted, duplicates) {
                        log(&format!(
                            "durable ACK progress failed; replay required on recovery: {error}"
                        ));
                        return delivered_any;
                    }
                    log(&format!(
                        "delivered {} events ({} duplicates acknowledged)",
                        accepted, duplicates
                    ));
                    self.sent_total = self.outbox.sent_total();
                    self.config.flush_events = self
                        .settings
                        .resources
                        .max_batch_events
                        .min(DEFAULT_FLUSH_EVENTS);
                    delivered_any = true;
                }
                Delivery::Rejected { reason } => {
                    log(&format!(
                        "server rejected batch of {} events; retaining it: {}",
                        chunk.events().len(),
                        reason.trim()
                    ));
                    if chunk.events().len() > 1 {
                        self.config.flush_events = (chunk.events().len() / 2).max(1);
                        return delivered_any;
                    }
                    if let Err(error) = self.outbox.reject(&chunk, &reason) {
                        log(&format!(
                            "quarantine unavailable; preserving batch: {error}"
                        ));
                        return delivered_any;
                    }
                    self.dropped_total = self.outbox.rejected_total();
                    log("rejected event preserved in local quarantine");
                    delivered_any = true;
                }
                Delivery::Unauthorized => {
                    log("server rejected the agent token (401); run with a valid token");
                    std::process::exit(4);
                }
                Delivery::Unreachable { reason } => {
                    self.retry_total += 1;
                    log(&format!("server unreachable: {reason}"));
                    return delivered_any;
                }
            }
        }
        if let Err(error) = self.refresh_checkpoints() {
            log(&format!(
                "collector checkpoint projection unavailable: {error}"
            ));
        }
        delivered_any
    }

    pub fn heartbeat_if_due(&mut self, endpoint: &ServerEndpoint) {
        if self.last_heartbeat.elapsed() < self.config.heartbeat {
            return;
        }
        self.reload_token();
        let mut report = self.outbox.telemetry().unwrap_or_default();
        report.pending_events = report
            .pending_events
            .saturating_add(self.module_pending.len() as u64);
        report.retry_total = self.retry_total;
        report.enqueue_refused_total = self.enqueue_refused_total;
        report.last_event_at = self.last_event_at.clone();
        report.modules = self.extended.health.values().cloned().collect();
        if self.settings.sources.system {
            report.modules.push(self.system_health.clone());
        }
        report.config_generation = self.config_generation;
        if let Some(ca) = &endpoint.ca_file {
            report.trust_sha256 = std::fs::read(ca)
                .ok()
                .map(|b| crate::ingest::hex(&crate::ingest::sha256(&b)))
                .unwrap_or_default();
        }
        let mut body: Value = serde_json::from_str(&build_heartbeat_body(
            &self.config.name,
            self.sent_total,
            self.dropped_total,
        ))
        .unwrap_or_default();
        body["telemetry"] = serde_json::to_value(report).unwrap_or_default();
        match http_post(
            endpoint,
            "/ingest/v1/heartbeat",
            &self.config.token,
            &body.to_string(),
        ) {
            Ok(response) if response.status == 200 => {
                self.last_heartbeat = std::time::Instant::now();
                if let Err(error) = self.apply_control(endpoint, &response.body) {
                    log(&format!("control update deferred: {error}"));
                }
            }
            Ok(response) if response.status == 401 => {
                log("server rejected the agent token (401); run with a valid token");
                std::process::exit(4);
            }
            Ok(response) => {
                log(&format!("heartbeat returned HTTP {}", response.status));
            }
            Err(error) => {
                log(&format!("heartbeat failed: {error}"));
            }
        }
    }
    fn reload_token(&mut self) {
        let path = std::env::var_os("REDTRACE_AGENT_TOKEN_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.config.state_dir.join("agent.token"));
        if path.exists() {
            match read_token_file(&path) {
                Ok(token) => self.config.token = token,
                Err(_) => log("token file reload failed; previous credential retained"),
            }
        }
    }
    fn apply_control(&mut self, endpoint: &ServerEndpoint, body: &str) -> std::io::Result<()> {
        let value: Value = serde_json::from_str(body).map_err(std::io::Error::other)?;
        if let Some(pem) = value.get("trust_pem").and_then(Value::as_str) {
            if pem.len() > 64 * 1024 {
                return Err(std::io::Error::other("trust bundle exceeds limit"));
            }
            let certificates = reqwest::Certificate::from_pem_bundle(pem.as_bytes())
                .map_err(std::io::Error::other)?;
            if certificates.is_empty() {
                return Err(std::io::Error::other("empty trust bundle"));
            }
            if let Some(path) = &endpoint.ca_file
                && std::fs::read(path).ok().as_deref() != Some(pem.as_bytes())
            {
                crate::service::write_private(path, pem.as_bytes())?;
            }
        }
        if let Some(token) = value.pointer("/credential/token").and_then(Value::as_str) {
            validate_token(token)?;
            let path = std::env::var_os("REDTRACE_AGENT_TOKEN_FILE")
                .map(PathBuf::from)
                .unwrap_or_else(|| self.config.state_dir.join("agent.token"));
            crate::service::write_private(&path, token.as_bytes())?;
            self.config.token = token.into();
        }
        if let Some(generation) = value
            .get("config_generation")
            .and_then(Value::as_u64)
            .filter(|g| *g > self.config_generation)
            && let Some(config) = value.get("config").filter(|v| !v.is_null())
        {
            let settings: crate::config::Config =
                serde_json::from_value(config.clone()).map_err(std::io::Error::other)?;
            settings.validate()?;
            let filter = crate::config::EventFilter::new(&settings)?;
            self.outbox.reconfigure_limits(SpoolLimits {
                max_events: settings.resources.spool_events,
                max_bytes: settings.resources.spool_bytes,
                ..SpoolLimits::default()
            })?;
            settings.save(&self.config.state_dir.join("config.json"))?;
            self.extended.reconfigure(settings.clone())?;
            self.config.poll = Duration::from_secs(settings.resources.poll_seconds);
            self.config.heartbeat = Duration::from_secs(settings.resources.heartbeat_seconds);
            self.config.flush_events = settings
                .resources
                .max_batch_events
                .min(DEFAULT_FLUSH_EVENTS);
            self.settings = settings;
            self.filter = filter;
            self.config_generation = generation;
        }
        Ok(())
    }
}

pub fn log(message: &str) {
    eprintln!(
        "{} [redtrace-agent] {message}",
        chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn event(uid_seed: &str) -> Event {
        Event::normalized(
            0,
            format!("2026-10-03T10:00:0{uid_seed}Z"),
            "linux.sshd".into(),
            "medium".into(),
            format!("event {uid_seed}"),
            BTreeMap::new(),
        )
    }

    #[test]
    fn parse_server_accepts_host_and_optional_port() {
        let with_port = parse_server("https://10.0.0.5:9711").unwrap();
        assert_eq!(with_port.addr, "10.0.0.5:9711");
        assert_eq!(with_port.host_header, "10.0.0.5:9711");
        let without_port = parse_server("https://siem.local").unwrap();
        assert_eq!(without_port.addr, "siem.local:443");
        assert!(parse_server("http://siem.local").is_err());
        assert!(parse_server("http://").is_err());
    }

    #[test]
    fn events_body_contains_normalized_wire_format() {
        let body = build_events_body("kali-01", &[event("7")]);
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["host"]["name"], "kali-01");
        assert_eq!(parsed["events"][0]["source"], "linux.sshd");
        assert_eq!(parsed["events"][0]["message"], "event 7");
        assert!(parsed["events"][0]["fields"].is_object());
    }

    #[test]
    fn heartbeat_body_reports_counters() {
        let body = build_heartbeat_body("kali-01", 42, 3);
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["sent_total"], 42);
        assert_eq!(parsed["dropped_total"], 3);
        assert_eq!(parsed["host"]["name"], "kali-01");
    }
}
