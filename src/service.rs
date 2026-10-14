use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

#[path = "service_security.rs"]
mod security;
#[cfg(windows)]
#[path = "service_windows.rs"]
pub mod windows;

pub const PROTOCOL_VERSION: u32 = 1;

pub fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

pub fn api_bind(value: &str) -> io::Result<SocketAddr> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| invalid("invalid local API bind"))?;
    if !address.ip().is_loopback() {
        return Err(invalid("local API bind must be a loopback IP address"));
    }
    Ok(address)
}

pub fn absolute_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        || path.to_str().is_none_or(|value| {
            value.contains(['"', '%', '$']) || value.chars().any(char::is_control)
        })
    {
        return Err(invalid(
            "service paths must be absolute and contain no control or expansion characters",
        ));
    }
    security::no_redirects(path)
}

pub fn protected_file(path: &Path) -> io::Result<()> {
    absolute_path(path)?;
    security::validate(path, false, true)?;
    security::validate(
        path.parent()
            .ok_or_else(|| invalid("private file has no parent"))?,
        true,
        true,
    )
}

pub fn protected_binary(path: &Path) -> io::Result<PathBuf> {
    absolute_path(path)?;
    security::validate(path, false, false)?;
    security::validate(
        path.parent()
            .ok_or_else(|| invalid("binary has no parent"))?,
        true,
        false,
    )?;
    fs::canonicalize(path)
}

pub fn private_directory(path: &Path) -> io::Result<()> {
    absolute_path(path)?;
    if !path.exists() {
        let parent = path
            .parent()
            .ok_or_else(|| invalid("service directory has no parent"))?;
        if !parent.exists() {
            private_directory(parent)?;
        }
        security::create_directory(path)?;
    }
    security::validate(path, true, true)
}

pub fn read_private(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    protected_file(path)?;
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("service file exceeds its size limit"));
    }
    Ok(bytes)
}

pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    absolute_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("service file has no parent"))?;
    private_directory(parent)?;
    let temporary = parent.join(format!(".session-{}.tmp", random_secret()?));
    let result = (|| {
        let mut file = security::create_file(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if path.exists() {
            protected_file(path)?;
        }
        security::replace(&temporary, path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub fn create_private_file(path: &Path) -> io::Result<File> {
    absolute_path(path)?;
    private_directory(
        path.parent()
            .ok_or_else(|| invalid("private file has no parent"))?,
    )?;
    security::create_file(path)
}

/// Public service-manager metadata contains binary/config paths, never credentials.
pub fn write_protected_metadata(path: &Path, bytes: &[u8]) -> io::Result<()> {
    absolute_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("metadata has no parent"))?;
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
    }
    security::validate(parent, true, false)?;
    let temporary = parent.join(format!(".redtrace-{}.tmp", random_secret()?));
    let mut file = security::create_file(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    if path.exists() {
        security::validate(path, false, false)?;
    }
    security::replace(&temporary, path)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn random_secret() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|_| io::Error::other("cannot generate local session secret"))?;
    Ok(crate::ingest::hex(&bytes))
}

pub fn persistent_secret(data_dir: &Path) -> io::Result<String> {
    private_directory(data_dir)?;
    let path = data_dir.join("session.key");
    if path.exists() {
        let token = String::from_utf8(read_private(&path, 64)?)
            .map_err(|_| invalid("invalid local service credential"))?;
        if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid("invalid local service credential"));
        }
        return Ok(token);
    }
    let token = random_secret()?;
    write_private(&path, token.as_bytes())?;
    Ok(token)
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub data_dir: PathBuf,
    #[serde(default)]
    pub session_file: Option<PathBuf>,
    #[serde(default = "default_bind")]
    pub api_bind: String,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

fn default_bind() -> String {
    "127.0.0.1:9710".into()
}

impl ServiceConfig {
    pub fn load(path: &Path) -> io::Result<Self> {
        let config: Self = serde_json::from_slice(&read_private(path, 64 * 1024)?)
            .map_err(|_| invalid("invalid service configuration"))?;
        absolute_path(&config.data_dir)?;
        if let Some(path) = &config.session_file {
            absolute_path(path)?;
            if path.file_name().is_none_or(|name| name != "session.json") {
                return Err(invalid(
                    "service session publication must be named session.json",
                ));
            }
        }
        api_bind(&config.api_bind)?;
        for (name, value) in &config.environment {
            if !name.starts_with("REDTRACE_")
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit())
                || matches!(
                    name.as_str(),
                    "REDTRACE_API_TOKEN"
                        | "REDTRACE_AGENT_TOKEN"
                        | "REDTRACE_ALLOW_UNAUTHENTICATED"
                        | "REDTRACE_DATA_DIR"
                        | "REDTRACE_API_BIND"
                        | "REDTRACE_SERVICE_MODE"
                        | "REDTRACE_SESSION_FILE"
                )
                || value.len() > 8192
                || value.contains('\0')
            {
                return Err(invalid("invalid service environment entry"));
            }
            if matches!(
                name.as_str(),
                "REDTRACE_AGENT_TOKEN_FILE" | "REDTRACE_INGEST_KEY"
            ) {
                protected_file(Path::new(value))?;
            }
            if matches!(name.as_str(), "REDTRACE_AGENT_CA" | "REDTRACE_INGEST_CERT") {
                protected_binary(Path::new(value))?;
            }
        }
        Ok(config)
    }

    pub fn apply(&self) {
        unsafe {
            for (name, _) in std::env::vars_os()
                .filter(|(name, _)| name.to_string_lossy().starts_with("REDTRACE_"))
            {
                std::env::remove_var(name);
            }
            std::env::set_var("REDTRACE_DATA_DIR", &self.data_dir);
            std::env::set_var("REDTRACE_API_BIND", &self.api_bind);
            std::env::set_var("REDTRACE_SERVICE_MODE", "persistent");
            std::env::remove_var("REDTRACE_API_TOKEN");
            std::env::remove_var("REDTRACE_ALLOW_UNAUTHENTICATED");
            if let Some(path) = &self.session_file {
                std::env::set_var("REDTRACE_SESSION_FILE", path);
            }
            for (name, value) in &self.environment {
                std::env::set_var(name, value);
            }
        }
    }
}

#[derive(Clone)]
pub struct Shutdown {
    sender: Arc<watch::Sender<bool>>,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl Shutdown {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(false);
        Self {
            sender: Arc::new(sender),
        }
    }

    pub fn request(&self) {
        self.sender.send_replace(true);
    }

    pub fn requested(&self) -> bool {
        *self.sender.borrow()
    }

    pub async fn wait(&self) {
        let mut receiver = self.sender.subscribe();
        while !*receiver.borrow_and_update() {
            if receiver.changed().await.is_err() {
                break;
            }
        }
    }

    pub fn listen(&self) -> tokio::task::JoinHandle<()> {
        let shutdown = self.clone();
        #[cfg(unix)]
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("register termination signal");
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = terminate.recv() => {},
                    _ = shutdown.wait() => return,
                }
            }
            #[cfg(not(unix))]
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = shutdown.wait() => return,
            }
            shutdown.request();
        })
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionIdentity {
    pub protocol: u32,
    pub version: String,
    pub pid: u32,
    pub process_start: String,
    pub owner: String,
    pub executable: PathBuf,
    pub data_dir: PathBuf,
    pub address: SocketAddr,
    pub instance: String,
    pub persistent: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSession {
    pub identity: SessionIdentity,
    pub token: String,
}

impl LocalSession {
    pub fn new(address: SocketAddr, persistent: bool, token: String) -> io::Result<Self> {
        let data_dir = crate::storage::data_directory();
        if persistent {
            private_directory(&data_dir)?;
        }
        Ok(Self {
            identity: SessionIdentity {
                protocol: PROTOCOL_VERSION,
                version: env!("CARGO_PKG_VERSION").into(),
                pid: std::process::id(),
                process_start: security::process_start(std::process::id())?,
                owner: security::current_owner()?,
                executable: fs::canonicalize(std::env::current_exe()?)?,
                data_dir: fs::canonicalize(data_dir)?,
                address,
                instance: random_secret()?,
                persistent,
            },
            token,
        })
    }
}

pub struct SessionPublication {
    path: PathBuf,
    instance: String,
    _lock: File,
}

impl SessionPublication {
    pub fn publish(path: PathBuf, session: &LocalSession) -> io::Result<Self> {
        if path.file_name().is_none_or(|name| name != "session.json") {
            return Err(invalid(
                "service session publication must be named session.json",
            ));
        }
        private_directory(
            path.parent()
                .ok_or_else(|| invalid("session file has no parent"))?,
        )?;
        let lock_path = path.with_extension("lock");
        let lock = if lock_path.exists() {
            protected_file(&lock_path)?;
            File::options().read(true).write(true).open(&lock_path)?
        } else {
            security::create_file(&lock_path)?
        };
        lock.try_lock().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "another collector owns the session",
            )
        })?;
        write_private(
            &path,
            &serde_json::to_vec(session).map_err(io::Error::other)?,
        )?;
        Ok(Self {
            path,
            instance: session.identity.instance.clone(),
            _lock: lock,
        })
    }
}

impl Drop for SessionPublication {
    fn drop(&mut self) {
        if let Ok(bytes) = read_private(&self.path, 16 * 1024)
            && let Ok(session) = serde_json::from_slice::<LocalSession>(&bytes)
            && session.identity.instance == self.instance
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn attach(
    path: &Path,
    expected_binary: &Path,
    expected_data: &Path,
) -> io::Result<LocalSession> {
    let session: LocalSession = serde_json::from_slice(&read_private(path, 16 * 1024)?)
        .map_err(|_| invalid("invalid local service session"))?;
    let identity = &session.identity;
    let binary = protected_binary(expected_binary)?;
    absolute_path(expected_data)?;
    security::validate(expected_data, true, true)?;
    if identity.protocol != PROTOCOL_VERSION
        || identity.version != env!("CARGO_PKG_VERSION")
        || !identity.persistent
        || !identity.address.ip().is_loopback()
        || identity.address.port() == 0
        || identity.executable != binary
        || identity.data_dir != fs::canonicalize(expected_data)?
        || identity.owner != security::current_owner()?
        || session.token.len() != 64
        || !session.token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid("local service identity mismatch"));
    }
    security::verify_listener(identity)?;
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(io::Error::other)?;
    let response = client
        .get(format!("http://{}/api/session", identity.address))
        .header("x-redtrace-token", &session.token)
        .send()
        .map_err(|_| invalid("local service authentication failed"))?;
    if !response.status().is_success() {
        return Err(invalid("local service authentication failed"));
    }
    let mut bytes = Vec::new();
    response.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    let verified: SessionIdentity = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("invalid local service identity response"))?;
    if verified != *identity {
        return Err(invalid("local service identity mismatch"));
    }
    security::verify_listener(identity)?;
    Ok(session)
}

pub fn request_stop(session: &LocalSession, portable_only: bool) -> io::Result<()> {
    if portable_only && session.identity.persistent {
        return Err(invalid("desktop does not own the persistent collector"));
    }
    api_bind(&session.identity.address.to_string())?;
    #[cfg(any(windows, target_os = "linux"))]
    security::verify_listener(&session.identity)?;
    let response = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(io::Error::other)?
        .post(format!(
            "http://{}/api/session/stop",
            session.identity.address
        ))
        .header("x-redtrace-token", &session.token)
        .header("x-redtrace-instance", &session.identity.instance)
        .send()
        .map_err(|_| invalid("local collector stop failed"))?;
    if !response.status().is_success() {
        return Err(invalid("local collector stop rejected"));
    }
    Ok(())
}

pub fn portable_session(
    address: SocketAddr,
    token: &str,
    pid: u32,
    binary: &Path,
) -> io::Result<LocalSession> {
    api_bind(&address.to_string())?;
    let response = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(io::Error::other)?
        .get(format!("http://{address}/api/session"))
        .header("x-redtrace-token", token)
        .send()
        .map_err(|_| invalid("desktop collector not ready"))?;
    if !response.status().is_success() {
        return Err(invalid("desktop collector authentication failed"));
    }
    let mut bytes = Vec::new();
    response.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    let identity: SessionIdentity = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("invalid desktop collector identity"))?;
    if identity.persistent
        || identity.pid != pid
        || identity.address != address
        || identity.executable != fs::canonicalize(binary)?
        || identity.protocol != PROTOCOL_VERSION
        || identity.version != env!("CARGO_PKG_VERSION")
        || identity.owner != security::current_owner()?
    {
        return Err(invalid("desktop collector ownership mismatch"));
    }
    #[cfg(any(windows, target_os = "linux"))]
    security::verify_listener(&identity)?;
    Ok(LocalSession {
        identity,
        token: token.into(),
    })
}

pub fn systemd_template(
    binary: &Path,
    config: &Path,
    identity: &str,
    agent: bool,
) -> io::Result<String> {
    protected_binary(binary)?;
    if identity.is_empty()
        || identity == "root"
        || identity.parse::<u64>() == Ok(0)
        || identity.len() > 64
        || !identity
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    {
        return Err(invalid("an explicit non-root service identity is required"));
    }
    let config_value = ServiceConfig::load(config)?;
    if config_value
        .session_file
        .as_ref()
        .is_some_and(|path| !path.starts_with(&config_value.data_dir))
    {
        return Err(invalid(
            "systemd session file must be inside the writable data directory",
        ));
    }
    let quote = |path: &Path| path.to_string_lossy().replace('\\', "\\\\");
    let role = if agent { "agent" } else { "collector" };
    Ok(format!(
        "[Unit]\nDescription=REDTRACE {role}\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=60\nStartLimitBurst=5\n\n[Service]\nType=simple\nUser={identity}\nExecStart=\"{}\" --persistent --config \"{}\"\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=45\nKillSignal=SIGTERM\nUMask=0077\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=\"{}\"\n\n[Install]\nWantedBy=multi-user.target\n",
        quote(binary),
        quote(config),
        quote(&config_value.data_dir)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_is_level_triggered_for_existing_and_late_subscribers() {
        let shutdown = Shutdown::new();
        let first = shutdown.clone();
        let waiting = tokio::spawn(async move {
            first.wait().await;
        });
        shutdown.request();
        shutdown.request();
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), shutdown.wait())
            .await
            .unwrap();
        assert!(shutdown.requested());
    }

    #[test]
    fn private_publication_lock_and_cleanup_preserve_a_replacement_instance() {
        let directory = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join("opencode")
            .join(format!("redtrace-session-{}", random_secret().unwrap()));
        private_directory(&directory).unwrap();
        let path = directory.join("session.json");
        let session = LocalSession {
            identity: SessionIdentity {
                protocol: PROTOCOL_VERSION,
                version: env!("CARGO_PKG_VERSION").into(),
                pid: std::process::id(),
                process_start: "fixture".into(),
                owner: "fixture".into(),
                executable: std::env::current_exe().unwrap(),
                data_dir: directory.clone(),
                address: "127.0.0.1:0".parse().unwrap(),
                instance: random_secret().unwrap(),
                persistent: true,
            },
            token: random_secret().unwrap(),
        };
        let first = SessionPublication::publish(path.clone(), &session).unwrap();
        assert!(SessionPublication::publish(path.clone(), &session).is_err());
        let mut replacement = session.clone();
        replacement.identity.instance = random_secret().unwrap();
        write_private(&path, &serde_json::to_vec(&replacement).unwrap()).unwrap();
        drop(first);
        assert!(path.exists());
        let second = SessionPublication::publish(path.clone(), &replacement).unwrap();
        drop(second);
        assert!(!path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
