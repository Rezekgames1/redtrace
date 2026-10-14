use crate::{
    config::Config,
    enrollment::Enrollment,
    ingest::{AgentRegistry, IngestState},
    pki::Pki,
    rules,
    service::{self, Shutdown},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::{Mutex as AsyncMutex, RwLock};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub bind: String,
    pub server: String,
}

pub struct Control {
    pub root: PathBuf,
    pub config: RwLock<Config>,
    pub generation: std::sync::atomic::AtomicU64,
    pub module_health: RwLock<BTreeMap<String, crate::modules::ModuleHealth>>,
    pub rules: Mutex<rules::Manager>,
    pub registry: Option<Arc<AgentRegistry>>,
    pub enrollment: Option<Arc<Enrollment>>,
    pub pki: Mutex<Pki>,
    pki_update: AsyncMutex<()>,
    pub tls: RwLock<Option<axum_server::tls_rustls::RustlsConfig>>,
    pub listener: AsyncMutex<Option<Listener>>,
    pub ingress: RwLock<Option<IngestState>>,
    pub maintenance: Arc<RwLock<()>>,
    pub shutdown: Shutdown,
    cases: Mutex<Vec<rules::Case>>,
}
impl Control {
    pub fn open(
        root: PathBuf,
        registry: Option<Arc<AgentRegistry>>,
        shutdown: Shutdown,
    ) -> io::Result<Self> {
        let root = std::fs::canonicalize(&root)?;
        service::private_directory(&root)?;
        crate::backup::migrate(&root)?;
        let config = Config::load(&root.join("config.json"))?;
        let cases = if root.join("cases.json").exists() {
            serde_json::from_slice(&service::read_private(
                &root.join("cases.json"),
                4 * 1024 * 1024,
            )?)
            .map_err(io::Error::other)?
        } else {
            Vec::new()
        };
        let enrollment = registry
            .as_ref()
            .map(|r| Enrollment::open(root.join("enrollment.json"), r.clone()).map(Arc::new))
            .transpose()?;
        let maintenance = registry
            .as_ref()
            .map(|r| r.maintenance.clone())
            .unwrap_or_else(|| Arc::new(RwLock::new(())));
        Ok(Self {
            config: RwLock::new(config),
            generation: std::sync::atomic::AtomicU64::new(1),
            rules: Mutex::new(rules::Manager::open(root.join("rules.json"))?),
            pki: Mutex::new(Pki::new(root.join("pki"))),
            pki_update: AsyncMutex::new(()),
            root,
            registry,
            enrollment,
            tls: RwLock::new(None),
            listener: AsyncMutex::new(None),
            ingress: RwLock::new(None),
            module_health: RwLock::new(BTreeMap::new()),
            maintenance,
            shutdown,
            cases: Mutex::new(cases),
        })
    }
    pub async fn enable(self: &Arc<Self>, listener: Listener) -> io::Result<()> {
        let address: std::net::SocketAddr = listener
            .bind
            .parse()
            .map_err(|_| service::invalid("invalid ingest bind address"))?;
        let url = reqwest::Url::parse(&listener.server).map_err(io::Error::other)?;
        if url.scheme() != "https" || url.port_or_known_default() != Some(address.port()) {
            return Err(service::invalid(
                "server must be an HTTPS origin matching the ingest port",
            ));
        }
        crate::agent::parse_server(&listener.server).map_err(io::Error::other)?;
        let mut current = self.listener.lock().await;
        if current.is_some() {
            return Err(service::invalid(
                "ingest listener is already running; change its bind at next restart",
            ));
        }
        let paths = self
            .pki
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .paths()?
            .ok_or_else(|| service::invalid("configure TLS first"))?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(paths.0, paths.1).await?;
        let socket = tokio::net::TcpListener::bind(address).await?;
        let ingress = self
            .ingress
            .read()
            .await
            .clone()
            .ok_or_else(|| service::invalid("agent registry unavailable"))?;
        let router = crate::ingest::ingest_router(ingress).merge(remote_router(self.clone()));
        let handle = axum_server::Handle::new();
        let stop = handle.clone();
        let shutdown = self.shutdown.clone();
        let signal = tokio::spawn(async move {
            shutdown.wait().await;
            stop.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
        });
        let server = axum_server::from_tcp_rustls(socket.into_std()?, tls.clone())?;
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let result = server
                .handle(handle)
                .serve(router.into_make_service())
                .await;
            signal.abort();
            if let Err(error) = result {
                tracing::error!(%error,"managed ingest stopped");
            }
            if let Some(c) = weak.upgrade() {
                *c.listener.lock().await = None;
            }
        });
        *self.tls.write().await = Some(tls);
        *current = Some(listener);
        Ok(())
    }
    pub async fn renew(&self) -> io::Result<crate::pki::PkiState> {
        let _gate = self.maintenance.read().await;
        let _update = self.pki_update.lock().await;
        let state = {
            let pki = self.pki.lock().unwrap_or_else(|e| e.into_inner());
            let old = pki
                .status()?
                .ok_or_else(|| service::invalid("TLS is not configured"))?;
            pki.provision(old.hosts, false)?
        };
        self.reload_tls().await?;
        Ok(state)
    }
    pub async fn reload_tls(&self) -> io::Result<()> {
        let paths = self.pki.lock().unwrap_or_else(|e| e.into_inner()).paths()?;
        if let (Some((cert, key)), Some(tls)) = (paths, self.tls.read().await.clone()) {
            tls.reload_from_pem_file(cert, key).await?;
        }
        Ok(())
    }
}
fn error(error: io::Error) -> Response {
    let status = if error.kind() == io::ErrorKind::AlreadyExists {
        StatusCode::CONFLICT
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, Json(serde_json::json!({"error":error.to_string()}))).into_response()
}
fn secret_response<T: Serialize>(value: T) -> Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
pub fn router<S: Clone + Send + Sync + 'static>(state: Arc<Control>) -> Router<S> {
    Router::new()
        .route("/api/config", get(config_get).put(config_set))
        .route("/api/modules", get(modules))
        .route("/api/onboarding", get(onboarding))
        .route("/api/onboarding/collector", post(setup))
        .route("/api/onboarding/package", post(package))
        .route(
            "/api/agents/{id}/config",
            get(agent_config_get).put(agent_config),
        )
        .route("/api/pki", get(pki_status))
        .route("/api/pki/renew", post(pki_renew))
        .route("/api/pki/prepare", post(pki_prepare))
        .route("/api/pki/activate", post(pki_activate))
        .route("/api/rules", get(rules_get).put(rules_set))
        .route("/api/rules/test", post(rule_test))
        .route("/api/cases", get(cases_get).put(cases_set))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(state)
}
pub fn remote_router(state: Arc<Control>) -> Router {
    Router::new()
        .route("/ingest/v1/enroll", post(enroll))
        .layer(DefaultBodyLimit::max(4096))
        .with_state(state)
}
async fn config_get(State(c): State<Arc<Control>>) -> Json<Config> {
    Json(c.config.read().await.clone())
}
async fn config_set(State(c): State<Arc<Control>>, Json(config): Json<Config>) -> Response {
    let _gate = c.maintenance.read().await;
    let mut current = c.config.write().await;
    match config.save(&c.root.join("config.json")) {
        Ok(()) => {
            *current = config;
            c.generation
                .fetch_add(1, std::sync::atomic::Ordering::Release);
            Json(serde_json::json!({"saved":true,"restart_required":false})).into_response()
        }
        Err(e) => error(e),
    }
}
async fn modules(State(c): State<Arc<Control>>) -> Json<serde_json::Value> {
    Json(
        serde_json::json!({"catalog":crate::modules::catalog(&*c.config.read().await),"health":c.module_health.read().await.values().cloned().collect::<Vec<_>>()}),
    )
}
async fn onboarding(State(c): State<Arc<Control>>) -> Json<serde_json::Value> {
    let default_host = std::net::UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|socket| {
            socket.connect("192.0.2.1:9").ok()?;
            socket.local_addr().ok().map(|a| a.ip().to_string())
        })
        .unwrap_or_else(|| "127.0.0.1".into());
    let saved = crate::service::read_private(&c.root.join("listener.json"), 4096)
        .ok()
        .and_then(|b| serde_json::from_slice::<Listener>(&b).ok());
    Json(
        serde_json::json!({"listener":c.listener.lock().await.clone(),"saved":saved,"default_port":9711,"default_host":default_host,"platform":std::env::consts::OS,"pki":c.pki.lock().unwrap_or_else(|e|e.into_inner()).certificate_warning().ok()}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    bind: String,
    host: String,
}
async fn setup(State(c): State<Arc<Control>>, Json(params): Json<Setup>) -> Response {
    let _gate = c.maintenance.read().await;
    let _update = c.pki_update.lock().await;
    if c.listener.lock().await.is_some() {
        return error(service::invalid(
            "ingest listener is already running; its address can be changed at next restart",
        ));
    }
    let address: std::net::SocketAddr = match params.bind.parse() {
        Ok(a) => a,
        Err(_) => return error(service::invalid("invalid bind")),
    };
    let host = if params.host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]", params.host)
    } else {
        params.host.clone()
    };
    let listener = Listener {
        bind: address.to_string(),
        server: format!("https://{host}:{}", address.port()),
    };
    let provision = {
        let pki = c.pki.lock().unwrap_or_else(|e| e.into_inner());
        match pki.status() {
            Ok(Some(state)) if state.hosts.contains(&params.host) => Ok(state),
            Ok(_) => pki.provision(vec![params.host], false),
            Err(error) => Err(error),
        }
    };
    if let Err(e) = provision {
        return error(e);
    }
    if let Err(e) = c.enable(listener.clone()).await {
        return error(e);
    }
    match service::write_private(
        &c.root.join("listener.json"),
        &serde_json::to_vec_pretty(&listener).unwrap_or_default(),
    ) {
        Ok(()) => Json(listener).into_response(),
        Err(e) => error(e),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageParams {
    name: String,
    #[serde(default)]
    config: Option<Config>,
}
async fn package(State(c): State<Arc<Control>>, Json(params): Json<PackageParams>) -> Response {
    let _gate = c.maintenance.read().await;
    let server = match c.listener.lock().await.as_ref() {
        Some(l) => l.server.clone(),
        None => {
            return error(service::invalid(
                "configure and start the collector listener first",
            ));
        }
    };
    let Some(enrollment) = &c.enrollment else {
        return error(service::invalid("agent registry unavailable"));
    };
    let ca = match c
        .pki
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .trust_bundle()
    {
        Ok(ca) => ca,
        Err(e) => return error(e),
    };
    match enrollment.issue(&params.name, &server, ca, params.config.unwrap_or_default()) {
        Ok(p) => secret_response(p),
        Err(e) => error(e),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Redeem {
    enrollment: String,
}
async fn enroll(State(c): State<Arc<Control>>, Json(params): Json<Redeem>) -> Response {
    let _gate = c.maintenance.read().await;
    match c
        .enrollment
        .as_ref()
        .ok_or_else(|| service::invalid("enrollment unavailable"))
        .and_then(|e| e.redeem(&params.enrollment))
    {
        Ok(result) => secret_response(result),
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"enrollment expired, invalid or already used"})),
        )
            .into_response(),
    }
}
async fn agent_config(
    State(c): State<Arc<Control>>,
    Path(id): Path<String>,
    Json(config): Json<Config>,
) -> Response {
    let _gate = c.maintenance.read().await;
    match c
        .registry
        .as_ref()
        .ok_or_else(|| service::invalid("registry unavailable"))
        .and_then(|r| r.configure_agent(&id, config))
    {
        Ok(true) => Json(serde_json::json!({"saved":true})).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => error(e),
    }
}
async fn agent_config_get(State(c): State<Arc<Control>>, Path(id): Path<String>) -> Response {
    match c
        .registry
        .as_ref()
        .and_then(|r| r.list().into_iter().find(|a| a.id == id))
    {
        Some(agent) => Json(
            serde_json::json!({"config":agent.desired_config,"generation":agent.config_generation}),
        )
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
async fn pki_status(State(c): State<Arc<Control>>) -> Response {
    match c
        .pki
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .certificate_warning()
    {
        Ok(state) => Json(state).into_response(),
        Err(e) => error(e),
    }
}
async fn pki_renew(State(c): State<Arc<Control>>) -> Response {
    match c.renew().await {
        Ok(state) => Json(state).into_response(),
        Err(e) => error(e),
    }
}

async fn pki_prepare(State(c): State<Arc<Control>>) -> Response {
    let _gate = c.maintenance.read().await;
    let _update = c.pki_update.lock().await;
    match c
        .pki
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .prepare_rotation()
    {
        Ok(state) => Json(state).into_response(),
        Err(e) => error(e),
    }
}
async fn pki_activate(State(c): State<Arc<Control>>) -> Response {
    let _gate = c.maintenance.read().await;
    let _update = c.pki_update.lock().await;
    let activated = (|| -> io::Result<crate::pki::PkiState> {
        let pki = c.pki.lock().unwrap_or_else(|e| e.into_inner());
        let state = pki
            .status()?
            .ok_or_else(|| service::invalid("PKI unavailable"))?;
        if state.pending_ca.is_none() {
            return Err(service::invalid("prepare CA rotation first"));
        }
        let digest = crate::ingest::hex(&crate::ingest::sha256(pki.trust_bundle()?.as_bytes()));
        let waiting: Vec<_> = c
            .registry
            .as_ref()
            .map(|r| {
                r.list()
                    .into_iter()
                    .filter(|a| {
                        !a.revoked
                            && a.token_expires_unix.is_none_or(|t| t > crate::pki::now())
                            && a.telemetry
                                .as_ref()
                                .is_none_or(|h| h.trust_sha256 != digest)
                    })
                    .map(|a| a.name)
                    .collect()
            })
            .unwrap_or_default();
        if !waiting.is_empty() {
            return Err(service::invalid(&format!(
                "waiting for trust acknowledgement from: {}",
                waiting.join(", ")
            )));
        }
        pki.provision(state.hosts, true)
    })();
    match activated {
        Ok(state) => match c.reload_tls().await {
            Ok(()) => Json(state).into_response(),
            Err(e) => error(e),
        },
        Err(e) => error(e),
    }
}
async fn rules_get(State(c): State<Arc<Control>>) -> Json<serde_json::Value> {
    let rules = c.rules.lock().unwrap_or_else(|e| e.into_inner());
    Json(serde_json::json!({"file":rules.file,"health":rules.engine.health()}))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesUpdate {
    generation: u64,
    rules: Vec<rules::Rule>,
}
async fn rules_set(State(c): State<Arc<Control>>, Json(update): Json<RulesUpdate>) -> Response {
    let _gate = c.maintenance.read().await;
    match c
        .rules
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .replace(update.generation, update.rules)
    {
        Ok(()) => Json(serde_json::json!({"saved":true})).into_response(),
        Err(e) => error(e),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleTest {
    rules: Vec<rules::Rule>,
    events: Vec<crate::model::Event>,
}
async fn rule_test(Json(test): Json<RuleTest>) -> Response {
    match tokio::task::spawn_blocking(move || rules::replay(test.rules, test.events)).await {
        Ok(Ok(result)) => Json(result).into_response(),
        Ok(Err(e)) => error(e),
        Err(_) => error(io::Error::other("rule test worker failed")),
    }
}
async fn cases_get(State(c): State<Arc<Control>>) -> Json<Vec<rules::Case>> {
    Json(c.cases.lock().unwrap_or_else(|e| e.into_inner()).clone())
}
async fn cases_set(
    State(c): State<Arc<Control>>,
    Json(mut cases): Json<Vec<rules::Case>>,
) -> Response {
    let _gate = c.maintenance.read().await;
    for case in &mut cases {
        case.updated_at = chrono::Utc::now().to_rfc3339();
    }
    match rules::save_cases(&c.root.join("cases.json"), &cases) {
        Ok(()) => {
            *c.cases.lock().unwrap_or_else(|e| e.into_inner()) = cases;
            Json(serde_json::json!({"saved":true})).into_response()
        }
        Err(e) => error(e),
    }
}
