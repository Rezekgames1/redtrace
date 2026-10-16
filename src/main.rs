use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response, Sse,
        sse::{Event as SseEvent, KeepAlive},
    },
    routing::{get, post},
};
use futures_util::StreamExt;
use redtrace::{
    audit::windows,
    collector::{self, SourceStatus},
    detection::{Alert, AlertLog, DetectionEngine, DetectionHealth},
    index::{
        EventIndex, EventSnapshot, ExecutionLimits, QueryBudget, QueryCancellation, QueryFailure,
        QueryMatches, QueryPage, QueryUsage, query_failure,
    },
    ingest::{
        self, AgentPublic, AgentRegistry, CreatedAgent, IngestState, IngestStats,
        IssuedAgentCredential, RotateAgentParams,
    },
    live::LiveUpdates,
    model::Event,
    privacy, query,
    service::{self, LocalSession, SessionIdentity, SessionPublication, Shutdown},
    storage::{CheckpointStore, QuarantineStats, SegmentStore, Wal},
    time_range::{TimeRange, TimeRangeParams},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{self, Write},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore, mpsc};
use tokio::time::timeout;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

const QUEUE_BOUND: usize = 512;
const INGEST_BATCH: usize = 256;
const SEGMENT_TARGET_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ALERTS_MEMORY: usize = 10_000;
const API_TOKEN_HEADER: &str = "x-redtrace-token";

#[derive(Clone)]
struct ApiAuth {
    token: Option<Arc<str>>,
}

#[derive(Clone)]
struct AppState {
    control: Arc<redtrace::control::Control>,
    shutdown: Shutdown,
    session: Arc<SessionIdentity>,
    retention: Arc<RwLock<RetentionHealth>>,
    live: LiveUpdates,
    query_limits: query::QueryLimits,
    query_executor: Arc<QueryExecutor>,
    query_snapshot: Arc<RwLock<()>>,
    index: Arc<RwLock<EventIndex>>,
    known_uids: Arc<RwLock<HashSet<String>>>,
    source: Arc<RwLock<SourceStatus>>,
    wal: Arc<Wal>,
    segments: Arc<SegmentStore>,
    checkpoints: Arc<CheckpointStore>,
    detector: Arc<Mutex<DetectionEngine>>,
    alert_log: Arc<AlertLog>,
    alerts: Arc<RwLock<Vec<Alert>>>,
    collect_lock: Arc<Mutex<()>>,
    agents: Option<Arc<AgentRegistry>>,
    ingest_stats: Arc<RwLock<IngestStats>>,
    ingest_bind: Option<String>,
    corrupted_wal_records: usize,
    wal_quarantine: Arc<RwLock<QuarantineStats>>,
    corrupted_segments: usize,
    corrupted_segment_indexes: usize,
    corrupted_alert_records: usize,
    started: Instant,
    events: mpsc::Sender<Event>,
    stats: Arc<RwLock<IngestionStats>>,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    service: &'static str,
    data_mode: &'static str,
    events_indexed: usize,
    uptime_seconds: u64,
    source: SourceStatus,
    storage: StorageHealth,
    ingestion: IngestionHealth,
    remote_ingest: IngestHealthReport,
    query_limits: query::QueryLimits,
    query_execution: QueryExecutionHealth,
    detection: DetectionHealth,
}

struct QueryExecutor {
    limits: ExecutionLimits,
    permits: Arc<Semaphore>,
    metrics: std::sync::Mutex<QueryMetrics>,
}

#[derive(Default, Clone, Serialize)]
struct QueryMetrics {
    active: usize,
    started: u64,
    completed: u64,
    rejected_busy: u64,
    deadline_exceeded: u64,
    timed_out_requests: u64,
    cancelled: u64,
    budget_exceeded: u64,
    failed: u64,
    last_usage: QueryUsage,
}

#[derive(Serialize)]
struct QueryExecutionHealth {
    limits: ExecutionLimits,
    metrics: QueryMetrics,
}

impl QueryExecutor {
    fn new(limits: ExecutionLimits) -> Self {
        Self {
            limits,
            permits: Arc::new(Semaphore::new(limits.max_concurrent)),
            metrics: std::sync::Mutex::new(QueryMetrics::default()),
        }
    }

    fn health(&self) -> QueryExecutionHealth {
        QueryExecutionHealth {
            limits: self.limits,
            metrics: self
                .metrics
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone(),
        }
    }

    fn acquire(self: &Arc<Self>) -> Result<QuerySlot, QueryApiError> {
        let permit = self.permits.clone().try_acquire_owned();
        let mut metrics = self
            .metrics
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Ok(permit) = permit else {
            metrics.rejected_busy += 1;
            return Err(QueryApiError::Busy);
        };
        metrics.active += 1;
        metrics.started += 1;
        Ok(QuerySlot {
            executor: self.clone(),
            _permit: permit,
            finished: false,
        })
    }
}

struct QuerySlot {
    executor: Arc<QueryExecutor>,
    _permit: OwnedSemaphorePermit,
    finished: bool,
}

impl QuerySlot {
    fn finish<T>(&mut self, result: &io::Result<T>, usage: QueryUsage) {
        let mut metrics = self
            .executor
            .metrics
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        metrics.last_usage = usage;
        match result {
            Ok(_) => metrics.completed += 1,
            Err(error) => match query_failure(error) {
                Some(QueryFailure::Deadline) => metrics.deadline_exceeded += 1,
                Some(QueryFailure::Cancelled) => metrics.cancelled += 1,
                Some(_) => metrics.budget_exceeded += 1,
                None => metrics.failed += 1,
            },
        }
        self.finished = true;
    }
}

impl Drop for QuerySlot {
    fn drop(&mut self) {
        let mut metrics = self
            .executor
            .metrics
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        metrics.active = metrics.active.saturating_sub(1);
        if !self.finished {
            metrics.cancelled += 1;
        }
    }
}

struct CancelQueryOnDrop(QueryCancellation);

impl Drop for CancelQueryOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[derive(Debug)]
enum QueryApiError {
    Busy,
    Execution(io::Error),
}

impl QueryApiError {
    fn response(self) -> Response {
        let (status, message, reason) = match self {
            Self::Busy => (
                StatusCode::TOO_MANY_REQUESTS,
                "query concurrency limit reached",
                None,
            ),
            Self::Execution(error) => match query_failure(&error) {
                Some(reason @ (QueryFailure::Deadline | QueryFailure::Cancelled)) => (
                    StatusCode::REQUEST_TIMEOUT,
                    "query execution deadline or cancellation",
                    Some(reason),
                ),
                Some(reason) => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "query execution budget exceeded",
                    Some(reason),
                ),
                None => {
                    tracing::warn!(%error, "query execution failed");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "query execution failed",
                        None,
                    )
                }
            },
        };
        (
            status,
            Json(serde_json::json!({ "error": message, "reason": reason })),
        )
            .into_response()
    }
}

async fn execute_query<T: Send + 'static>(
    state: AppState,
    work: impl FnOnce(EventSnapshot, Arc<SegmentStore>, &mut QueryBudget) -> io::Result<T>
    + Send
    + 'static,
) -> Result<T, QueryApiError> {
    let mut slot = state.query_executor.acquire()?;
    let mut budget = QueryBudget::new(state.query_executor.limits);
    let _cancel = CancelQueryOnDrop(budget.cancellation());
    let duration = Duration::from_millis(budget.limits.deadline_ms);
    let executor = state.query_executor.clone();
    match timeout(duration, async move {
        let snapshot_guard = state.query_snapshot.clone().read_owned().await;
        if let Err(error) = budget.check() {
            let result: io::Result<T> = Err(error);
            slot.finish(&result, budget.usage);
            return result;
        }
        let snapshot = state.index.read().await.snapshot(&mut budget);
        let snapshot = match snapshot {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let result: io::Result<T> = Err(error);
                slot.finish(&result, budget.usage);
                return result;
            }
        };
        tokio::task::spawn_blocking(move || {
            let result = budget
                .check()
                .and_then(|()| work(snapshot, state.segments, &mut budget))
                .and_then(|value| {
                    budget.check()?;
                    Ok(value)
                });
            slot.finish(&result, budget.usage);
            drop(snapshot_guard);
            result
        })
        .await
        .map_err(|_| io::Error::other("query worker failed"))?
    })
    .await
    {
        Ok(result) => result.map_err(QueryApiError::Execution),
        Err(_) => {
            executor
                .metrics
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .timed_out_requests += 1;
            Err(QueryApiError::Execution(io::Error::other(
                QueryFailure::Deadline,
            )))
        }
    }
}

struct QueryOutput<'a> {
    bytes: Vec<u8>,
    budget: &'a mut QueryBudget,
    failure: Option<QueryFailure>,
}

impl Write for QueryOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Err(error) = self
            .budget
            .scan(bytes.len() as u64)
            .and_then(|()| self.budget.allocate(bytes.len().saturating_mul(2)))
        {
            self.failure = query_failure(&error);
            return Err(error);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.budget.check()
    }
}

fn query_json(value: &impl Serialize, budget: &mut QueryBudget) -> io::Result<Response> {
    let mut output = QueryOutput {
        bytes: Vec::new(),
        budget,
        failure: None,
    };
    if let Err(error) = serde_json::to_writer(&mut output, value) {
        return Err(output
            .failure
            .map(io::Error::other)
            .unwrap_or_else(|| io::Error::other(error)));
    }
    Ok(([(header::CONTENT_TYPE, "application/json")], output.bytes).into_response())
}

#[cfg(test)]
fn visit_query(
    snapshot: &EventSnapshot,
    segments: &SegmentStore,
    expression: &query::Expr,
    budget: &mut QueryBudget,
    mut visitor: impl FnMut(&Event, &mut QueryBudget) -> io::Result<()>,
) -> io::Result<usize> {
    let mut matches = QueryMatches::new();
    let mut unique = |event: &Event, budget: &mut QueryBudget| {
        if matches.accept(event, budget)? {
            visitor(event, budget)?;
        }
        Ok(())
    };
    segments.search_into(expression, budget, &mut unique)?;
    snapshot.visit(expression, budget, &mut unique)?;
    Ok(matches.total())
}

fn visit_time_query(
    snapshot: &EventSnapshot,
    segments: &SegmentStore,
    expression: &query::Expr,
    budget: &mut QueryBudget,
    range: &TimeRange,
    mut visitor: impl FnMut(&Event, &mut QueryBudget) -> io::Result<()>,
) -> io::Result<usize> {
    let mut matches = QueryMatches::new();
    let mut total = 0;
    let mut unique = |event: &Event, budget: &mut QueryBudget| {
        budget.work(1)?;
        if matches.accept(event, budget)?
            && !event.fields.contains_key("event.filtered")
            && range.contains(&event.timestamp)
        {
            total += 1;
            visitor(event, budget)?;
        }
        Ok(())
    };
    segments.search_into_time_range(expression, budget, range, &mut unique)?;
    snapshot.visit(expression, budget, &mut unique)?;
    Ok(total)
}

#[derive(Serialize)]
struct IngestHealthReport {
    budget: Option<ingest::IngestBudgetHealth>,
    enabled: bool,
    bind: Option<String>,
    agents_total: usize,
    agents_active: usize,
    remote_events_total: u64,
    duplicate_events_total: u64,
    rejected_batches: u64,
    heartbeats_total: u64,
    last_remote_event_at: Option<String>,
}

#[derive(Serialize)]
struct StorageHealth {
    retention: RetentionHealth,
    wal_quarantine: QuarantineStats,
    wal_bytes: u64,
    segment_bytes: u64,
    segment_count: usize,
    corrupted_records: usize,
    corrupted_segments: usize,
    corrupted_segment_indexes: usize,
    checkpoint_sources: usize,
    alert_records: usize,
    corrupted_alert_records: usize,
}

#[derive(Clone, Default, Serialize)]
struct RetentionHealth {
    runs: u64,
    changes: u64,
    failures: u64,
    cap_failures: u64,
    last_success_unix: Option<u64>,
    last_failure: Option<&'static str>,
}

#[derive(Default, Serialize, Clone)]
struct IngestionStats {
    ingested_total: usize,
    dropped_events: usize,
    wal_errors: usize,
    segment_errors: usize,
    checkpoint_errors: usize,
    detection_errors: usize,
    alerts_created: usize,
    last_event_at: Option<String>,
}

#[derive(Serialize)]
struct IngestionHealth {
    queue_depth: usize,
    queue_bound: usize,
    ingested_total: usize,
    dropped_events: usize,
    wal_errors: usize,
    segment_errors: usize,
    checkpoint_errors: usize,
    detection_errors: usize,
    alerts_created: usize,
    last_event_at: Option<String>,
}

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
    #[serde(flatten)]
    range: TimeRangeParams,
}

#[derive(Deserialize)]
struct AlertParams {
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct ExportParams {
    q: Option<String>,
    format: Option<String>,
    limit: Option<usize>,
    #[serde(flatten)]
    range: TimeRangeParams,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "redtrace=info,tower_http=info".into()),
        )
        .compact()
        .init();

    if let Err(error) = service_entry() {
        tracing::error!(%error, "collector startup or shutdown failed");
        std::process::exit(2);
    }
}

fn service_entry() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let mut scm = false;
    let mut configured = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--persistent" => unsafe {
                std::env::set_var("REDTRACE_SERVICE_MODE", "persistent");
            },
            "--windows-service" => scm = true,
            "--config" => {
                index += 1;
                let path = arguments
                    .get(index)
                    .ok_or_else(|| service::invalid("missing service configuration"))?;
                service::ServiceConfig::load(std::path::Path::new(path))?.apply();
                configured = true;
            }
            _ => {
                return Err(service::invalid(
                    "usage: redtrace [--persistent] [--windows-service] [--config ABSOLUTE_PRIVATE_JSON]",
                ));
            }
        }
        index += 1;
    }
    if scm && !configured {
        return Err(service::invalid(
            "SCM mode requires an explicit private configuration",
        ));
    }
    let run = |shutdown| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(run_collector(shutdown))
    };
    #[cfg(windows)]
    if scm {
        return service::windows::dispatch("REDTRACE", run);
    }
    #[cfg(not(windows))]
    if scm {
        return Err(service::invalid(
            "Windows SCM mode is unavailable on this platform",
        ));
    }
    run(Shutdown::new())
}

async fn run_collector(shutdown: Shutdown) -> io::Result<()> {
    let persistent = match std::env::var("REDTRACE_SERVICE_MODE").as_deref() {
        Ok("persistent") => true,
        Ok("portable") | Err(_) => false,
        _ => return Err(service::invalid("invalid service mode")),
    };
    let address = service::api_bind(
        &std::env::var("REDTRACE_API_BIND").unwrap_or_else(|_| "127.0.0.1:9710".into()),
    )?;
    let mut token: Option<Arc<str>> = if persistent {
        Some(Arc::from(service::random_secret()?))
    } else {
        match std::env::var("REDTRACE_API_TOKEN") {
            Ok(token)
                if token.len() >= 32
                    && token.len() <= 4096
                    && token.is_ascii()
                    && !token
                        .bytes()
                        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace()) =>
            {
                Some(Arc::from(token))
            }
            Err(_) if std::env::var("REDTRACE_ALLOW_UNAUTHENTICATED").as_deref() == Ok("1") => None,
            _ => return Err(service::invalid("a valid local API token is required")),
        }
    };
    let listener = tokio::net::TcpListener::bind(address).await?;
    let address = listener.local_addr()?;
    if persistent {
        service::protected_binary(&std::env::current_exe()?)?;
        service::private_directory(&std::path::PathBuf::from(
            std::env::var_os("REDTRACE_DATA_DIR").ok_or_else(|| {
                service::invalid("persistent mode requires an explicit REDTRACE_DATA_DIR")
            })?,
        ))?;
    }
    let signal_task = shutdown.listen();

    let query_limits = match query::QueryLimits::from_env() {
        Ok(limits) => limits,
        Err(error) => {
            tracing::error!(%error, "invalid query configuration");
            std::process::exit(2);
        }
    };
    let execution_limits = match ExecutionLimits::from_env() {
        Ok(limits) => limits,
        Err(error) => {
            tracing::error!(%error, "invalid query execution configuration");
            std::process::exit(2);
        }
    };
    let data_directory = std::path::absolute(redtrace::storage::data_directory())?;
    if !data_directory.exists() {
        service::private_directory(&data_directory)?;
    }
    let wal = match Wal::open_default() {
        Ok(wal) => wal,
        Err(error) => {
            tracing::error!(%error, "cannot acquire local WAL ownership");
            std::process::exit(2);
        }
    };
    if persistent {
        let data = std::path::PathBuf::from(
            std::env::var_os("REDTRACE_DATA_DIR")
                .ok_or_else(|| service::invalid("persistent data directory is required"))?,
        );
        token = Some(Arc::from(service::persistent_secret(&data)?));
    }
    let wal_recovery = match wal.recover_with_repair() {
        Ok(recovery) => recovery,
        Err(error) => {
            tracing::error!(%error, "safe WAL recovery failed; data preserved");
            std::process::exit(2);
        }
    };
    let wal_quarantine = Arc::new(RwLock::new(
        wal.quarantine_stats().expect("read WAL quarantine status"),
    ));
    if wal_recovery.quarantined_records > 0 {
        tracing::warn!(
            quarantined_records = wal_recovery.quarantined_records,
            salvaged_records = wal_recovery.salvaged_records,
            "WAL recovered; original bytes preserved in quarantine"
        );
    }
    let segments = SegmentStore::open_default().expect("open local segment store");
    let agents = match AgentRegistry::open_default() {
        Ok(registry) => Some(Arc::new(registry)),
        Err(error) => {
            tracing::warn!(%error, "could not open agent registry; remote agents disabled");
            None
        }
    };
    if let Some(registry) = &agents {
        registry.confirm_durable(&wal_recovery.events)?;
    }
    let checkpoints = Arc::new(CheckpointStore::open_default().expect("open source checkpoints"));
    let alert_log = Arc::new(AlertLog::open_default().expect("open alert log"));
    let (mut recovered_alerts, corrupted_alert_records) =
        alert_log.recover().expect("recover alert log");
    if recovered_alerts.len() > MAX_ALERTS_MEMORY {
        recovered_alerts.drain(..recovered_alerts.len() - MAX_ALERTS_MEMORY);
    }
    if let Err(error) = segments.ensure_indexes() {
        tracing::warn!(%error, "could not build missing segment indexes");
    }
    let segment_recovery = segments.recover().expect("recover local segments");
    let corrupted_wal_records = wal_recovery.corrupted_records;
    let corrupted_segments = segment_recovery.corrupted_segments;
    let corrupted_segment_indexes = segment_recovery.corrupted_indexes;
    let wal_had_events = !wal_recovery.events.is_empty();
    let segment_uids: HashSet<_> = segment_recovery
        .events
        .iter()
        .map(|event| event.uid.clone())
        .collect();
    let fresh_wal_events: Vec<_> = wal_recovery
        .events
        .iter()
        .filter(|event| !segment_uids.contains(&event.uid))
        .cloned()
        .collect();
    let next_id = segment_recovery
        .events
        .iter()
        .chain(&wal_recovery.events)
        .map(|event| event.id)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    let mut known_uids = segment_uids;
    known_uids.extend(wal_recovery.events.iter().map(|event| event.uid.clone()));
    let mut active_events = fresh_wal_events.clone();
    tracing::info!(
        recovered = known_uids.len(),
        corrupted_wal = corrupted_wal_records,
        corrupted_segments,
        corrupted_segment_indexes,
        segments = segment_recovery.segment_count,
        "storage recovery finished"
    );
    let remote_receipts_ready = agents.is_some()
        || !wal_recovery
            .events
            .iter()
            .any(|event| event.fields.contains_key("agent.id"));
    if corrupted_wal_records == 0 && wal_had_events && remote_receipts_ready {
        match segments.commit(&fresh_wal_events) {
            Ok(_) => {
                if let Err(error) = wal.reset() {
                    tracing::warn!(%error, "could not reset migrated WAL");
                } else {
                    active_events.clear();
                }
            }
            Err(error) => tracing::warn!(%error, "could not migrate recovered WAL to segment"),
        }
    }
    known_uids = segments
        .recover()?
        .events
        .into_iter()
        .map(|event| event.uid)
        .collect();
    known_uids.extend(wal.recover()?.events.into_iter().map(|event| event.uid));
    // Recovery vectors must not remain captured by this long-lived async function.
    drop(segment_recovery);
    drop(wal_recovery);
    drop(fresh_wal_events);

    let (tx, rx) = mpsc::channel::<Event>(QUEUE_BOUND);
    let stats = Arc::new(RwLock::new(IngestionStats::default()));
    let ingest_stats = Arc::new(RwLock::new(IngestStats::default()));
    let mut state = AppState {
        control: Arc::new(redtrace::control::Control::open(
            redtrace::storage::data_directory(),
            agents.clone(),
            shutdown.clone(),
        )?),
        shutdown: shutdown.clone(),
        session: Arc::new(
            LocalSession::new(
                address,
                persistent,
                token.as_deref().unwrap_or_default().into(),
            )?
            .identity,
        ),
        retention: Arc::new(RwLock::new(RetentionHealth::default())),
        live: LiveUpdates::default(),
        query_limits,
        query_executor: Arc::new(QueryExecutor::new(execution_limits)),
        query_snapshot: Arc::new(RwLock::new(())),
        index: Arc::new(RwLock::new(EventIndex::from_events(active_events))),
        known_uids: Arc::new(RwLock::new(known_uids)),
        source: Arc::new(RwLock::new(collector::initial_status())),
        wal: Arc::new(wal),
        segments: Arc::new(segments),
        checkpoints: checkpoints.clone(),
        detector: Arc::new(Mutex::new(DetectionEngine::default())),
        alert_log: alert_log.clone(),
        alerts: Arc::new(RwLock::new(recovered_alerts)),
        collect_lock: Arc::new(Mutex::new(())),
        agents: agents.clone(),
        ingest_stats: ingest_stats.clone(),
        ingest_bind: std::env::var("REDTRACE_INGEST_BIND")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        corrupted_wal_records,
        wal_quarantine,
        corrupted_segments,
        corrupted_segment_indexes,
        corrupted_alert_records,
        started: Instant::now(),
        events: tx.clone(),
        stats: stats.clone(),
    };

    enforce_retention(&state).await;
    *state.control.ingress.write().await = state.agents.as_ref().map(|registry| IngestState {
        registry: registry.clone(),
        events: tx.clone(),
        known_uids: state.known_uids.clone(),
        stats: state.ingest_stats.clone(),
    });
    let session = LocalSession {
        identity: (*state.session).clone(),
        token: token.as_deref().unwrap_or_default().into(),
    };
    let _publication = if persistent {
        let path = std::env::var_os("REDTRACE_SESSION_FILE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| session.identity.data_dir.join("session.json"));
        Some(SessionPublication::publish(path, &session)?)
    } else {
        None
    };

    let ingestion_task = spawn_ingestion(rx, state.clone(), next_id);
    let collection_task = spawn_configured_collection(state.clone());
    let retention_task = spawn_retention(state.clone());
    let certificate_task = spawn_certificate_renewal(state.control.clone());

    let cors = CorsLayer::new()
        .allow_origin([
            HeaderValue::from_static("http://localhost:3000"),
            HeaderValue::from_static("http://127.0.0.1:3000"),
            HeaderValue::from_static("http://localhost:1420"),
            HeaderValue::from_static("http://127.0.0.1:1420"),
            HeaderValue::from_static("tauri://localhost"),
            HeaderValue::from_static("http://tauri.localhost"),
            HeaderValue::from_static("https://tauri.localhost"),
        ])
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([
            header::CONTENT_TYPE,
            HeaderName::from_static(API_TOKEN_HEADER),
        ]);
    let auth = ApiAuth { token };
    let ingest_task = spawn_remote_ingest(tx.clone(), state.clone()).await;
    if ingest_task.is_none() {
        state.ingest_bind = None;
    }
    if let Some(listener) = state.control.listener.lock().await.as_ref() {
        state.ingest_bind = Some(listener.bind.clone());
    }
    let app = Router::new()
        .merge(redtrace::control::router(state.control.clone()))
        .route("/api/session", get(local_session))
        .route("/api/session/stop", post(stop_session))
        .route("/api/health", get(health))
        .route("/api/live", get(live_updates))
        .route("/api/sources", get(sources))
        .route("/api/collect", post(collect_now))
        .route("/api/search", get(search))
        .route("/api/aggregations", get(aggregations))
        .route("/api/alerts", get(alerts))
        .route("/api/detections/rules", get(detection_rules))
        .route("/api/diagnostics", get(diagnostics))
        .route("/api/export", get(export_events))
        .route("/api/backup", post(backup_snapshot))
        .route("/api/rules/replay", post(replay_rules))
        .route("/api/agents", get(agents_list).post(agents_create))
        .route("/api/agents/{id}", axum::routing::delete(agents_revoke))
        .route("/api/agents/{id}/rotate", post(agents_rotate))
        .route("/api/audit/windows/plan", get(windows_audit_plan))
        .route("/api/audit/windows/status", get(windows_audit_status))
        .layer(middleware::from_fn_with_state(auth, authorize_api))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    tracing::info!(%address, "RED//TRACE local API started");
    #[cfg(windows)]
    service::windows::ready();

    let api_shutdown = shutdown.clone();
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(async move { api_shutdown.wait().await })
        .await;
    shutdown.request();
    if let Some(task) = ingest_task {
        let _ = task.await;
    }
    collection_task.abort();
    let _ = collection_task.await;
    let _ = retention_task.await;
    let _ = certificate_task.await;
    drop(tx);
    let mut ingestion_task = ingestion_task;
    match timeout(Duration::from_secs(30), &mut ingestion_task).await {
        Ok(Ok(Ok(()))) => tracing::info!("ingestion queue drained"),
        Ok(Ok(Err(error))) => return Err(error),
        Ok(Err(_)) => return Err(io::Error::other("ingestion task stopped unexpectedly")),
        Err(_) => {
            ingestion_task.abort();
            let _ = ingestion_task.await;
            return Err(io::Error::other(
                "ingestion queue drain timed out; durable WAL preserved",
            ));
        }
    }
    signal_task.abort();
    served
}

async fn spawn_remote_ingest(
    tx: mpsc::Sender<Event>,
    state: AppState,
) -> Option<tokio::task::JoinHandle<()>> {
    let listener_path = state.control.root.join("listener.json");
    if listener_path.exists() {
        match service::read_private(&listener_path, 4096).and_then(|bytes| {
            serde_json::from_slice::<redtrace::control::Listener>(&bytes).map_err(io::Error::other)
        }) {
            Ok(listener) => match state.control.enable(listener).await {
                Ok(()) => return None,
                Err(error) => {
                    tracing::error!(%error,"configured ingest unavailable");
                    return None;
                }
            },
            Err(error) => {
                tracing::error!(%error,"invalid stored ingest configuration");
                return None;
            }
        }
    }
    let bind = std::env::var("REDTRACE_INGEST_BIND")
        .ok()
        .filter(|value| !value.trim().is_empty())?;
    let address: std::net::SocketAddr = match bind.trim().parse() {
        Ok(address) => address,
        Err(error) => {
            tracing::error!(%error, "ingest bind must be an IP socket address");
            return None;
        }
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = match (
        std::env::var_os("REDTRACE_INGEST_CERT"),
        std::env::var_os("REDTRACE_INGEST_KEY"),
    ) {
        (Some(cert), Some(key)) => {
            match axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await {
                Ok(config) => Some(config),
                Err(error) => {
                    tracing::error!(%error, "cannot load ingest TLS certificate");
                    return None;
                }
            }
        }
        (None, None) if address.ip().is_loopback() => None,
        _ => {
            tracing::error!(
                "non-loopback ingest requires REDTRACE_INGEST_CERT and REDTRACE_INGEST_KEY"
            );
            return None;
        }
    };
    let Some(registry) = state.agents.clone() else {
        tracing::error!("REDTRACE_INGEST_BIND is set but the agent registry is unavailable");
        return None;
    };
    let ingest_state = IngestState {
        registry,
        events: tx,
        known_uids: state.known_uids.clone(),
        stats: state.ingest_stats.clone(),
    };
    let router = ingest::ingest_router(ingest_state);
    let listener = match tokio::net::TcpListener::bind(bind.trim()).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(%error, bind = bind.trim(), "could not bind remote ingest listener");
            return None;
        }
    };
    tracing::info!(
        bind = bind.trim(),
        tls = tls.is_some(),
        "agent ingest enabled"
    );
    Some(tokio::spawn(async move {
        let shutdown_signal = state.shutdown.clone();
        if let Some(tls) = tls {
            let handle = axum_server::Handle::new();
            let shutdown = handle.clone();
            let signal = tokio::spawn(async move {
                shutdown_signal.wait().await;
                shutdown.graceful_shutdown(Some(Duration::from_secs(5)));
            });
            match listener.into_std() {
                Ok(listener) => match axum_server::from_tcp_rustls(listener, tls) {
                    Ok(server) => {
                        if let Err(error) = server
                            .handle(handle)
                            .serve(router.into_make_service())
                            .await
                        {
                            tracing::error!(%error, "TLS ingest stopped");
                        }
                    }
                    Err(error) => tracing::error!(%error, "TLS listener initialization failed"),
                },
                Err(error) => tracing::error!(%error, "TLS listener conversion failed"),
            }
            signal.abort();
            return;
        }
        if let Err(error) = axum::serve(listener, router)
            .with_graceful_shutdown(async move { shutdown_signal.wait().await })
            .await
        {
            tracing::error!(%error, "remote ingest server stopped unexpectedly");
        }
    }))
}

fn spawn_certificate_renewal(
    control: Arc<redtrace::control::Control>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = control.shutdown.wait() => break,
                _ = interval.tick() => {
                    let due = control.pki.lock().unwrap_or_else(|e| e.into_inner())
                        .status().ok().flatten().is_some_and(|s| s.server_expires <= redtrace::pki::now().saturating_add(14 * 86400));
                    if due && let Err(error) = control.renew().await {
                        tracing::warn!(%error, "certificate renewal deferred");
                    }
                }
            }
        }
    })
}

async fn authorize_api(State(auth): State<ApiAuth>, request: Request, next: Next) -> Response {
    let Some(expected) = auth.token.as_deref() else {
        if request.uri().path() == "/api/agents"
            || request.uri().path().starts_with("/api/agents/")
            || request.uri().path().starts_with("/api/session")
            || request.uri().path().starts_with("/api/config")
            || request.uri().path().starts_with("/api/onboarding")
            || request.uri().path().starts_with("/api/pki")
            || request.uri().path().starts_with("/api/rules")
            || request.uri().path().starts_with("/api/cases")
            || request.uri().path().starts_with("/api/backup")
        {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "authenticated local session required"})),
            )
                .into_response();
        }
        return next.run(request).await;
    };
    let supplied = request
        .headers()
        .get(API_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if ingest::constant_time_equal(expected.as_bytes(), supplied.as_bytes()) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid local session token" })),
        )
            .into_response()
    }
}

fn spawn_ingestion(
    mut rx: mpsc::Receiver<Event>,
    state: AppState,
    mut next_id: u64,
) -> tokio::task::JoinHandle<io::Result<()>> {
    let shutdown = state.shutdown;
    let live = state.live;
    let wal = state.wal;
    let wal_quarantine = state.wal_quarantine;
    let segments = state.segments;
    let checkpoints = state.checkpoints;
    let detector = state.detector;
    let alert_log = state.alert_log;
    let alerts = state.alerts;
    let index = state.index;
    let known_uids = state.known_uids;
    let source = state.source;
    let stats = state.stats;
    let query_snapshot = state.query_snapshot;
    let registry = state.agents;
    let control = state.control;
    tokio::spawn(async move {
        let mut buffer = Vec::with_capacity(INGEST_BATCH);
        let mut filter_config = control.config.read().await.clone();
        let mut filter = redtrace::config::EventFilter::new(&filter_config)?;
        loop {
            buffer.clear();
            let received = tokio::select! {
                received = rx.recv_many(&mut buffer, INGEST_BATCH) => received,
                _ = shutdown.wait(), if !rx.is_closed() => {
                    rx.close();
                    rx.recv_many(&mut buffer, INGEST_BATCH).await
                }
            };
            if received == 0 {
                tracing::info!("ingestion channel closed");
                return Ok(());
            }
            let _maintenance = control.maintenance.read().await;
            let config = control.config.read().await.clone();
            if config != filter_config {
                filter = redtrace::config::EventFilter::new(&config)?;
                filter_config = config.clone();
            }
            for event in buffer.iter_mut() {
                redtrace::modules::normalize(event);
                if !event.fields.contains_key("agent.id") && !filter.accepts(event) {
                    event.fields.retain(|k, _| k.starts_with("collector."));
                    event.fields.insert("event.filtered".into(), "true".into());
                    event.message = "Event excluded by collection policy".into();
                }
                event.id = next_id;
                next_id += 1;
            }
            let cursor_events: Vec<_> = buffer
                .iter()
                .filter(|e| e.fields.contains_key("collector.cursor"))
                .map(|e| Event {
                    id: e.id,
                    uid: e.uid.clone(),
                    schema_version: e.schema_version,
                    timestamp: e.timestamp.clone(),
                    source: e.source.clone(),
                    level: "low".into(),
                    message: String::new(),
                    fields: e
                        .fields
                        .iter()
                        .filter(|(k, _)| k.starts_with("collector."))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                })
                .collect();
            let known = known_uids.read().await;
            let mut batch_uids = HashSet::new();
            let fresh: Vec<_> = buffer
                .drain(..)
                .filter(|event| !known.contains(&event.uid) && batch_uids.insert(event.uid.clone()))
                .collect();
            drop(known);
            if fresh.is_empty() {
                if let Err(error) = checkpoints.update_events(&cursor_events) {
                    tracing::error!(%error,"duplicate durable cursor update failed");
                    stats.write().await.checkpoint_errors += 1;
                }
                continue;
            }
            let mut wal_failed = false;
            loop {
                match wal.append(&fresh) {
                    Ok(()) => break,
                    Err(error) => {
                        if !wal_failed {
                            tracing::error!(%error, "WAL append failed; batch retained for retry");
                            stats.write().await.wal_errors += 1;
                            wal_failed = true;
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_millis(250)) => {},
                            _ = shutdown.wait() => return Err(io::Error::other("WAL unavailable during drain; unacknowledged sources must replay")),
                        }
                    }
                }
            }
            known_uids
                .write()
                .await
                .extend(fresh.iter().map(|event| event.uid.clone()));
            if let Some(registry) = &registry {
                loop {
                    match registry.confirm_durable(&fresh) {
                        Ok(()) => break,
                        Err(error) => {
                            tracing::error!(%error, "durable receipt publication failed; WAL retained");
                            stats.write().await.wal_errors += 1;
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                                _ = shutdown.wait() => return Err(io::Error::other("durable receipt unavailable during drain")),
                            }
                        }
                    }
                }
            }
            if let Err(error) = checkpoints.update_events(&cursor_events) {
                tracing::error!(%error, "source checkpoint update failed");
                stats.write().await.checkpoint_errors += 1;
            }
            let detected = {
                let mut detector = detector.lock().await;
                let mut detected = fresh
                    .iter()
                    .filter(|event| !event.fields.contains_key("event.filtered"))
                    .flat_map(|event| {
                        if config.builtin_detections {
                            detector.evaluate(event)
                        } else {
                            Vec::new()
                        }
                    })
                    .collect::<Vec<_>>();
                let mut rules = control.rules.lock().unwrap_or_else(|e| e.into_inner());
                for event in fresh
                    .iter()
                    .filter(|event| !event.fields.contains_key("event.filtered"))
                {
                    detected.extend(rules.engine.evaluate(event, redtrace::pki::now()));
                }
                detected
            };
            if !detected.is_empty() {
                let log = alert_log.clone();
                let journal_alerts = detected.clone();
                let persisted =
                    tokio::task::spawn_blocking(move || log.append(&journal_alerts)).await;
                if matches!(persisted, Ok(Ok(()))) {
                    let mut alerts_guard = alerts.write().await;
                    alerts_guard.extend(detected.iter().cloned());
                    if alerts_guard.len() > MAX_ALERTS_MEMORY {
                        let excess = alerts_guard.len() - MAX_ALERTS_MEMORY;
                        alerts_guard.drain(..excess);
                    }
                    stats.write().await.alerts_created += detected.len();
                } else {
                    match persisted {
                        Ok(Err(error)) => tracing::error!(%error, "alert journal append failed"),
                        Err(error) => tracing::error!(%error, "alert journal task failed"),
                        Ok(Ok(())) => unreachable!(),
                    }
                    stats.write().await.detection_errors += 1;
                }
            }
            let rule_control = control.clone();
            match tokio::task::spawn_blocking(move || {
                rule_control
                    .rules
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .checkpoint()
            })
            .await
            {
                Ok(Ok(())) => {}
                _ => {
                    stats.write().await.detection_errors += 1;
                    tracing::warn!(
                        "custom detection checkpoint failed; durable events can be replayed"
                    );
                }
            }
            let mut last_at = None;
            let mut ingested = 0;
            let mut index_guard = index.write().await;
            for event in fresh {
                last_at = Some(event.timestamp.clone());
                index_guard.push(event);
                ingested += 1;
            }
            let mut stats_guard = stats.write().await;
            stats_guard.ingested_total += ingested;
            if let Some(at) = last_at {
                stats_guard.last_event_at = Some(at);
            }
            source.write().await.events_collected = stats_guard.ingested_total;
            drop(stats_guard);
            drop(index_guard);

            if wal.size_bytes().unwrap_or(0) >= segment_target_bytes() {
                let _query_snapshot = query_snapshot.write().await;
                match wal.recover_with_repair() {
                    Ok(recovery) if recovery.corrupted_records == 0 => {
                        if recovery.quarantined_records > 0 {
                            if let Ok(status) = wal.quarantine_stats() {
                                *wal_quarantine.write().await = status;
                            }
                            tracing::warn!(
                                quarantined_records = recovery.quarantined_records,
                                salvaged_records = recovery.salvaged_records,
                                "damaged WAL isolated before rotation"
                            );
                        }
                        match segments.commit(&recovery.events) {
                            Ok(_) => {
                                if let Err(error) = wal.reset() {
                                    tracing::error!(%error, "WAL reset after segment commit failed");
                                    stats.write().await.segment_errors += 1;
                                } else {
                                    *index.write().await = EventIndex::default();
                                    if let Ok(recovery) = segments.recover() {
                                        *known_uids.write().await = recovery
                                            .events
                                            .into_iter()
                                            .map(|event| event.uid)
                                            .collect();
                                    }
                                }
                            }
                            Err(error) => {
                                tracing::error!(%error, "segment commit failed");
                                stats.write().await.segment_errors += 1;
                            }
                        }
                    }
                    Ok(_) => {
                        tracing::error!("WAL rotation skipped because corruption was detected");
                        stats.write().await.segment_errors += 1;
                    }
                    Err(error) => {
                        tracing::error!(%error, "WAL recovery before rotation failed");
                        stats.write().await.segment_errors += 1;
                    }
                }
            }
            live.notify();
        }
    })
}

async fn live_updates(State(state): State<AppState>) -> impl IntoResponse {
    let shutdown = state.shutdown;
    let updates = state
        .live
        .subscribe()
        .take_until(async move { shutdown.wait().await })
        .map(|revision| {
            Ok::<_, std::convert::Infallible>(
                SseEvent::default()
                    .event("update")
                    .id(revision.to_string())
                    .data(revision.to_string()),
            )
        });
    Sse::new(updates).keep_alive(KeepAlive::new().interval(Duration::from_secs(10)))
}

fn spawn_collection(
    tx: mpsc::Sender<Event>,
    source: Arc<RwLock<SourceStatus>>,
    checkpoints: Arc<CheckpointStore>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let initial_checkpoints = checkpoints.clone();
        match tokio::task::spawn_blocking(move || {
            collector::collect_platform_events(&initial_checkpoints)
        })
        .await
        {
            Ok(batch) => {
                tracing::info!(
                    state = %batch.status.state,
                    events = batch.events.len(),
                    "initial backfill finished"
                );
                let mut initial = batch.status;
                if matches!(initial.state.as_str(), "ready" | "degraded") {
                    initial.state = "backfilling".into();
                }
                *source.write().await = initial;
                for event in batch.events {
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
                while tx.capacity() < tx.max_capacity() {
                    if tx.is_closed() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            Err(error) => tracing::error!(%error, "initial backfill task failed"),
        }
        collector::stream_platform_events(tx, source, checkpoints).await;
    })
}

struct CollectorTask(tokio::task::JoinHandle<()>);
impl Drop for CollectorTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn spawn_configured_collection(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut generation = 0;
        let mut native: Option<CollectorTask> = None;
        let mut extended = match collector::extended::ExtendedCollectors::new(
            state.control.config.read().await.clone(),
        ) {
            Ok(e) => e,
            Err(error) => {
                tracing::error!(%error,"module configuration invalid");
                return;
            }
        };
        loop {
            let next = state
                .control
                .generation
                .load(std::sync::atomic::Ordering::Acquire);
            let config = state.control.config.read().await.clone();
            if next != generation {
                if let Some(mut task) = native.take() {
                    task.0.abort();
                    let _ = (&mut task.0).await;
                }
                if config.sources.system
                    && std::env::var("REDTRACE_COLLECT_LOCAL").as_deref() != Ok("0")
                {
                    native = Some(CollectorTask(spawn_collection(
                        state.events.clone(),
                        state.source.clone(),
                        state.checkpoints.clone(),
                    )));
                } else {
                    state.source.write().await.state = "disabled".into();
                }
                if let Err(error) = extended.reconfigure(config.clone()) {
                    tracing::error!(%error,"module reconfiguration failed");
                    return;
                }
                generation = next;
            }
            let cp = state.checkpoints.clone();
            let result = tokio::task::spawn_blocking(move || {
                let events = if std::env::var("REDTRACE_COLLECT_LOCAL").as_deref() == Ok("0") {
                    Vec::new()
                } else {
                    extended.collect(&cp)
                };
                (extended, events)
            })
            .await;
            let events = match result {
                Ok((collector, events)) => {
                    extended = collector;
                    events
                }
                Err(error) => {
                    tracing::error!(%error,"module worker failed");
                    return;
                }
            };
            *state.control.module_health.write().await = extended.health.clone();
            for event in events {
                if state.events.send(event).await.is_err() {
                    return;
                }
            }
            let _maintenance = state.control.maintenance.read().await;
            let due = {
                state
                    .control
                    .rules
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .engine
                    .tick(redtrace::pki::now())
            };
            if !due.is_empty() {
                let log = state.alert_log.clone();
                let alerts = due.clone();
                if matches!(
                    tokio::task::spawn_blocking(move || log.append(&alerts)).await,
                    Ok(Ok(()))
                ) {
                    let mut alerts = state.alerts.write().await;
                    alerts.extend(due);
                    if alerts.len() > MAX_ALERTS_MEMORY {
                        let excess = alerts.len() - MAX_ALERTS_MEMORY;
                        alerts.drain(..excess);
                    }
                    state.live.notify();
                    let control = state.control.clone();
                    if !matches!(
                        tokio::task::spawn_blocking(move || control
                            .rules
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .checkpoint())
                        .await,
                        Ok(Ok(()))
                    ) {
                        state.stats.write().await.detection_errors += 1;
                    }
                } else {
                    state.stats.write().await.detection_errors += 1;
                }
            }
            drop(_maintenance);
            tokio::select! {_=state.shutdown.wait()=>break,_=tokio::time::sleep(Duration::from_secs(config.resources.poll_seconds))=>{}}
        }
        if let Some(mut task) = native {
            task.0.abort();
            let _ = (&mut task.0).await;
        }
    })
}

async fn health(State(state): State<AppState>) -> Json<Health> {
    let source = state.source.read().await.clone();
    let stats = state.stats.read().await.clone();
    let ingest_stats = state.ingest_stats.read().await.clone();
    let wal_bytes = state.wal.size_bytes().unwrap_or(0);
    let (segment_count, segment_bytes) = state.segments.stats().unwrap_or_default();
    let managed = state.control.listener.lock().await.clone();
    let ingest_enabled = managed.is_some() || state.ingest_bind.is_some();
    let (agents_total, agents_active) = match &state.agents {
        Some(registry) => {
            let records = registry.list();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let active = records
                .iter()
                .filter(|record| {
                    !record.revoked
                        && record.last_seen_unix > 0
                        && now.saturating_sub(record.last_seen_unix) < 120
                })
                .count();
            (records.len(), active)
        }
        None => (0, 0),
    };
    Json(Health {
        detection: state.detector.lock().await.health(),
        query_limits: state.query_limits,
        query_execution: state.query_executor.health(),
        status: "ok",
        service: "redtrace",
        data_mode: "real",
        events_indexed: state.known_uids.read().await.len(),
        uptime_seconds: state.started.elapsed().as_secs(),
        source,
        storage: StorageHealth {
            retention: state.retention.read().await.clone(),
            wal_quarantine: state.wal_quarantine.read().await.clone(),
            wal_bytes,
            segment_bytes,
            segment_count,
            corrupted_records: state.corrupted_wal_records,
            corrupted_segments: state.corrupted_segments,
            corrupted_segment_indexes: state.corrupted_segment_indexes,
            checkpoint_sources: state.checkpoints.len(),
            alert_records: state.alerts.read().await.len(),
            corrupted_alert_records: state.corrupted_alert_records,
        },
        ingestion: IngestionHealth {
            queue_depth: QUEUE_BOUND - state.events.capacity(),
            queue_bound: QUEUE_BOUND,
            ingested_total: stats.ingested_total,
            dropped_events: stats.dropped_events,
            wal_errors: stats.wal_errors,
            segment_errors: stats.segment_errors,
            checkpoint_errors: stats.checkpoint_errors,
            detection_errors: stats.detection_errors,
            alerts_created: stats.alerts_created,
            last_event_at: stats.last_event_at,
        },
        remote_ingest: IngestHealthReport {
            budget: ingest_budget_health(&state).await,
            enabled: ingest_enabled,
            bind: managed
                .map(|l| l.bind)
                .or_else(|| state.ingest_bind.clone()),
            agents_total,
            agents_active,
            remote_events_total: ingest_stats.remote_events_total,
            duplicate_events_total: ingest_stats.duplicate_events_total,
            rejected_batches: ingest_stats.rejected_batches,
            heartbeats_total: ingest_stats.heartbeats_total,
            last_remote_event_at: ingest_stats.last_remote_event_at,
        },
    })
}

fn segment_target_bytes() -> u64 {
    std::env::var("REDTRACE_SEGMENT_MB")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.saturating_mul(1024 * 1024))
        .filter(|value| *value > 0)
        .unwrap_or(SEGMENT_TARGET_BYTES)
}

async fn sources(State(state): State<AppState>) -> Json<Vec<SourceStatus>> {
    let mut list = vec![state.source.read().await.clone()];
    list.extend(
        state
            .control
            .module_health
            .read()
            .await
            .values()
            .map(|h| SourceStatus {
                name: h.id.clone(),
                platform: std::env::consts::OS.into(),
                state: h.state.clone(),
                events_collected: h.events as usize,
                lookback: "extended module".into(),
                last_error: h.error.clone(),
            }),
    );
    if let Some(registry) = &state.agents {
        list.extend(ingest::agent_source_status(&registry.list()));
    }
    Json(list)
}

#[derive(Deserialize)]
struct CreateAgentParams {
    name: String,
}

async fn agents_list(State(state): State<AppState>) -> Response {
    match &state.agents {
        Some(registry) => Json(serde_json::json!({
            "agents": registry.list().iter().map(AgentPublic::from).collect::<Vec<_>>(),
        }))
        .into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "agent registry is unavailable" })),
        )
            .into_response(),
    }
}

async fn agents_create(
    State(state): State<AppState>,
    Json(params): Json<CreateAgentParams>,
) -> Response {
    let _maintenance = state.control.maintenance.read().await;
    let Some(registry) = &state.agents else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "agent registry is unavailable" })),
        )
            .into_response();
    };
    let response = match registry.create(&params.name) {
        Ok((record, token)) => {
            tracing::info!(agent = %record.id, name = %record.name, "remote agent registered");
            (
                StatusCode::CREATED,
                Json(CreatedAgent {
                    id: record.id,
                    name: record.name,
                    token,
                    created_unix: record.created_unix,
                }),
            )
                .into_response()
        }
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid agent name" })),
        )
            .into_response(),
        Err(error) => {
            tracing::warn!(%error, "agent creation failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "could not create agent" })),
            )
                .into_response()
        }
    };
    no_store(response)
}

async fn agents_revoke(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let _maintenance = state.control.maintenance.read().await;
    let Some(registry) = &state.agents else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "agent registry is unavailable" })),
        )
            .into_response();
    };
    match registry.revoke(&id) {
        Ok(true) => {
            tracing::info!(agent = %id, "remote agent revoked");
            (
                StatusCode::OK,
                Json(serde_json::json!({ "id": id, "revoked": true })),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown agent or already revoked" })),
        )
            .into_response(),
        Err(error) => {
            tracing::warn!(%error, "agent revocation failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "could not revoke agent" })),
            )
                .into_response()
        }
    }
}

async fn collect_now(State(state): State<AppState>) -> impl IntoResponse {
    let _guard = state.collect_lock.lock().await;
    let checkpoints = state.checkpoints.clone();
    let batch =
        match tokio::task::spawn_blocking(move || collector::collect_platform_events(&checkpoints))
            .await
        {
            Ok(batch) => batch,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("collector task failed: {error}") })),
                );
            }
        };
    if batch.status.state == "error" {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": batch.status.last_error.unwrap_or_default() })),
        );
    }
    let accepted = batch.events.len();
    let mut queued = 0;
    for event in batch.events {
        if state.events.send(event).await.is_err() {
            break;
        }
        queued += 1;
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "accepted": accepted, "queued": queued })),
    )
}

async fn search(State(state): State<AppState>, Query(params): Query<SearchParams>) -> Response {
    let range = match TimeRange::parse(&params.range) {
        Ok(range) => range,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": error})),
            )
                .into_response();
        }
    };
    let raw = params.q.unwrap_or_else(|| "*".into());
    let expression = match query::parse_with_limits(&raw, state.query_limits) {
        Ok(expression) => expression,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                query_error(error, state.query_limits),
            )
                .into_response();
        }
    };
    let before = match params.cursor.as_deref() {
        Some(cursor) => match decode_cursor(cursor) {
            Some((timestamp, uid)) => Some((timestamp.to_owned(), uid.to_owned())),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid search cursor" })),
                )
                    .into_response();
            }
        },
        None => None,
    };
    let limit = params
        .limit
        .unwrap_or(100)
        .clamp(1, 1000)
        .min(state.query_executor.limits.max_results);
    match execute_query(state, move |snapshot, segments, budget| {
        let started = Instant::now();
        let mut page = QueryPage::new(limit, before, budget)?;
        let total = visit_time_query(
            &snapshot,
            &segments,
            &expression,
            budget,
            &range,
            |event, budget| page.offer(event, budget),
        )?;
        let events = page.into_events(budget)?;
        let next_cursor = events.last().map(encode_cursor);
        #[derive(Serialize)]
        struct SearchResponse {
            total: usize,
            took_micros: u128,
            events: Vec<Event>,
            next_cursor: Option<String>,
            execution: QueryUsage,
        }
        query_json(
            &SearchResponse {
                total,
                took_micros: started.elapsed().as_micros(),
                events,
                next_cursor,
                execution: budget.usage,
            },
            budget,
        )
    })
    .await
    {
        Ok(response) => response,
        Err(error) => error.response(),
    }
}

fn query_error(error: query::QueryError, limits: query::QueryLimits) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "error": error.message,
        "offset": error.offset,
        "max_nodes": limits.max_nodes,
        "limits": limits,
    }))
}

fn encode_cursor(event: &Event) -> String {
    format!("{}|{}", event.timestamp, event.uid)
}

fn decode_cursor(cursor: &str) -> Option<(&str, &str)> {
    if cursor.len() > 128 {
        return None;
    }
    let (timestamp, uid) = cursor.rsplit_once('|')?;
    (!timestamp.is_empty()
        && timestamp.is_ascii()
        && uid.len() == 16
        && uid.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then_some((timestamp, uid))
}

async fn aggregations(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> Response {
    let range = match TimeRange::parse(&params.range) {
        Ok(range) => range,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": error})),
            )
                .into_response();
        }
    };
    let raw = params.q.unwrap_or_else(|| "*".into());
    let expression = match query::parse_with_limits(&raw, state.query_limits) {
        Ok(expression) => expression,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                query_error(error, state.query_limits),
            )
                .into_response();
        }
    };
    let cap = params.limit.unwrap_or(50_000).clamp(1_000, 100_000);
    match execute_query(state, move |snapshot, segments, budget| {
        let mut buckets = QueryAggregations::default();
        let total = visit_time_query(&snapshot, &segments, &expression, budget, &range, |event, budget| {
            if buckets.sampled < cap { buckets.offer(event, budget)?; }
            Ok(())
        })?;
        query_json(&serde_json::json!({
            "total": total, "sampled": buckets.sampled, "truncated": total > buckets.sampled,
            "sampling": "segment_then_ram_scan_order", "hours": buckets.hours,
            "sources": top_terms(buckets.sources, 20, budget)?, "event_ids": top_terms(buckets.event_ids, 20, budget)?,
            "levels": top_terms(buckets.levels, 10, budget)?, "execution": budget.usage,
        }), budget)
    }).await {
        Ok(response) => response,
        Err(error) => error.response(),
    }
}

#[derive(Default)]
struct QueryAggregations {
    sampled: usize,
    hours: BTreeMap<String, usize>,
    sources: HashMap<String, usize>,
    event_ids: HashMap<String, usize>,
    levels: HashMap<String, usize>,
}

fn count_term(
    values: &mut HashMap<String, usize>,
    key: &str,
    budget: &mut QueryBudget,
) -> io::Result<()> {
    budget.work(1)?;
    if let Some(count) = values.get_mut(key) {
        *count += 1;
        return Ok(());
    }
    if values.len() >= budget.limits.max_aggregate_buckets {
        return Err(io::Error::other(QueryFailure::AggregateBuckets));
    }
    budget.allocate(key.len().saturating_mul(4) + 256)?;
    values.insert(key.to_owned(), 1);
    Ok(())
}

impl QueryAggregations {
    fn offer(&mut self, event: &Event, budget: &mut QueryBudget) -> io::Result<()> {
        if let Some(hour) = event.timestamp.get(..13) {
            let hour = hour.replace('T', " ");
            if !self.hours.contains_key(&hour) {
                if self.hours.len() >= budget.limits.max_aggregate_buckets {
                    return Err(io::Error::other(QueryFailure::AggregateBuckets));
                }
                budget.allocate(hour.len().saturating_mul(4) + 256)?;
            }
            *self.hours.entry(hour).or_default() += 1;
        }
        count_term(&mut self.sources, &event.source, budget)?;
        count_term(&mut self.levels, &event.level, budget)?;
        if let Some(event_id) = event.fields.get("event.id") {
            count_term(&mut self.event_ids, event_id, budget)?;
        }
        self.sampled += 1;
        Ok(())
    }
}

fn top_terms(
    values: HashMap<String, usize>,
    limit: usize,
    budget: &mut QueryBudget,
) -> io::Result<Vec<serde_json::Value>> {
    budget.work(values.len() as u64 * (1 + values.len().checked_ilog2().unwrap_or(0) as u64))?;
    budget.allocate(values.len().saturating_mul(64))?;
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    budget.check()?;
    Ok(values
        .into_iter()
        .take(limit)
        .map(|(key, count)| serde_json::json!({ "key": key, "count": count }))
        .collect())
}

async fn alerts(
    State(state): State<AppState>,
    Query(params): Query<AlertParams>,
) -> Json<serde_json::Value> {
    let limit = params.limit.unwrap_or(100).clamp(1, 1000);
    let alerts = state.alerts.read().await;
    let total = alerts.len();
    let results: Vec<_> = alerts.iter().rev().take(limit).cloned().collect();
    Json(serde_json::json!({
        "total": total,
        "alerts": results,
    }))
}

async fn detection_rules() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "rules": [
            { "id": "auth.bruteforce", "title": "Множественные неуспешные попытки входа", "severity": "high", "mitre_technique": "T1110", "status": "enabled" },
            { "id": "account.lockout", "title": "Учётная запись заблокирована", "severity": "high", "mitre_technique": "T1110", "status": "enabled" },
            { "id": "powershell.script_block", "title": "Выполнен PowerShell Script Block", "severity": "medium", "mitre_technique": "T1059.001", "status": "enabled" },
            { "id": "process.suspicious_command", "title": "Подозрительная командная строка", "severity": "critical", "mitre_technique": "T1059", "status": "enabled" },
            { "id": "privilege.sudo_failure", "title": "Отказ повышения привилегий", "severity": "medium", "mitre_technique": "T1548.003", "status": "enabled" }
        ]
    }))
}

async fn diagnostics(State(state): State<AppState>) -> Json<serde_json::Value> {
    let source = state.source.read().await.clone();
    let stats = state.stats.read().await.clone();
    let (segment_count, segment_bytes) = state.segments.stats().unwrap_or_default();
    let wal_quarantine = state.wal_quarantine.read().await.clone();
    Json(serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "application": {
            "name": "RED//TRACE",
            "version": env!("CARGO_PKG_VERSION"),
            "target_os": std::env::consts::OS,
            "target_arch": std::env::consts::ARCH,
            "data_mode": "real"
        },
        "source": source,
        "storage": {
            "wal_quarantine_archives": wal_quarantine.archives,
            "wal_quarantine_bytes": wal_quarantine.bytes,
            "quarantined_wal_records": wal_quarantine.corrupted_records,
            "salvageable_wal_records": wal_quarantine.salvageable_records,
            "wal_bytes": state.wal.size_bytes().unwrap_or(0),
            "segment_bytes": segment_bytes,
            "segment_count": segment_count,
            "checkpoint_sources": state.checkpoints.len(),
            "alert_records": state.alerts.read().await.len(),
            "corrupted_wal_records": state.corrupted_wal_records,
            "corrupted_segments": state.corrupted_segments,
            "corrupted_segment_indexes": state.corrupted_segment_indexes,
            "corrupted_alert_records": state.corrupted_alert_records
        },
        "ingestion": stats,
        "detection": state.detector.lock().await.health(),
        "remote_ingest_budget": ingest_budget_health(&state).await,
        "retention": state.retention.read().await.clone(),
        "lifecycle": { "persistent": state.session.persistent, "protocol": state.session.protocol },
        "query_limits": state.query_limits,
        "query_execution": state.query_executor.health(),
        "privacy": {
            "contains_event_content": false,
            "contains_file_paths": false,
            "contains_user_names": false
        }
    }))
}

async fn export_events(
    State(state): State<AppState>,
    Query(params): Query<ExportParams>,
) -> Response {
    let range = match TimeRange::parse(&params.range) {
        Ok(range) => range,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": error})),
            )
                .into_response();
        }
    };
    let raw = params.q.unwrap_or_else(|| "*".into());
    let expression = match query::parse_with_limits(&raw, state.query_limits) {
        Ok(expression) => expression,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                query_error(error, state.query_limits),
            )
                .into_response();
        }
    };
    let limit = params.limit.unwrap_or(10_000).clamp(1, 10_000);
    let limit = limit.min(state.query_executor.limits.max_results);
    let format = params.format.unwrap_or_else(|| "jsonl".into());
    match execute_query(state, move |snapshot, segments, budget| {
        let mut page = QueryPage::new(limit, None, budget)?;
        visit_time_query(
            &snapshot,
            &segments,
            &expression,
            budget,
            &range,
            |event, budget| page.offer(event, budget),
        )?;
        encode_export(page.into_events(budget)?, &format, budget)
    })
    .await
    {
        Ok(response) => response,
        Err(error) => error.response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayParams {
    q: String,
    #[serde(default)]
    rules: Option<Vec<redtrace::rules::Rule>>,
}
async fn replay_rules(State(state): State<AppState>, Json(params): Json<ReplayParams>) -> Response {
    let expression = match query::parse_with_limits(&params.q, state.query_limits) {
        Ok(q) => q,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, query_error(e, state.query_limits)).into_response();
        }
    };
    let rules = params.rules.unwrap_or_else(|| {
        state
            .control
            .rules
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .file
            .rules
            .clone()
    });
    match execute_query(state, move |snapshot, segments, budget| {
        let mut page = QueryPage::new(5000, None, budget)?;
        let range = TimeRange::parse(&TimeRangeParams::default()).map_err(io::Error::other)?;
        visit_time_query(&snapshot, &segments, &expression, budget, &range, |e, b| {
            page.offer(e, b)
        })?;
        redtrace::rules::replay(rules, page.into_events(budget)?)
    })
    .await
    {
        Ok(result) => Json(result).into_response(),
        Err(e) => e.response(),
    }
}

async fn backup_snapshot(State(state): State<AppState>) -> Response {
    let _maintenance = state.control.maintenance.clone().write_owned().await;
    let _snapshot = state.query_snapshot.clone().write_owned().await;
    let root = state.control.root.clone();
    let filename = format!("redtrace-{}.rtbackup", redtrace::pki::now());
    let output = root.join("backups").join(&filename);
    let destination = output.clone();
    if let Err(error) = tokio::task::spawn_blocking(move || {
        // The worker owns both guards so client cancellation cannot expose a live snapshot.
        let _maintenance = _maintenance;
        let _snapshot = _snapshot;
        redtrace::backup::create(&root, &destination)
    })
    .await
    .unwrap_or_else(|_| Err(io::Error::other("backup worker failed")))
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":error.to_string()})),
        )
            .into_response();
    }
    let file = match tokio::fs::File::open(output).await {
        Ok(file) => file,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error":e.to_string()})),
            )
                .into_response();
        }
    };
    let stream = futures_util::stream::try_unfold(file, |mut file| async move {
        use tokio::io::AsyncReadExt;
        let mut bytes = vec![0u8; 65536];
        let size = file.read(&mut bytes).await?;
        if size == 0 {
            Ok::<_, io::Error>(None)
        } else {
            bytes.truncate(size);
            Ok(Some((bytes, file)))
        }
    });
    let mut response = axum::body::Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    response
}

fn encode_export(
    events: Vec<Event>,
    format: &str,
    budget: &mut QueryBudget,
) -> io::Result<Response> {
    let (content_type, filename) = match format {
        "json" => ("application/json; charset=utf-8", "redtrace-events.json"),
        "csv" => ("text/csv; charset=utf-8", "redtrace-events.csv"),
        _ => (
            "application/x-ndjson; charset=utf-8",
            "redtrace-events.jsonl",
        ),
    };
    let fields = [
        "@timestamp",
        "level",
        "source",
        "event.id",
        "event.description",
        "user.name",
        "source.ip",
        "process.name",
        "process.command_line",
        "process.pid",
        "process.parent.pid",
    ];
    let mut output = QueryOutput {
        bytes: Vec::new(),
        budget,
        failure: None,
    };
    if format == "json" {
        output.write_all(b"[")?;
    }
    if format == "csv" {
        output.write_all(fields.join(",").as_bytes())?;
    }
    for (position, event) in events.into_iter().enumerate() {
        output.budget.work(1)?;
        let original_memory = redtrace::index::event_memory_bytes(&event);
        let temporary = redaction_memory_bytes(&event);
        output.budget.allocate(temporary)?;
        let event = privacy::redact_event(&event);
        if format == "csv" {
            output.write_all(b"\r\n")?;
            for (column, field) in fields.iter().enumerate() {
                if column > 0 {
                    output.write_all(b",")?;
                }
                output.write_all(privacy::csv_cell(event.field(field).unwrap_or("")).as_bytes())?;
            }
        } else {
            if position > 0 {
                output.write_all(if format == "json" { b"," } else { b"\n" })?;
            }
            if let Err(error) = serde_json::to_writer(&mut output, &event) {
                return Err(output
                    .failure
                    .map(io::Error::other)
                    .unwrap_or_else(|| io::Error::other(error)));
            }
        }
        output.budget.release(temporary);
        output.budget.release(original_memory);
    }
    if format == "json" {
        output.write_all(b"]")?;
    }
    let mut response = output.bytes.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .expect("static export filename"),
    );
    Ok(response)
}

fn redaction_memory_bytes(event: &Event) -> usize {
    redtrace::index::event_memory_bytes(event).saturating_mul(40)
}

async fn windows_audit_plan() -> Json<windows::WindowsAuditPlan> {
    Json(windows::recommended_plan())
}

async fn windows_audit_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "platform_supported": cfg!(target_os = "windows"),
        "executor_available": false,
        "mode": "preview_only",
        "confirmation_text": windows::CONFIRMATION_TEXT,
        "reason": if cfg!(target_os = "windows") {
            "Для применения требуется отдельный подписанный privileged helper."
        } else {
            "Профиль Windows можно просмотреть, но применить только в Windows-сборке."
        }
    }))
}

async fn local_session(State(state): State<AppState>) -> Response {
    no_store(Json(&*state.session).into_response())
}

async fn stop_session(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    let supplied = headers
        .get("x-redtrace-instance")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !ingest::constant_time_equal(supplied.as_bytes(), state.session.instance.as_bytes()) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "collector instance mismatch" })),
        )
            .into_response();
    }
    state.shutdown.request();
    no_store(StatusCode::ACCEPTED.into_response())
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn agents_rotate(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(params): Json<RotateAgentParams>,
) -> Response {
    let _maintenance = state.control.maintenance.read().await;
    let Some(registry) = &state.agents else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "agent registry is unavailable"})),
        )
            .into_response();
    };
    match registry.rotate(&id, params.ttl_seconds, params.overlap_seconds) {
        Ok(Some(credential)) => {
            let credential: IssuedAgentCredential = credential;
            no_store(Json(credential).into_response())
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "unknown or revoked agent"})),
        )
            .into_response(),
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid credential lifetime or overlap"})),
        )
            .into_response(),
        Err(error) => {
            tracing::warn!(%error, "agent rotation failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "could not rotate agent credential"})),
            )
                .into_response()
        }
    }
}

async fn ingest_budget_health(state: &AppState) -> Option<ingest::IngestBudgetHealth> {
    match &state.agents {
        Some(registry) => Some(registry.budget_health_with_known(&*state.known_uids.read().await)),
        None => None,
    }
}

async fn enforce_retention(state: &AppState) {
    let _maintenance = state.control.maintenance.read().await;
    let guard = state.query_snapshot.clone().write_owned().await;
    let segments = state.segments.clone();
    let worker = tokio::task::spawn_blocking(move || {
        let result = (|| {
            let before = segments
                .recover()?
                .events
                .into_iter()
                .map(|event| event.uid)
                .collect::<HashSet<_>>();
            let changed = segments.enforce_retention()?;
            let after = if changed {
                segments
                    .recover()?
                    .events
                    .into_iter()
                    .map(|event| event.uid)
                    .collect()
            } else {
                before.clone()
            };
            Ok::<_, io::Error>((
                changed,
                before.difference(&after).cloned().collect::<HashSet<_>>(),
            ))
        })();
        (guard, result)
    })
    .await;
    let (_guard, result) = match worker {
        Ok((guard, result)) => (Some(guard), result),
        Err(_) => (None, Err(io::Error::other("retention worker failed"))),
    };
    let mut report = state.retention.write().await;
    report.runs += 1;
    match result {
        Ok((changed, mut removed)) => {
            let index = state.index.read().await;
            let mut budget = QueryBudget::new(ExecutionLimits::default());
            if let Ok(snapshot) = index.snapshot(&mut budget) {
                let mut keep = |event: &Event, _: &mut QueryBudget| {
                    removed.remove(&event.uid);
                    Ok(())
                };
                if snapshot
                    .visit(&query::Expr::MatchAll, &mut budget, &mut keep)
                    .is_ok()
                {
                    state
                        .known_uids
                        .write()
                        .await
                        .retain(|uid| !removed.contains(uid));
                }
            }
            report.changes += u64::from(changed);
            report.last_success_unix = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
            report.last_failure = None;
            if changed {
                state.live.notify();
            }
        }
        Err(error) => {
            report.failures += 1;
            let cap = error.kind() == io::ErrorKind::StorageFull;
            report.cap_failures += u64::from(cap);
            report.last_failure = Some(if cap {
                "storage_cap"
            } else {
                "retention_failed"
            });
            tracing::warn!(%error, "retention enforcement failed; original storage preserved");
        }
    }
}

fn spawn_retention(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = state.shutdown.wait() => break,
                _ = interval.tick() => enforce_retention(&state).await,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use redtrace::ingest::constant_time_equal;

    #[tokio::test]
    async fn failed_wal_batch_is_retried_without_reenqueue_or_checkpoint_advance() {
        let (mut state, root) = query_state(ExecutionLimits::default());
        let path = root.join("active.wal");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let (tx, rx) = mpsc::channel(QUEUE_BOUND);
        state.events = tx.clone();
        let event = Event::normalized(
            1,
            "2026-10-12T12:00:00Z".into(),
            "wal-retry.fixture".into(),
            "low".into(),
            "retained pending batch".into(),
            BTreeMap::new(),
        );
        let uid = event.uid.clone();
        tx.send(event).await.unwrap();
        let worker = spawn_ingestion(rx, state.clone(), 100);
        timeout(Duration::from_secs(2), async {
            while state.stats.read().await.wal_errors == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(!state.known_uids.read().await.contains(&uid));
        assert!(state.checkpoints.is_empty());
        std::fs::remove_dir(&path).unwrap();
        timeout(Duration::from_secs(2), async {
            while !state.known_uids.read().await.contains(&uid) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        state.shutdown.request();
        worker.await.unwrap().unwrap();
        let recovered = state.wal.recover().unwrap().events;
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].uid, uid);
        assert_eq!(state.stats.read().await.wal_errors, 1);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn shutdown_drains_every_queued_event_before_releasing_ownership() {
        let (mut state, root) = query_state(ExecutionLimits::default());
        let (tx, rx) = mpsc::channel(QUEUE_BOUND);
        state.events = tx.clone();
        let expected: HashSet<_> = (0..512)
            .map(|id| {
                Event::normalized(
                    id,
                    "2026-10-12T12:00:00Z".into(),
                    "drain.fixture".into(),
                    "low".into(),
                    format!("drain {id}"),
                    BTreeMap::new(),
                )
            })
            .map(|event| {
                let uid = event.uid.clone();
                tx.try_send(event).unwrap();
                uid
            })
            .collect();
        state.shutdown.request();
        let worker = spawn_ingestion(rx, state.clone(), 100);
        timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(expected.is_subset(&*state.known_uids.read().await));
        let recovered: HashSet<_> = state
            .wal
            .recover_with_repair()
            .unwrap()
            .events
            .into_iter()
            .map(|event| event.uid)
            .collect();
        assert_eq!(recovered, expected);
        assert!(tx.is_closed());
        assert_eq!(state.stats.read().await.wal_errors, 0);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn retention_waits_for_query_gate_and_refreshes_disk_uids() {
        let (mut state, root) = query_state(ExecutionLimits::default());
        drop(state.segments);
        state.segments = Arc::new(
            SegmentStore::open_with_limits(
                root.clone(),
                1024 * 1024,
                60,
                256 * 1024,
                2 * 1024 * 1024,
            )
            .unwrap(),
        );
        let oldest = Event::normalized(
            90,
            "2000-01-01T00:00:00Z".into(),
            "retention.fixture".into(),
            "low".into(),
            "expired".into(),
            BTreeMap::new(),
        );
        state
            .segments
            .commit(std::slice::from_ref(&oldest))
            .unwrap();
        let manifest_path = root.join("catalog.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        for segment in manifest["segments"].as_array_mut().unwrap() {
            segment["created_unix"] = 0.into();
        }
        std::fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        state.known_uids.write().await.insert(oldest.uid.clone());
        let gate = state.query_snapshot.clone().read_owned().await;
        let worker_state = state.clone();
        let worker = tokio::spawn(async move {
            enforce_retention(&worker_state).await;
        });
        tokio::task::yield_now().await;
        assert_eq!(state.retention.read().await.runs, 0);
        drop(gate);
        worker.await.unwrap();
        assert!(!state.known_uids.read().await.contains(&oldest.uid));
        assert_eq!(state.retention.read().await.runs, 1);
        assert_eq!(state.retention.read().await.failures, 0);
        let ram = state
            .index
            .read()
            .await
            .search(&query::Expr::MatchAll, 10)
            .unwrap()
            .events;
        for event in ram {
            assert!(state.known_uids.read().await.contains(&event.uid));
        }
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn query_state(limits: ExecutionLimits) -> (AppState, std::path::PathBuf) {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join("opencode")
            .join(format!(
                "redtrace-api-query-{}-{}",
                std::process::id(),
                service::random_secret().unwrap()
            ));
        service::private_directory(&root).unwrap();
        let segments = Arc::new(SegmentStore::open(root.clone()).unwrap());
        let mut events: Vec<_> = (0..4)
            .map(|id| {
                Event::normalized(
                    id,
                    format!("2026-10-12T10:00:{id:02}Z"),
                    "query.fixture".into(),
                    "low".into(),
                    format!("fixture {id}"),
                    BTreeMap::from([("event.id".into(), "4624".into())]),
                )
            })
            .collect();
        events[3].fields.insert(
            "http.authorization".into(),
            "synthetic-fixture-value".into(),
        );
        events[3]
            .fields
            .insert("user.name".into(), "=formula".into());
        segments.commit(&events[..3]).unwrap();
        let known_uids = events.iter().map(|event| event.uid.clone()).collect();
        let (tx, _rx) = mpsc::channel(QUEUE_BOUND);
        let state = AppState {
            control: Arc::new(
                redtrace::control::Control::open(root.clone(), None, Shutdown::new()).unwrap(),
            ),
            shutdown: Shutdown::new(),
            session: Arc::new(SessionIdentity {
                protocol: service::PROTOCOL_VERSION,
                version: env!("CARGO_PKG_VERSION").into(),
                pid: std::process::id(),
                process_start: "fixture".into(),
                owner: "fixture".into(),
                executable: std::env::current_exe().unwrap(),
                data_dir: root.clone(),
                address: "127.0.0.1:0".parse().unwrap(),
                instance: "fixture".into(),
                persistent: false,
            }),
            retention: Arc::new(RwLock::new(RetentionHealth::default())),
            live: LiveUpdates::default(),
            query_limits: query::QueryLimits::default(),
            query_executor: Arc::new(QueryExecutor::new(limits)),
            query_snapshot: Arc::new(RwLock::new(())),
            index: Arc::new(RwLock::new(EventIndex::from_events(events[2..].to_vec()))),
            known_uids: Arc::new(RwLock::new(known_uids)),
            source: Arc::new(RwLock::new(collector::initial_status())),
            wal: Arc::new(Wal::open(root.join("active.wal")).unwrap()),
            segments,
            checkpoints: Arc::new(CheckpointStore::open(root.join("checkpoints.json")).unwrap()),
            detector: Arc::new(Mutex::new(DetectionEngine::default())),
            alert_log: Arc::new(AlertLog::open(root.join("alerts.jsonl")).unwrap()),
            alerts: Arc::new(RwLock::new(Vec::new())),
            collect_lock: Arc::new(Mutex::new(())),
            agents: None,
            ingest_stats: Arc::new(RwLock::new(IngestStats::default())),
            ingest_bind: None,
            corrupted_wal_records: 0,
            wal_quarantine: Arc::new(RwLock::new(QuarantineStats::default())),
            corrupted_segments: 0,
            corrupted_segment_indexes: 0,
            corrupted_alert_records: 0,
            started: Instant::now(),
            events: tx,
            stats: Arc::new(RwLock::new(IngestionStats::default())),
        };
        (state, root)
    }

    async fn response_json(response: Response) -> serde_json::Value {
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    fn search_params(cursor: Option<String>) -> SearchParams {
        SearchParams {
            range: TimeRangeParams::default(),
            q: Some("*".into()),
            limit: Some(2),
            cursor,
        }
    }

    #[tokio::test]
    async fn query_handlers_share_unique_counts_cursor_order_and_export_redaction() {
        let (state, root) = query_state(ExecutionLimits::default());
        let first =
            response_json(search(State(state.clone()), Query(search_params(None))).await).await;
        assert_eq!(first["total"], 4);
        assert_eq!(first["events"][0]["id"], 3);
        assert_eq!(first["events"][1]["id"], 2);
        let second = response_json(
            search(
                State(state.clone()),
                Query(search_params(Some(
                    first["next_cursor"].as_str().unwrap().into(),
                ))),
            )
            .await,
        )
        .await;
        assert_eq!(second["total"], 4);
        assert_eq!(second["events"][0]["id"], 1);
        assert_eq!(second["events"][1]["id"], 0);
        let aggregates =
            response_json(aggregations(State(state.clone()), Query(search_params(None))).await)
                .await;
        assert_eq!(aggregates["total"], 4);
        assert_eq!(aggregates["sampled"], 4);
        assert_eq!(aggregates["sources"][0]["count"], 4);
        assert_eq!(aggregates["truncated"], false);
        let exported = response_json(
            export_events(
                State(state.clone()),
                Query(ExportParams {
                    q: None,
                    format: Some("json".into()),
                    limit: Some(4),
                    range: TimeRangeParams::default(),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(exported.as_array().unwrap().len(), 4);
        assert_eq!(exported[0]["fields"]["http.authorization"], "[REDACTED]");
        let response = export_events(
            State(state.clone()),
            Query(ExportParams {
                q: None,
                format: Some("csv".into()),
                limit: Some(4),
                range: TimeRangeParams::default(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let csv = String::from_utf8(
            axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(csv.contains("\"'=formula\""));
        let report = state.query_executor.health();
        assert_eq!(report.metrics.active, 0);
        assert_eq!(report.metrics.completed, 5);
        assert!(report.metrics.last_usage.peak_memory_bytes <= report.limits.max_memory_bytes);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn all_query_handlers_return_budget_failure_without_partial_data() {
        let (state, root) = query_state(ExecutionLimits {
            max_scan_bytes: 1,
            ..Default::default()
        });
        for response in [
            search(State(state.clone()), Query(search_params(None))).await,
            aggregations(State(state.clone()), Query(search_params(None))).await,
            export_events(
                State(state.clone()),
                Query(ExportParams {
                    q: None,
                    format: None,
                    limit: None,
                    range: TimeRangeParams::default(),
                }),
            )
            .await,
        ] {
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(body["reason"], "scan_bytes");
            assert!(body.get("events").is_none());
        }
        assert_eq!(state.query_executor.health().metrics.budget_exceeded, 3);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn time_filter_is_shared_by_search_paging_aggregations_and_export() {
        let (state, root) = query_state(ExecutionLimits::default());
        let range = || TimeRangeParams {
            from: Some("2026-10-12T13:00:01+03:00".into()),
            to: Some("2026-10-12T10:00:03Z".into()),
        };
        let mut params = search_params(None);
        params.range = range();
        params.limit = Some(1);
        let first = response_json(search(State(state.clone()), Query(params)).await).await;
        assert_eq!(first["total"], 2);
        assert_eq!(first["events"][0]["id"], 2);
        let mut params = search_params(Some(first["next_cursor"].as_str().unwrap().into()));
        params.range = range();
        let second = response_json(search(State(state.clone()), Query(params)).await).await;
        assert_eq!(second["events"].as_array().unwrap().len(), 1);
        assert_eq!(second["events"][0]["id"], 1);
        let mut params = search_params(None);
        params.range = range();
        let aggregate =
            response_json(aggregations(State(state.clone()), Query(params)).await).await;
        assert_eq!(aggregate["total"], 2);
        assert_eq!(aggregate["sampled"], 2);
        let export = response_json(
            export_events(
                State(state.clone()),
                Query(ExportParams {
                    q: None,
                    format: Some("json".into()),
                    limit: None,
                    range: range(),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(export.as_array().unwrap().len(), 2);
        let mut params = search_params(None);
        params.range.from = Some("invalid".into());
        assert_eq!(
            search(State(state.clone()), Query(params)).await.status(),
            StatusCode::BAD_REQUEST
        );
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn recent_search_prunes_history_before_the_scan_budget() {
        let (state, root) = query_state(ExecutionLimits {
            max_scan_bytes: 64 * 1024,
            ..ExecutionLimits::default()
        });
        let historical = Event::normalized(
            99,
            "2020-01-01T00:00:00Z".into(),
            "old.fixture".into(),
            "low".into(),
            "historical payload ".repeat(12000),
            BTreeMap::new(),
        );
        state.segments.commit(&[historical]).unwrap();
        let mut params = search_params(None);
        params.range.from = Some("2026-10-12T00:00:00Z".into());
        let response = search(State(state.clone()), Query(params)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["total"], 4);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rotation_waits_for_snapshot_and_new_ingestion_does_not_change_query() {
        let (state, root) = query_state(ExecutionLimits::default());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_release = release.clone();
        let worker_state = state.clone();
        let caller = tokio::spawn(async move {
            execute_query(worker_state, move |snapshot, segments, budget| {
                started_tx.send(()).unwrap();
                while !worker_release.load(std::sync::atomic::Ordering::Relaxed) {
                    budget.check()?;
                    std::thread::sleep(Duration::from_millis(1));
                }
                visit_query(
                    &snapshot,
                    &segments,
                    &query::Expr::MatchAll,
                    budget,
                    |_, _| Ok(()),
                )
            })
            .await
        });
        timeout(Duration::from_secs(2), started_rx)
            .await
            .unwrap()
            .unwrap();
        state.index.write().await.push(Event::normalized(
            4,
            "2026-10-12T10:00:04Z".into(),
            "query.fixture".into(),
            "low".into(),
            "new ingestion".into(),
            BTreeMap::new(),
        ));
        assert!(state.query_snapshot.try_write().is_err());
        let rotating_state = state.clone();
        let rotation = tokio::spawn(async move {
            let _guard = rotating_state.query_snapshot.write().await;
            let events = rotating_state
                .index
                .read()
                .await
                .search(&query::Expr::MatchAll, 10)
                .unwrap()
                .events;
            rotating_state.segments.commit(&events).unwrap();
            *rotating_state.index.write().await = EventIndex::default();
        });
        release.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(caller.await.unwrap().unwrap(), 4);
        rotation.await.unwrap();
        let page =
            response_json(search(State(state.clone()), Query(search_params(None))).await).await;
        assert_eq!(page["total"], 5);
        assert_eq!(page["events"][0]["id"], 4);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timeout_cancels_worker_and_keeps_shared_slot_until_it_exits() {
        let (state, root) = query_state(ExecutionLimits {
            max_concurrent: 1,
            deadline_ms: 40,
            ..Default::default()
        });
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (cancelled_tx, cancelled_rx) = tokio::sync::oneshot::channel();
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_release = release.clone();
        let worker_state = state.clone();
        let caller = tokio::spawn(async move {
            execute_query(worker_state, move |_, _, budget| {
                started_tx.send(()).unwrap();
                let failure = loop {
                    if let Err(error) = budget.check() {
                        break error;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                };
                cancelled_tx.send(()).unwrap();
                while !worker_release.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err::<(), _>(failure)
            })
            .await
        });
        timeout(Duration::from_secs(2), started_rx)
            .await
            .unwrap()
            .unwrap();
        let result = caller.await.unwrap();
        assert!(
            matches!(result, Err(QueryApiError::Execution(error)) if matches!(query_failure(&error), Some(QueryFailure::Deadline | QueryFailure::Cancelled)))
        );
        timeout(Duration::from_secs(2), cancelled_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.query_executor.health().metrics.active, 1);
        for response in [
            search(State(state.clone()), Query(search_params(None))).await,
            aggregations(State(state.clone()), Query(search_params(None))).await,
            export_events(
                State(state.clone()),
                Query(ExportParams {
                    q: None,
                    format: None,
                    limit: None,
                    range: TimeRangeParams::default(),
                }),
            )
            .await,
        ] {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
        release.store(true, std::sync::atomic::Ordering::Relaxed);
        timeout(Duration::from_secs(2), async {
            while state.query_executor.health().metrics.active != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(state.query_executor.health().metrics.rejected_busy, 3);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_request_cooperatively_cancels_worker() {
        let (state, root) = query_state(ExecutionLimits::default());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let worker_state = state.clone();
        let caller = tokio::spawn(async move {
            execute_query::<()>(worker_state, move |_, _, budget| {
                started_tx.send(()).unwrap();
                loop {
                    budget.check()?;
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
            .await
        });
        timeout(Duration::from_secs(2), started_rx)
            .await
            .unwrap()
            .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        timeout(Duration::from_secs(2), async {
            while state.query_executor.health().metrics.active != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(state.query_executor.health().metrics.cancelled, 1);
        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn aggregate_cardinality_and_output_encoding_use_the_query_budget() {
        let mut aggregates = QueryAggregations::default();
        let mut budget = QueryBudget::new(ExecutionLimits {
            max_aggregate_buckets: 1,
            ..Default::default()
        });
        let mut event = Event::normalized(
            1,
            "2026-10-12T10:00:00Z".into(),
            "first".into(),
            "low".into(),
            "fixture".into(),
            BTreeMap::new(),
        );
        aggregates.offer(&event, &mut budget).unwrap();
        event.source = "second".into();
        assert_eq!(
            query_failure(&aggregates.offer(&event, &mut budget).unwrap_err()),
            Some(QueryFailure::AggregateBuckets)
        );
        let error = query_json(
            &vec!["large-output"; 100],
            &mut QueryBudget::new(ExecutionLimits {
                max_scan_bytes: 32,
                ..Default::default()
            }),
        )
        .unwrap_err();
        assert_eq!(query_failure(&error), Some(QueryFailure::ScanBytes));
        let error = encode_export(
            vec![event],
            "jsonl",
            &mut QueryBudget::new(ExecutionLimits {
                max_memory_bytes: 32,
                ..Default::default()
            }),
        )
        .unwrap_err();
        assert_eq!(query_failure(&error), Some(QueryFailure::Memory));
        assert!(decode_cursor("invalid").is_none());
        assert!(decode_cursor(&format!("{}|0000000000000001", "x".repeat(200))).is_none());
    }

    #[test]
    fn session_tokens_require_exact_bytes() {
        assert!(constant_time_equal(b"same-token", b"same-token"));
        assert!(!constant_time_equal(b"same-token", b"wrong-token"));
        assert!(!constant_time_equal(b"same-token", b"same-token-extra"));
    }
}
