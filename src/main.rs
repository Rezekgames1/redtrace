use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderValue, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use redtrace::{
    audit::windows,
    collector::{self, SourceStatus},
    index::EventIndex,
    query,
    storage::Wal,
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Instant};
use tokio::sync::{Mutex, RwLock};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

#[derive(Clone)]
struct AppState {
    index: Arc<RwLock<EventIndex>>,
    source: Arc<RwLock<SourceStatus>>,
    wal: Arc<Wal>,
    collect_lock: Arc<Mutex<()>>,
    corrupted_wal_records: usize,
    started: Instant,
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
}

#[derive(Serialize)]
struct StorageHealth {
    wal_bytes: u64,
    corrupted_records: usize,
}

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    limit: Option<usize>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "redtrace=info,tower_http=info".into()),
        )
        .compact()
        .init();

    let wal = Wal::open_default().expect("open local WAL");
    let recovery = wal.recover().expect("recover local WAL");
    let corrupted_wal_records = recovery.corrupted_records;
    let initial = collector::collect_platform_events();
    tracing::info!(
        source = %initial.status.name,
        state = %initial.status.state,
        events = initial.events.len(),
        "native event collection finished"
    );
    let mut index = EventIndex::from_events(recovery.events);
    let new_events: Vec<_> = initial
        .events
        .into_iter()
        .filter(|event| !index.contains_uid(&event.uid))
        .collect();
    wal.append(&new_events).expect("append initial WAL batch");
    for event in new_events {
        index.push(event);
    }
    let state = AppState {
        index: Arc::new(RwLock::new(index)),
        source: Arc::new(RwLock::new(initial.status)),
        wal: Arc::new(wal),
        collect_lock: Arc::new(Mutex::new(())),
        corrupted_wal_records,
        started: Instant::now(),
    };
    let cors = CorsLayer::new()
        .allow_origin([
            HeaderValue::from_static("http://localhost:3000"),
            HeaderValue::from_static("http://127.0.0.1:3000"),
        ])
        .allow_methods([Method::GET, Method::POST]);
    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/sources", get(sources))
        .route("/api/collect", post(collect_now))
        .route("/api/search", get(search))
        .route("/api/audit/windows/plan", get(windows_audit_plan))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let address = "127.0.0.1:9710";
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("bind local API");
    tracing::info!(%address, "RED//TRACE local API started");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("serve local API");
}

async fn health(State(state): State<AppState>) -> Json<Health> {
    let index = state.index.read().await;
    let source = state.source.read().await.clone();
    let wal_bytes = state.wal.size_bytes().unwrap_or(0);
    Json(Health {
        status: "ok",
        service: "redtrace",
        data_mode: "real",
        events_indexed: index.len(),
        uptime_seconds: state.started.elapsed().as_secs(),
        source,
        storage: StorageHealth {
            wal_bytes,
            corrupted_records: state.corrupted_wal_records,
        },
    })
}

async fn sources(State(state): State<AppState>) -> Json<Vec<SourceStatus>> {
    Json(vec![state.source.read().await.clone()])
}

async fn collect_now(State(state): State<AppState>) -> impl IntoResponse {
    let _guard = state.collect_lock.lock().await;
    let batch = match tokio::task::spawn_blocking(collector::collect_platform_events).await {
        Ok(batch) => batch,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("collector task failed: {error}") })),
            );
        }
    };
    let status = batch.status.clone();
    let mut index = state.index.write().await;
    let new_events: Vec<_> = batch
        .events
        .into_iter()
        .filter(|event| !index.contains_uid(&event.uid))
        .collect();
    if let Err(error) = state.wal.append(&new_events) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("WAL append failed: {error}") })),
        );
    }
    let ingested = new_events.len();
    for event in new_events {
        index.push(event);
    }
    *state.source.write().await = status.clone();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "source": status, "ingested": ingested })),
    )
}

async fn search(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    let raw = params.q.unwrap_or_else(|| "*".into());
    match query::parse(&raw) {
        Ok(expression) => {
            let index = state.index.read().await;
            (
                StatusCode::OK,
                Json(
                    serde_json::to_value(
                        index.search(&expression, params.limit.unwrap_or(100).min(1000)),
                    )
                    .unwrap(),
                ),
            )
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error.message, "offset": error.offset })),
        ),
    }
}

async fn windows_audit_plan() -> Json<windows::WindowsAuditPlan> {
    Json(windows::recommended_plan())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
