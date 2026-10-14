use redtrace::{
    agent::{AgentConfig, AgentRuntime, DiskSpool, SpoolLimits, build_events_body},
    collector::{CollectionBatch, SourceStatus},
    index::{ExecutionLimits, QueryBudget, QueryFailure, query_failure},
    ingest::{
        AgentRegistry, INGEST_TOKEN_HEADER, IngestLimits, IngestState, IngestStats, ingest_router,
    },
    model::Event,
    query::Expr,
    storage::{SegmentStore, Wal},
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{RwLock, mpsc},
    task::JoinHandle,
};

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).unwrap();
        let directory = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join("opencode")
            .join(format!(
                "redtrace-hardening-{}",
                redtrace::ingest::hex(&random)
            ));
        fs::create_dir_all(&directory).unwrap();
        Self(directory)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct IngestFixture {
    url: String,
    token: String,
    state: IngestState,
    incoming: mpsc::Receiver<Event>,
    server: JoinHandle<()>,
}

impl IngestFixture {
    async fn start(directory: &Directory) -> Self {
        let registry = Arc::new(
            AgentRegistry::open_with_limits(
                directory.0.join("agents.json"),
                IngestLimits {
                    request_timeout_ms: 300,
                    ..IngestLimits::default()
                },
            )
            .unwrap(),
        );
        let (_, token) = registry.create("hardening-fixture").unwrap();
        let (events, incoming) = mpsc::channel(64);
        let state = IngestState {
            registry,
            events,
            known_uids: Arc::new(RwLock::new(HashSet::new())),
            stats: Arc::new(RwLock::new(IngestStats::default())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/ingest/v1/events", listener.local_addr().unwrap());
        let router = ingest_router(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            url,
            token,
            state,
            incoming,
            server,
        }
    }

    fn post(&self, events: &[Event]) -> JoinHandle<reqwest::Response> {
        let url = self.url.clone();
        let token = self.token.clone();
        let body = build_events_body("hardening-fixture", events);
        tokio::spawn(async move {
            reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap()
                .post(url)
                .header(INGEST_TOKEN_HEADER, token)
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .unwrap()
        })
    }

    async fn receive(&mut self, count: usize) -> Vec<Event> {
        let mut events = Vec::new();
        for _ in 0..count {
            events.push(
                tokio::time::timeout(Duration::from_secs(2), self.incoming.recv())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        events
    }

    async fn confirm(&self, wal: &Wal, events: &[Event]) {
        wal.append(events).unwrap();
        self.state.registry.confirm_durable(events).unwrap();
        self.state
            .known_uids
            .write()
            .await
            .extend(events.iter().map(|event| event.uid.clone()));
    }

    async fn rotate(&self, wal: &Wal, segments: &SegmentStore) {
        segments.commit(&wal.recover().unwrap().events).unwrap();
        wal.reset().unwrap();
        *self.state.known_uids.write().await = segments
            .recover()
            .unwrap()
            .events
            .into_iter()
            .map(|event| event.uid)
            .collect();
    }

    async fn restart(&mut self, directory: &Directory) {
        self.server.abort();
        let registry = Arc::new(AgentRegistry::open(directory.0.join("agents.json")).unwrap());
        let (events, incoming) = mpsc::channel(64);
        let state = IngestState {
            registry,
            events,
            known_uids: Arc::new(RwLock::new(HashSet::new())),
            stats: Arc::new(RwLock::new(IngestStats::default())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        self.url = format!("http://{}/ingest/v1/events", listener.local_addr().unwrap());
        let router = ingest_router(state.clone());
        self.server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        self.state = state;
        self.incoming = incoming;
    }
}

impl Drop for IngestFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn event(sequence: u64) -> Event {
    let mut event = Event::normalized(
        sequence,
        format!("2026-10-12T12:00:{sequence:02}Z"),
        "linux.hardening".into(),
        "low".into(),
        format!("synthetic integration event {sequence} {}", "x".repeat(160)),
        BTreeMap::from([
            ("collector.cursor".into(), format!("cursor-{sequence}")),
            ("event.record_id".into(), format!("record-{sequence}")),
        ]),
    );
    event.identify(&format!("record-{sequence}"));
    event
}

fn store(directory: &Directory, cap: u64) -> SegmentStore {
    SegmentStore::open_with_limits(
        directory.0.join("core"),
        cap,
        7 * 24 * 60 * 60,
        2_500,
        4 * 1024 * 1024,
    )
    .unwrap()
}

async fn acknowledgement(response: reqwest::Response) -> (usize, usize) {
    assert_eq!(response.status(), 200);
    let value: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    (
        value["accepted"].as_u64().unwrap() as usize,
        value["duplicates"].as_u64().unwrap() as usize,
    )
}

#[tokio::test]
async fn spool_ingest_wal_rotation_query_and_lost_ack_replay_are_durable() {
    let directory = Directory::new();
    let mut fixture = IngestFixture::start(&directory).await;
    let segments = store(&directory, 100_000);
    let wal = Wal::open(directory.0.join("core").join("active.wal")).unwrap();
    let state_dir = directory.0.join("spool");
    let mut spool = DiskSpool::open(state_dir.clone(), SpoolLimits::default()).unwrap();
    for sequence in 1..=6 {
        spool.push(event(sequence)).unwrap();
    }
    let chunk = spool.peek_chunk(6).unwrap();
    let request = fixture.post(chunk.events());
    let received = fixture.receive(6).await;
    assert!(
        received
            .iter()
            .all(|event| !event.fields.contains_key("collector.cursor"))
    );
    fixture.confirm(&wal, &received).await;
    fixture.rotate(&wal, &segments).await;
    assert_eq!(acknowledgement(request.await.unwrap()).await, (6, 0));
    assert_eq!(fixture.state.budget_health().await.usage.pending_events, 0);
    drop(spool);
    drop(segments);
    let segments = store(&directory, 100_000);
    let mut spool = DiskSpool::open(state_dir, SpoolLimits::default()).unwrap();
    assert_eq!(spool.len(), 6);
    let replay = spool.peek_chunk(6).unwrap();
    let ack = acknowledgement(fixture.post(replay.events()).await.unwrap()).await;
    assert_eq!(ack, (0, 6));
    assert!(fixture.incoming.try_recv().is_err());
    spool.acknowledge(&replay, ack.0, ack.1).unwrap();
    assert!(spool.is_empty());
    assert_eq!(
        spool
            .server_ack_checkpoint("linux.hardening")
            .unwrap()
            .cursor,
        "cursor-6"
    );
    let result = segments.search(&Expr::MatchAll, 100).unwrap();
    assert_eq!(result.total, 6);
    assert_eq!(
        result
            .events
            .iter()
            .map(|event| event.uid.clone())
            .collect::<HashSet<_>>(),
        received.iter().map(|event| event.uid.clone()).collect()
    );
    let wire = serde_json::to_value(&result).unwrap();
    assert!(wire["total"].is_number());
    assert!(wire["took_micros"].is_number());
    for value in wire["events"].as_array().unwrap() {
        assert!(value["uid"].is_string());
        assert!(value["timestamp"].is_string());
        assert!(value["message"].is_string());
        assert!(
            value["fields"]
                .as_object()
                .unwrap()
                .values()
                .all(Value::is_string)
        );
    }
}

#[tokio::test]
async fn durable_batch_ack_survives_eviction_within_the_same_wal_rotation() {
    let directory = Directory::new();
    let mut fixture = IngestFixture::start(&directory).await;
    let segments = store(&directory, 4_000);
    let wal = Wal::open(directory.0.join("core").join("active.wal")).unwrap();
    let mut spool = DiskSpool::open(directory.0.join("spool"), SpoolLimits::default()).unwrap();
    for sequence in 1..=12 {
        spool.push(event(sequence)).unwrap();
    }
    let chunk = spool.peek_chunk(12).unwrap();
    let request = fixture.post(chunk.events());
    let received = fixture.receive(12).await;
    fixture.confirm(&wal, &received).await;
    fixture.rotate(&wal, &segments).await;
    let retained = segments.search(&Expr::MatchAll, 100).unwrap().total;
    assert!(retained > 0 && retained < received.len());
    assert!(segments.stats().unwrap().1 <= 4_000);
    assert!(wal.recover().unwrap().events.is_empty());
    let response = request.await.unwrap();
    let status = response.status();
    let retry = fixture.post(chunk.events()).await.unwrap();
    let health = fixture.state.budget_health().await;
    eprintln!(
        "rotation eviction: durable={}, retained={retained}, first={status}, retry={}, pending={}, spool={}",
        received.len(),
        retry.status(),
        health.usage.pending_events,
        spool.len()
    );
    assert!(fixture.incoming.try_recv().is_err());
    assert_eq!(
        status,
        200,
        "durable receipt disappeared during retention; retry status {}, pending {}",
        retry.status(),
        health.usage.pending_events
    );
    let ack = acknowledgement(response).await;
    spool.acknowledge(&chunk, ack.0, ack.1).unwrap();
    assert!(spool.is_empty());
    assert_eq!(health.usage.pending_events, 0);
    fixture.restart(&directory).await;
    assert_eq!(
        acknowledgement(fixture.post(chunk.events()).await.unwrap()).await,
        (0, 12)
    );
    assert!(fixture.incoming.try_recv().is_err());
}

#[tokio::test]
async fn retry_reenqueues_after_wal_append_failure_and_storage_recovery() {
    let directory = Directory::new();
    let mut fixture = IngestFixture::start(&directory).await;
    let wal = Wal::open(directory.0.join("active.wal")).unwrap();
    let events = [event(1)];
    let first = fixture.post(&events);
    let received = fixture.receive(1).await;
    fs::remove_file(wal.path()).unwrap();
    fs::create_dir(wal.path()).unwrap();
    assert!(wal.append(&received).is_err());
    fixture.state.registry.storage_rejected(&received);
    assert_eq!(first.await.unwrap().status(), 429);
    fs::remove_dir(wal.path()).unwrap();
    fs::write(wal.path(), []).unwrap();
    let retry = fixture.post(&events);
    let replay = tokio::time::timeout(Duration::from_millis(600), fixture.incoming.recv()).await;
    if let Ok(Some(event)) = &replay {
        fixture.confirm(&wal, std::slice::from_ref(event)).await;
    }
    let response = retry.await.unwrap();
    let pending = fixture.state.budget_health().await.usage.pending_events;
    eprintln!(
        "WAL recovery retry: reenqueued={}, status={}, pending={pending}, recovered={}",
        replay.is_ok(),
        response.status(),
        wal.recover().unwrap().events.len()
    );
    assert!(
        replay.is_ok(),
        "storage recovered but the failed event is permanently reserved as pending"
    );
    assert_eq!(response.status(), 200);
    assert_eq!(pending, 0);
}

#[test]
fn query_cache_reuse_preserves_limits_cancellation_and_retention_invalidation() {
    let directory = Directory::new();
    let segments = store(&directory, 4_000);
    segments.commit(&[event(1)]).unwrap();
    let mut cold = QueryBudget::new(ExecutionLimits::default());
    let first = segments
        .search_page_bounded(&Expr::MatchAll, 10, None, &mut cold)
        .unwrap();
    let mut warm = QueryBudget::new(ExecutionLimits::default());
    let second = segments
        .search_page_bounded(&Expr::MatchAll, 10, None, &mut warm)
        .unwrap();
    assert_eq!(first.events, second.events);
    assert!(warm.usage.scan_bytes < cold.usage.scan_bytes);
    assert!(warm.usage.peak_memory_bytes <= warm.limits.max_memory_bytes);
    let mut cancelled = QueryBudget::new(ExecutionLimits::default());
    cancelled.cancellation().cancel();
    assert_eq!(
        query_failure(
            &segments
                .search_page_bounded(&Expr::MatchAll, 10, None, &mut cancelled)
                .unwrap_err()
        ),
        Some(QueryFailure::Cancelled)
    );
    let mut bounded = QueryBudget::new(ExecutionLimits {
        max_work: 1,
        ..ExecutionLimits::default()
    });
    assert_eq!(
        query_failure(
            &segments
                .search_page_bounded(&Expr::MatchAll, 0, None, &mut bounded)
                .unwrap_err()
        ),
        Some(QueryFailure::Work)
    );
    segments.commit(&[event(2), event(3), event(4)]).unwrap();
    let retained = segments.recover().unwrap().events;
    assert!(
        !retained
            .iter()
            .any(|event| event.uid == first.events[0].uid)
    );
    let current = segments.search(&Expr::MatchAll, 10).unwrap();
    assert_eq!(current.total, retained.len());
    assert_eq!(
        current
            .events
            .iter()
            .map(|event| event.uid.clone())
            .collect::<HashSet<_>>(),
        retained.into_iter().map(|event| event.uid).collect()
    );
}

#[test]
fn collector_error_and_degraded_prefix_do_not_skip_refused_spool_cursors() {
    let directory = Directory::new();
    let mut runtime = AgentRuntime::new_with_spool_limits(
        AgentConfig {
            server: "http://127.0.0.1:9".into(),
            token: "synthetic-integration-fixture".into(),
            name: "hardening-fixture".into(),
            state_dir: directory.0.join("spool"),
            poll: Duration::from_secs(1),
            heartbeat: Duration::from_secs(30),
            flush_events: 500,
            outbox_cap: 2,
            lookback: None,
        },
        SpoolLimits {
            max_events: 2,
            ..SpoolLimits::default()
        },
    )
    .unwrap();
    for (state, events) in [
        ("error", vec![event(1)]),
        ("degraded", vec![event(1), event(2), event(3)]),
    ] {
        runtime.collect_with(|_| CollectionBatch {
            status: SourceStatus {
                name: "synthetic".into(),
                platform: "linux".into(),
                state: state.into(),
                events_collected: events.len(),
                lookback: "none".into(),
                last_error: Some("synthetic source read barrier".into()),
            },
            events,
        });
        if state == "error" {
            assert!(runtime.outbox.is_empty());
            assert!(runtime.outbox.read_checkpoint("linux.hardening").is_none());
        }
    }
    assert_eq!(runtime.outbox.len(), 2);
    assert_eq!(
        runtime.checkpoints.get("linux.hardening").unwrap().cursor,
        "cursor-2"
    );
    assert!(
        runtime
            .outbox
            .server_ack_checkpoint("linux.hardening")
            .is_none()
    );
    let mut expected = [event(1), event(2)];
    for event in &mut expected {
        redtrace::modules::normalize(event);
    }
    assert_eq!(runtime.outbox.peek_chunk(10).unwrap().events(), &expected);
}

#[test]
fn journald_resume_uses_last_durable_cursor_when_timestamps_tie_across_sources() {
    let directory = Directory::new();
    let mut spool = DiskSpool::open(directory.0.join("spool"), SpoolLimits::default()).unwrap();
    let mut first = event(1);
    first.source = "linux.zulu".into();
    let mut second = event(2);
    second.source = "linux.alpha".into();
    second.timestamp = first.timestamp.clone();
    spool.push(first).unwrap();
    spool.push(second).unwrap();
    let checkpoints = spool.collector_checkpoints().unwrap();
    let resume = checkpoints.newest_with_prefix("linux.").unwrap();
    assert_eq!(
        resume.cursor, "cursor-2",
        "wall-clock/source-name order selected an older journal position than the durable spool tail"
    );
}
