use redtrace::{
    ingest::{
        AgentRegistry, INGEST_TOKEN_HEADER, IngestLimits, IngestState, IngestStats, ingest_router,
    },
    model::Event,
};
use serde_json::{Value, json};
use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    sync::{RwLock, mpsc},
    task::JoinHandle,
};

struct Fixture {
    url: String,
    token: String,
    id: String,
    state: IngestState,
    incoming: mpsc::Receiver<Event>,
    server: JoinHandle<()>,
    path: PathBuf,
}

fn limits() -> IngestLimits {
    IngestLimits {
        max_body_bytes: 16 * 1024,
        max_event_bytes: 1024,
        max_batch_bytes: 4096,
        global_concurrency: 2,
        agent_concurrency: 1,
        global_inflight_bytes: 40 * 1024,
        agent_inflight_bytes: 20 * 1024,
        global_waiters: 2,
        agent_waiters: 1,
        global_waiting_bytes: 40 * 1024,
        agent_waiting_bytes: 20 * 1024,
        global_pending_events: 4,
        agent_pending_events: 2,
        global_pending_bytes: 8192,
        agent_pending_bytes: 4096,
        queue_wait_ms: 100,
        request_timeout_ms: 500,
        ..IngestLimits::default()
    }
}

impl Fixture {
    async fn start(config: IngestLimits, capacity: usize) -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "redtrace-budget-{}",
            redtrace::ingest::hex(&random)
        ));
        let registry =
            Arc::new(AgentRegistry::open_with_limits(path.join("agents.json"), config).unwrap());
        let (agent, token) = registry.create("budget-endpoint").unwrap();
        let (events, incoming) = mpsc::channel(capacity);
        let state = IngestState {
            registry,
            events,
            known_uids: Arc::new(RwLock::new(HashSet::new())),
            stats: Arc::new(RwLock::new(IngestStats::default())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = ingest_router(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            url,
            token,
            id: agent.id,
            state,
            incoming,
            server,
            path,
        }
    }

    fn post(&self, route: &str, body: Value) -> JoinHandle<reqwest::Response> {
        let url = format!("{}{route}", self.url);
        let token = self.token.clone();
        tokio::spawn(async move {
            reqwest::Client::new()
                .post(url)
                .header(INGEST_TOKEN_HEADER, token)
                .header("content-type", "application/json")
                .body(body.to_string())
                .send()
                .await
                .unwrap()
        })
    }

    async fn durable(&mut self) -> Event {
        let event = tokio::time::timeout(Duration::from_secs(2), self.incoming.recv())
            .await
            .unwrap()
            .unwrap();
        self.state
            .known_uids
            .write()
            .await
            .insert(event.uid.clone());
        event
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn payload(identity: &str) -> Value {
    json!({
        "agent_version": "0.1.0+dev",
        "host": {"name": "endpoint.local", "os": "linux", "architecture": "x86_64"},
        "events": [{
            "timestamp": "2026-10-12T00:00:00Z", "source": "linux.sshd", "level": "low",
            "message": "budget fixture", "fields": {"event.record_id": identity}
        }]
    })
}

fn assert_throttle(response: &reqwest::Response) {
    assert_eq!(response.status(), 429);
    assert_eq!(response.headers().get("retry-after").unwrap(), "1");
}

#[tokio::test]
async fn authentication_precedes_body_limits_json_parsing_and_budget_admission() {
    let fixture = Fixture::start(limits(), 4).await;
    let client = reqwest::Client::new();
    for route in ["/ingest/v1/events", "/ingest/v1/heartbeat"] {
        let response = client
            .post(format!("{}{route}", fixture.url))
            .body("x".repeat(20 * 1024))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
        let response = client
            .post(format!("{}{route}", fixture.url))
            .header(INGEST_TOKEN_HEADER, &fixture.token)
            .header("content-type", "application/json")
            .body("x".repeat(20 * 1024))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 413);
        let response = client
            .post(format!("{}{route}", fixture.url))
            .header(INGEST_TOKEN_HEADER, &fixture.token)
            .header("content-type", "application/json")
            .body(format!("{{\"secret-{}\":", fixture.token))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        assert!(!response.text().await.unwrap().contains(&fixture.token));
    }
    let snapshot = fixture.state.budget_health().await;
    assert_eq!(snapshot.unauthorized_total, 2);
    assert_eq!(snapshot.usage.active_requests, 0);
    assert_eq!(snapshot.usage.pending_events, 0);
}

#[tokio::test]
async fn invalid_metadata_is_rejected_for_empty_batches_and_heartbeats() {
    let fixture = Fixture::start(limits(), 4).await;
    let bad = [
        json!({"host": {"os": "x".repeat(17)}}),
        json!({"host": {"os": "LINUX"}}),
        json!({"host": {"name": "x".repeat(129)}}),
        json!({"host": {"name": "endpoint\nsecret"}}),
        json!({"host": {"arch": "unknown"}}),
        json!({"host": {"architecture": "x".repeat(17)}}),
        json!({"agent_version": "x".repeat(65)}),
        json!({"agent_version": "0.1\nsecret"}),
    ];
    for route in ["/ingest/v1/events", "/ingest/v1/heartbeat"] {
        for body in &bad {
            assert_eq!(
                fixture.post(route, body.clone()).await.unwrap().status(),
                400
            );
        }
    }
    let agent = &fixture.state.registry.list()[0];
    assert_eq!(agent.last_seen_unix, 0);
    assert!(agent.platform.is_none());
    assert_eq!(fixture.state.stats.read().await.heartbeats_total, 0);
    assert_eq!(fixture.state.budget_health().await.usage.pending_events, 0);
}

#[tokio::test]
async fn normalized_event_and_aggregate_bytes_reject_batches_before_any_enqueue() {
    let mut config = limits();
    config.max_batch_bytes = 1024;
    let mut fixture = Fixture::start(config, 4).await;
    let mut oversized = payload("oversized");
    oversized["events"][0]["message"] = json!("\u{1}".repeat(200));
    assert_eq!(
        fixture
            .post("/ingest/v1/events", oversized)
            .await
            .unwrap()
            .status(),
        413
    );
    let mut aggregate = payload("1");
    aggregate["events"][0]["message"] = json!("x".repeat(400));
    let mut second = aggregate["events"][0].clone();
    second["fields"]["event.record_id"] = json!("2");
    aggregate["events"].as_array_mut().unwrap().push(second);
    assert_eq!(
        fixture
            .post("/ingest/v1/events", aggregate)
            .await
            .unwrap()
            .status(),
        413
    );
    assert!(fixture.incoming.try_recv().is_err());
    assert_eq!(fixture.state.budget_health().await.usage.pending_bytes, 0);
    let valid = fixture.post("/ingest/v1/events", payload("valid"));
    let event = fixture.durable().await;
    assert_eq!(event.fields["host.os"], "linux");
    assert_eq!(event.fields["host.architecture"], "x86_64");
    assert_eq!(valid.await.unwrap().status(), 200);
}

#[tokio::test]
async fn per_agent_concurrency_and_waiter_caps_return_retry_after() {
    let mut fixture = Fixture::start(limits(), 4).await;
    let first = fixture.post("/ingest/v1/events", payload("first"));
    let event = fixture.incoming.recv().await.unwrap();
    let waiter = fixture.post("/ingest/v1/heartbeat", json!({}));
    for _ in 0..100 {
        if fixture.state.budget_health().await.usage.waiting_requests == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        fixture.state.budget_health().await.usage.waiting_requests,
        1
    );
    assert_throttle(
        &fixture
            .post("/ingest/v1/heartbeat", json!({}))
            .await
            .unwrap(),
    );
    assert_throttle(&waiter.await.unwrap());
    fixture.state.known_uids.write().await.insert(event.uid);
    assert_eq!(first.await.unwrap().status(), 200);
    assert_eq!(
        fixture
            .post("/ingest/v1/heartbeat", json!({}))
            .await
            .unwrap()
            .status(),
        200
    );
    let snapshot = fixture.state.budget_health().await;
    assert_eq!(snapshot.usage.active_requests, 0);
    assert_eq!(snapshot.usage.waiting_requests, 0);
    assert_eq!(snapshot.throttled_total, 2);
}

#[tokio::test]
async fn timeout_keeps_pending_bytes_and_retries_wait_for_original_durable_ack() {
    let mut fixture = Fixture::start(limits(), 4).await;
    let first = fixture.post("/ingest/v1/events", payload("retry"));
    let event = fixture.incoming.recv().await.unwrap();
    assert_throttle(&first.await.unwrap());
    let before = fixture.state.budget_health().await;
    assert_eq!(before.usage.pending_events, 1);
    assert!(before.usage.pending_bytes > 0);
    assert_eq!(before.usage.active_requests, 0);
    assert_eq!(before.request_timeouts_total, 1);
    let retry = fixture.post("/ingest/v1/events", payload("retry"));
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!retry.is_finished());
    assert!(fixture.incoming.try_recv().is_err());
    fixture.state.known_uids.write().await.insert(event.uid);
    let response = retry.await.unwrap();
    assert_eq!(response.status(), 200);
    let result: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(result, json!({"accepted": 0, "duplicates": 1}));
    assert_eq!(fixture.state.budget_health().await.usage.pending_bytes, 0);
}

#[tokio::test]
async fn partial_queue_timeout_releases_only_unsent_reservations() {
    let mut fixture = Fixture::start(limits(), 1).await;
    let mut batch = payload("first");
    batch["events"]
        .as_array_mut()
        .unwrap()
        .push(payload("second")["events"][0].clone());
    assert_throttle(&fixture.post("/ingest/v1/events", batch).await.unwrap());
    let snapshot = fixture.state.budget_health().await;
    assert_eq!(snapshot.usage.pending_events, 1);
    assert_eq!(snapshot.agents[&fixture.id].pending_events, 1);
    fixture.durable().await;
    assert_eq!(fixture.state.budget_health().await.usage.pending_events, 0);
    let request = fixture.post("/ingest/v1/events", payload("second"));
    fixture.durable().await;
    assert_eq!(request.await.unwrap().status(), 200);
}

#[tokio::test]
async fn rotation_preserves_agent_identity_uid_dedup_and_all_token_revocation() {
    let mut fixture = Fixture::start(limits(), 4).await;
    let first = fixture.post("/ingest/v1/events", payload("identity"));
    let original = fixture.durable().await;
    assert_eq!(first.await.unwrap().status(), 200);
    let previous = fixture.token.clone();
    let issued = fixture
        .state
        .registry
        .rotate(&fixture.id, 60, 30)
        .unwrap()
        .unwrap();
    assert_eq!(issued.id, fixture.id);
    fixture.token = issued.token;
    let response = fixture
        .post("/ingest/v1/events", payload("identity"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let result: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(result, json!({"accepted": 0, "duplicates": 1}));
    assert!(fixture.incoming.try_recv().is_err());
    assert!(fixture.state.registry.verify(&previous).is_some());
    let request = fixture.post("/ingest/v1/events", payload("next"));
    let next = fixture.durable().await;
    assert_eq!(request.await.unwrap().status(), 200);
    assert_eq!(original.fields["agent.id"], next.fields["agent.id"]);
    assert!(fixture.state.registry.revoke(&fixture.id).unwrap());
    assert_eq!(
        fixture
            .post("/ingest/v1/heartbeat", json!({}))
            .await
            .unwrap()
            .status(),
        401
    );
    fixture.token = previous;
    assert_eq!(
        fixture
            .post("/ingest/v1/heartbeat", json!({}))
            .await
            .unwrap()
            .status(),
        401
    );
}

#[tokio::test]
async fn global_concurrency_and_waiting_byte_limits_apply_across_agents() {
    let mut config = limits();
    config.global_waiting_bytes = config.agent_waiting_bytes;
    let mut fixture = Fixture::start(config, 4).await;
    let first = fixture.post("/ingest/v1/events", payload("a"));
    let a = fixture.incoming.recv().await.unwrap();
    fixture.token = fixture.state.registry.create("b").unwrap().1;
    let second = fixture.post("/ingest/v1/events", payload("b"));
    let b = fixture.incoming.recv().await.unwrap();
    fixture.token = fixture.state.registry.create("c").unwrap().1;
    let waiting = fixture.post("/ingest/v1/heartbeat", json!({}));
    for _ in 0..100 {
        if fixture.state.budget_health().await.usage.waiting_requests == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let snapshot = fixture.state.budget_health().await;
    assert_eq!(snapshot.usage.active_requests, 2);
    assert_eq!(snapshot.usage.waiting_requests, 1);
    assert_eq!(snapshot.usage.waiting_bytes, 20 * 1024);
    fixture.token = fixture.state.registry.create("d").unwrap().1;
    assert_throttle(
        &fixture
            .post("/ingest/v1/heartbeat", json!({}))
            .await
            .unwrap(),
    );
    assert_throttle(&waiting.await.unwrap());
    fixture
        .state
        .known_uids
        .write()
        .await
        .extend([a.uid, b.uid]);
    assert_eq!(first.await.unwrap().status(), 200);
    assert_eq!(second.await.unwrap().status(), 200);
    assert_eq!(fixture.state.budget_health().await.usage.active_requests, 0);
}

#[tokio::test]
async fn pending_limits_bound_durable_waits_across_agents_after_request_timeouts() {
    let mut config = limits();
    config.request_timeout_ms = 200;
    let mut fixture = Fixture::start(config, 4).await;
    let mut too_many = payload("a");
    too_many["events"].as_array_mut().unwrap().extend([
        payload("b")["events"][0].clone(),
        payload("c")["events"][0].clone(),
    ]);
    assert_throttle(&fixture.post("/ingest/v1/events", too_many).await.unwrap());
    assert!(fixture.incoming.try_recv().is_err());
    let mut batch = payload("a");
    batch["events"]
        .as_array_mut()
        .unwrap()
        .push(payload("b")["events"][0].clone());
    let first = fixture.post("/ingest/v1/events", batch.clone());
    let a = fixture.incoming.recv().await.unwrap();
    let b = fixture.incoming.recv().await.unwrap();
    fixture.token = fixture.state.registry.create("second").unwrap().1;
    let second = fixture.post("/ingest/v1/events", batch);
    let c = fixture.incoming.recv().await.unwrap();
    let d = fixture.incoming.recv().await.unwrap();
    assert_throttle(&first.await.unwrap());
    assert_throttle(&second.await.unwrap());
    assert_eq!(fixture.state.budget_health().await.usage.pending_events, 4);
    fixture.token = fixture.state.registry.create("third").unwrap().1;
    assert_throttle(
        &fixture
            .post("/ingest/v1/events", payload("next"))
            .await
            .unwrap(),
    );
    assert!(fixture.incoming.try_recv().is_err());
    fixture
        .state
        .known_uids
        .write()
        .await
        .extend([a.uid, b.uid, c.uid, d.uid]);
    assert_eq!(fixture.state.budget_health().await.usage.pending_bytes, 0);
    let next = fixture.post("/ingest/v1/events", payload("next"));
    fixture.durable().await;
    assert_eq!(next.await.unwrap().status(), 200);
}

#[tokio::test]
async fn revoked_token_is_rechecked_after_waiting_for_admission() {
    let mut fixture = Fixture::start(limits(), 4).await;
    let first = fixture.post("/ingest/v1/events", payload("already-admitted"));
    let event = fixture.incoming.recv().await.unwrap();
    let waiting = fixture.post("/ingest/v1/heartbeat", json!({}));
    for _ in 0..100 {
        if fixture.state.budget_health().await.usage.waiting_requests == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        fixture.state.budget_health().await.usage.waiting_requests,
        1
    );
    fixture.state.registry.revoke(&fixture.id).unwrap();
    fixture.state.known_uids.write().await.insert(event.uid);
    assert_eq!(first.await.unwrap().status(), 200);
    assert_eq!(waiting.await.unwrap().status(), 401);
    assert_eq!(fixture.state.stats.read().await.heartbeats_total, 0);
}
