use redtrace::agent::{Delivery, deliver_chunk, parse_server, send_heartbeat};
use redtrace::ingest::AgentRegistry;
use redtrace::ingest::ingest_router;
use redtrace::ingest::{IngestState, IngestStats, MAX_EVENTS_PER_BATCH};
use redtrace::model::Event;
use redtrace::storage::CheckpointStore;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};

fn sample_events(count: usize) -> Vec<Event> {
    (0..count)
        .map(|index| {
            let mut fields = BTreeMap::new();
            fields.insert("event.id".to_string(), "ssh.login.failure".to_string());
            fields.insert(
                "source.ip".to_string(),
                format!("10.0.0.{}", 10 + index % 200),
            );
            fields.insert("collector.cursor".to_string(), format!("cursor-{index}"));
            Event::normalized(
                0,
                format!("2026-10-03T12:00:{index:02}Z"),
                "linux.sshd".into(),
                "medium".into(),
                format!("Failed password for user{index} from 10.0.0.{index} port 22 ssh2"),
                fields,
            )
        })
        .collect()
}

struct TestServer {
    address: String,
    token: String,
    agent_id: String,
    rx: mpsc::Receiver<Event>,
    known_uids: Arc<RwLock<HashSet<String>>>,
    stats: Arc<RwLock<IngestStats>>,
    registry: Arc<AgentRegistry>,
    data_dir: std::path::PathBuf,
}

impl TestServer {
    async fn start() -> Self {
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let data_dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "redtrace-ingest-test-{}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let registry = Arc::new(AgentRegistry::open(data_dir.join("agents.json")).unwrap());
        let (record, token) = registry.create("integration-host").unwrap();
        let (tx, mut incoming) = mpsc::channel::<Event>(4096);
        let (captured, rx) = mpsc::channel(4096);
        let known_uids = Arc::new(RwLock::new(HashSet::new()));
        let stats = Arc::new(RwLock::new(IngestStats::default()));
        let durable_uids = known_uids.clone();
        let wal = redtrace::storage::Wal::open(data_dir.join("test.wal")).unwrap();
        tokio::spawn(async move {
            while let Some(event) = incoming.recv().await {
                wal.append(std::slice::from_ref(&event)).unwrap();
                durable_uids.write().await.insert(event.uid.clone());
                captured.send(event).await.unwrap();
            }
        });
        let state = IngestState {
            registry: registry.clone(),
            events: tx,
            known_uids: known_uids.clone(),
            stats: stats.clone(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            axum::serve(listener, ingest_router(state))
                .await
                .expect("serve test ingest router");
        });
        Self {
            address,
            token,
            agent_id: record.id,
            rx,
            known_uids,
            stats,
            registry,
            data_dir,
        }
    }

    async fn drain_into_known_uids(&mut self) -> Vec<Event> {
        let mut received = Vec::new();
        while let Ok(event) = self.rx.try_recv() {
            self.known_uids.write().await.insert(event.uid.clone());
            received.push(event);
        }
        received
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_gate_holds_heartbeat_mutations_until_snapshot_finishes() {
    let server = TestServer::start().await;
    let guard = server.registry.maintenance.clone().write_owned().await;
    let endpoint = parse_server(&format!("http://{}", server.address)).unwrap();
    let token = server.token.clone();
    let mut heartbeat = tokio::task::spawn_blocking(move || {
        send_heartbeat(&endpoint, &token, "integration-host", 0, 0)
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut heartbeat)
            .await
            .is_err()
    );
    assert_eq!(server.registry.list()[0].last_seen_unix, 0);
    drop(guard);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), heartbeat)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        200
    );
    assert!(server.registry.list()[0].last_seen_unix > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_waits_until_event_is_durable() {
    let dir = std::env::temp_dir().join(format!("redtrace-ack-{}", std::process::id()));
    let registry = Arc::new(AgentRegistry::open(dir.join("agents.json")).unwrap());
    let (_, token) = registry.create("ack-test").unwrap();
    let (tx, mut rx) = mpsc::channel::<Event>(16);
    let known = Arc::new(RwLock::new(HashSet::new()));
    let state = IngestState {
        registry,
        events: tx,
        known_uids: known.clone(),
        stats: Arc::new(RwLock::new(IngestStats::default())),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, ingest_router(state)).await.unwrap();
    });
    let request = tokio::task::spawn_blocking(move || {
        deliver_chunk(
            &parse_server(&url).unwrap(),
            &token,
            "ack-test",
            &sample_events(1),
        )
    });
    let event = rx.recv().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!request.is_finished());
    let wal = redtrace::storage::Wal::open(dir.join("events.wal")).unwrap();
    wal.append(std::slice::from_ref(&event)).unwrap();
    known.write().await.insert(event.uid);
    assert_eq!(
        request.await.unwrap(),
        Delivery::Accepted {
            accepted: 1,
            duplicates: 0
        }
    );
    assert_eq!(wal.recover().unwrap().events.len(), 1);
    server.abort();
    let _ = server.await;
    drop(wal);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_event_is_quarantined_without_blocking_valid_events() {
    use redtrace::agent::{AgentConfig, AgentRuntime};
    let server = TestServer::start().await;
    let endpoint = parse_server(&format!("http://{}", server.address)).unwrap();
    let config = AgentConfig {
        server: endpoint.url.clone(),
        token: server.token.clone(),
        name: "quarantine-test".into(),
        state_dir: server.data_dir.join("agent"),
        poll: std::time::Duration::from_secs(1),
        heartbeat: std::time::Duration::from_secs(30),
        flush_events: 500,
        outbox_cap: 100,
        lookback: None,
    };
    let mut runtime = AgentRuntime::new(config).unwrap();
    let mut events = sample_events(2);
    events[0]
        .fields
        .insert("oversized".into(), "x".repeat(65537));
    let bad_uid = events[0].uid.clone();
    let good_cursor = events[1].fields["collector.cursor"].clone();
    for event in events {
        runtime.outbox.push(event).unwrap();
    }
    runtime.flush(&endpoint);
    runtime.flush(&endpoint);
    assert!(runtime.outbox.is_empty());
    assert!(
        runtime
            .config
            .state_dir
            .join("quarantine")
            .join(format!("{bad_uid}.json"))
            .exists()
    );
    assert_eq!(
        runtime.checkpoints.get("linux.sshd").unwrap().cursor,
        good_cursor
    );
    assert_eq!(runtime.sent_total, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_delivery_round_trip_with_dedup_and_revocation() {
    let mut server = TestServer::start().await;
    let endpoint = parse_server(&format!("http://{}", server.address)).unwrap();
    let events = sample_events(3);

    let delivery = deliver_chunk(&endpoint, &server.token, "integration-host", &events);
    assert_eq!(
        delivery,
        Delivery::Accepted {
            accepted: 3,
            duplicates: 0
        }
    );
    server.drain_into_known_uids().await;

    let delivery = deliver_chunk(&endpoint, &server.token, "integration-host", &events);
    assert_eq!(
        delivery,
        Delivery::Accepted {
            accepted: 0,
            duplicates: 3
        }
    );

    let agent = server.registry.list()[0].clone();
    assert_eq!(server.stats.read().await.duplicate_events_total, 3);
    assert_eq!(agent.events_received, 3);
    assert!(agent.last_seen_unix > 0);

    let mut received = Vec::new();
    while let Ok(event) = server.rx.try_recv() {
        received.push(event);
    }
    assert!(received.is_empty());

    let status = send_heartbeat(&endpoint, &server.token, "integration-host", 3, 0).unwrap();
    assert_eq!(status, 200);
    assert_eq!(server.stats.read().await.heartbeats_total, 1);

    assert!(server.registry.revoke(&server.agent_id).unwrap());
    let delivery = deliver_chunk(&endpoint, &server.token, "integration-host", &events);
    assert_eq!(delivery, Delivery::Unauthorized);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_events_inside_a_batch_are_acknowledged_as_duplicates() {
    let mut server = TestServer::start().await;
    let endpoint = parse_server(&format!("http://{}", server.address)).unwrap();
    let mut events = sample_events(3);
    events.extend(events.clone());
    assert_eq!(
        deliver_chunk(&endpoint, &server.token, "integration-host", &events),
        Delivery::Accepted {
            accepted: 3,
            duplicates: 3
        }
    );
    assert_eq!(server.drain_into_known_uids().await.len(), 3);
    assert_eq!(server.stats.read().await.duplicate_events_total, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_payloads_are_rejected_without_poisoning_the_queue() {
    let mut server = TestServer::start().await;
    let endpoint = parse_server(&format!("http://{}", server.address)).unwrap();

    let mut bad = sample_events(1);
    bad[0].timestamp = "yesterday-ish".into();
    assert!(matches!(
        deliver_chunk(&endpoint, &server.token, "integration-host", &bad),
        Delivery::Rejected { .. }
    ));

    let oversized: Vec<_> = (0..=MAX_EVENTS_PER_BATCH)
        .map(|index| {
            let mut event = sample_events(1).remove(0);
            event.message = format!("overflow {index}");
            event
        })
        .collect();
    assert!(matches!(
        deliver_chunk(&endpoint, &server.token, "integration-host", &oversized),
        Delivery::Rejected { .. }
    ));

    let good = sample_events(2);
    assert_eq!(
        deliver_chunk(&endpoint, &server.token, "integration-host", &good),
        Delivery::Accepted {
            accepted: 2,
            duplicates: 0
        }
    );
    let received = server.drain_into_known_uids().await;
    assert_eq!(received.len(), 2);
    assert!(
        received
            .iter()
            .all(|event| !event.fields.contains_key("collector.cursor"))
    );
    assert!(
        received
            .iter()
            .all(|event| event.fields.get("agent.id").map(String::as_str)
                == Some(server.agent_id.as_str()))
    );
    assert!(received.iter().all(
        |event| event.fields.get("agent.name").map(String::as_str) == Some("integration-host")
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_from_different_agents_get_distinct_uids() {
    let mut server = TestServer::start().await;
    let endpoint = parse_server(&format!("http://{}", server.address)).unwrap();
    let (other, other_token) = server.registry.create("second-host").unwrap();

    let events = sample_events(2);
    assert_eq!(
        deliver_chunk(&endpoint, &server.token, "integration-host", &events),
        Delivery::Accepted {
            accepted: 2,
            duplicates: 0
        }
    );
    assert_eq!(
        deliver_chunk(&endpoint, &other_token, "second-host", &events),
        Delivery::Accepted {
            accepted: 2,
            duplicates: 0
        }
    );

    let mut grouped: std::collections::HashMap<String, HashSet<String>> =
        std::collections::HashMap::new();
    while let Ok(event) = server.rx.try_recv() {
        grouped
            .entry(event.fields["agent.id"].clone())
            .or_default()
            .insert(event.uid.clone());
    }
    assert_eq!(grouped.len(), 2);
    let sets: Vec<&HashSet<String>> = grouped.values().collect();
    assert!(sets[0].is_disjoint(sets[1]));
    assert!(grouped.contains_key(&other.id));
    assert!(grouped.contains_key(&server.agent_id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_events_do_not_pollute_local_checkpoints() {
    let mut server = TestServer::start().await;
    let endpoint = parse_server(&format!("http://{}", server.address)).unwrap();
    let events = sample_events(2);
    assert_eq!(
        deliver_chunk(&endpoint, &server.token, "integration-host", &events),
        Delivery::Accepted {
            accepted: 2,
            duplicates: 0
        }
    );

    let checkpoint_dir = server.data_dir.join("server-side-checkpoints");
    std::fs::create_dir_all(&checkpoint_dir).unwrap();
    let local_checkpoints = CheckpointStore::open(checkpoint_dir.join("checkpoints.json")).unwrap();
    let mut received = Vec::new();
    while let Ok(event) = server.rx.try_recv() {
        received.push(event);
    }
    local_checkpoints.update_events(&received).unwrap();
    assert_eq!(local_checkpoints.len(), 0);
}
