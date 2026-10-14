use redtrace::{
    agent::{
        AgentConfig, AgentRuntime, DiskSpool, Enqueued, SpoolLimits, parse_server, read_token_file,
    },
    collector::{CollectionBatch, SourceStatus},
    ingest::{AuthenticatedAgent, IngestRequest, normalize_event},
    model::Event,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join("opencode");
        fs::create_dir_all(&parent).unwrap();
        let directory = parent.join(format!(
            "redtrace-agent-spool-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }

    fn state(&self) -> PathBuf {
        self.0.join("state")
    }
    fn open(&self) -> DiskSpool {
        DiskSpool::open(self.state(), SpoolLimits::default()).unwrap()
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn event(sequence: usize) -> Event {
    let mut event = Event::normalized(
        sequence as u64,
        format!("2026-10-12T12:{:02}:{:02}Z", sequence / 60, sequence % 60),
        "linux.spool".into(),
        "low".into(),
        format!("synthetic spool event {sequence}"),
        BTreeMap::from([
            ("collector.cursor".into(), format!("cursor-{sequence}")),
            ("event.record_id".into(), format!("record-{sequence}")),
        ]),
    );
    event.identify(&format!("record-{sequence}"));
    event
}

fn config(directory: &Directory) -> AgentConfig {
    AgentConfig {
        server: "http://127.0.0.1:9".into(),
        token: "synthetic-spool-token".into(),
        name: "spool-host".into(),
        state_dir: directory.state(),
        poll: Duration::from_secs(1),
        heartbeat: Duration::from_secs(30),
        flush_events: 500,
        outbox_cap: 20_000,
        lookback: None,
    }
}

fn batch(events: Vec<Event>) -> CollectionBatch {
    CollectionBatch {
        status: SourceStatus {
            name: "synthetic".into(),
            platform: "test".into(),
            state: "ready".into(),
            events_collected: events.len(),
            lookback: "none".into(),
            last_error: None,
        },
        events,
    }
}

fn durable_write(path: &Path, bytes: &[u8]) {
    let mut file = File::create(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn record_path(directory: &Directory, sequence: u64) -> PathBuf {
    directory
        .state()
        .join("pending")
        .join(format!("{sequence:020}.json"))
}

fn receive(stream: &mut TcpStream) -> String {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let count = stream.read(&mut buffer).unwrap();
        assert_ne!(count, 0);
        bytes.extend_from_slice(&buffer[..count]);
        assert!(bytes.len() < 8 * 1024 * 1024);
        if let Some(offset) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&bytes[..offset]);
            assert!(headers.starts_with("POST /ingest/v1/events "));
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            if bytes.len() >= offset + 4 + length {
                return String::from_utf8(bytes[offset + 4..offset + 4 + length].to_vec()).unwrap();
            }
        }
    }
}

fn server(statuses: Vec<u16>) -> (String, std::thread::JoinHandle<(Vec<String>, usize)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let mut known = HashSet::new();
        let mut bodies = Vec::new();
        for status in statuses {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "synthetic ingest request timed out"
                        );
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            let body = receive(&mut stream);
            let request: IngestRequest = serde_json::from_str(&body).unwrap();
            let mut accepted = 0;
            let mut duplicates = 0;
            for raw in request.events {
                let event = normalize_event(
                    &AuthenticatedAgent {
                        id: "synthetic-agent".into(),
                        name: "spool-host".into(),
                    },
                    request.host.as_ref(),
                    raw,
                )
                .unwrap();
                if known.insert(event.uid) {
                    accepted += 1;
                } else {
                    duplicates += 1;
                }
            }
            let response =
                serde_json::json!({"accepted": accepted, "duplicates": duplicates}).to_string();
            write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
            bodies.push(body);
        }
        (bodies, known.len())
    });
    (origin, handle)
}

#[test]
fn offline_collection_continues_to_cap_and_never_skips_refused_cursor() {
    let directory = Directory::new();
    let limits = SpoolLimits {
        max_events: 3,
        ..SpoolLimits::default()
    };
    let mut runtime = AgentRuntime::new_with_spool_limits(config(&directory), limits).unwrap();
    runtime.collect_with(|checkpoints| {
        assert!(checkpoints.is_empty());
        batch(vec![event(1), event(2)])
    });
    let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = parse_server(&format!("http://{}", unavailable.local_addr().unwrap())).unwrap();
    drop(unavailable);
    assert!(!runtime.flush(&endpoint));
    runtime.collect_with(|checkpoints| {
        assert_eq!(checkpoints.get("linux.spool").unwrap().cursor, "cursor-2");
        batch(vec![event(3), event(4), event(5)])
    });
    assert_eq!(runtime.outbox.len(), 3);
    assert_eq!(
        runtime.checkpoints.get("linux.spool").unwrap().cursor,
        "cursor-3"
    );
    assert!(
        runtime
            .outbox
            .server_ack_checkpoint("linux.spool")
            .is_none()
    );
    drop(runtime);
    let mut runtime = AgentRuntime::new_with_spool_limits(config(&directory), limits).unwrap();
    let (origin, handle) = server(vec![200]);
    assert!(runtime.flush(&parse_server(&origin).unwrap()));
    assert!(runtime.outbox.is_empty());
    assert_eq!(
        runtime
            .outbox
            .server_ack_checkpoint("linux.spool")
            .unwrap()
            .cursor,
        "cursor-3"
    );
    assert_eq!(handle.join().unwrap().1, 3);
    runtime.collect_with(|checkpoints| {
        assert_eq!(checkpoints.get("linux.spool").unwrap().cursor, "cursor-3");
        batch(vec![event(4), event(5)])
    });
    assert_eq!(runtime.outbox.len(), 2);
    assert_eq!(
        runtime.checkpoints.get("linux.spool").unwrap().cursor,
        "cursor-5"
    );
}

#[test]
fn count_cap_duplicate_and_byte_cap_are_explicit_without_cursor_advance() {
    let directory = Directory::new();
    let limits = SpoolLimits {
        max_events: 1,
        ..SpoolLimits::default()
    };
    let mut spool = DiskSpool::open(directory.state(), limits).unwrap();
    assert_eq!(spool.push(event(1)).unwrap(), Enqueued::Stored);
    let mut replay = event(1);
    replay.id = 99;
    assert_eq!(spool.push(replay).unwrap(), Enqueued::Duplicate);
    assert_eq!(
        spool.push(event(2)).unwrap_err().kind(),
        std::io::ErrorKind::StorageFull
    );
    let bytes = spool.size_bytes();
    drop(spool);
    let limits = SpoolLimits {
        max_events: 3,
        max_bytes: bytes,
        ..limits
    };
    let mut spool = DiskSpool::open(directory.state(), limits).unwrap();
    assert_eq!(
        spool.push(event(2)).unwrap_err().kind(),
        std::io::ErrorKind::StorageFull
    );
    assert_eq!(
        spool.read_checkpoint("linux.spool").unwrap().cursor,
        "cursor-1"
    );
    assert_eq!(spool.size_bytes(), bytes);
    assert!(spool.server_ack_checkpoint("linux.spool").is_none());
}

#[test]
fn oversized_record_and_uid_path_traversal_are_refused_before_writes() {
    let directory = Directory::new();
    let limits = SpoolLimits {
        max_record_bytes: 4096,
        ..SpoolLimits::default()
    };
    let mut spool = DiskSpool::open(directory.state(), limits).unwrap();
    let mut oversized = event(1);
    oversized.message = "x".repeat(4097);
    assert!(spool.push(oversized).is_err());
    let mut traversal = event(2);
    traversal.uid = "../../escape".into();
    assert!(spool.push(traversal).is_err());
    assert!(spool.is_empty());
    assert!(spool.read_checkpoint("linux.spool").is_none());
    assert_eq!(
        fs::read_dir(directory.state().join("pending"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn restart_delivers_without_the_original_source() {
    let directory = Directory::new();
    let source = directory.0.join("source.json");
    durable_write(
        &source,
        &serde_json::to_vec(&vec![event(1), event(2)]).unwrap(),
    );
    let mut runtime = AgentRuntime::new(config(&directory)).unwrap();
    runtime.collect_with(|_| batch(serde_json::from_slice(&fs::read(&source).unwrap()).unwrap()));
    drop(runtime);
    fs::remove_file(&source).unwrap();
    let mut runtime = AgentRuntime::new(config(&directory)).unwrap();
    runtime.collect_with(|_| {
        let error = fs::read(&source).unwrap_err();
        let mut batch = batch(Vec::new());
        batch.status.state = "error".into();
        batch.status.last_error = Some(error.to_string());
        batch
    });
    let (origin, handle) = server(vec![200]);
    assert!(runtime.flush(&parse_server(&origin).unwrap()));
    assert_eq!(handle.join().unwrap().1, 2);
    assert!(runtime.outbox.is_empty());
    assert_eq!(runtime.sent_total, 2);
}

#[test]
fn enqueue_crash_after_record_rename_recovers_orphan_and_read_checkpoint() {
    let directory = Directory::new();
    let mut spool = directory.open();
    let initial = fs::read(directory.state().join("spool.json")).unwrap();
    spool.push(event(1)).unwrap();
    drop(spool);
    durable_write(&directory.state().join("spool.json"), &initial);
    let mut spool = directory.open();
    assert_eq!(spool.len(), 1);
    assert_eq!(
        spool.read_checkpoint("linux.spool").unwrap().cursor,
        "cursor-1"
    );
    assert!(spool.server_ack_checkpoint("linux.spool").is_none());
    assert_eq!(spool.peek_chunk(10).unwrap().events(), &[event(1)]);
    spool.push(event(2)).unwrap();
    drop(spool);
    assert_eq!(directory.open().len(), 2);
}

#[test]
fn incomplete_uncommitted_record_and_manifest_temps_do_not_advance_cursor() {
    let directory = Directory::new();
    drop(directory.open());
    durable_write(
        &directory
            .state()
            .join("pending")
            .join("00000000000000000001.tmp"),
        b"{\"version\":1",
    );
    durable_write(&directory.state().join("spool.tmp"), b"{\"version\":1");
    let mut spool = directory.open();
    assert!(spool.is_empty());
    assert!(spool.read_checkpoint("linux.spool").is_none());
    spool.push(event(1)).unwrap();
    assert_eq!(spool.len(), 1);
}

#[test]
fn enqueue_progress_failure_preserves_orphan_and_requires_recovery() {
    let directory = Directory::new();
    let mut spool = directory.open();
    let blocker = directory.state().join("spool.tmp");
    fs::create_dir(&blocker).unwrap();
    assert!(spool.push(event(1)).is_err());
    assert!(spool.is_failed());
    assert!(spool.read_checkpoint("linux.spool").is_none());
    assert!(spool.push(event(2)).is_err());
    assert!(record_path(&directory, 1).exists());
    drop(spool);
    fs::remove_dir(blocker).unwrap();
    let spool = directory.open();
    assert_eq!(spool.len(), 1);
    assert_eq!(
        spool.read_checkpoint("linux.spool").unwrap().cursor,
        "cursor-1"
    );
}

#[test]
fn server_acceptance_followed_by_local_ack_failure_replays_idempotently() {
    let directory = Directory::new();
    let mut runtime = AgentRuntime::new(config(&directory)).unwrap();
    runtime
        .enqueue_events([event(1), event(2), event(3)])
        .unwrap();
    let blocker = directory.state().join("spool.tmp");
    fs::create_dir(&blocker).unwrap();
    let (origin, handle) = server(vec![200, 200]);
    let endpoint = parse_server(&origin).unwrap();
    assert!(!runtime.flush(&endpoint));
    assert_eq!(runtime.outbox.len(), 3);
    assert!(runtime.outbox.is_failed());
    assert!(
        runtime
            .outbox
            .server_ack_checkpoint("linux.spool")
            .is_none()
    );
    drop(runtime);
    fs::remove_dir(blocker).unwrap();
    let mut runtime = AgentRuntime::new(config(&directory)).unwrap();
    assert!(runtime.flush(&endpoint));
    let (bodies, unique) = handle.join().unwrap();
    assert_eq!(unique, 3);
    assert_eq!(bodies[0], bodies[1]);
    assert!(runtime.outbox.is_empty());
    assert_eq!(
        runtime
            .outbox
            .server_ack_checkpoint("linux.spool")
            .unwrap()
            .cursor,
        "cursor-3"
    );
}

#[test]
fn transient_and_throttle_responses_preserve_identical_batch_until_ack() {
    let directory = Directory::new();
    let mut runtime = AgentRuntime::new(config(&directory)).unwrap();
    runtime.enqueue_events([event(1), event(2)]).unwrap();
    let (origin, handle) = server(vec![503, 429, 200]);
    let endpoint = parse_server(&origin).unwrap();
    for _ in 0..2 {
        assert!(!runtime.flush(&endpoint));
        assert_eq!(runtime.outbox.len(), 2);
        assert!(
            runtime
                .outbox
                .server_ack_checkpoint("linux.spool")
                .is_none()
        );
    }
    assert!(runtime.flush(&endpoint));
    let (bodies, unique) = handle.join().unwrap();
    assert_eq!(unique, 2);
    assert_eq!(bodies[0], bodies[1]);
    assert_eq!(bodies[1], bodies[2]);
}

#[test]
fn committed_ack_recovers_with_undeleted_records_without_replay() {
    let directory = Directory::new();
    let mut spool = directory.open();
    spool.push(event(1)).unwrap();
    spool.push(event(2)).unwrap();
    let saved = [
        fs::read(record_path(&directory, 1)).unwrap(),
        fs::read(record_path(&directory, 2)).unwrap(),
    ];
    let chunk = spool.peek_chunk(2).unwrap();
    spool.acknowledge(&chunk, 2, 0).unwrap();
    drop(spool);
    for (index, bytes) in saved.iter().enumerate() {
        durable_write(&record_path(&directory, index as u64 + 1), bytes);
    }
    let spool = directory.open();
    assert!(spool.is_empty());
    assert_eq!(spool.sent_total(), 2);
    assert_eq!(
        spool.server_ack_checkpoint("linux.spool").unwrap().cursor,
        "cursor-2"
    );
    assert_eq!(
        fs::read_dir(directory.state().join("pending"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn malformed_and_stale_ack_cannot_retire_pending_records() {
    let directory = Directory::new();
    let mut spool = directory.open();
    spool.push(event(1)).unwrap();
    spool.push(event(2)).unwrap();
    let first = spool.peek_chunk(1).unwrap();
    assert!(spool.acknowledge(&first, 0, 0).is_err());
    assert!(spool.acknowledge(&first, usize::MAX, 1).is_err());
    assert_eq!(spool.len(), 2);
    spool.acknowledge(&first, 1, 0).unwrap();
    assert!(spool.acknowledge(&first, 1, 0).is_err());
    assert_eq!(spool.len(), 1);
}

#[test]
fn rejection_archive_is_durable_before_failed_retirement_and_reused_on_restart() {
    let directory = Directory::new();
    let mut spool = directory.open();
    spool.push(event(1)).unwrap();
    let chunk = spool.peek_chunk(1).unwrap();
    let blocker = directory.state().join("spool.tmp");
    fs::create_dir(&blocker).unwrap();
    assert!(spool.reject(&chunk, "synthetic server rejection").is_err());
    let archive = directory
        .state()
        .join("quarantine")
        .join(format!("{}.json", event(1).uid));
    let encoded = fs::read(&archive).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&encoded).unwrap()["payload"]["event"]["uid"],
        event(1).uid
    );
    assert!(record_path(&directory, 1).exists());
    drop(spool);
    fs::remove_dir(blocker).unwrap();
    let mut spool = directory.open();
    let chunk = spool.peek_chunk(1).unwrap();
    spool.reject(&chunk, "synthetic server rejection").unwrap();
    assert!(spool.is_empty());
    assert_eq!(spool.rejected_total(), 1);
    assert!(spool.server_ack_checkpoint("linux.spool").is_none());
    assert_eq!(fs::read(archive).unwrap(), encoded);
    drop(spool);
    assert_eq!(directory.open().rejected_total(), 1);
}

#[test]
fn quarantine_cap_prevents_rejected_record_removal() {
    let directory = Directory::new();
    let mut spool = DiskSpool::open(
        directory.state(),
        SpoolLimits {
            max_quarantine_bytes: 1,
            ..SpoolLimits::default()
        },
    )
    .unwrap();
    spool.push(event(1)).unwrap();
    let chunk = spool.peek_chunk(1).unwrap();
    assert_eq!(
        spool
            .reject(&chunk, "synthetic rejection")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::StorageFull
    );
    assert_eq!(spool.len(), 1);
    assert!(record_path(&directory, 1).exists());
    assert_eq!(spool.rejected_total(), 0);
    assert!(spool.server_ack_checkpoint("linux.spool").is_none());
}

#[test]
fn corrupt_committed_record_is_preserved_archived_and_fails_closed() {
    let directory = Directory::new();
    let mut spool = directory.open();
    spool.push(event(1)).unwrap();
    drop(spool);
    let path = record_path(&directory, 1);
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["payload"]["event"]["message"] = Value::String("corrupted payload".into());
    let original = serde_json::to_vec(&value).unwrap();
    durable_write(&path, &original);
    assert!(DiskSpool::open(directory.state(), SpoolLimits::default()).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    let archives: Vec<_> = fs::read_dir(directory.state().join("quarantine"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(archives.len(), 1);
    assert_eq!(fs::read(&archives[0]).unwrap(), original);
}

#[test]
fn corrupt_progress_and_missing_pending_tail_fail_closed() {
    for corrupt_manifest in [false, true] {
        let directory = Directory::new();
        let mut spool = directory.open();
        spool.push(event(1)).unwrap();
        drop(spool);
        if corrupt_manifest {
            let manifest = directory.state().join("spool.json");
            let mut value: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
            value["version"] = 2.into();
            durable_write(&manifest, &serde_json::to_vec(&value).unwrap());
        } else {
            fs::remove_file(record_path(&directory, 1)).unwrap();
        }
        assert!(DiskSpool::open(directory.state(), SpoolLimits::default()).is_err());
        assert!(directory.state().join("spool.json").exists());
        assert_eq!(
            fs::read_dir(directory.state().join("quarantine"))
                .unwrap()
                .count(),
            1
        );
    }
}

#[test]
fn corruption_quarantine_budget_exhaustion_keeps_original_pending_record() {
    let directory = Directory::new();
    let mut spool = directory.open();
    spool.push(event(1)).unwrap();
    drop(spool);
    let original = b"not valid JSON";
    durable_write(&record_path(&directory, 1), original);
    assert!(
        DiskSpool::open(
            directory.state(),
            SpoolLimits {
                max_quarantine_bytes: 1,
                ..SpoolLimits::default()
            }
        )
        .is_err()
    );
    assert_eq!(fs::read(record_path(&directory, 1)).unwrap(), original);
    assert_eq!(
        fs::read_dir(directory.state().join("quarantine"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn exclusive_owner_lock_releases_on_drop() {
    let directory = Directory::new();
    let spool = directory.open();
    assert_eq!(
        DiskSpool::open(directory.state(), SpoolLimits::default())
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    let output = Command::new(env!("CARGO_BIN_EXE_redtrace-agent"))
        .args([
            "--server",
            "http://127.0.0.1:9",
            "--token",
            "synthetic-owner-probe",
            "--state-dir",
        ])
        .arg(directory.state())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("another agent owns")
    );
    drop(spool);
    drop(directory.open());
}

#[test]
fn record_write_failure_retains_read_cursor_until_source_can_be_reread() {
    let directory = Directory::new();
    let mut spool = directory.open();
    let blocker = directory
        .state()
        .join("pending")
        .join("00000000000000000001.tmp");
    fs::create_dir(&blocker).unwrap();
    assert!(spool.push(event(1)).is_err());
    assert!(spool.is_failed());
    assert!(spool.read_checkpoint("linux.spool").is_none());
    assert!(!record_path(&directory, 1).exists());
    drop(spool);
    fs::remove_dir(blocker).unwrap();
    let mut spool = directory.open();
    assert!(spool.is_empty());
    assert!(spool.read_checkpoint("linux.spool").is_none());
    spool.push(event(1)).unwrap();
    assert_eq!(spool.len(), 1);
}

#[test]
fn corrupt_record_discovered_during_delivery_blocks_enqueue_and_ack() {
    let directory = Directory::new();
    let mut spool = directory.open();
    spool.push(event(1)).unwrap();
    durable_write(&record_path(&directory, 1), b"corrupted after open");
    assert!(spool.peek_chunk(1).is_err());
    assert!(spool.is_failed());
    assert!(spool.push(event(2)).is_err());
    assert!(spool.server_ack_checkpoint("linux.spool").is_none());
    assert_eq!(spool.len(), 1);
    assert_eq!(
        fs::read_dir(directory.state().join("quarantine"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn missing_manifest_after_initialization_never_reinitializes_progress() {
    let directory = Directory::new();
    drop(AgentRuntime::new(config(&directory)).unwrap());
    fs::remove_file(directory.state().join("spool.json")).unwrap();
    assert!(DiskSpool::open(directory.state(), SpoolLimits::default()).is_err());
    assert!(!directory.state().join("spool.json").exists());
}

#[test]
fn legacy_ack_checkpoints_migrate_once_to_separate_read_and_ack_progress() {
    let directory = Directory::new();
    fs::create_dir(directory.state()).unwrap();
    let legacy = directory.state().join("checkpoints.json");
    let store = redtrace::storage::CheckpointStore::open(legacy.clone()).unwrap();
    store.update_events(&[event(1)]).unwrap();
    drop(store);
    let original = fs::read(&legacy).unwrap();
    let mut spool = directory.open();
    assert_eq!(
        spool.read_checkpoint("linux.spool").unwrap().cursor,
        "cursor-1"
    );
    assert_eq!(
        spool.server_ack_checkpoint("linux.spool").unwrap().cursor,
        "cursor-1"
    );
    spool.push(event(2)).unwrap();
    drop(spool);
    let spool = directory.open();
    assert_eq!(
        spool.read_checkpoint("linux.spool").unwrap().cursor,
        "cursor-2"
    );
    assert_eq!(
        spool.server_ack_checkpoint("linux.spool").unwrap().cursor,
        "cursor-1"
    );
    assert_eq!(fs::read(legacy).unwrap(), original);
}

#[test]
fn delivery_chunks_are_count_and_byte_bounded() {
    let directory = Directory::new();
    let mut spool = directory.open();
    for sequence in 1..=10 {
        let mut event = event(sequence);
        event.message = "x".repeat(430_000);
        spool.push(event).unwrap();
    }
    drop(spool);
    let mut spool = directory.open();
    assert_eq!(spool.peek_chunk(1).unwrap().events().len(), 1);
    let chunk = spool.peek_chunk(usize::MAX).unwrap();
    assert_eq!(chunk.events().len(), 9);
    assert!(serde_json::to_vec(chunk.events()).unwrap().len() < 4 * 1024 * 1024);
    assert_eq!(spool.len(), 10);
}

#[test]
fn cli_rejects_remote_argument_tokens_and_invalid_caps_before_opening_state() {
    let directory = Directory::new();
    let marker = "synthetic-process-argument-token";
    let output = Command::new(env!("CARGO_BIN_EXE_redtrace-agent"))
        .args([
            "--server",
            "https://example.invalid:9711",
            "--token",
            marker,
            "--state-dir",
        ])
        .arg(directory.state())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("--token is not permitted"));
    assert!(!error.contains(marker));
    assert!(!directory.state().exists());
    let output = Command::new(env!("CARGO_BIN_EXE_redtrace-agent"))
        .args([
            "--server",
            "http://127.0.0.1:9",
            "--token",
            marker,
            "--spool-events",
            "0",
            "--state-dir",
        ])
        .arg(directory.state())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!directory.state().exists());
}

#[test]
fn private_token_file_is_bounded_and_validated_without_secret_in_errors() {
    let directory = Directory::new();
    let token = directory.0.join("token");
    durable_write(&token, b"synthetic-file-token\r\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(read_token_file(&token).unwrap(), "synthetic-file-token");
    let output = Command::new(env!("CARGO_BIN_EXE_redtrace-agent"))
        .args(["--server", "https://example.invalid:9711", "--token-file"])
        .arg(&token)
        .args(["--spool-events", "0", "--state-dir"])
        .arg(directory.state())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("invalid agent spool limits")
    );
    assert!(!directory.state().exists());
    durable_write(&token, b"synthetic-secret\ninjected");
    let error = read_token_file(&token).unwrap_err().to_string();
    assert!(!error.contains("synthetic-secret"));
    durable_write(&token, &vec![b'x'; 4097]);
    assert!(read_token_file(&token).is_err());
}

#[cfg(unix)]
#[test]
fn unix_spool_privacy_and_redirected_state_are_enforced() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = Directory::new();
    let mut spool = directory.open();
    spool.push(event(1)).unwrap();
    for path in [
        directory.state(),
        directory.state().join("pending"),
        directory.state().join("quarantine"),
    ] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    for path in [
        directory.state().join("spool.json"),
        record_path(&directory, 1),
        directory.state().join("agent.lock"),
    ] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let link = directory.0.join("link");
    symlink(directory.state(), &link).unwrap();
    assert!(DiskSpool::open(link, SpoolLimits::default()).is_err());
}

#[cfg(windows)]
#[test]
fn windows_spool_dacl_is_protected_and_contains_only_system_and_current_user() {
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
                SE_FILE_OBJECT,
            },
            DACL_SECURITY_INFORMATION,
        },
    };
    let directory = Directory::new();
    let mut spool = directory.open();
    spool.push(event(1)).unwrap();
    for path in [
        directory.state(),
        directory.state().join("spool.json"),
        record_path(&directory, 1),
    ] {
        let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let mut descriptor = ptr::null_mut();
        assert_eq!(
            unsafe {
                GetNamedSecurityInfoW(
                    path.as_ptr(),
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
        let actual = String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(text, length.saturating_sub(1) as usize)
        });
        unsafe {
            LocalFree(text.cast());
            LocalFree(descriptor);
        }
        assert!(actual.starts_with("D:P"), "{actual}");
        assert_eq!(actual.matches("(A;").count(), 2, "{actual}");
        assert!(actual.contains(";;;SY)"), "{actual}");
        assert!(
            !actual.contains(";;;WD)") && !actual.contains(";;;BU)") && !actual.contains(";;;BA)"),
            "{actual}"
        );
    }
}
