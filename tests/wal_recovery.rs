use redtrace::{model::Event, storage::Wal};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Core {
    child: Child,
    directory: PathBuf,
}

impl Drop for Core {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn fixture(message: &str) -> Event {
    Event::normalized(
        1,
        chrono::Utc::now().to_rfc3339(),
        "test.wal-recovery".into(),
        "low".into(),
        message.into(),
        BTreeMap::new(),
    )
}

fn start(directory: &PathBuf, token: &str, ingest_port: u16, api_port: u16) -> Child {
    Command::new(env!("CARGO_BIN_EXE_redtrace"))
        .env("REDTRACE_DATA_DIR", directory)
        .env("REDTRACE_API_TOKEN", token)
        .env("REDTRACE_API_BIND", format!("127.0.0.1:{api_port}"))
        .env("REDTRACE_INGEST_BIND", format!("127.0.0.1:{ingest_port}"))
        .env("REDTRACE_SEGMENT_MB", "1")
        .env("REDTRACE_COLLECT_LOCAL", "0")
        .env("REDTRACE_LOOKBACK", "1m")
        .env_remove("REDTRACE_INGEST_CERT")
        .env_remove("REDTRACE_INGEST_KEY")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn json(response: reqwest::blocking::Response) -> serde_json::Value {
    let status = response.status();
    let body = response.text().unwrap();
    assert!(status.is_success(), "HTTP {status}: {body}");
    serde_json::from_str(&body).unwrap()
}

fn ready(
    client: &reqwest::blocking::Client,
    token: &str,
    child: &mut Child,
    api_port: u16,
) -> serde_json::Value {
    for _ in 0..100 {
        assert!(
            child.try_wait().unwrap().is_none(),
            "core exited during recovery"
        );
        if let Ok(response) = client
            .get(format!("http://127.0.0.1:{api_port}/api/health"))
            .header("x-redtrace-token", token)
            .send()
            && response.status().is_success()
        {
            return json(response);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("core recovery readiness timed out");
}

#[test]
fn repaired_core_preserves_ack_events_across_rotation_crash_and_replay() {
    let api_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let base = format!("http://127.0.0.1:{api_port}");
    let ingest_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).unwrap();
    let token = redtrace::ingest::hex(&random);
    let directory = std::env::temp_dir().join(format!("redtrace-wal-process-{}", &token[..16]));
    let first = fixture("valid before interruption");
    let restored = fixture("valid merged after interruption");
    {
        let wal = Wal::open(directory.join("active.wal")).unwrap();
        wal.append(std::slice::from_ref(&first)).unwrap();
        let candidate = Wal::open(directory.join("candidate.wal")).unwrap();
        candidate.append(std::slice::from_ref(&restored)).unwrap();
        let mut file = OpenOptions::new().append(true).open(wal.path()).unwrap();
        file.write_all(b"{\"version\":1,\"checksum\":123,\"event\":{")
            .unwrap();
        file.write_all(&fs::read(candidate.path()).unwrap())
            .unwrap();
        file.sync_all().unwrap();
    }
    let original = fs::read(directory.join("active.wal")).unwrap();
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(12))
        .build()
        .unwrap();
    let child = start(&directory, &token, ingest_port, api_port);
    let mut core = Core { child, directory };
    let health = ready(&client, &token, &mut core.child, api_port);
    assert_eq!(health["storage"]["corrupted_records"], 0);
    assert_eq!(health["storage"]["wal_quarantine"]["archives"], 1);
    assert_eq!(health["storage"]["wal_quarantine"]["corrupted_records"], 1);
    assert_eq!(
        health["storage"]["wal_quarantine"]["salvageable_records"],
        1
    );
    let archive = fs::read_dir(core.directory.join("wal-quarantine"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|extension| extension == "wal"))
        .unwrap();
    assert_eq!(fs::read(archive).unwrap(), original);
    let search = |query: &str| {
        json(
            client
                .get(format!("{base}/api/search"))
                .header("x-redtrace-token", &token)
                .query(&[("q", query), ("limit", "1000")])
                .send()
                .unwrap(),
        )
    };
    let recovered = search("source=\"test.wal-recovery\"");
    assert_eq!(recovered["total"], 2);
    let uids: HashSet<_> = recovered["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["uid"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(uids, HashSet::from([first.uid, restored.uid]));
    let refused = Command::new(env!("CARGO_BIN_EXE_redtrace"))
        .env("REDTRACE_DATA_DIR", &core.directory)
        .env("REDTRACE_API_TOKEN", &token)
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(2));
    let agent = json(
        client
            .post(format!("{base}/api/agents"))
            .header("x-redtrace-token", &token)
            .header("content-type", "application/json")
            .body("{\"name\":\"wal-fixture\"}")
            .send()
            .unwrap(),
    );
    let timestamp = chrono::Utc::now().to_rfc3339();
    let events: Vec<_> = (0..1000)
        .map(|sequence| {
            serde_json::json!({
                "timestamp": timestamp,
                "source": "test.wal-ack",
                "level": "low",
                "message": format!("wal-ack-fixture-{sequence} {}", "x".repeat(2048)),
                "fields": {},
            })
        })
        .collect();
    let body = serde_json::json!({"events": events, "host": {"name": "wal-fixture", "os": std::env::consts::OS}})
        .to_string();
    let send = || {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let response = client
                .post(format!("http://127.0.0.1:{ingest_port}/ingest/v1/events"))
                .header("x-redtrace-ingest-token", agent["token"].as_str().unwrap())
                .header("content-type", "application/json")
                .body(body.clone())
                .send()
                .unwrap();
            if response.status() != 429 || std::time::Instant::now() >= deadline {
                break json(response);
            }
            // Backpressure may follow a durable prefix; retry the identical batch.
            std::thread::sleep(Duration::from_secs(1));
        }
    };
    let ack = send();
    assert_eq!(
        ack["accepted"].as_u64().unwrap() + ack["duplicates"].as_u64().unwrap(),
        1000
    );
    let rotated = json(
        client
            .get(format!("{base}/api/health"))
            .header("x-redtrace-token", &token)
            .send()
            .unwrap(),
    );
    assert!(rotated["storage"]["segment_count"].as_u64().unwrap() >= 2);
    assert_eq!(rotated["ingestion"]["segment_errors"], 0);
    core.child.kill().unwrap();
    core.child.wait().unwrap();
    core.child = start(&core.directory, &token, ingest_port, api_port);
    let health = ready(&client, &token, &mut core.child, api_port);
    assert_eq!(health["storage"]["corrupted_records"], 0);
    let query = format!(
        "agent.id=\"{}\" AND source=\"test.wal-ack\"",
        agent["id"].as_str().unwrap()
    );
    let confirmed = search(&query);
    assert_eq!(confirmed["total"], 1000);
    let uids: HashSet<_> = confirmed["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["uid"].as_str().unwrap())
        .collect();
    assert_eq!(uids.len(), 1000);
    assert_eq!(send()["duplicates"], 1000);
    assert_eq!(search(&query)["total"], 1000);
}
