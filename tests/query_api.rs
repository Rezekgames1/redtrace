use redtrace::{model::Event, storage::Wal};
use std::{
    collections::BTreeMap,
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
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn api_enforces_parser_budgets_and_keeps_valid_queries_working() {
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).unwrap();
    let token = redtrace::ingest::hex(&random);
    let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "redtrace-query-api-{}-{}",
        std::process::id(),
        &token[..16]
    ));
    redtrace::service::private_directory(&directory).unwrap();
    let fixture = Event::normalized(
        1,
        chrono::Utc::now().to_rfc3339(),
        "test.query-budgets".into(),
        "low".into(),
        "Parser fixture Я\"\\() NOT".into(),
        BTreeMap::from([("event.id".into(), "query-fixture".into())]),
    );
    Wal::open(directory.join("active.wal"))
        .unwrap()
        .append(std::slice::from_ref(&fixture))
        .unwrap();
    drop(listener);
    let child = Command::new(env!("CARGO_BIN_EXE_redtrace"))
        .env("REDTRACE_DATA_DIR", &directory)
        .env("REDTRACE_API_BIND", address.to_string())
        .env("REDTRACE_COLLECT_LOCAL", "0")
        .env("REDTRACE_API_TOKEN", &token)
        .env("REDTRACE_QUERY_MAX_BYTES", "1024")
        .env("REDTRACE_QUERY_MAX_TOKENS", "128")
        .env("REDTRACE_QUERY_MAX_DEPTH", "8")
        .env("REDTRACE_QUERY_MAX_NODES", "32")
        .env_remove("REDTRACE_INGEST_BIND")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut core = Core { child, directory };
    let base = format!("http://{address}/api");
    let expected_limits = serde_json::json!({
        "max_bytes": 1024, "max_tokens": 128, "max_depth": 8, "max_nodes": 32,
    });
    let mut ready = false;
    for _ in 0..100 {
        assert!(core.child.try_wait().unwrap().is_none(), "core exited");
        if let Ok(response) = client
            .get(format!("{base}/health"))
            .header("x-redtrace-token", &token)
            .send()
            && response.status().is_success()
        {
            let body: serde_json::Value = serde_json::from_str(&response.text().unwrap()).unwrap();
            assert_eq!(body["query_limits"], expected_limits);
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready, "core startup timed out");
    assert_eq!(
        client
            .get(format!("{base}/health"))
            .send()
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let diagnostic: serde_json::Value = serde_json::from_str(
        &client
            .get(format!("{base}/diagnostics"))
            .header("x-redtrace-token", &token)
            .send()
            .unwrap()
            .text()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(diagnostic["query_limits"], expected_limits);
    let rejected = [
        (" ".repeat(1025), "query exceeds byte limit", 1024),
        ("(".repeat(129), "query exceeds token limit", 128),
        (
            format!("{}x{}", "(".repeat(9), ")".repeat(9)),
            "query exceeds nesting limit",
            8,
        ),
        (
            format!("{}x", "NOT ".repeat(9)),
            "query exceeds nesting limit",
            32,
        ),
        (vec!["x"; 17].join(" OR "), "query is too complex", 80),
        ("я AND )".into(), "expected search term", 7),
    ];
    let valid = [
        "source=\"test.query-budgets\" AND event.id=query-fixture".to_owned(),
        "source=\"test.query-budgets\" AND event.id:* AND NOT event.id=other".to_owned(),
        r#"source="test.query-budgets" AND message~"Я\"\\() NOT""#.to_owned(),
        format!(
            "{}source=\"test.query-budgets\"{}",
            "(".repeat(8),
            ")".repeat(8)
        ),
        vec!["source=\"test.query-budgets\""; 16].join(" OR "),
    ];
    for endpoint in ["search", "aggregations", "export"] {
        for (input, message, offset) in &rejected {
            let response = client
                .get(format!("{base}/{endpoint}"))
                .header("x-redtrace-token", &token)
                .query(&[("q", input.as_str())])
                .send()
                .unwrap();
            assert_eq!(
                response.status(),
                reqwest::StatusCode::BAD_REQUEST,
                "{endpoint}: {input}"
            );
            let body: serde_json::Value = serde_json::from_str(&response.text().unwrap()).unwrap();
            assert_eq!(body["error"], *message, "{endpoint}");
            assert_eq!(body["offset"], *offset, "{endpoint}");
            assert_eq!(body["limits"], expected_limits);
            assert_eq!(body["max_nodes"], 32);
        }
        for input in &valid {
            let response = client
                .get(format!("{base}/{endpoint}"))
                .header("x-redtrace-token", &token)
                .query(&[("q", input.as_str())])
                .send()
                .unwrap();
            assert!(response.status().is_success(), "{endpoint}: {input}");
            let body: serde_json::Value = serde_json::from_str(&response.text().unwrap()).unwrap();
            if endpoint == "export" {
                assert_eq!(body["uid"], fixture.uid);
            } else {
                assert_eq!(body["total"], 1, "{endpoint}: {input}");
                if endpoint == "search" {
                    assert_eq!(body["events"][0]["uid"], fixture.uid);
                }
            }
        }
    }
    drop(core);
    let invalid_directory = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("redtrace-invalid-query-{}", &token[..16]));
    let output = Command::new(env!("CARGO_BIN_EXE_redtrace"))
        .env("REDTRACE_QUERY_MAX_DEPTH", "100000")
        .env("REDTRACE_DATA_DIR", &invalid_directory)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!invalid_directory.exists());
}
