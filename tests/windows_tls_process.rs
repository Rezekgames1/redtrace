#![cfg(windows)]

use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Processes(Vec<Child>);

impl Drop for Processes {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn windows_core_and_agent_exchange_real_events_over_tls() {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let dir = std::env::temp_dir().join(format!("redtrace-windows-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("certificate.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, certificate.cert.pem()).unwrap();
    std::fs::write(&key, certificate.signing_key.serialize_pem()).unwrap();
    let ingest_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = ingest_listener.local_addr().unwrap().port();
    let api_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let api_address = api_listener.local_addr().unwrap();
    let api_base = format!("http://{api_address}");
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).unwrap();
    let api_token = redtrace::ingest::hex(&random);
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    drop(ingest_listener);
    drop(api_listener);
    let core = Command::new(env!("CARGO_BIN_EXE_redtrace"))
        .env("REDTRACE_DATA_DIR", dir.join("core"))
        .env("REDTRACE_API_BIND", api_address.to_string())
        .env("REDTRACE_COLLECT_LOCAL", "0")
        .env("REDTRACE_LOOKBACK", "24h")
        .env("REDTRACE_API_TOKEN", &api_token)
        .env("REDTRACE_INGEST_BIND", format!("127.0.0.1:{port}"))
        .env("REDTRACE_INGEST_CERT", &cert)
        .env("REDTRACE_INGEST_KEY", &key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut processes = Processes(vec![core]);
    let mut ready = false;
    for _ in 0..100 {
        if let Ok(response) = client
            .get(format!("{api_base}/api/health"))
            .header("x-redtrace-token", &api_token)
            .send()
            && response.status().is_success()
        {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready, "core startup timed out");
    let registered = client
        .post(format!("{api_base}/api/agents"))
        .header("x-redtrace-token", &api_token)
        .header("content-type", "application/json")
        .body("{\"name\":\"windows-tls-process\"}")
        .send()
        .unwrap()
        .text()
        .unwrap();
    let registered: serde_json::Value = serde_json::from_str(&registered).unwrap();
    let id = registered["id"].as_str().unwrap();
    let agent = Command::new(env!("CARGO_BIN_EXE_redtrace-agent"))
        .args([
            "--server",
            &format!("https://localhost:{port}"),
            "--name",
            "windows-tls-process",
            "--poll",
            "1",
        ])
        .env(
            "REDTRACE_AGENT_TOKEN",
            registered["token"].as_str().unwrap(),
        )
        .env("REDTRACE_AGENT_CA", &cert)
        .env("REDTRACE_AGENT_STATE", dir.join("agent"))
        .env("REDTRACE_LOOKBACK", "24h")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    processes.0.push(agent);
    let mut received = false;
    for _ in 0..120 {
        let response = client
            .get(format!("{api_base}/api/search?q=agent.id:{id}&limit=1"))
            .header("x-redtrace-token", &api_token)
            .send()
            .unwrap()
            .text()
            .unwrap();
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        if response["total"].as_u64().unwrap_or(0) > 0 {
            assert_eq!(response["events"][0]["fields"]["collector.mode"], "native");
            received = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    drop(processes);
    std::fs::remove_dir_all(dir).unwrap();
    assert!(
        received,
        "no readable Windows events reached the TLS listener"
    );
}
