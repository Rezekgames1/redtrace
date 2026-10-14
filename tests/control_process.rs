use redtrace::{
    agent::{AgentConfig, AgentRuntime},
    config::Config,
    model::Event,
    service,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct Fixture {
    root: PathBuf,
    child: Option<Child>,
    token: String,
    base: String,
}
impl Fixture {
    fn new() -> Self {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "redtrace-control-{}",
                service::random_secret().unwrap()
            ));
        service::private_directory(&root).unwrap();
        let port = port();
        let token = service::random_secret().unwrap();
        let mut fixture = Self {
            root,
            child: None,
            token,
            base: format!("http://127.0.0.1:{port}"),
        };
        fixture.start();
        fixture
    }
    fn start(&mut self) {
        self.child = Some(
            Command::new(env!("CARGO_BIN_EXE_redtrace"))
                .env("REDTRACE_DATA_DIR", self.root.join("data"))
                .env("REDTRACE_API_BIND", self.base.trim_start_matches("http://"))
                .env("REDTRACE_API_TOKEN", &self.token)
                .env("REDTRACE_COLLECT_LOCAL", "0")
                .env_remove("REDTRACE_INGEST_BIND")
                .env_remove("REDTRACE_SERVICE_MODE")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            assert!(self.child.as_mut().unwrap().try_wait().unwrap().is_none());
            if client()
                .get(format!("{}/api/health", self.base))
                .header("x-redtrace-token", &self.token)
                .send()
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn request(&self, path: &str, method: &str, body: Option<Value>) -> Value {
        let mut request = client()
            .request(method.parse().unwrap(), format!("{}{path}", self.base))
            .header("x-redtrace-token", &self.token);
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        let response = request.send().unwrap();
        let status = response.status();
        let text = response.text().unwrap();
        assert!(status.is_success(), "{path} HTTP {status}: {text}");
        serde_json::from_str(&text).unwrap()
    }
    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop();
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap()
}
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
#[test]
fn collector_enrollment_rules_fleet_rotation_backup_and_restart() {
    let mut f = Fixture::new();
    let ingest_port = port();
    let setup = f.request(
        "/api/onboarding/collector",
        "POST",
        Some(json!({"host":"localhost","bind":format!("127.0.0.1:{ingest_port}")})),
    );
    assert!(
        setup["server"]
            .as_str()
            .unwrap()
            .starts_with("https://localhost:")
    );
    assert_eq!(
        f.request("/api/health", "GET", None)["remote_ingest"]["enabled"],
        true
    );
    let preflight = client()
        .request(reqwest::Method::OPTIONS, format!("{}/api/config", f.base))
        .header("origin", "http://localhost:1420")
        .header("access-control-request-method", "PUT")
        .header(
            "access-control-request-headers",
            "x-redtrace-token,content-type",
        )
        .send()
        .unwrap();
    assert!(
        preflight.headers()["access-control-allow-methods"]
            .to_str()
            .unwrap()
            .contains("PUT")
    );
    let mut settings = Config::default();
    settings.sources.system = false;
    settings.resources.heartbeat_seconds = 5;
    let package = f.request(
        "/api/onboarding/package",
        "POST",
        Some(json!({"name":"fixture-host","config":settings})),
    );
    let file = f.root.join("fixture.redtrace-enroll.json");
    service::write_private(&file, &serde_json::to_vec(&package).unwrap()).unwrap();
    let state = f.root.join("agent");
    let enrolled = redtrace::enrollment::install_package(&file, &state).unwrap();
    let trust_before = fs::read(state.join("ca.pem")).unwrap();
    assert!(redtrace::enrollment::install_package(&file, &state).is_err());
    assert_eq!(fs::read(state.join("ca.pem")).unwrap(), trust_before);
    assert!(redtrace::enrollment::install_package(&file, &f.root.join("duplicate-agent")).is_err());
    let server = setup["server"].as_str().unwrap().to_owned();
    let mut endpoint = redtrace::agent::parse_server(&server).unwrap();
    endpoint.ca_file = Some(state.join("ca.pem"));
    let config = AgentConfig {
        server,
        token: enrolled.token,
        name: "fixture-host".into(),
        state_dir: state.clone(),
        poll: Duration::from_secs(1),
        heartbeat: Duration::from_secs(5),
        flush_events: 100,
        outbox_cap: 20000,
        lookback: None,
    };
    let mut agent = AgentRuntime::new(config).unwrap();
    let config_path = format!("/api/agents/{}/config", enrolled.id);
    assert_eq!(
        f.request(&config_path, "GET", None)["config"]["sources"]["system"],
        false
    );
    let mut desired = settings.clone();
    desired.resources.poll_seconds = 3;
    desired.resources.max_batch_events = 4;
    desired.include = "event.id=process.exec".into();
    f.request(
        &config_path,
        "PUT",
        Some(serde_json::to_value(&desired).unwrap()),
    );
    agent.heartbeat_if_due(&endpoint);
    assert_eq!(agent.config.poll, Duration::from_secs(3));
    assert_eq!(agent.config.flush_events, 4);
    assert_eq!(Config::load(&state.join("config.json")).unwrap(), desired);
    f.request("/api/rules","PUT",Some(json!({"generation":0,"rules":[{"id":"fixture.exec","title":"fixture exec","query":"event.id=process.exec","kind":"match","suppression_seconds":0}]})));
    let event = Event::normalized(
        0,
        chrono::Utc::now().to_rfc3339(),
        "fixture.telemetry".into(),
        "low".into(),
        "fixture process exec".into(),
        BTreeMap::from([
            ("event.id".into(), "process.exec".into()),
            ("process.executable".into(), "/bin/fixture".into()),
        ]),
    );
    agent.enqueue_events([event]).unwrap();
    let filtered = Event::normalized(
        0,
        chrono::Utc::now().to_rfc3339(),
        "fixture.telemetry".into(),
        "low".into(),
        "filtered event".into(),
        BTreeMap::from([("event.id".into(), "excluded".into())]),
    );
    agent.enqueue_events([filtered]).unwrap();
    assert!(agent.flush(&endpoint));
    std::thread::sleep(Duration::from_secs(5));
    agent.heartbeat_if_due(&endpoint);
    let agents = f.request("/api/agents", "GET", None);
    let host = &agents["agents"][0];
    assert_eq!(host["id"], enrolled.id);
    assert_eq!(host["telemetry"]["pending_events"], 0);
    assert_eq!(host["state"], "online");
    let alerts = f.request("/api/alerts", "GET", None);
    assert!(
        alerts["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["rule_id"] == "fixture.exec")
    );
    let replay = f.request(
        "/api/rules/replay",
        "POST",
        Some(json!({"q":"source=fixture.telemetry"})),
    );
    assert_eq!(replay["events"], 1);
    assert_eq!(replay["alerts"].as_array().unwrap().len(), 1);
    f.request("/api/pki/renew", "POST", None);
    assert!(!agent.flush(&endpoint)); // No pending events; TLS still checked by heartbeat below.
    f.request("/api/pki/prepare", "POST", None);
    let never_connected = f.request(
        "/api/agents",
        "POST",
        Some(json!({"name":"waiting-for-trust"})),
    );
    let response = client()
        .post(format!("{}/api/pki/activate", f.base))
        .header("x-redtrace-token", &f.token)
        .send()
        .unwrap();
    assert_eq!(response.status(), 400);
    std::thread::sleep(Duration::from_secs(5));
    agent.heartbeat_if_due(&endpoint); // Receives both trust anchors.
    std::thread::sleep(Duration::from_secs(5));
    agent.heartbeat_if_due(&endpoint); // Acknowledges durable trust.
    let blocked = client()
        .post(format!("{}/api/pki/activate", f.base))
        .header("x-redtrace-token", &f.token)
        .send()
        .unwrap();
    assert_eq!(blocked.status(), 400);
    f.request(
        &format!("/api/agents/{}", never_connected["id"].as_str().unwrap()),
        "DELETE",
        None,
    );
    f.request("/api/pki/activate", "POST", None);
    std::thread::sleep(Duration::from_secs(5));
    agent.heartbeat_if_due(&endpoint); // Verifies the new CA with the cached-client reload.
    let response = client()
        .post(format!("{}/api/backup", f.base))
        .header("x-redtrace-token", &f.token)
        .send()
        .unwrap();
    assert!(response.status().is_success());
    let archive = f.root.join("backup.rtbackup");
    service::write_private(&archive, &response.bytes().unwrap()).unwrap();
    let restore = f.root.join("restored");
    redtrace::backup::restore(&archive, &restore).unwrap();
    assert!(restore.join("rules.json").exists());
    drop(agent);
    f.stop();
    f.start();
    let result = f.request("/api/search?q=source%3Dfixture.telemetry", "GET", None);
    assert_eq!(result["total"], 1);
    assert_eq!(
        f.request("/api/rules", "GET", None)["file"]["rules"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
