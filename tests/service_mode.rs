use redtrace::{
    model::Event,
    service::{self, LocalSession},
    storage::Wal,
};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Fixture {
    root: PathBuf,
    children: Vec<Child>,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join("opencode")
            .join(format!(
                "redtrace-service-{}",
                service::random_secret().unwrap()
            ));
        service::private_directory(&root).unwrap();
        Self {
            root,
            children: Vec::new(),
        }
    }

    fn executable(&self) -> PathBuf {
        let built = PathBuf::from(env!("CARGO_BIN_EXE_redtrace"));
        #[cfg(windows)]
        {
            // The CI checkout may grant write access to groups that a service
            // executable must not trust. Stage it with a private Windows DACL.
            let staged = self.root.join("redtrace.exe");
            if !staged.exists() {
                service::write_private(&staged, &std::fs::read(&built).unwrap()).unwrap();
            }
            staged
        }
        #[cfg(not(windows))]
        built
    }

    fn launch(
        &mut self,
        persistent: bool,
        unauthenticated: bool,
    ) -> (String, Option<LocalSession>) {
        let data = self.root.join("data");
        let config = self.root.join("collector.json");
        let executable = self.executable();
        service::write_private(&config, &serde_json::to_vec(&serde_json::json!({
            "data_dir": data, "api_bind": "127.0.0.1:0", "environment": {"REDTRACE_COLLECT_LOCAL": "0"}
        })).unwrap()).unwrap();
        let token = service::random_secret().unwrap();
        let mut command = Command::new(&executable);
        command
            .env("REDTRACE_COLLECT_LOCAL", "0")
            .env_remove("REDTRACE_INGEST_BIND")
            .env_remove("REDTRACE_SESSION_FILE")
            .env_remove("REDTRACE_API_TOKEN")
            .env("REDTRACE_LOOKBACK", "1s")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if persistent {
            command.args(["--persistent", "--config"]).arg(&config);
        } else {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            drop(listener);
            command
                .env("REDTRACE_SERVICE_MODE", "portable")
                .env("REDTRACE_DATA_DIR", &data)
                .env("REDTRACE_API_BIND", address.to_string());
            if unauthenticated {
                command.env("REDTRACE_ALLOW_UNAUTHENTICATED", "1");
            } else {
                command.env("REDTRACE_API_TOKEN", &token);
            }
            self.children.push(command.spawn().unwrap());
            let base = format!("http://{address}");
            wait_health(
                self.children.last_mut().unwrap(),
                &base,
                if unauthenticated { None } else { Some(&token) },
            );
            return (base, None);
        }
        self.children.push(command.spawn().unwrap());
        let session_file = data.join("session.json");
        let deadline = Instant::now() + Duration::from_secs(20);
        let session = loop {
            assert!(
                self.children
                    .last_mut()
                    .unwrap()
                    .try_wait()
                    .unwrap()
                    .is_none(),
                "isolated persistent collector exited"
            );
            if let Ok(session) = service::attach(&session_file, &executable, &data) {
                break session;
            }
            assert!(Instant::now() < deadline, "persistent attachment timed out");
            std::thread::sleep(Duration::from_millis(50));
        };
        (
            format!("http://{}", session.identity.address),
            Some(session),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

fn wait_health(child: &mut Child, base: &str, token: Option<&str>) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(child.try_wait().unwrap().is_none());
        let mut request = client().get(format!("{base}/api/health"));
        if let Some(token) = token {
            request = request.header("x-redtrace-token", token);
        }
        if request
            .send()
            .is_ok_and(|response| response.status().is_success())
        {
            return;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn json(response: reqwest::blocking::Response) -> serde_json::Value {
    serde_json::from_str(&response.text().unwrap()).unwrap()
}

#[test]
fn persistent_attachment_rotation_stop_and_recovery_are_isolated() {
    let mut fixture = Fixture::new();
    let event = Event::normalized(
        1,
        chrono::Utc::now().to_rfc3339(),
        "service.fixture".into(),
        "low".into(),
        "durable service fixture".into(),
        BTreeMap::new(),
    );
    service::private_directory(&fixture.root.join("data")).unwrap();
    Wal::open(fixture.root.join("data/active.wal"))
        .unwrap()
        .append(std::slice::from_ref(&event))
        .unwrap();
    let (base, session) = fixture.launch(true, false);
    let session = session.unwrap();
    let path = fixture.root.join("data/session.json");
    let bytes = service::read_private(&path, 16 * 1024).unwrap();
    assert!(service::request_stop(&session, true).is_err());
    assert!(
        fixture
            .children
            .last_mut()
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none()
    );
    assert_eq!(
        client()
            .get(format!("{base}/api/session"))
            .send()
            .unwrap()
            .status(),
        401
    );
    let mut wrong = session.clone();
    wrong.token = service::random_secret().unwrap();
    service::write_private(&path, &serde_json::to_vec(&wrong).unwrap()).unwrap();
    assert!(
        service::attach(
            &path,
            &session.identity.executable,
            &session.identity.data_dir
        )
        .is_err()
    );
    wrong = session.clone();
    wrong.identity.pid = std::process::id();
    service::write_private(&path, &serde_json::to_vec(&wrong).unwrap()).unwrap();
    assert!(
        service::attach(
            &path,
            &session.identity.executable,
            &session.identity.data_dir
        )
        .is_err()
    );
    wrong = session.clone();
    wrong.identity.version = "wrong-version".into();
    service::write_private(&path, &serde_json::to_vec(&wrong).unwrap()).unwrap();
    assert!(
        service::attach(
            &path,
            &session.identity.executable,
            &session.identity.data_dir
        )
        .is_err()
    );
    service::write_private(&path, &bytes).unwrap();
    let bad_stop = client()
        .post(format!("{base}/api/session/stop"))
        .header("x-redtrace-token", &session.token)
        .header("x-redtrace-instance", "wrong")
        .send()
        .unwrap();
    assert_eq!(bad_stop.status(), 409);
    let created = client()
        .post(format!("{base}/api/agents"))
        .header("x-redtrace-token", &session.token)
        .header("content-type", "application/json")
        .body(r#"{"name":"service-fixture"}"#)
        .send()
        .unwrap();
    assert_eq!(created.status(), 201);
    assert_eq!(created.headers()["cache-control"], "no-store");
    let created = json(created);
    let rotated = client()
        .post(format!(
            "{base}/api/agents/{}/rotate",
            created["id"].as_str().unwrap()
        ))
        .header("x-redtrace-token", &session.token)
        .header("content-type", "application/json")
        .body(r#"{"ttl_seconds":3600,"overlap_seconds":0}"#)
        .send()
        .unwrap();
    assert_eq!(rotated.status(), 200);
    assert_eq!(rotated.headers()["cache-control"], "no-store");
    let rotated = json(rotated);
    assert_eq!(rotated["id"], created["id"]);
    assert_eq!(rotated["token_generation"], 2);
    assert_ne!(rotated["token"], created["token"]);
    let health = json(
        client()
            .get(format!("{base}/api/health"))
            .header("x-redtrace-token", &session.token)
            .send()
            .unwrap(),
    );
    assert_eq!(health["storage"]["retention"]["runs"], 1);
    assert!(health["remote_ingest"]["budget"]["limits"].is_object());
    let search = json(
        client()
            .get(format!("{base}/api/search"))
            .query(&[("q", "source=service.fixture")])
            .header("x-redtrace-token", &session.token)
            .send()
            .unwrap(),
    );
    assert_eq!(search["total"], 1);
    service::request_stop(&session, false).unwrap();
    let deadline = Instant::now() + Duration::from_secs(35);
    loop {
        if let Some(status) = fixture.children.last_mut().unwrap().try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "collector drain did not finish");
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(!path.exists());
    let (base, restarted) = fixture.launch(true, false);
    let restarted = restarted.unwrap();
    assert_eq!(restarted.token, session.token);
    assert_ne!(restarted.identity.instance, session.identity.instance);
    let search = json(
        client()
            .get(format!("{base}/api/search"))
            .query(&[("q", "source=service.fixture")])
            .header("x-redtrace-token", &restarted.token)
            .send()
            .unwrap(),
    );
    assert_eq!(search["total"], 1);
    fixture.children.last_mut().unwrap().kill().unwrap();
    fixture.children.last_mut().unwrap().wait().unwrap();
    assert!(path.exists());
    let (_, recovered) = fixture.launch(true, false);
    assert_ne!(
        recovered.unwrap().identity.instance,
        restarted.identity.instance
    );
}

#[test]
fn development_unauthenticated_mode_cannot_manage_agents() {
    let mut fixture = Fixture::new();
    let (base, _) = fixture.launch(false, true);
    let original = std::fs::read(fixture.root.join("data/agents.json")).unwrap();
    for request in [
        client().get(format!("{base}/api/agents")),
        client()
            .post(format!("{base}/api/agents"))
            .header("content-type", "application/json")
            .body(r#"{"name":"blocked"}"#),
        client().delete(format!("{base}/api/agents/unknown")),
        client()
            .post(format!("{base}/api/agents/unknown/rotate"))
            .header("content-type", "application/json")
            .body("{}"),
        client().post(format!("{base}/api/session/stop")),
    ] {
        assert_eq!(request.send().unwrap().status(), 401);
    }
    assert_eq!(
        std::fs::read(fixture.root.join("data/agents.json")).unwrap(),
        original
    );
    assert_eq!(
        json(client().get(format!("{base}/api/health")).send().unwrap())["remote_ingest"]["agents_total"],
        0
    );
}

#[test]
fn occupied_loopback_is_never_killed_or_mutated() {
    let fixture = Fixture::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_redtrace"))
        .env("REDTRACE_API_BIND", address.to_string())
        .env("REDTRACE_SERVICE_MODE", "portable")
        .env("REDTRACE_API_TOKEN", service::random_secret().unwrap())
        .env("REDTRACE_DATA_DIR", fixture.root.join("untouched"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!fixture.root.join("untouched").exists());
    let connected = std::net::TcpStream::connect(address).unwrap();
    let (_accepted, _) = listener.accept().unwrap();
    drop(connected);
}

#[test]
fn service_files_are_private_and_reject_untrusted_permissions() {
    let fixture = Fixture::new();
    let path = fixture.root.join("private.json");
    service::write_private(&path, b"private fixture").unwrap();
    assert_eq!(
        service::read_private(&path, 100).unwrap(),
        b"private fixture"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(service::read_private(&path, 100).is_err());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::{
                Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
                DACL_SECURITY_INFORMATION, SetFileSecurityW,
            },
        };
        let descriptor: Vec<_> = "D:P(A;;FA;;;WD)".encode_utf16().chain([0]).collect();
        let mut security = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    descriptor.as_ptr(),
                    1,
                    &mut security,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let wide: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
        assert_ne!(
            unsafe { SetFileSecurityW(wide.as_ptr(), DACL_SECURITY_INFORMATION, security) },
            0
        );
        unsafe {
            LocalFree(security);
        }
        assert!(service::read_private(&path, 100).is_err());
    }
}

#[test]
fn bind_and_provisioning_reject_external_addresses_and_expansion_paths() {
    assert!(service::api_bind("127.0.0.1:0").is_ok());
    assert!(service::api_bind("[::1]:0").is_ok());
    for address in [
        "0.0.0.0:9710",
        "[::]:9710",
        "192.0.2.1:9710",
        "localhost:9710",
    ] {
        assert!(service::api_bind(address).is_err());
    }
    for path in ["relative", "/tmp/a\nb", "/tmp/%n", "/tmp/../escape"] {
        assert!(service::absolute_path(std::path::Path::new(path)).is_err());
    }
}

#[test]
fn protected_templates_and_config_reject_secret_and_identity_shortcuts() {
    let fixture = Fixture::new();
    let config = fixture.root.join("service.json");
    let valid = serde_json::json!({"data_dir": fixture.root.join("state")});
    service::write_private(&config, &serde_json::to_vec(&valid).unwrap()).unwrap();
    let binary = fixture.executable();
    let template = service::systemd_template(&binary, &config, "fixture-user", false).unwrap();
    assert!(template.contains("User=fixture-user\n"));
    assert!(template.contains("Restart=on-failure\n"));
    assert!(template.contains("TimeoutStopSec=45\n"));
    for identity in ["", "root", "0", "user\nExecStart=bad"] {
        assert!(service::systemd_template(&binary, &config, identity, false).is_err());
    }
    for variable in [
        "REDTRACE_API_TOKEN",
        "REDTRACE_AGENT_TOKEN",
        "PATH",
        "REDTRACE_ALLOW_UNAUTHENTICATED",
    ] {
        let mut invalid = valid.clone();
        invalid["environment"] = serde_json::json!({variable: "rejected"});
        service::write_private(&config, &serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(service::ServiceConfig::load(&config).is_err());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn foreground_collector_and_agent_handle_sigterm_with_durable_state() {
    use redtrace::agent::{DiskSpool, SpoolLimits};
    use std::io::BufRead;
    let mut fixture = Fixture::new();
    let (_, session) = fixture.launch(true, false);
    let collector = fixture.children.last_mut().unwrap();
    assert_eq!(
        unsafe { libc::kill(collector.id() as i32, libc::SIGTERM) },
        0
    );
    assert!(collector.wait().unwrap().success());
    assert!(
        !session
            .unwrap()
            .identity
            .data_dir
            .join("session.json")
            .exists()
    );
    let state = fixture.root.join("agent-state");
    service::private_directory(&state).unwrap();
    let event = Event::normalized(
        1,
        chrono::Utc::now().to_rfc3339(),
        "service.agent.fixture".into(),
        "low".into(),
        "pending offline delivery".into(),
        BTreeMap::new(),
    );
    let mut spool = DiskSpool::open(state.clone(), SpoolLimits::default()).unwrap();
    spool.push(event.clone()).unwrap();
    drop(spool);
    let token_file = fixture.root.join("agent.token");
    service::write_private(&token_file, service::random_secret().unwrap().as_bytes()).unwrap();
    let config = fixture.root.join("agent.json");
    let refused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let server = format!("http://{}", refused.local_addr().unwrap());
    drop(refused);
    service::write_private(
        &config,
        &serde_json::to_vec(&serde_json::json!({
            "data_dir": state, "environment": {
                "REDTRACE_AGENT_SERVER": server, "REDTRACE_AGENT_TOKEN_FILE": token_file,
                "REDTRACE_AGENT_POLL_SECONDS": "1", "REDTRACE_COLLECT_LOCAL": "0"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_redtrace-service-agent"))
        .arg("--persistent")
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let output = std::thread::spawn(move || {
        let mut ready = Some(ready_tx);
        for line in std::io::BufReader::new(stderr).lines() {
            let line = line.unwrap();
            if line.contains("persistent agent ready")
                && let Some(ready) = ready.take()
            {
                ready.send(()).unwrap();
            }
        }
    });
    fixture.children.push(child);
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let child = fixture.children.last_mut().unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "agent did not stop gracefully");
        std::thread::sleep(Duration::from_millis(25));
    }
    output.join().unwrap();
    let mut spool = DiskSpool::open(state, SpoolLimits::default()).unwrap();
    assert_eq!(spool.len(), 1);
    assert_eq!(spool.peek_chunk(1).unwrap().events()[0].uid, event.uid);
}
