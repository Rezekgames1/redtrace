use redtrace::{
    collector::audit_file,
    config::{Config, Resources},
    enrollment,
    ingest::AgentRegistry,
    model::Event,
    pki::Pki,
    rules, service,
    storage::CheckpointStore,
};
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    sync::Arc,
};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "redtrace-feature-{}",
                service::random_secret().unwrap()
            ));
        service::private_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn write(path: &std::path::Path, content: &str) {
    service::write_private(path, content.as_bytes()).unwrap();
}
fn audit(id: u64, kind: &str, extra: &str) -> String {
    format!("type={kind} msg=audit(1700000000.123:{id}): {extra}\n")
}
#[test]
fn audit_interleaved_groups_hold_safe_frontier_and_follow_numeric_rotation() {
    let f = Fixture::new();
    let path = f.0.join("audit.log");
    let cp = CheckpointStore::open(f.0.join("checkpoints.json")).unwrap();
    let prefix = audit(1, "SYSCALL", "pid=11 ppid=1 exe=2F62696E2F7368 success=yes");
    let second_start = prefix.len();
    write(
        &path,
        &[
            prefix,
            audit(2, "SYSCALL", "pid=22 ppid=1 exe=2F62696E2F7368 success=yes"),
            audit(1, "EXECVE", "argc=1 a0=2F62696E2F7368"),
            audit(1, "EOE", ""),
        ]
        .concat(),
    );
    let first = audit_file::collect(&path, &cp, &Resources::default());
    assert_eq!(first.events.len(), 1);
    let cursor: serde_json::Value =
        serde_json::from_str(&first.events[0].fields["collector.cursor"]).unwrap();
    assert_eq!(cursor["offset"], second_start);
    cp.update_events(&first.events).unwrap();
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    write!(
        file,
        "{}{}",
        audit(2, "EXECVE", "argc=2 a0=2F62696E2F7368 a1=2D63"),
        audit(2, "EOE", "")
    )
    .unwrap();
    file.sync_all().unwrap();
    let second = audit_file::collect(&path, &cp, &Resources::default());
    assert!(
        second
            .events
            .iter()
            .any(|e| e.fields["audit.event_id"].ends_with(":2") && e.fields["process.pid"] == "22")
    );
    cp.update_events(&second.events).unwrap();
    fs::rename(&path, f.0.join("audit.log.1")).unwrap();
    write(
        &path,
        &[
            audit(3, "SYSCALL", "pid=33 exe=2F62696E2F7368 success=yes"),
            audit(3, "EOE", ""),
        ]
        .concat(),
    );
    let third = audit_file::collect(&path, &cp, &Resources::default());
    assert_eq!(third.events.len(), 1);
    assert_eq!(third.events[0].fields["process.pid"], "33");
}
#[test]
fn audit_oversized_record_does_not_advance_past_unconfirmed_bytes() {
    let f = Fixture::new();
    let path = f.0.join("audit.log");
    let cp = CheckpointStore::open(f.0.join("checkpoints.json")).unwrap();
    let first = [
        audit(1, "SYSCALL", "pid=1 exe=2F62696E2F7368"),
        audit(1, "EOE", ""),
    ]
    .concat();
    write(
        &path,
        &format!(
            "{first}{}\n{}{}",
            "x".repeat(4096),
            audit(2, "SYSCALL", "pid=2"),
            audit(2, "EOE", "")
        ),
    );
    let result = audit_file::collect(
        &path,
        &cp,
        &Resources {
            max_record_bytes: 1024,
            ..Resources::default()
        },
    );
    assert_eq!(result.events.len(), 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&result.events[0].fields["collector.cursor"])
            .unwrap()["offset"],
        first.len()
    );
    assert!(result.status.last_error.unwrap().contains("oversized"));
}
#[test]
fn enrollment_is_one_time_and_state_survives_restart() {
    let f = Fixture::new();
    let registry = Arc::new(AgentRegistry::open(f.0.join("agents.json")).unwrap());
    let pki = Pki::new(f.0.join("pki"));
    pki.provision(vec!["localhost".into()], false).unwrap();
    let store =
        enrollment::Enrollment::open(f.0.join("enrollment.json"), registry.clone()).unwrap();
    let package = store
        .issue(
            "fixture-host",
            "https://localhost:9711",
            pki.trust_bundle().unwrap(),
            Config::default(),
        )
        .unwrap();
    let issued = store.redeem(&package.enrollment).unwrap();
    assert_eq!(registry.verify(&issued.token).unwrap().id, issued.id);
    assert!(store.redeem(&package.enrollment).is_err());
    drop(store);
    let reopened = enrollment::Enrollment::open(f.0.join("enrollment.json"), registry).unwrap();
    assert!(reopened.redeem(&package.enrollment).is_err());
}
#[test]
fn lost_automatic_rotation_reply_can_be_recovered_after_server_restart() {
    let f = Fixture::new();
    let path = f.0.join("agents.json");
    let registry = AgentRegistry::open(path.clone()).unwrap();
    let (agent, old) = registry.create_with_ttl("retry-host", 60).unwrap();
    let first = registry
        .automatic_credential(&agent.id, &old)
        .unwrap()
        .unwrap();
    let retry = registry
        .automatic_credential(&agent.id, &old)
        .unwrap()
        .unwrap();
    assert_eq!(first.token, retry.token);
    drop(registry);
    let reopened = AgentRegistry::open(path.clone()).unwrap();
    let retry = reopened
        .automatic_credential(&agent.id, &old)
        .unwrap()
        .unwrap();
    assert_eq!(first.token, retry.token);
    assert!(
        reopened
            .automatic_credential(&agent.id, &first.token)
            .unwrap()
            .is_none()
    );
    assert!(!fs::read_to_string(path).unwrap().contains(&first.token));
    reopened.revoke(&agent.id).unwrap();
    assert!(
        reopened
            .automatic_credential(&agent.id, &old)
            .unwrap()
            .is_none()
    );
}
#[test]
fn server_certificate_renewal_retains_trust_and_rotation_prepares_overlap() {
    let f = Fixture::new();
    let pki = Pki::new(f.0.join("pki"));
    let before = pki.provision(vec!["localhost".into()], false).unwrap();
    let trust = pki.trust_bundle().unwrap();
    let after = pki.provision(vec!["localhost".into()], false).unwrap();
    assert_eq!(before.ca_sha256, after.ca_sha256);
    assert_eq!(trust, pki.trust_bundle().unwrap());
    let pending = pki.prepare_rotation().unwrap();
    let prepared_ca = fs::read(
        f.0.join("pki")
            .join(pending.pending_ca.unwrap())
            .join("ca.pem"),
    )
    .unwrap();
    assert_eq!(
        reqwest::Certificate::from_pem_bundle(pki.trust_bundle().unwrap().as_bytes())
            .unwrap()
            .len(),
        2
    );
    assert_eq!(pki.status().unwrap().unwrap().active, after.active);
    let rotated = pki.provision(vec!["localhost".into()], true).unwrap();
    assert_ne!(rotated.ca_sha256, before.ca_sha256);
    assert!(rotated.pending_ca.is_none());
    assert_eq!(
        fs::read(f.0.join("pki").join(rotated.active).join("ca.pem")).unwrap(),
        prepared_ca
    );
}
#[test]
fn pki_refuses_redirected_state_and_exhausted_generations() {
    let f = Fixture::new();
    let pki = Pki::new(f.0.join("pki"));
    let original = pki.provision(vec!["localhost".into()], false).unwrap();
    let path = f.0.join("pki/pki.json");
    let mut redirected = original.clone();
    redirected.previous_ca = Some("../outside".into());
    service::write_private(&path, &serde_json::to_vec(&redirected).unwrap()).unwrap();
    assert!(pki.trust_bundle().is_err());
    let mut exhausted = original;
    exhausted.generation = u64::MAX;
    service::write_private(&path, &serde_json::to_vec(&exhausted).unwrap()).unwrap();
    assert!(pki.provision(vec!["localhost".into()], false).is_err());
    assert_eq!(pki.status().unwrap().unwrap().generation, u64::MAX);
}
#[test]
fn rule_revision_conflicts_and_history_survive_restart() {
    let f = Fixture::new();
    let path = f.0.join("rules.json");
    let mut manager = rules::Manager::open(path.clone()).unwrap();
    let rule = rules::Rule::default();
    manager.replace(0, vec![rule.clone()]).unwrap();
    assert!(manager.replace(0, vec![rule.clone()]).is_err());
    assert!(
        manager
            .replace(
                1,
                vec![rules::Rule {
                    query: "event.id=changed".into(),
                    ..rule.clone()
                }]
            )
            .is_err()
    );
    manager
        .replace(
            1,
            vec![rules::Rule {
                revision: 2,
                ..rule
            }],
        )
        .unwrap();
    let reopened = rules::Manager::open(path).unwrap();
    assert_eq!(reopened.file.rules[0].revision, 2);
    assert_eq!(reopened.file.history.len(), 1);
}
#[test]
fn corrupt_backup_never_activates_restore_and_future_configs_are_refused() {
    let f = Fixture::new();
    let data = f.0.join("data");
    service::private_directory(&data).unwrap();
    write(&data.join("fixture"), "fixture bytes");
    let archive = f.0.join("backup.rtbackup");
    redtrace::backup::create(&data, &archive).unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(&archive).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(b"X").unwrap();
    file.sync_all().unwrap();
    let restored = f.0.join("restored");
    assert!(redtrace::backup::restore(&archive, &restored).is_err());
    assert!(!restored.exists());
    assert!(
        Config {
            version: 2,
            ..Config::default()
        }
        .validate()
        .is_err()
    );
}
#[test]
fn live_rule_state_is_bounded_under_high_cardinality() {
    let r = rules::Rule {
        kind: rules::Kind::Threshold,
        group_by: vec!["user.name".into()],
        ..rules::Rule::default()
    };
    let mut engine = rules::Engine::new(vec![r]).unwrap();
    for seq in 0..3000 {
        let event = Event::normalized(
            0,
            "2026-10-13T10:00:00Z".into(),
            "fixture".into(),
            "low".into(),
            seq.to_string(),
            std::collections::BTreeMap::from([("user.name".into(), seq.to_string())]),
        );
        engine.evaluate(&event, 10);
    }
    let health = engine.health();
    assert!(health["state_keys"].as_u64().unwrap() <= 2048);
    assert!(health["state_bytes"].as_u64().unwrap() <= 4 * 1024 * 1024);
    assert!(health["refused_total"].as_u64().unwrap() > 0);
}
