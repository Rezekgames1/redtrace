use redtrace::{
    backup,
    config::{Config, ModuleInput},
    model::Event,
    rules::{self, Kind, Rule},
    service,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "redtrace-rule-backup-{}",
                service::random_secret().unwrap()
            ));
        service::private_directory(&root).unwrap();
        Self(root)
    }
    fn directory(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        service::private_directory(&path).unwrap();
        path
    }
    fn assert_no_staging(&self) {
        assert!(fs::read_dir(&self.0).unwrap().all(|entry| {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            !name.starts_with(".restore-") && !name.starts_with(".backup-")
        }));
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn event(id: &str, timestamp: &str, uid: &str) -> Event {
    let mut result = Event::normalized(
        0,
        timestamp.into(),
        "fixture".into(),
        "low".into(),
        id.into(),
        BTreeMap::from([
            ("event.id".into(), id.into()),
            ("agent.id".into(), "agent-a".into()),
        ]),
    );
    result.uid = uid.into();
    result
}
fn sequence() -> Rule {
    Rule {
        kind: Kind::Sequence,
        sequence: vec!["event.id=start".into(), "event.id=end".into()],
        suppression_seconds: 0,
        ..Rule::default()
    }
}
#[test]
fn replay_orders_real_event_time_and_preserves_equal_timestamp_sequence() {
    let start = event("start", "2026-10-13T13:00:00+03:00", "z-start");
    let end = event("end", "2026-10-13T10:00:01Z", "a-end");
    assert_eq!(
        rules::replay(vec![sequence()], vec![end, start]).unwrap()["alerts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let start = event("start", "2026-10-13T10:00:00Z", "z-start");
    let end = event("end", "2026-10-13T10:00:00Z", "a-end");
    assert_eq!(
        rules::replay(vec![sequence()], vec![start, end]).unwrap()["alerts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn final_absence_alerts_are_included_in_replay_budget() {
    let matching = Rule {
        id: "matching".into(),
        suppression_seconds: 0,
        ..Rule::default()
    };
    let missing = Rule {
        id: "missing".into(),
        kind: Kind::Absence,
        ..sequence()
    };
    let events = (0..10_000)
        .map(|n| {
            event(
                if n == 0 { "start" } else { "other" },
                "2026-10-13T10:00:00Z",
                &format!("uid-{n}"),
            )
        })
        .collect();
    assert!(
        rules::replay(vec![matching, missing], events)
            .unwrap_err()
            .to_string()
            .contains("alert cap")
    );
}
#[test]
fn deleted_rule_revision_cannot_be_reused_and_generation_cannot_overflow() {
    let f = Fixture::new();
    let path = f.0.join("rules.json");
    let mut manager = rules::Manager::open(path.clone()).unwrap();
    let rule = Rule {
        revision: 3,
        ..Rule::default()
    };
    manager.replace(0, vec![rule.clone()]).unwrap();
    manager.replace(1, vec![]).unwrap();
    assert!(manager.replace(2, vec![rule.clone()]).is_err());
    manager
        .replace(
            2,
            vec![Rule {
                revision: 4,
                ..rule
            }],
        )
        .unwrap();
    let saved = fs::read(&path).unwrap();
    manager.file.generation = u64::MAX;
    assert!(
        manager
            .replace(u64::MAX, manager.file.rules.clone())
            .is_err()
    );
    assert_eq!(fs::read(path).unwrap(), saved);
}
#[test]
fn threshold_suppression_and_dedup_survive_checkpoint_restart() {
    let f = Fixture::new();
    let path = f.0.join("rules.json");
    let mut manager = rules::Manager::open(path.clone()).unwrap();
    manager
        .replace(
            0,
            vec![Rule {
                kind: Kind::Threshold,
                threshold: 2,
                suppression_seconds: 10,
                ..Rule::default()
            }],
        )
        .unwrap();
    let first = event("fail", "2026-10-13T10:00:00Z", "first");
    let second = event("fail", "2026-10-13T10:00:01Z", "second");
    assert!(manager.engine.evaluate(&first, 1).is_empty());
    manager.checkpoint().unwrap();
    drop(manager);
    let mut manager = rules::Manager::open(path.clone()).unwrap();
    assert!(manager.engine.evaluate(&first, 2).is_empty());
    assert_eq!(manager.engine.evaluate(&second, 3).len(), 1);
    manager.checkpoint().unwrap();
    drop(manager);
    let mut manager = rules::Manager::open(path).unwrap();
    assert!(
        manager
            .engine
            .evaluate(&event("fail", "2026-10-13T10:00:02Z", "third"), 4)
            .is_empty()
    );
}
#[test]
fn invalid_snapshot_keys_and_future_state_times_are_refused() {
    let f = Fixture::new();
    let path = f.0.join("rules.json");
    let mut manager = rules::Manager::open(path.clone()).unwrap();
    manager.replace(0, vec![Rule::default()]).unwrap();
    manager
        .engine
        .evaluate(&event("x", "2026-10-13T10:00:00Z", "first"), 1);
    manager.checkpoint().unwrap();
    let snapshot_path = f.0.join("rules-state.json");
    let snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(&snapshot_path).unwrap()).unwrap();
    let mut invalid = snapshot.clone();
    let states = invalid["states"].as_object_mut().unwrap();
    let key = states.keys().next().unwrap().clone();
    let state = states.remove(&key).unwrap();
    invalid["states"] = json!({"custom.rule:not-a-hash":state});
    service::write_private(&snapshot_path, &serde_json::to_vec(&invalid).unwrap()).unwrap();
    assert!(rules::Manager::open(path.clone()).is_err());
    let mut invalid = snapshot;
    invalid["clock"] = json!(0);
    service::write_private(&snapshot_path, &serde_json::to_vec(&invalid).unwrap()).unwrap();
    assert!(rules::Manager::open(path).is_err());
}
#[test]
fn case_ids_are_unique_and_evidence_is_bounded() {
    let f = Fixture::new();
    let case = rules::Case {
        id: "case-1".into(),
        status: "open".into(),
        evidence: vec!["uid".into()],
        ..rules::Case::default()
    };
    let path = f.0.join("cases.json");
    rules::save_cases(&path, std::slice::from_ref(&case)).unwrap();
    let saved = fs::read(&path).unwrap();
    assert!(rules::save_cases(&path, &[case.clone(), case.clone()]).is_err());
    assert!(
        rules::save_cases(
            &path,
            &[rules::Case {
                evidence: vec!["x".repeat(257)],
                ..case
            }]
        )
        .is_err()
    );
    assert_eq!(fs::read(path).unwrap(), saved);
}
#[test]
fn legacy_migration_is_idempotent_and_future_data_is_not_modified_or_backed_up() {
    let f = Fixture::new();
    let data = f.directory("data");
    let payload = b"compatible legacy data";
    service::write_private(&data.join("payload"), payload).unwrap();
    backup::migrate(&data).unwrap();
    let marker = data.join("data-version.json");
    let migrated = fs::read(&marker).unwrap();
    backup::migrate(&data).unwrap();
    assert_eq!(fs::read(&marker).unwrap(), migrated);
    assert_eq!(fs::read(data.join("payload")).unwrap(), payload);
    let future = b"{\"version\":1,\"minimum_reader\":1,\"config_version\":2}";
    service::write_private(&marker, future).unwrap();
    assert!(backup::migrate(&data).is_err());
    let archive = f.0.join("future.rtbackup");
    assert!(backup::create(&data, &archive).is_err());
    assert!(!archive.exists());
    assert_eq!(fs::read(marker).unwrap(), future);
}
#[test]
fn future_config_does_not_gain_a_misleading_compatibility_marker() {
    let f = Fixture::new();
    let data = f.directory("data");
    service::write_private(&data.join("config.json"), b"{\"version\":2}").unwrap();
    assert!(backup::migrate(&data).is_err());
    assert!(!data.join("data-version.json").exists());
}
#[test]
fn corrupt_archives_fail_inspection_and_restore_without_staging_leaks() {
    let f = Fixture::new();
    let data = f.directory("data");
    service::write_private(&data.join("payload"), b"fixture bytes").unwrap();
    let archive = f.0.join("archive.rtbackup");
    backup::create(&data, &archive).unwrap();
    backup::inspect(&archive).unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(&archive).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(b"X").unwrap();
    file.sync_all().unwrap();
    assert!(backup::inspect(&archive).is_err());
    let target = f.0.join("restored");
    assert!(backup::restore(&archive, &target).is_err());
    assert!(!target.exists());
    f.assert_no_staging();
}
#[test]
fn restore_rebases_owned_paths_and_preserves_rule_filter_strings() {
    let f = Fixture::new();
    let data = f.directory("data");
    let old = data.to_string_lossy().into_owned();
    let mut config = Config::default();
    config.sources.audit_path = data.join("audit.log").to_string_lossy().into_owned();
    config.sources.module_inputs = vec![ModuleInput {
        id: "fixture".into(),
        path: data.join("module.jsonl").to_string_lossy().into_owned(),
        query: format!("message=\"{old}\""),
    }];
    config.include = format!("message=\"{old}\"");
    config.save(&data.join("config.json")).unwrap();
    service::write_private(&data.join("service.json"), &serde_json::to_vec(&json!({"data_dir": old, "environment": {"REDTRACE_AGENT_TOKEN_FILE": data.join("token"), "REDTRACE_NAME": old}})).unwrap()).unwrap();
    let archive = f.0.join("archive.rtbackup");
    backup::create(&data, &archive).unwrap();
    let target = f.0.join("restored");
    backup::restore(&archive, &target).unwrap();
    let restored = Config::load(&target.join("config.json")).unwrap();
    assert_eq!(restored.include, config.include);
    assert_eq!(
        restored.sources.module_inputs[0].query,
        config.sources.module_inputs[0].query
    );
    assert_eq!(
        PathBuf::from(restored.sources.audit_path),
        target.join("audit.log")
    );
    assert_eq!(
        PathBuf::from(&restored.sources.module_inputs[0].path),
        target.join("module.jsonl")
    );
    let service: serde_json::Value =
        serde_json::from_slice(&fs::read(target.join("service.json")).unwrap()).unwrap();
    assert_eq!(service["data_dir"], target.to_string_lossy().as_ref());
    assert_eq!(service["environment"]["REDTRACE_NAME"], old);
    assert_eq!(
        service["environment"]["REDTRACE_AGENT_TOKEN_FILE"],
        target.join("token").to_string_lossy().as_ref()
    );
    f.assert_no_staging();
}
#[cfg(unix)]
#[test]
fn cross_platform_name_collisions_do_not_produce_unrestorable_archives() {
    let f = Fixture::new();
    let data = f.directory("data");
    service::write_private(&data.join("CON.txt"), b"x").unwrap();
    let archive = f.0.join("archive.rtbackup");
    assert!(backup::create(&data, &archive).is_err());
    assert!(!archive.exists());
    f.assert_no_staging();
}
