use redtrace::{
    collector::{audit_file, endpoint_security::parse_record, extended::ExtendedCollectors},
    config::{Config, ModuleInput, Resources},
    model::Event,
    modules::{ModuleEvent, PROTOCOL},
    service,
    storage::CheckpointStore,
};
use std::{collections::BTreeMap, fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "redtrace-telemetry-{}",
                service::random_secret().unwrap()
            ));
        service::private_directory(&path).unwrap();
        Self(path)
    }
    fn checkpoints(&self) -> CheckpointStore {
        CheckpointStore::open(self.0.join("checkpoints.json")).unwrap()
    }
    fn module(&self, name: &str, records: &[ModuleEvent]) -> ModuleInput {
        let path = self.0.join(format!("{name}.ndjson"));
        let mut bytes = Vec::new();
        for record in records {
            serde_json::to_writer(&mut bytes, record).unwrap();
            bytes.push(b'\n');
        }
        service::write_private(&path, &bytes).unwrap();
        ModuleInput {
            id: name.into(),
            path: path.to_str().unwrap().into(),
            query: "*".into(),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn module(name: &str, message: &str) -> ModuleEvent {
    ModuleEvent {
        protocol: PROTOCOL,
        module: name.into(),
        event: Event::normalized(
            7,
            "2026-10-13T10:00:00+03:00".into(),
            "producer".into(),
            "low".into(),
            message.into(),
            BTreeMap::from([
                ("event.id".into(), "network.connect".into()),
                ("destination.ip".into(), "192.0.2.1".into()),
            ]),
        ),
    }
}
fn config(inputs: Vec<ModuleInput>) -> Config {
    let mut config = Config::default();
    config.sources.system = false;
    config.sources.module_inputs = inputs;
    config
}

#[test]
fn module_inputs_share_event_budget_and_rotate_without_starvation() {
    let fixture = Fixture::new();
    let checkpoints = fixture.checkpoints();
    let mut config = config(vec![
        fixture.module("nta.one", &[module("nta.one", "a"), module("nta.one", "b")]),
        fixture.module("nta.two", &[module("nta.two", "c"), module("nta.two", "d")]),
    ]);
    config.resources.max_batch_events = 1;
    let mut collectors = ExtendedCollectors::new(config).unwrap();
    let mut sources = Vec::new();
    for _ in 0..4 {
        let batch = collectors.collect(&checkpoints);
        assert_eq!(batch.len(), 1);
        sources.push(batch[0].source.clone());
        assert_eq!(batch[0].id, 0);
        assert_eq!(batch[0].timestamp, "2026-10-13T07:00:00.000000000Z");
        checkpoints.update_events(&batch).unwrap();
    }
    assert_eq!(
        sources,
        [
            "module.nta.one",
            "module.nta.two",
            "module.nta.one",
            "module.nta.two"
        ]
    );
    assert!(collectors.collect(&checkpoints).is_empty());
    assert_eq!(collectors.health["nta.one"].events, 2);
    assert_eq!(collectors.health["nta.two"].events, 2);
    assert!(collectors.health["nta.one"].last_event_at.is_some());
}

#[test]
fn module_inputs_share_normalized_byte_budget_and_hold_remaining_cursor() {
    let fixture = Fixture::new();
    let checkpoints = fixture.checkpoints();
    let mut config = config(vec![
        fixture.module("nta.one", &[module("nta.one", &"a".repeat(1000))]),
        fixture.module("nta.two", &[module("nta.two", &"b".repeat(1000))]),
    ]);
    config.resources.max_batch_bytes = 2048;
    config.resources.max_record_bytes = 2048;
    let mut collectors = ExtendedCollectors::new(config).unwrap();
    let first = collectors.collect(&checkpoints);
    assert_eq!(first.len(), 1);
    assert!(
        first
            .iter()
            .map(|event| serde_json::to_vec(event).unwrap().len())
            .sum::<usize>()
            <= 2048
    );
    checkpoints.update_events(&first).unwrap();
    assert!(checkpoints.get("module.nta.two").is_none());
    let next = collectors.collect(&checkpoints);
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].source, "module.nta.two");
}

#[test]
fn malformed_module_record_preserves_valid_prefix_and_stops_at_bad_bytes() {
    let fixture = Fixture::new();
    let checkpoints = fixture.checkpoints();
    let input = fixture.module("nta", &[module("nta", "accepted")]);
    let prefix = fs::read(&input.path).unwrap();
    let mut bytes = prefix.clone();
    bytes.extend_from_slice(b"{invalid}\n");
    bytes.extend_from_slice(&serde_json::to_vec(&module("nta", "later")).unwrap());
    bytes.push(b'\n');
    service::write_private(std::path::Path::new(&input.path), &bytes).unwrap();
    let mut collectors = ExtendedCollectors::new(config(vec![input])).unwrap();
    let first = collectors.collect(&checkpoints);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].message, "accepted");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&first[0].fields["collector.cursor"]).unwrap()["offset"],
        prefix.len()
    );
    assert_eq!(collectors.health["nta"].state, "degraded");
    checkpoints.update_events(&first).unwrap();
    assert!(collectors.collect(&checkpoints).is_empty());
    assert_eq!(collectors.health["nta"].state, "error");
    assert_eq!(collectors.health["nta"].events, 1);
}

#[test]
fn module_query_filter_advances_cursor_using_sanitized_marker() {
    let fixture = Fixture::new();
    let checkpoints = fixture.checkpoints();
    let mut input = fixture.module("nta", &[module("nta", "sensitive payload")]);
    input.query = "event.category:process".into();
    let mut collectors = ExtendedCollectors::new(config(vec![input])).unwrap();
    let batch = collectors.collect(&checkpoints);
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].fields["event.filtered"], "true");
    assert!(!batch[0].fields.contains_key("destination.ip"));
    assert_ne!(batch[0].message, "sensitive payload");
    assert_eq!(collectors.health["nta"].filtered, 1);
    checkpoints.update_events(&batch).unwrap();
    assert!(collectors.collect(&checkpoints).is_empty());
}

#[test]
fn module_contract_rejects_newer_event_schema_and_invalid_field_names() {
    let mut event = module("nta", "fixture");
    event.event.schema_version = 2;
    assert!(event.validate("nta").is_err());
    event.event.schema_version = 1;
    event
        .event
        .fields
        .insert("invalid key".into(), "value".into());
    assert!(event.validate("nta").is_err());
}

#[test]
fn audit_invalid_utf8_preserves_valid_prefix_and_its_checkpoint() {
    let fixture = Fixture::new();
    let checkpoints = fixture.checkpoints();
    let path = fixture.0.join("audit.log");
    let prefix = b"type=SYSCALL msg=audit(1700000000.123:1): pid=1 success=yes\ntype=EOE msg=audit(1700000000.123:1):\n";
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(b"\xff\n");
    service::write_private(&path, &bytes).unwrap();
    let batch = audit_file::collect(&path, &checkpoints, &Resources::default());
    assert_eq!(batch.events.len(), 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&batch.events[0].fields["collector.cursor"])
            .unwrap()["offset"],
        prefix.len()
    );
    assert!(batch.status.last_error.unwrap().contains("invalid UTF-8"));
}

#[test]
fn eslogger_file_variants_authentication_and_exit_are_normalized() {
    for (action, event, expected) in [
        (
            "create",
            serde_json::json!({"destination":{"new_path":{"dir":{"path":"/tmp"},"filename":"new file"}}}),
            "/tmp/new file",
        ),
        (
            "create",
            serde_json::json!({"destination":{"existing_file":{"path":"/tmp/existing"}}}),
            "/tmp/existing",
        ),
        (
            "open",
            serde_json::json!({"file":{"path":"/tmp/open"}}),
            "/tmp/open",
        ),
    ] {
        let raw = serde_json::json!({"time":"2026-10-13T10:00:00Z","event":{action:event}});
        let event = parse_record(&serde_json::to_vec(&raw).unwrap()).unwrap();
        assert_eq!(event.fields["file.path"], expected);
    }
    let auth = parse_record(br#"{"time":"2026-10-13T10:00:00Z","event":{"openssh_login":{"success":false,"username":"alice","source_address":"192.0.2.1","has_uid":false}}}"#).unwrap();
    assert_eq!(auth.fields["event.category"], "authentication");
    assert_eq!(auth.fields["event.outcome"], "failure");
    assert_eq!(auth.fields["user.name"], "alice");
    assert_eq!(auth.fields["source.ip"], "192.0.2.1");
    let exit =
        parse_record(br#"{"time":"2026-10-13T10:00:00Z","event":{"exit":{"stat":1792}}}"#).unwrap();
    assert_eq!(exit.fields["process.exit_status"], "1792");
    assert_eq!(exit.fields["process.exit_code"], "7");
}

#[test]
fn eslogger_argv_keeps_boundaries_and_identity_without_optional_sequences() {
    let raw =
        br#"{"time":"2026-10-13T10:00:00Z","event":{"exec":{"args":["/bin/echo","hello world"]}}}"#;
    let event = parse_record(raw).unwrap();
    assert_eq!(
        event.fields["process.command_line"],
        "/bin/echo \"hello world\""
    );
    assert_eq!(event.uid, parse_record(raw).unwrap().uid);
    let other = parse_record(
        br#"{"time":"2026-10-13T10:00:00Z","event":{"exec":{"args":["/bin/echo","different"]}}}"#,
    )
    .unwrap();
    assert_ne!(event.uid, other.uid);
    assert!(parse_record(br#"{"redtrace_es":1,"time":"2026-10-13T10:00:00Z","action":"exec","fields":{"process.pid":12}}"#).is_err());
}
