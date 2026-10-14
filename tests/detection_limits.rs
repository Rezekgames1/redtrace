use redtrace::{detection::DetectionEngine, model::Event};
use std::collections::BTreeMap;

fn failure(agent: &str, sequence: usize, key: String) -> Event {
    let mut event = Event::normalized(
        sequence as u64,
        "2099-01-01T00:00:00Z".into(),
        "linux.sshd".into(),
        "medium".into(),
        format!("failed {sequence}"),
        BTreeMap::from([
            ("event.id".into(), "4625".into()),
            ("agent.id".into(), agent.into()),
            ("source.ip".into(), key),
        ]),
    );
    event.identify(&sequence.to_string());
    event
}

fn command(agent: &str, timestamp: &str, sequence: usize) -> Event {
    Event::normalized(
        sequence as u64,
        timestamp.into(),
        "windows.sysmon".into(),
        "high".into(),
        format!("command {sequence}"),
        BTreeMap::from([
            ("agent.id".into(), agent.into()),
            ("process.name".into(), "powershell.exe".into()),
            (
                "process.command_line".into(),
                "powershell.exe -EncodedCommand synthetic".into(),
            ),
        ]),
    )
}

#[test]
fn sequential_high_cardinality_input_cannot_grow_detector_state_without_bound() {
    let mut engine = DetectionEngine::default();
    for sequence in 0..3000 {
        engine.evaluate_at(
            &failure(
                "1111111111111111",
                sequence,
                format!("{sequence}{}", "x".repeat(65500)),
            ),
            1,
        );
    }
    let health = engine.health();
    assert!(health.failure_keys <= health.max_scope_keys);
    assert!(health.state_bytes <= health.max_scope_bytes);
    assert!(health.refused_total > 0);
    for scope in 2..14 {
        for sequence in 0..300 {
            engine.evaluate_at(
                &failure(
                    &format!("{scope:016x}"),
                    sequence,
                    format!("unique-{sequence}"),
                ),
                1,
            );
        }
    }
    let health = engine.health();
    assert!(health.failure_keys + health.suppression_keys <= health.max_state_keys);
    assert!(health.state_bytes <= health.max_state_bytes);
    engine.evaluate_at(
        &command("2222222222222222", "2026-10-13T00:00:00Z", 1),
        1000,
    );
    assert_eq!(engine.health().failure_keys, 0);
}

#[test]
fn future_sender_timestamp_cannot_suppress_another_agent_or_extend_receiver_window() {
    let mut engine = DetectionEngine::default();
    assert_eq!(
        engine
            .evaluate_at(&command("1111111111111111", "2099-01-01T00:00:00Z", 1), 10)
            .len(),
        1
    );
    assert_eq!(
        engine
            .evaluate_at(&command("2222222222222222", "2026-10-13T00:00:00Z", 2), 11)
            .len(),
        1
    );
    assert!(
        engine
            .evaluate_at(&command("1111111111111111", "2026-10-13T00:00:00Z", 3), 12)
            .is_empty()
    );
    assert_eq!(
        engine
            .evaluate_at(&command("1111111111111111", "2026-10-13T00:00:00Z", 4), 611)
            .len(),
        1
    );
}

#[test]
fn authentication_windows_are_agent_scoped_and_ignore_duplicate_evidence() {
    let mut engine = DetectionEngine::default();
    let first = failure("1111111111111111", 1, "10.0.0.9".into());
    for _ in 0..10 {
        assert!(engine.evaluate_at(&first, 1).is_empty());
    }
    for sequence in 2..5 {
        assert!(
            engine
                .evaluate_at(&failure("1111111111111111", sequence, "10.0.0.9".into()), 2)
                .is_empty()
        );
    }
    assert!(
        engine
            .evaluate_at(&failure("2222222222222222", 5, "10.0.0.9".into()), 3)
            .is_empty()
    );
    let alerts = engine.evaluate_at(&failure("1111111111111111", 5, "10.0.0.9".into()), 4);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].evidence.len(), 5);
}
