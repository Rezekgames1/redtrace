use super::*;
use crate::storage::Wal;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).unwrap();
        let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        Self(
            std::env::temp_dir()
                .join("opencode")
                .join(format!("redtrace-retention-{id}")),
        )
    }

    fn open(&self, cap: u64, segment: u64) -> SegmentStore {
        let mut store =
            SegmentStore::open_with_limits(self.0.clone(), cap, 2_000, segment, 8 * 1024 * 1024)
                .unwrap();
        store.clock = Some(10_000);
        store
    }

    fn catalog(&self) -> Vec<u8> {
        fs::read(self.0.join("catalog.json")).unwrap()
    }

    fn files(&self) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(self.0.join("segments"))
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    fs::read(entry.path()).unwrap(),
                )
            })
            .collect()
    }

    fn assert_no_staging(&self) {
        assert!(fs::read_dir(&self.0).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".segments-")
        }));
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn event(id: u64, message: &str) -> Event {
    Event::normalized(
        id,
        format!("2026-01-01T00:00:00.{id:09}Z"),
        "test.retention".into(),
        "low".into(),
        message.into(),
        BTreeMap::new(),
    )
}

fn save_manifest(store: &SegmentStore, manifest: &Manifest) {
    fs::write(&store.manifest_path, serde_json::to_vec(manifest).unwrap()).unwrap();
}

fn seed_legacy(store: &SegmentStore, events: &[Event], age: u64) -> SegmentMeta {
    let mut manifest = store.read_manifest().unwrap();
    let id = manifest.next_id;
    let stem = format!("{id:016}");
    let file = format!("{stem}.jsonl");
    let directory = store.root.join("segments");
    let path = directory.join(&file);
    let mut output = File::create(&path).unwrap();
    for event in events {
        serde_json::to_writer(&mut output, event).unwrap();
        output.write_all(b"\n").unwrap();
    }
    output.sync_all().unwrap();
    drop(output);
    let index = segment_index::write(&directory, &stem, events).unwrap();
    let meta = SegmentMeta {
        id,
        file,
        events: events.len(),
        bytes: fs::metadata(&path).unwrap().len(),
        checksum: checksum_file(&path).unwrap(),
        index: Some(index),
        created_unix: age,
        min_timestamp: events
            .iter()
            .map(|event| event.timestamp.as_str())
            .min()
            .unwrap_or_default()
            .into(),
        max_timestamp: events
            .iter()
            .map(|event| event.timestamp.as_str())
            .max()
            .unwrap_or_default()
            .into(),
    };
    manifest.next_id += 1;
    manifest.segments.push(meta.clone());
    save_manifest(store, &manifest);
    meta
}

#[test]
fn compaction_preserves_separate_age_cohorts_and_expiration() {
    let fixture = Fixture::new();
    let mut store = fixture.open(100_000, 16_000);
    seed_legacy(&store, &[event(1, "old cohort")], 9_000);
    seed_legacy(&store, &[event(2, "new cohort")], 9_900);
    assert!(store.compact_all().unwrap());
    assert_eq!(
        store
            .read_manifest()
            .unwrap()
            .segments
            .iter()
            .map(|meta| meta.created_unix)
            .collect::<Vec<_>>(),
        vec![9_000, 9_900]
    );
    store.clock = Some(11_001);
    assert!(store.enforce_retention().unwrap());
    let recovered = store.recover().unwrap();
    assert_eq!(recovered.events, vec![event(2, "new cohort")]);
    assert_eq!(
        store.read_manifest().unwrap().segments[0].created_unix,
        9_900
    );
}

#[test]
fn compaction_merges_only_same_age_without_refreshing_it() {
    let fixture = Fixture::new();
    let store = fixture.open(100_000, 16_000);
    seed_legacy(&store, &[event(1, "first")], 9_000);
    seed_legacy(&store, &[event(2, "second")], 9_000);
    assert!(store.compact_all().unwrap());
    let manifest = store.read_manifest().unwrap();
    assert_eq!(manifest.segments.len(), 1);
    assert_eq!(manifest.segments[0].created_unix, 9_000);
    assert_eq!(store.recover().unwrap().events.len(), 2);
}

#[test]
fn age_boundary_is_inclusive_and_uses_storage_age() {
    let fixture = Fixture::new();
    let store = fixture.open(100_000, 16_000);
    seed_legacy(&store, &[event(1, "expired")], 7_999);
    seed_legacy(&store, &[event(2, "boundary")], 8_000);
    assert!(store.enforce_retention().unwrap());
    assert_eq!(store.recover().unwrap().events, vec![event(2, "boundary")]);
    assert!(!store.enforce_retention().unwrap());
}

#[test]
fn sole_expired_segment_can_be_removed_completely() {
    let fixture = Fixture::new();
    let store = fixture.open(100_000, 16_000);
    seed_legacy(&store, &[event(1, "expired")], 7_999);
    assert!(store.enforce_retention().unwrap());
    assert_eq!(store.stats().unwrap(), (0, 0));
    assert!(fixture.files().is_empty());
}

#[test]
fn sole_legacy_segment_is_split_and_hard_capped() {
    let fixture = Fixture::new();
    let store = fixture.open(4_000, 2_000);
    let events: Vec<_> = (0..12)
        .map(|id| event(id, &format!("legacy-{id} {}", "x".repeat(120))))
        .collect();
    let original = seed_legacy(&store, &events, 9_000);
    assert!(original.storage_bytes() > store.max_bytes);
    assert!(store.enforce_retention().unwrap());
    let manifest = store.read_manifest().unwrap();
    assert!(!manifest.segments.is_empty());
    assert!(
        manifest
            .segments
            .iter()
            .all(|meta| meta.storage_bytes() <= 2_000 && meta.created_unix == 9_000)
    );
    assert!(store.stats().unwrap().1 <= 4_000);
    let recovered = store.recover().unwrap();
    assert!(recovered.events.len() < events.len());
    assert!(recovered.events.contains(events.last().unwrap()));
    assert_eq!(recovered.corrupted_segments, 0);
    assert_eq!(recovered.corrupted_indexes, 0);
    assert_eq!(
        fixture
            .files()
            .values()
            .map(|bytes| bytes.len() as u64)
            .sum::<u64>(),
        recovered.bytes
    );
}

#[test]
fn commit_and_compaction_bound_data_plus_all_sidecars() {
    let fixture = Fixture::new();
    let store = fixture.open(100_000, 4_000);
    let events: Vec<_> = (0..20)
        .map(|id| event(id, &format!("bounded-{id} {}", "a b c d ".repeat(20))))
        .collect();
    store.commit(&events).unwrap();
    assert!(store.stats().unwrap().0 > 1);
    assert!(
        store
            .read_manifest()
            .unwrap()
            .segments
            .iter()
            .all(|meta| meta.storage_bytes() <= 4_000)
    );
    store.compact_all().unwrap();
    assert!(
        store
            .read_manifest()
            .unwrap()
            .segments
            .iter()
            .all(|meta| meta.storage_bytes() <= 4_000)
    );
    assert_eq!(store.recover().unwrap().events, events);
}

#[test]
fn exact_cap_keeps_a_segment_and_one_byte_less_evicts_oldest() {
    let fixture = Fixture::new();
    let mut store = fixture.open(100_000, 16_000);
    let first = store.commit(&[event(1, "first")]).unwrap().unwrap();
    let second = store.commit(&[event(2, "second")]).unwrap().unwrap();
    store.max_bytes = first.storage_bytes() + second.storage_bytes();
    assert!(!store.enforce_retention().unwrap());
    store.max_bytes -= 1;
    assert!(store.enforce_retention().unwrap());
    assert_eq!(store.recover().unwrap().events, vec![event(2, "second")]);
}

#[test]
fn oversized_new_event_rejects_whole_batch_and_preserves_wal() {
    let fixture = Fixture::new();
    let store = fixture.open(4_000, 2_000);
    store.commit(&[event(1, "confirmed")]).unwrap();
    let catalog = fixture.catalog();
    let files = fixture.files();
    let wal = Wal::open(fixture.0.join("active.wal")).unwrap();
    let batch = [
        event(2, "small before oversized"),
        event(3, &"x".repeat(4_000)),
    ];
    wal.append(&batch).unwrap();
    let bytes = fs::read(wal.path()).unwrap();
    assert_eq!(
        store
            .commit(&wal.recover().unwrap().events)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(fixture.catalog(), catalog);
    assert_eq!(fixture.files(), files);
    assert_eq!(fs::read(wal.path()).unwrap(), bytes);
    assert_eq!(wal.recover().unwrap().events, batch);
    fixture.assert_no_staging();
}

#[test]
fn sole_oversized_legacy_event_is_preserved_on_refusal() {
    let fixture = Fixture::new();
    let store = fixture.open(4_000, 2_000);
    let oversized = event(1, &"x".repeat(4_000));
    seed_legacy(&store, std::slice::from_ref(&oversized), 9_000);
    let catalog = fixture.catalog();
    let files = fixture.files();
    assert_eq!(
        store.enforce_retention().unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(fixture.catalog(), catalog);
    assert_eq!(fixture.files(), files);
    assert_eq!(store.recover().unwrap().events, vec![oversized]);
}

#[test]
fn duplicate_wal_retry_does_not_refresh_age_or_rewrite_events() {
    let fixture = Fixture::new();
    let mut store = fixture.open(100_000, 16_000);
    let original = event(1, "already confirmed");
    seed_legacy(&store, std::slice::from_ref(&original), 9_000);
    store.commit(std::slice::from_ref(&original)).unwrap();
    assert_eq!(
        store.read_manifest().unwrap().segments[0].created_unix,
        9_000
    );
    assert_eq!(store.recover().unwrap().events, vec![original.clone()]);
    store.clock = Some(11_001);
    store.commit(&[original]).unwrap();
    assert_eq!(store.stats().unwrap(), (0, 0));
}

#[test]
fn prepublication_failures_preserve_catalog_segments_and_confirmed_wal() {
    for stage in [
        "segment_write",
        "segment_partial_write",
        "segment_sync",
        "index_write",
        "index_complete",
        "segment_install",
        "segment_partial_install",
        "manifest_write",
        "manifest_partial_write",
        "manifest_replace",
    ] {
        let fixture = Fixture::new();
        let store = fixture.open(100_000, 16_000);
        let first = event(1, "confirmed segment");
        store.commit(std::slice::from_ref(&first)).unwrap();
        let catalog = fixture.catalog();
        let files = fixture.files();
        let wal = Wal::open(fixture.0.join("active.wal")).unwrap();
        let second = event(2, "confirmed WAL");
        wal.append(std::slice::from_ref(&second)).unwrap();
        let bytes = fs::read(wal.path()).unwrap();
        *store.failure.lock().unwrap() = Some(stage);
        assert!(
            store.commit(&wal.recover().unwrap().events).is_err(),
            "{stage}"
        );
        assert_eq!(fixture.catalog(), catalog, "{stage}");
        assert_eq!(fixture.files(), files, "{stage}");
        assert_eq!(fs::read(wal.path()).unwrap(), bytes, "{stage}");
        assert_eq!(store.recover().unwrap().events, vec![first], "{stage}");
        assert_eq!(wal.recover().unwrap().events, vec![second], "{stage}");
        fixture.assert_no_staging();
    }
}

#[test]
fn compaction_failures_keep_all_originals_before_publication() {
    for stage in [
        "segment_partial_write",
        "index_write",
        "segment_partial_install",
        "manifest_partial_write",
        "manifest_replace",
    ] {
        let fixture = Fixture::new();
        let store = fixture.open(100_000, 16_000);
        let events = [event(1, "first"), event(2, "second")];
        seed_legacy(&store, &events[..1], 9_000);
        seed_legacy(&store, &events[1..], 9_000);
        let catalog = fixture.catalog();
        let files = fixture.files();
        *store.failure.lock().unwrap() = Some(stage);
        assert!(store.compact_all().is_err(), "{stage}");
        assert_eq!(fixture.catalog(), catalog, "{stage}");
        assert_eq!(fixture.files(), files, "{stage}");
        assert_eq!(store.recover().unwrap().events, events, "{stage}");
        fixture.assert_no_staging();
    }
}

#[test]
fn postpublication_failures_keep_new_catalog_recoverable_and_wal_owned() {
    for stage in ["manifest_sync", "cleanup"] {
        let fixture = Fixture::new();
        let store = fixture.open(100_000, 16_000);
        let first = event(1, "first");
        let second = event(2, "second");
        seed_legacy(&store, std::slice::from_ref(&first), 9_000);
        seed_legacy(&store, std::slice::from_ref(&second), 9_000);
        let files = fixture.files();
        let wal = Wal::open(fixture.0.join("active.wal")).unwrap();
        wal.append(&[first.clone(), second.clone()]).unwrap();
        let bytes = fs::read(wal.path()).unwrap();
        *store.failure.lock().unwrap() = Some(stage);
        assert!(store.compact_all().is_err());
        let current = fixture.files();
        assert!(
            files
                .iter()
                .all(|(name, bytes)| current.get(name) == Some(bytes))
        );
        assert!(current.len() > files.len());
        assert_eq!(
            store.recover().unwrap().events,
            vec![first.clone(), second.clone()]
        );
        assert_eq!(fs::read(wal.path()).unwrap(), bytes);
        assert_eq!(
            Wal::open(fixture.0.join("active.wal")).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        *store.failure.lock().unwrap() = None;
        drop(store);
        let reopened = fixture.open(100_000, 16_000);
        assert_eq!(reopened.recover().unwrap().events, vec![first, second]);
        fixture.assert_no_staging();
    }
}

#[test]
fn temporary_budget_refuses_compaction_before_deleting_originals() {
    let fixture = Fixture::new();
    let mut store = fixture.open(100_000, 16_000);
    seed_legacy(&store, &[event(1, "first")], 9_000);
    seed_legacy(&store, &[event(2, "second")], 9_000);
    let catalog = fixture.catalog();
    let files = fixture.files();
    store.max_temporary_bytes = MAX_MANIFEST_BYTES;
    assert_eq!(
        store.compact_all().unwrap_err().kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(fixture.catalog(), catalog);
    assert_eq!(fixture.files(), files);
    fixture.assert_no_staging();
}

#[test]
fn temporary_budget_counts_crash_staging_and_preserved_orphans() {
    let fixture = Fixture::new();
    let mut store = fixture.open(100_000, 16_000);
    store.commit(&[event(1, "confirmed")]).unwrap();
    let leftover = fixture.0.join(".segments-crash.tmp");
    fs::create_dir(&leftover).unwrap();
    fs::write(leftover.join("data.tmp"), vec![0_u8; 400]).unwrap();
    fs::write(
        fixture.0.join("segments").join("unknown.evidence"),
        vec![1_u8; 400],
    )
    .unwrap();
    let catalog = fixture.catalog();
    let files = fixture.files();
    store.max_temporary_bytes = 700;
    assert_eq!(
        store.commit(&[event(2, "next")]).unwrap_err().kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(fixture.catalog(), catalog);
    assert_eq!(fixture.files(), files);
    assert_eq!(
        fs::read(leftover.join("data.tmp")).unwrap(),
        vec![0_u8; 400]
    );
}

#[test]
fn orphan_id_is_not_overwritten_by_retry_after_crash() {
    let fixture = Fixture::new();
    let store = fixture.open(100_000, 16_000);
    let path = fixture.0.join("segments").join("0000000000000001.jsonl");
    fs::write(&path, b"preserved crash evidence").unwrap();
    let meta = store.commit(&[event(1, "new event")]).unwrap().unwrap();
    assert_eq!(meta.id, 2);
    assert_eq!(fs::read(path).unwrap(), b"preserved crash evidence");
    assert_eq!(store.recover().unwrap().events, vec![event(1, "new event")]);
}

#[test]
fn corrupt_expired_data_is_preserved_and_retention_fails_closed() {
    let fixture = Fixture::new();
    let store = fixture.open(100_000, 16_000);
    let meta = seed_legacy(&store, &[event(1, "expired evidence")], 7_999);
    fs::write(
        fixture.0.join("segments").join(meta.file),
        b"corrupt original bytes",
    )
    .unwrap();
    let catalog = fixture.catalog();
    let files = fixture.files();
    assert_eq!(
        store.enforce_retention().unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        store.compact_all().unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        store.commit(&[event(2, "fresh")]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(fixture.catalog(), catalog);
    assert_eq!(fixture.files(), files);
    assert_eq!(store.recover().unwrap().corrupted_segments, 1);
}

#[test]
fn checksum_valid_invalid_json_and_count_mismatch_are_preserved() {
    for invalid_json in [false, true] {
        let fixture = Fixture::new();
        let store = fixture.open(100_000, 16_000);
        let meta = seed_legacy(&store, &[event(1, "evidence")], 7_999);
        let mut manifest = store.read_manifest().unwrap();
        if invalid_json {
            let path = fixture.0.join("segments").join(meta.file);
            fs::write(&path, b"{invalid}\n").unwrap();
            manifest.segments[0].bytes = fs::metadata(&path).unwrap().len();
            manifest.segments[0].checksum = checksum_file(&path).unwrap();
        } else {
            manifest.segments[0].events = 2;
        }
        save_manifest(&store, &manifest);
        let catalog = fixture.catalog();
        let files = fixture.files();
        assert_eq!(
            store.enforce_retention().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(fixture.catalog(), catalog);
        assert_eq!(fixture.files(), files);
    }
}

#[test]
fn corrupt_index_bytes_are_preserved_on_age_eviction() {
    let fixture = Fixture::new();
    let store = fixture.open(100_000, 16_000);
    let meta = seed_legacy(&store, &[event(1, "index evidence")], 7_999);
    let index = meta.index.unwrap();
    fs::write(
        fixture.0.join("segments").join(index.postings.file),
        b"corrupt sidecar",
    )
    .unwrap();
    let catalog = fixture.catalog();
    let files = fixture.files();
    assert_eq!(
        store.enforce_retention().unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(fixture.catalog(), catalog);
    assert_eq!(fixture.files(), files);
    assert_eq!(store.recover().unwrap().corrupted_indexes, 1);
}

#[test]
fn catalog_ownership_survives_clones_and_serializes_commits() {
    let fixture = Fixture::new();
    let store = fixture.open(100_000, 16_000);
    assert_eq!(
        SegmentStore::open(fixture.0.clone()).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let clone = store.clone();
    let worker = std::thread::spawn(move || clone.commit(&[event(1, "thread one")]).unwrap());
    store.commit(&[event(2, "thread two")]).unwrap();
    worker.join().unwrap();
    let recovery = store.recover().unwrap();
    assert_eq!(recovery.events.len(), 2);
    assert_eq!(recovery.corrupted_segments, 0);
    drop(store);
    assert!(SegmentStore::open(fixture.0.clone()).is_ok());
}

#[test]
fn output_reservation_bounds_unicode_escaping_and_repeated_terms() {
    let fixture = Fixture::new();
    let store = fixture.open(100_000, 16_000);
    let mut first = event(1, "İ İ İ \"quoted\" \\path\n\t emoji 🦊");
    first
        .fields
        .insert("custom.İ".into(), "İ\u{0001}\\\"".into());
    let events = [first, event(2, "same same same")];
    let estimate = segment_output_bound(&events).unwrap();
    store.commit(&events).unwrap();
    assert!(store.stats().unwrap().1 <= estimate);
    assert_eq!(store.recover().unwrap().events, events);
}

#[test]
fn invalid_limits_and_identifier_exhaustion_fail_without_replacement() {
    let fixture = Fixture::new();
    assert_eq!(
        SegmentStore::open_with_limits(fixture.0.clone(), 0, 1, 1, 1)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    let store = fixture.open(100_000, 16_000);
    let mut manifest = store.read_manifest().unwrap();
    manifest.next_id = u64::MAX;
    save_manifest(&store, &manifest);
    let catalog = fixture.catalog();
    assert_eq!(
        store
            .commit(&[event(1, "cannot allocate")])
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(fixture.catalog(), catalog);
    assert!(fixture.files().is_empty());
}

#[test]
fn partial_cleanup_failure_leaves_published_data_recoverable() {
    let fixture = Fixture::new();
    let store = fixture.open(100_000, 16_000);
    let events = [event(1, "first"), event(2, "second")];
    let old = seed_legacy(&store, &events[..1], 9_000);
    seed_legacy(&store, &events[1..], 9_000);
    *store.failure.lock().unwrap() = Some("cleanup_partial");
    assert!(store.compact_all().is_err());
    assert!(!fixture.0.join("segments").join(old.file).exists());
    assert_eq!(store.recover().unwrap().events, events);
    *store.failure.lock().unwrap() = None;
    drop(store);
    let reopened = fixture.open(100_000, 16_000);
    assert_eq!(reopened.recover().unwrap().events, events);
}

#[test]
fn index_expansion_can_reject_an_event_whose_json_fits() {
    let fixture = Fixture::new();
    let store = fixture.open(4_000, 2_000);
    let large = event(1, &"x".repeat(1_000));
    assert!(serialized_bytes(&large).unwrap() < 2_000);
    let catalog = fixture.catalog();
    assert_eq!(
        store.commit(&[large]).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(fixture.catalog(), catalog);
    assert!(fixture.files().is_empty());
}

#[test]
fn successful_rotation_reset_and_reopen_preserve_confirmed_uids() {
    let fixture = Fixture::new();
    let store = fixture.open(100_000, 2_000);
    let wal = Wal::open(fixture.0.join("active.wal")).unwrap();
    let events: Vec<_> = (0..12)
        .map(|id| event(id, &format!("confirmed-{id} {}", "x".repeat(100))))
        .collect();
    wal.append(&events).unwrap();
    store
        .commit(&wal.recover_with_repair().unwrap().events)
        .unwrap();
    wal.reset().unwrap();
    assert!(wal.recover().unwrap().events.is_empty());
    drop(store);
    let reopened = fixture.open(100_000, 2_000);
    assert_eq!(reopened.recover().unwrap().events, events);
    assert!(reopened.stats().unwrap().1 <= 100_000);
}

#[test]
fn failed_age_eviction_does_not_delete_original_before_publication() {
    let fixture = Fixture::new();
    let store = fixture.open(100_000, 16_000);
    seed_legacy(&store, &[event(1, "expired")], 7_999);
    let catalog = fixture.catalog();
    let files = fixture.files();
    *store.failure.lock().unwrap() = Some("manifest_replace");
    assert!(store.enforce_retention().is_err());
    assert_eq!(fixture.catalog(), catalog);
    assert_eq!(fixture.files(), files);
    assert_eq!(store.recover().unwrap().events, vec![event(1, "expired")]);
}
