use redtrace::storage::{SegmentStore, Wal};
use std::{collections::HashSet, io, path::PathBuf};

fn main() -> io::Result<()> {
    let path =
        PathBuf::from(std::env::args_os().nth(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "provide a copied WAL path")
        })?);
    if !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "copied WAL does not exist",
        ));
    }
    let root = path
        .parent()
        .ok_or_else(|| io::Error::other("copied WAL parent missing"))?;
    if root.join("catalog.json").exists() {
        return Err(io::Error::other(
            "use a separate WAL-only working copy, not an existing database",
        ));
    }
    let wal = Wal::open(path.clone())?;
    let before = wal.recover()?;
    let expected: HashSet<_> = before
        .events
        .iter()
        .map(|event| event.uid.clone())
        .collect();
    let recovery = wal.recover_with_repair()?;
    let clean = wal.recover()?;
    if clean.corrupted_records != 0 || clean.events != recovery.events {
        return Err(io::Error::other("clean WAL verification failed"));
    }
    let segments = SegmentStore::open(root.into())?;
    segments.commit(&clean.events)?;
    let committed = segments.recover()?;
    let actual: HashSet<_> = committed
        .events
        .iter()
        .map(|event| event.uid.clone())
        .collect();
    if committed.corrupted_segments != 0 || committed.corrupted_indexes != 0 || actual != expected {
        return Err(io::Error::other(
            "segment verification failed; WAL retained",
        ));
    }
    wal.reset()?;
    println!(
        "{}",
        serde_json::json!({
            "result": "PASS",
            "original_corrupted_records": before.corrupted_records,
            "salvaged_records": recovery.salvaged_records,
            "validated_records": clean.events.len(),
            "unique_uids_preserved": actual.len(),
            "wal_bytes_after_rotation": wal.size_bytes()?,
            "quarantine": wal.quarantine_stats()?,
        })
    );
    Ok(())
}
