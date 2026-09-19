use crate::model::Event;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

const WAL_VERSION: u16 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct WalRecord {
    version: u16,
    checksum: u64,
    event: Event,
}

#[derive(Debug, Default)]
pub struct Recovery {
    pub events: Vec<Event>,
    pub corrupted_records: usize,
}

#[derive(Clone, Debug)]
pub struct Wal {
    path: PathBuf,
}

impl Wal {
    pub fn open_default() -> io::Result<Self> {
        Self::open(data_directory().join("active.wal"))
    }

    pub fn open(path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { path })
    }

    pub fn append(&self, events: &[Event]) -> io::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        for event in events {
            let event_bytes = serde_json::to_vec(event).map_err(io::Error::other)?;
            let record = WalRecord {
                version: WAL_VERSION,
                checksum: checksum(&event_bytes),
                event: event.clone(),
            };
            serde_json::to_writer(&mut file, &record).map_err(io::Error::other)?;
            file.write_all(b"\n")?;
        }
        file.flush()?;
        file.sync_data()
    }

    pub fn recover(&self) -> io::Result<Recovery> {
        let file = File::open(&self.path)?;
        let mut recovery = Recovery::default();
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else {
                recovery.corrupted_records += 1;
                continue;
            };
            if line.trim().is_empty() {
                continue;
            }
            let Ok(record) = serde_json::from_str::<WalRecord>(&line) else {
                recovery.corrupted_records += 1;
                continue;
            };
            let Ok(bytes) = serde_json::to_vec(&record.event) else {
                recovery.corrupted_records += 1;
                continue;
            };
            if record.version != WAL_VERSION || checksum(&bytes) != record.checksum {
                recovery.corrupted_records += 1;
                continue;
            }
            recovery.events.push(record.event);
        }
        Ok(recovery)
    }

    pub fn size_bytes(&self) -> io::Result<u64> {
        Ok(fs::metadata(&self.path)?.len())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn checksum(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn data_directory() -> PathBuf {
    if let Some(path) = std::env::var_os("REDTRACE_DATA_DIR") {
        return PathBuf::from(path);
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join("Library/Application Support/REDTRACE");
    }
    #[cfg(target_os = "windows")]
    if let Some(path) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(path).join("REDTRACE");
    }
    if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(path).join("redtrace");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local/share/redtrace");
    }
    PathBuf::from(".redtrace-data")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn event(message: &str) -> Event {
        Event::normalized(
            1,
            "2026-01-01T00:00:00Z".into(),
            "test.source".into(),
            "low".into(),
            message.into(),
            BTreeMap::new(),
        )
    }

    #[test]
    fn recovers_valid_records_and_isolates_corruption() {
        let path = std::env::temp_dir().join(format!("redtrace-wal-{}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);
        let wal = Wal::open(path.clone()).unwrap();
        wal.append(&[event("first"), event("second")]).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"broken record\n")
            .unwrap();
        let recovery = wal.recover().unwrap();
        assert_eq!(recovery.events.len(), 2);
        assert_eq!(recovery.corrupted_records, 1);
        let _ = fs::remove_file(path);
    }
}
