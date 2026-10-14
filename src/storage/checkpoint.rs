use crate::model::Event;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::RwLock,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::fs::File;

const CHECKPOINT_VERSION: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceCheckpoint {
    pub cursor: String,
    pub timestamp: String,
    pub event_uid: String,
    pub updated_unix: u64,
    #[serde(default)]
    pub sequence: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CheckpointFile {
    version: u16,
    sources: BTreeMap<String, SourceCheckpoint>,
}

impl Default for CheckpointFile {
    fn default() -> Self {
        Self {
            version: CHECKPOINT_VERSION,
            sources: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct CheckpointStore {
    path: PathBuf,
    state: RwLock<CheckpointFile>,
}

impl CheckpointStore {
    pub fn open_default() -> io::Result<Self> {
        Self::open(super::wal::data_directory().join("checkpoints.json"))
    }

    pub fn open(path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let state = if path.exists() {
            let data = fs::read(&path)?;
            let parsed: CheckpointFile = serde_json::from_slice(&data).map_err(io::Error::other)?;
            if parsed.version != CHECKPOINT_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported checkpoint version {}", parsed.version),
                ));
            }
            parsed
        } else {
            CheckpointFile::default()
        };
        let store = Self {
            path,
            state: RwLock::new(state),
        };
        if !store.path.exists() {
            store.persist(
                &store
                    .state
                    .read()
                    .unwrap_or_else(|error| error.into_inner()),
            )?;
        }
        Ok(store)
    }

    pub fn get(&self, source: &str) -> Option<SourceCheckpoint> {
        self.state
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .sources
            .get(source)
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.state
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .sources
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn newest_with_prefix(&self, prefix: &str) -> Option<SourceCheckpoint> {
        self.state
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .sources
            .iter()
            .filter(|(source, _)| source.starts_with(prefix))
            .map(|(_, checkpoint)| checkpoint)
            .max_by(|left, right| {
                left.timestamp
                    .cmp(&right.timestamp)
                    .then_with(|| left.sequence.cmp(&right.sequence))
            })
            .cloned()
    }

    pub fn update_events(&self, events: &[Event]) -> io::Result<usize> {
        let mut guard = self
            .state
            .write()
            .unwrap_or_else(|error| error.into_inner());
        let mut state = guard.clone();
        let mut sequence = state
            .sources
            .values()
            .map(|checkpoint| checkpoint.sequence)
            .max()
            .unwrap_or(0);
        let mut changed = 0;
        for event in events {
            let Some(cursor) = event.fields.get("collector.cursor") else {
                continue;
            };
            let replace = state.sources.get(&event.source).is_none_or(|current| {
                current.cursor != *cursor
                    && (event
                        .fields
                        .get("collector.cursor_kind")
                        .is_some_and(|kind| kind == "file")
                        || event.timestamp >= current.timestamp)
            });
            if replace {
                sequence = sequence
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("checkpoint sequence exhausted"))?;
                state.sources.insert(
                    event.source.clone(),
                    SourceCheckpoint {
                        cursor: cursor.clone(),
                        timestamp: event.timestamp.clone(),
                        event_uid: event.uid.clone(),
                        updated_unix: now_unix(),
                        sequence,
                    },
                );
                changed += 1;
            }
        }
        if changed > 0 {
            self.persist(&state)?;
            *guard = state;
        }
        Ok(changed)
    }

    fn persist(&self, state: &CheckpointFile) -> io::Result<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let temp = parent.join(format!(
            ".{}.tmp",
            self.path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or("checkpoints.json")
        ));
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        serde_json::to_writer_pretty(&mut file, state).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_all()?;
        fs::rename(temp, &self.path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn event(timestamp: &str, cursor: &str) -> Event {
        Event::normalized(
            1,
            timestamp.into(),
            "linux.journald".into(),
            "low".into(),
            "event".into(),
            BTreeMap::from([("collector.cursor".into(), cursor.into())]),
        )
    }

    #[test]
    fn persists_only_the_newest_durable_checkpoint() {
        let path =
            std::env::temp_dir().join(format!("redtrace-checkpoint-{}.json", std::process::id()));
        let _ = fs::remove_file(&path);
        let store = CheckpointStore::open(path.clone()).unwrap();
        store
            .update_events(&[
                event("2026-01-01T00:00:02Z", "new"),
                event("2026-01-01T00:00:01Z", "old"),
            ])
            .unwrap();
        let reopened = CheckpointStore::open(path.clone()).unwrap();
        assert_eq!(reopened.get("linux.journald").unwrap().cursor, "new");
        let _ = fs::remove_file(path);
    }
}
