use super::files::{self, invalid};
use crate::{
    ingest::{hex, sha256},
    model::Event,
    storage::{CheckpointStore, SourceCheckpoint},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const VERSION: u16 = 1;
const STATE_BYTES: u64 = 1024 * 1024;
const MAX_SOURCES: usize = 1024;
const MAX_QUARANTINE_FILES: usize = 10_000;
pub const DEFAULT_SPOOL_BYTES: u64 = 32 * 1024 * 1024;
pub const DEFAULT_RECORD_BYTES: u64 = 1024 * 1024;
pub const DEFAULT_QUARANTINE_BYTES: u64 = 64 * 1024 * 1024;
const CHUNK_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct SpoolLimits {
    pub max_events: usize,
    pub max_bytes: u64,
    pub max_record_bytes: u64,
    pub max_quarantine_bytes: u64,
}

impl Default for SpoolLimits {
    fn default() -> Self {
        Self {
            max_events: super::DEFAULT_OUTBOX_CAP,
            max_bytes: DEFAULT_SPOOL_BYTES,
            max_record_bytes: DEFAULT_RECORD_BYTES,
            max_quarantine_bytes: DEFAULT_QUARANTINE_BYTES,
        }
    }
}

impl SpoolLimits {
    pub fn validate(self) -> io::Result<Self> {
        if self.max_events == 0
            || self.max_events > 100_000
            || self.max_bytes == 0
            || self.max_bytes > 1024 * 1024 * 1024
            || self.max_record_bytes == 0
            || self.max_record_bytes > DEFAULT_RECORD_BYTES
            || self.max_quarantine_bytes == 0
            || self.max_quarantine_bytes > 1024 * 1024 * 1024
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid agent spool limits",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct State {
    next_sequence: u64,
    retired_through: u64,
    read_sources: BTreeMap<String, SourceCheckpoint>,
    server_ack_sources: BTreeMap<String, SourceCheckpoint>,
    sent_total: u64,
    rejected_total: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    version: u16,
    checksum: String,
    payload: T,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    sequence: u64,
    event: Event,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rejection {
    event: Event,
    reason: String,
}

#[derive(Clone)]
struct Entry {
    sequence: u64,
    uid: String,
    bytes: u64,
    checksum: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enqueued {
    Stored,
    Duplicate,
}

pub struct SpoolChunk {
    entries: Vec<Entry>,
    events: Vec<Event>,
}

impl SpoolChunk {
    pub fn events(&self) -> &[Event] {
        &self.events
    }
}

pub struct DiskSpool {
    directory: PathBuf,
    limits: SpoolLimits,
    state: State,
    entries: VecDeque<Entry>,
    seen: HashMap<String, String>,
    bytes: u64,
    failed: bool,
    _ownership: File,
}

impl DiskSpool {
    pub fn open(directory: PathBuf, limits: SpoolLimits) -> io::Result<Self> {
        let limits = limits.validate()?;
        files::private_directory(&directory)?;
        let ownership = files::ownership(&directory.join("agent.lock"))?;
        let pending = directory.join("pending");
        files::private_directory(&pending)?;
        files::private_directory(&directory.join("quarantine"))?;
        let mut spool = Self {
            directory,
            limits,
            state: State::default(),
            entries: VecDeque::new(),
            seen: HashMap::new(),
            bytes: 0,
            failed: false,
            _ownership: ownership,
        };
        let manifest = spool.manifest();
        if manifest.exists() {
            spool.state = match spool.read_checked(&manifest, STATE_BYTES) {
                Ok(state) => state,
                Err(error) => {
                    spool.archive_corrupt(&manifest)?;
                    return Err(error);
                }
            };
            if spool.state.next_sequence == 0
                || spool.state.retired_through >= spool.state.next_sequence
                || spool.state.read_sources.len() > MAX_SOURCES
                || spool.state.server_ack_sources.len() > MAX_SOURCES
            {
                spool.archive_corrupt(&manifest)?;
                return Err(invalid("invalid agent spool progress"));
            }
        } else {
            if fs::read_dir(&pending)?.next().is_some()
                || spool.directory.join("collector-checkpoints.json").exists()
            {
                return Err(invalid("spool manifest missing; pending files preserved"));
            }
            spool.state.next_sequence = 1;
            let legacy = spool.directory.join("checkpoints.json");
            if legacy.exists() {
                #[derive(Deserialize)]
                struct Legacy {
                    version: u16,
                    sources: BTreeMap<String, SourceCheckpoint>,
                }
                let value: Legacy =
                    serde_json::from_slice(&files::read_bounded(&legacy, STATE_BYTES)?)
                        .map_err(io::Error::other)?;
                if value.version != 1 || value.sources.len() > MAX_SOURCES {
                    return Err(invalid("invalid legacy agent checkpoints"));
                }
                spool.state.read_sources = value.sources.clone();
                spool.state.server_ack_sources = value.sources;
            }
            spool.remove_temporary(&manifest)?;
            spool.persist(&spool.state)?;
        }
        spool.remove_temporary(&manifest)?;
        spool.remove_temporary(&spool.directory.join("collector-checkpoints.json"))?;
        let mut entries = BTreeMap::new();
        for item in fs::read_dir(&pending)? {
            let path = item?.path();
            files::regular(&path)?;
            let sequence = parse_sequence(&path)?;
            if path.extension().is_some_and(|value| value == "tmp") {
                if sequence != spool.state.next_sequence {
                    return Err(invalid("unexpected agent spool temporary record"));
                }
                fs::remove_file(path)?;
                continue;
            }
            if sequence <= spool.state.retired_through {
                fs::remove_file(path)?;
                continue;
            }
            if entries.len() >= limits.max_events {
                return Err(invalid(
                    "existing spool exceeds event cap; records preserved",
                ));
            }
            let record: Record = match spool.read_checked(&path, limits.max_record_bytes) {
                Ok(record) => record,
                Err(error) => {
                    spool.archive_corrupt(&path)?;
                    return Err(error);
                }
            };
            if let Err(error) = validate_event(&record.event) {
                spool.archive_corrupt(&path)?;
                return Err(error);
            }
            if record.sequence != sequence || sequence > spool.state.next_sequence {
                spool.archive_corrupt(&path)?;
                return Err(invalid("invalid agent spool sequence"));
            }
            let bytes = fs::metadata(&path)?.len();
            spool.bytes = spool
                .bytes
                .checked_add(bytes)
                .ok_or_else(|| invalid("spool byte overflow"))?;
            if spool.bytes > limits.max_bytes {
                return Err(invalid(
                    "existing spool exceeds byte cap; records preserved",
                ));
            }
            let checksum = event_checksum(&record.event, limits.max_record_bytes)?;
            if spool
                .seen
                .insert(record.event.uid.clone(), checksum.clone())
                .is_some()
            {
                spool.archive_corrupt(&path)?;
                return Err(invalid("duplicate identity in agent spool"));
            }
            if sequence == spool.state.next_sequence {
                update_sources(&mut spool.state.read_sources, &record.event, sequence)?;
            }
            entries.insert(
                sequence,
                Entry {
                    sequence,
                    uid: record.event.uid,
                    bytes,
                    checksum,
                },
            );
        }
        files::sync_directory(&pending)?;
        let mut expected = spool.state.retired_through + 1;
        for sequence in entries.keys() {
            if *sequence != expected {
                spool.archive_corrupt(&manifest)?;
                return Err(invalid("agent spool has a missing pending record"));
            }
            expected = expected
                .checked_add(1)
                .ok_or_else(|| invalid("spool sequence exhausted"))?;
        }
        if expected != spool.state.next_sequence
            && Some(expected) != spool.state.next_sequence.checked_add(1)
        {
            spool.archive_corrupt(&manifest)?;
            return Err(invalid("agent spool has a missing pending tail"));
        }
        if expected > spool.state.next_sequence {
            spool.state.next_sequence = expected;
            spool.persist(&spool.state)?;
        }
        spool.entries = entries.into_values().collect();
        Ok(spool)
    }

    pub fn push(&mut self, event: Event) -> io::Result<Enqueued> {
        self.ensure_available()?;
        validate_event(&event)?;
        let checksum = event_checksum(&event, self.limits.max_record_bytes)?;
        if let Some(existing) = self.seen.get(&event.uid) {
            return if existing == &checksum {
                Ok(Enqueued::Duplicate)
            } else {
                Err(invalid("agent event identity collision"))
            };
        }
        if self
            .state
            .read_sources
            .get(&event.source)
            .is_some_and(|checkpoint| {
                checkpoint.event_uid == event.uid
                    && event.fields.get("collector.cursor") == Some(&checkpoint.cursor)
            })
        {
            return Ok(Enqueued::Duplicate);
        }
        if self.entries.len() >= self.limits.max_events {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "agent spool event cap reached; cursor retained",
            ));
        }
        let sequence = self.state.next_sequence;
        let record = Record { sequence, event };
        let encoded = encode(&record, self.limits.max_record_bytes)?;
        if self.bytes.saturating_add(encoded.len() as u64) > self.limits.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "agent spool byte cap reached; cursor retained",
            ));
        }
        let mut state = self.state.clone();
        state.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("spool sequence exhausted"))?;
        update_sources(&mut state.read_sources, &record.event, sequence)?;
        let state_bytes = encode(&state, STATE_BYTES)?;
        if let Err(error) = files::atomic_write(&self.record_path(sequence), &encoded)
            .and_then(|_| files::atomic_write(&self.manifest(), &state_bytes))
        {
            self.failed = true;
            return Err(error);
        }
        let entry = Entry {
            sequence,
            uid: record.event.uid,
            bytes: encoded.len() as u64,
            checksum,
        };
        self.bytes += entry.bytes;
        self.seen.insert(entry.uid.clone(), entry.checksum.clone());
        self.entries.push_back(entry);
        self.state = state;
        Ok(Enqueued::Stored)
    }

    pub fn peek_chunk(&mut self, count: usize) -> io::Result<SpoolChunk> {
        self.ensure_available()?;
        let mut chunk = SpoolChunk {
            entries: Vec::new(),
            events: Vec::new(),
        };
        let mut bytes = 0u64;
        for entry in self.entries.iter().take(count.clamp(1, 1000)) {
            if bytes.saturating_add(entry.bytes) > CHUNK_BYTES && !chunk.entries.is_empty() {
                break;
            }
            let path = self.record_path(entry.sequence);
            let record: Record = match self.read_checked(&path, self.limits.max_record_bytes) {
                Ok(record) => record,
                Err(error) => {
                    self.failed = true;
                    if path.exists() {
                        self.archive_corrupt(&path)?;
                    }
                    return Err(error);
                }
            };
            if record.sequence != entry.sequence
                || record.event.uid != entry.uid
                || event_checksum(&record.event, self.limits.max_record_bytes)? != entry.checksum
            {
                self.failed = true;
                self.archive_corrupt(&path)?;
                return Err(invalid("agent spool record changed"));
            }
            bytes += entry.bytes;
            chunk.entries.push(entry.clone());
            chunk.events.push(record.event);
        }
        Ok(chunk)
    }

    pub fn acknowledge(
        &mut self,
        chunk: &SpoolChunk,
        accepted: usize,
        duplicates: usize,
    ) -> io::Result<()> {
        if accepted.checked_add(duplicates) != Some(chunk.events.len()) {
            return Err(invalid("invalid batch acknowledgement"));
        }
        self.retire(chunk, Some(accepted as u64))
    }

    pub fn reject(&mut self, chunk: &SpoolChunk, reason: &str) -> io::Result<()> {
        self.check_chunk(chunk)?;
        if chunk.events.len() != 1 {
            return Err(invalid("only single rejected events may be quarantined"));
        }
        let rejection = Rejection {
            event: chunk.events[0].clone(),
            reason: reason.chars().take(4096).collect(),
        };
        let path = self
            .directory
            .join("quarantine")
            .join(format!("{}.json", rejection.event.uid));
        if path.exists() {
            let previous: Rejection =
                self.read_checked(&path, self.limits.max_record_bytes + 8192)?;
            if previous.event != rejection.event {
                return Err(invalid(
                    "quarantine identity collision; pending record retained",
                ));
            }
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)?
                .sync_all()?;
            files::sync_directory(&self.directory.join("quarantine"))?;
        } else {
            let encoded = encode(&rejection, self.limits.max_record_bytes + 8192)?;
            self.reserve_quarantine(encoded.len() as u64)?;
            self.remove_temporary(&path)?;
            files::atomic_write(&path, &encoded)?;
        }
        self.retire(chunk, None)
    }

    fn retire(&mut self, chunk: &SpoolChunk, accepted: Option<u64>) -> io::Result<()> {
        self.check_chunk(chunk)?;
        let mut state = self.state.clone();
        state.retired_through = chunk
            .entries
            .last()
            .ok_or_else(|| invalid("empty spool ACK"))?
            .sequence;
        if let Some(accepted) = accepted {
            for (event, entry) in chunk.events.iter().zip(&chunk.entries) {
                update_sources(&mut state.server_ack_sources, event, entry.sequence)?;
            }
            state.sent_total = state.sent_total.saturating_add(accepted);
        } else {
            state.rejected_total = state.rejected_total.saturating_add(1);
        }
        if let Err(error) = self.persist(&state) {
            self.failed = true;
            return Err(error);
        }
        self.state = state;
        for entry in &chunk.entries {
            if let Err(error) = fs::remove_file(self.record_path(entry.sequence)) {
                self.failed = true;
                return Err(error);
            }
        }
        if let Err(error) = files::sync_directory(&self.directory.join("pending")) {
            self.failed = true;
            return Err(error);
        }
        for entry in &chunk.entries {
            self.entries.pop_front();
            self.seen.remove(&entry.uid);
            self.bytes -= entry.bytes;
        }
        Ok(())
    }

    fn check_chunk(&self, chunk: &SpoolChunk) -> io::Result<()> {
        self.ensure_available()?;
        if chunk.entries.is_empty()
            || chunk.entries.len() != chunk.events.len()
            || chunk.entries.len() > self.entries.len()
            || !chunk
                .entries
                .iter()
                .zip(&self.entries)
                .all(|(left, right)| {
                    left.sequence == right.sequence && left.checksum == right.checksum
                })
        {
            return Err(invalid("stale or nonprefix spool acknowledgement"));
        }
        Ok(())
    }

    pub fn collector_checkpoints(&self) -> io::Result<CheckpointStore> {
        #[derive(Serialize)]
        struct Projection<'a> {
            version: u16,
            sources: &'a BTreeMap<String, SourceCheckpoint>,
        }
        self.ensure_available()?;
        let path = self.directory.join("collector-checkpoints.json");
        let bytes = bounded_json(
            &Projection {
                version: 1,
                sources: &self.state.read_sources,
            },
            STATE_BYTES,
        )?;
        self.remove_temporary(&path)?;
        files::atomic_write(&path, &bytes)?;
        CheckpointStore::open(path)
    }

    pub fn read_checkpoint(&self, source: &str) -> Option<SourceCheckpoint> {
        self.state.read_sources.get(source).cloned()
    }

    pub fn server_ack_checkpoint(&self, source: &str) -> Option<SourceCheckpoint> {
        self.state.server_ack_sources.get(source).cloned()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn size_bytes(&self) -> u64 {
        self.bytes
    }

    pub fn telemetry(&self) -> io::Result<crate::fleet::Report> {
        let oldest = if let Some(entry) = self.entries.front() {
            let path = self.record_path(entry.sequence);
            let record: Record = self.read_checked(&path, self.limits.max_record_bytes)?;
            Some(record.event.timestamp)
        } else {
            None
        };
        let mut count = 0;
        let mut bytes = 0;
        for item in fs::read_dir(self.directory.join("quarantine"))?.take(MAX_QUARANTINE_FILES) {
            let meta = item?.metadata()?;
            if meta.is_file() {
                count += 1;
                bytes += meta.len();
            }
        }
        Ok(crate::fleet::Report {
            pending_events: self.len() as u64,
            spool_bytes: self.bytes,
            spool_limit_bytes: self.limits.max_bytes,
            oldest_pending_at: oldest,
            quarantine_events: count,
            quarantine_bytes: bytes,
            ..crate::fleet::Report::default()
        })
    }

    pub fn reconfigure_limits(&mut self, limits: SpoolLimits) -> io::Result<()> {
        let limits = limits.validate()?;
        if self.len() > limits.max_events || self.bytes > limits.max_bytes {
            return Err(io::Error::other(
                "new spool limits are smaller than the current backlog; drain pending records first",
            ));
        }
        self.limits = limits;
        Ok(())
    }
    pub fn sent_total(&self) -> u64 {
        self.state.sent_total
    }
    pub fn rejected_total(&self) -> u64 {
        self.state.rejected_total
    }
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    fn ensure_available(&self) -> io::Result<()> {
        if self.failed {
            Err(io::Error::other(
                "agent spool requires recovery; stop and reopen this instance",
            ))
        } else {
            Ok(())
        }
    }

    fn record_path(&self, sequence: u64) -> PathBuf {
        self.directory
            .join("pending")
            .join(format!("{sequence:020}.json"))
    }

    fn manifest(&self) -> PathBuf {
        self.directory.join("spool.json")
    }

    fn persist(&self, state: &State) -> io::Result<()> {
        files::atomic_write(&self.manifest(), &encode(state, STATE_BYTES)?)
    }

    fn read_checked<T: Serialize + DeserializeOwned>(
        &self,
        path: &Path,
        limit: u64,
    ) -> io::Result<T> {
        let bytes = files::read_bounded(path, limit)?;
        let envelope: Envelope<T> =
            serde_json::from_slice(&bytes).map_err(|_| invalid("invalid agent spool JSON"))?;
        if envelope.version != VERSION
            || envelope.checksum != hex(&sha256(&bounded_json(&envelope.payload, limit)?))
        {
            return Err(invalid("agent spool checksum or version mismatch"));
        }
        Ok(envelope.payload)
    }

    fn remove_temporary(&self, path: &Path) -> io::Result<()> {
        let path = files::temporary(path);
        if path.exists() {
            files::regular(&path)?;
            fs::remove_file(&path)?;
            files::sync_directory(
                path.parent()
                    .ok_or_else(|| invalid("temporary has no parent"))?,
            )?;
        }
        Ok(())
    }

    fn reserve_quarantine(&self, extra: u64) -> io::Result<()> {
        let mut bytes = extra;
        for (count, entry) in fs::read_dir(self.directory.join("quarantine"))?.enumerate() {
            if count >= MAX_QUARANTINE_FILES {
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "agent quarantine file cap reached; pending records preserved",
                ));
            }
            let path = entry?.path();
            files::regular(&path)?;
            bytes = bytes.saturating_add(fs::metadata(path)?.len());
            if bytes > self.limits.max_quarantine_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "agent quarantine cap reached; pending records preserved",
                ));
            }
        }
        if bytes > self.limits.max_quarantine_bytes {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "agent quarantine cap reached; pending records preserved",
            ));
        }
        Ok(())
    }

    fn archive_corrupt(&self, path: &Path) -> io::Result<()> {
        files::regular(path)?;
        let size = fs::metadata(path)?.len();
        self.reserve_quarantine(size)?;
        let name = path
            .file_name()
            .ok_or_else(|| invalid("corrupt file has no name"))?;
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
        let target = self.directory.join("quarantine").join(format!(
            "corrupt-{}-{}.raw",
            hex(&random),
            name.to_string_lossy()
        ));
        let temporary = files::temporary(&target);
        let mut output = files::new_file(&temporary)?;
        let copied = io::copy(&mut File::open(path)?.take(size + 1), &mut output)?;
        if copied != size {
            return Err(invalid("corrupt agent file changed during quarantine"));
        }
        output.sync_all()?;
        drop(output);
        files::replace(&temporary, &target)?;
        files::sync_directory(&self.directory.join("quarantine"))
    }
}

fn parse_sequence(path: &Path) -> io::Result<u64> {
    let name = path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| invalid("invalid spool filename"))?;
    if name.len() != 20
        || !name.bytes().all(|byte| byte.is_ascii_digit())
        || !path
            .extension()
            .is_some_and(|value| value == "json" || value == "tmp")
    {
        return Err(invalid("unexpected file in pending spool"));
    }
    name.parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| invalid("invalid spool sequence"))
}

fn validate_event(event: &Event) -> io::Result<()> {
    if event.schema_version != 1
        || event.uid.len() != 16
        || !event.uid.bytes().all(|byte| byte.is_ascii_hexdigit())
        || event.source.is_empty()
        || event.source.len() > 128
        || event.timestamp.len() > 128
        || event
            .fields
            .get("collector.cursor")
            .is_some_and(|cursor| cursor.len() > 64 * 1024)
    {
        return Err(invalid("invalid agent event identity or checkpoint"));
    }
    Ok(())
}

fn update_sources(
    sources: &mut BTreeMap<String, SourceCheckpoint>,
    event: &Event,
    sequence: u64,
) -> io::Result<()> {
    let Some(cursor) = event.fields.get("collector.cursor") else {
        return Ok(());
    };
    if sources.len() >= MAX_SOURCES && !sources.contains_key(&event.source) {
        return Err(invalid("agent source checkpoint cap reached"));
    }
    sources.insert(
        event.source.clone(),
        SourceCheckpoint {
            cursor: cursor.clone(),
            timestamp: event.timestamp.clone(),
            event_uid: event.uid.clone(),
            updated_unix: 0,
            sequence,
        },
    );
    Ok(())
}

fn event_checksum(event: &Event, limit: u64) -> io::Result<String> {
    #[derive(Serialize)]
    struct Identity<'a> {
        uid: &'a str,
        timestamp: &'a str,
        source: &'a str,
        message: &'a str,
        record_id: Option<&'a String>,
    }
    Ok(hex(&sha256(&bounded_json(
        &Identity {
            uid: &event.uid,
            timestamp: &event.timestamp,
            source: &event.source,
            message: &event.message,
            record_id: event.fields.get("event.record_id"),
        },
        limit,
    )?)))
}

fn encode<T: Serialize>(payload: &T, limit: u64) -> io::Result<Vec<u8>> {
    let bytes = bounded_json(payload, limit)?;
    bounded_json(
        &Envelope {
            version: VERSION,
            checksum: hex(&sha256(&bytes)),
            payload,
        },
        limit,
    )
}

fn bounded_json<T: Serialize>(value: &T, limit: u64) -> io::Result<Vec<u8>> {
    struct Bounded {
        bytes: Vec<u8>,
        limit: u64,
    }
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if (self.bytes.len() as u64).saturating_add(bytes.len() as u64) > self.limit {
                return Err(invalid("agent spool record or progress exceeds size limit"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut output, value).map_err(io::Error::other)?;
    Ok(output.bytes)
}
