use crate::model::Event;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const WAL_VERSION: u16 = 1;
const MAX_QUARANTINE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 64 * 1024;
const RECORD_PREFIX: &[u8] = b"{\"version\":";

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
    pub quarantined_records: usize,
    pub salvaged_records: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct QuarantineStats {
    pub archives: usize,
    pub bytes: u64,
    pub corrupted_records: usize,
    pub salvageable_records: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct InvalidRange {
    offset: u64,
    bytes: usize,
    reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct QuarantineReport {
    version: u16,
    original_bytes: u64,
    original_checksum: u64,
    valid_records: usize,
    corrupted_records: usize,
    salvageable_records: usize,
    invalid_samples: Vec<InvalidRange>,
}

struct Scan {
    recovery: Recovery,
    bytes: u64,
    checksum: u64,
    invalid_samples: Vec<InvalidRange>,
}

struct TemporaryFile(PathBuf);

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[derive(Clone, Debug)]
pub struct Wal {
    path: PathBuf,
    _ownership: Arc<File>,
    write_lock: Arc<Mutex<()>>,
}

impl Wal {
    pub fn open_default() -> io::Result<Self> {
        Self::open(data_directory().join("active.wal"))
    }

    pub fn open(path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut ownership_options = OpenOptions::new();
        ownership_options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            ownership_options.mode(0o600);
        }
        let ownership = ownership_options.open(path.with_extension("lock"))?;
        ownership.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => {
                io::Error::new(io::ErrorKind::WouldBlock, "another collector owns this WAL")
            }
            fs::TryLockError::Error(error) => error,
        })?;
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self {
            path,
            _ownership: Arc::new(ownership),
            write_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn append(&self, events: &[Event]) -> io::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let _guard = self.lock_writer()?;
        let mut options = OpenOptions::new();
        options.read(true).create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.path)?;
        if file.metadata()?.len() > 0 {
            file.seek(SeekFrom::End(-1))?;
            let mut last = [0_u8];
            file.read_exact(&mut last)?;
            if last[0] != b'\n' {
                file.write_all(b"\n")?;
            }
        }
        for event in events {
            write_record(&mut file, event)?;
        }
        file.flush()?;
        file.sync_data()
    }

    pub fn recover(&self) -> io::Result<Recovery> {
        let _guard = self.lock_writer()?;
        Ok(scan(&self.path)?.recovery)
    }

    pub fn recover_with_repair(&self) -> io::Result<Recovery> {
        self.recover_with_repair_limit(MAX_QUARANTINE_BYTES)
    }

    fn recover_with_repair_limit(&self, limit: u64) -> io::Result<Recovery> {
        let _guard = self.lock_writer()?;
        let mut scanned = scan(&self.path)?;
        if scanned.recovery.corrupted_records == 0 {
            return Ok(scanned.recovery);
        }
        let directory = self.quarantine_directory();
        private_directory(&directory)?;
        let stats = self.quarantine_stats()?;
        if scanned
            .bytes
            .saturating_add(stats.bytes)
            .saturating_add(MAX_REPORT_BYTES)
            > limit
        {
            return Err(io::Error::other(
                "WAL quarantine budget exhausted; original WAL preserved",
            ));
        }
        let id = random_id()?;
        let archived = directory.join(format!("{id}.wal"));
        let mut backup = private_new_file(&archived)?;
        io::copy(&mut File::open(&self.path)?, &mut backup)?;
        backup.sync_all()?;
        drop(backup);
        if fingerprint(&archived)? != (scanned.bytes, scanned.checksum) {
            return Err(io::Error::other(
                "WAL changed while archiving; original WAL preserved",
            ));
        }
        let report = QuarantineReport {
            version: WAL_VERSION,
            original_bytes: scanned.bytes,
            original_checksum: scanned.checksum,
            valid_records: scanned.recovery.events.len(),
            corrupted_records: scanned.recovery.corrupted_records,
            salvageable_records: scanned.recovery.salvaged_records,
            invalid_samples: scanned.invalid_samples,
        };
        let report_path = directory.join(format!("{id}.report.tmp"));
        let mut report_file = private_new_file(&report_path)?;
        let _report_cleanup = TemporaryFile(report_path.clone());
        serde_json::to_writer(&mut report_file, &report).map_err(io::Error::other)?;
        report_file.sync_all()?;
        drop(report_file);
        fs::rename(&report_path, directory.join(format!("{id}.json")))?;
        sync_directory(&directory)?;

        let temporary = self.parent().join(format!(".wal-recovery-{id}.tmp"));
        let mut clean = private_new_file(&temporary)?;
        let _cleanup = TemporaryFile(temporary.clone());
        for event in &scanned.recovery.events {
            write_record(&mut clean, event)?;
        }
        clean.sync_all()?;
        drop(clean);
        if fingerprint(&self.path)? != (scanned.bytes, scanned.checksum) {
            return Err(io::Error::other(
                "WAL changed during recovery; original WAL preserved",
            ));
        }
        fs::rename(&temporary, &self.path)?;
        sync_directory(self.parent())?;
        scanned.recovery.quarantined_records = scanned.recovery.corrupted_records;
        scanned.recovery.corrupted_records = 0;
        Ok(scanned.recovery)
    }

    pub fn quarantine_stats(&self) -> io::Result<QuarantineStats> {
        let directory = self.quarantine_directory();
        let mut stats = QuarantineStats::default();
        if !directory.exists() {
            return Ok(stats);
        }
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err(io::Error::other("unexpected entry in WAL quarantine"));
            }
            let metadata = entry.metadata()?;
            stats.bytes = stats.bytes.saturating_add(metadata.len());
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                if metadata.len() > MAX_REPORT_BYTES {
                    return Err(io::Error::other("WAL quarantine report exceeds limit"));
                }
                let report: QuarantineReport =
                    serde_json::from_reader(File::open(entry.path())?).map_err(io::Error::other)?;
                if report.version != WAL_VERSION {
                    return Err(io::Error::other(
                        "unsupported WAL quarantine report version",
                    ));
                }
                stats.archives = stats.archives.saturating_add(1);
                stats.corrupted_records = stats
                    .corrupted_records
                    .saturating_add(report.corrupted_records);
                stats.salvageable_records = stats
                    .salvageable_records
                    .saturating_add(report.salvageable_records);
            }
        }
        Ok(stats)
    }

    pub fn size_bytes(&self) -> io::Result<u64> {
        Ok(fs::metadata(&self.path)?.len())
    }

    pub fn reset(&self) -> io::Result<()> {
        let _guard = self.lock_writer()?;
        let parent = self.parent();
        let temp_path = parent.join(format!(".wal-reset-{}.tmp", random_id()?));
        let file = private_new_file(&temp_path)?;
        let _cleanup = TemporaryFile(temp_path.clone());
        file.sync_all()?;
        drop(file);
        fs::rename(temp_path, &self.path)?;
        sync_directory(parent)?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn parent(&self) -> &Path {
        self.path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }

    fn quarantine_directory(&self) -> PathBuf {
        self.parent().join("wal-quarantine")
    }

    fn lock_writer(&self) -> io::Result<std::sync::MutexGuard<'_, ()>> {
        self.write_lock
            .lock()
            .map_err(|_| io::Error::other("WAL writer lock poisoned"))
    }
}

fn write_record(file: &mut File, event: &Event) -> io::Result<()> {
    let event_bytes = serde_json::to_vec(event).map_err(io::Error::other)?;
    let record = WalRecord {
        version: WAL_VERSION,
        checksum: checksum(&event_bytes),
        event: event.clone(),
    };
    let mut encoded = serde_json::to_vec(&record).map_err(io::Error::other)?;
    encoded.push(b'\n');
    file.write_all(&encoded)
}

fn validate_record(record: WalRecord) -> Result<Event, &'static str> {
    if record.version != WAL_VERSION {
        return Err("unsupported_version");
    }
    let bytes = serde_json::to_vec(&record.event).map_err(|_| "invalid_event")?;
    if checksum(&bytes) != record.checksum {
        return Err("checksum_mismatch");
    }
    Ok(record.event)
}

fn scan(path: &Path) -> io::Result<Scan> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut scanned = Scan {
        recovery: Recovery::default(),
        bytes: 0,
        checksum: 0xcbf29ce484222325,
        invalid_samples: Vec::new(),
    };
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        let offset = scanned.bytes;
        scanned.bytes += line.len() as u64;
        for byte in &line {
            scanned.checksum = (scanned.checksum ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let parsed = serde_json::from_slice::<WalRecord>(&line);
        let reason = match parsed {
            Ok(record) => match validate_record(record) {
                Ok(event) => {
                    scanned.recovery.events.push(event);
                    continue;
                }
                Err(reason) => reason,
            },
            Err(_) => "invalid_json",
        };
        scanned.recovery.corrupted_records += 1;
        if scanned.invalid_samples.len() < 64 {
            scanned.invalid_samples.push(InvalidRange {
                offset,
                bytes: line.len(),
                reason: reason.into(),
            });
        }
        if reason == "invalid_json" {
            let mut position = 0;
            while position + RECORD_PREFIX.len() <= line.len() {
                let Some(relative) = line[position..]
                    .windows(RECORD_PREFIX.len())
                    .position(|window| window == RECORD_PREFIX)
                else {
                    break;
                };
                position += relative;
                let mut stream = serde_json::Deserializer::from_slice(&line[position..])
                    .into_iter::<WalRecord>();
                if let Some(Ok(record)) = stream.next()
                    && let Ok(event) = validate_record(record)
                {
                    scanned.recovery.events.push(event);
                    scanned.recovery.salvaged_records += 1;
                    position += stream.byte_offset();
                } else {
                    position += RECORD_PREFIX.len();
                }
            }
        }
    }
    Ok(scanned)
}

fn private_new_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn private_directory(path: &Path) -> io::Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.is_dir() || metadata.file_type().is_symlink())
    {
        return Err(io::Error::other(
            "WAL quarantine is not a private directory",
        ));
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn random_id() -> io::Result<String> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(format!("{:016x}", u64::from_le_bytes(bytes)))
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn fingerprint(path: &Path) -> io::Result<(u64, u64)> {
    let mut file = File::open(path)?;
    let mut buffer = [0_u8; 64 * 1024];
    let mut bytes = 0;
    let mut hash = 0xcbf29ce484222325_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        for byte in &buffer[..count] {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
        }
    }
    Ok((bytes, hash))
}

fn checksum(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn data_directory() -> PathBuf {
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

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("redtrace-wal-tests-{}", random_id().unwrap()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn wal(&self) -> Wal {
            Wal::open(self.0.join("active.wal")).unwrap()
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn encoded(event: Event) -> Vec<u8> {
        serde_json::to_vec(&WalRecord {
            version: WAL_VERSION,
            checksum: checksum(&serde_json::to_vec(&event).unwrap()),
            event,
        })
        .unwrap()
    }

    fn append_bytes(wal: &Wal, bytes: &[u8]) {
        OpenOptions::new()
            .append(true)
            .open(wal.path())
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

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

    #[test]
    fn reset_atomically_clears_the_active_log() {
        let path =
            std::env::temp_dir().join(format!("redtrace-wal-reset-{}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);
        let wal = Wal::open(path.clone()).unwrap();
        wal.append(&[event("persisted")]).unwrap();
        wal.reset().unwrap();
        assert_eq!(wal.size_bytes().unwrap(), 0);
        assert!(wal.recover().unwrap().events.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn append_separates_a_torn_tail_from_new_confirmed_records() {
        let directory = Directory::new();
        let wal = directory.wal();
        let first = event("before crash");
        let second = event("confirmed after crash");
        wal.append(std::slice::from_ref(&first)).unwrap();
        append_bytes(&wal, b"{\"version\":1,\"checksum\":123,\"event\":{");
        wal.append(std::slice::from_ref(&second)).unwrap();
        let recovery = wal.recover().unwrap();
        assert_eq!(recovery.events, vec![first, second]);
        assert_eq!(recovery.corrupted_records, 1);
        assert_eq!(recovery.salvaged_records, 0);
    }

    #[test]
    fn append_preserves_a_complete_record_without_its_last_newline() {
        let directory = Directory::new();
        let wal = directory.wal();
        let first = event("complete unsuffixed record");
        let second = event("new confirmed record");
        append_bytes(&wal, &encoded(first.clone()));
        wal.append(std::slice::from_ref(&second)).unwrap();
        let recovery = wal.recover().unwrap();
        assert_eq!(recovery.events, vec![first, second]);
        assert_eq!(recovery.corrupted_records, 0);
    }

    #[test]
    fn repairs_merged_records_and_archives_exact_original_bytes_before_rotation() {
        let directory = Directory::new();
        let wal = directory.wal();
        let first = event("ordinary record");
        let restored =
            event("confirmed record with literal {\"version\":1,\"checksum\":0,\"event\":{}} text");
        wal.append(std::slice::from_ref(&first)).unwrap();
        append_bytes(
            &wal,
            b"{\"version\":1,\"checksum\":123,\"event\":{\"message\":\"unfinished",
        );
        append_bytes(&wal, &encoded(restored.clone()));
        append_bytes(&wal, b"\n");
        let original = fs::read(wal.path()).unwrap();
        let readonly = wal.recover().unwrap();
        assert_eq!(readonly.events, vec![first.clone(), restored.clone()]);
        assert_eq!(readonly.corrupted_records, 1);
        assert_eq!(readonly.salvaged_records, 1);
        assert_eq!(fs::read(wal.path()).unwrap(), original);

        let repaired = wal.recover_with_repair().unwrap();
        assert_eq!(repaired.events, readonly.events);
        assert_eq!(repaired.corrupted_records, 0);
        assert_eq!(repaired.quarantined_records, 1);
        assert_eq!(repaired.salvaged_records, 1);
        let archive = fs::read_dir(wal.quarantine_directory())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|extension| extension == "wal"))
            .unwrap();
        assert_eq!(fs::read(archive).unwrap(), original);
        let stats = wal.quarantine_stats().unwrap();
        assert_eq!(stats.archives, 1);
        assert_eq!(stats.corrupted_records, 1);
        assert_eq!(stats.salvageable_records, 1);
        let clean = wal.recover_with_repair().unwrap();
        assert_eq!(clean.quarantined_records, 0);
        assert_eq!(wal.quarantine_stats().unwrap().archives, 1);

        let after = event("after recovery");
        wal.append(std::slice::from_ref(&after)).unwrap();
        let store = crate::storage::SegmentStore::open(directory.0.clone()).unwrap();
        store.commit(&wal.recover().unwrap().events).unwrap();
        wal.reset().unwrap();
        assert_eq!(wal.size_bytes().unwrap(), 0);
        assert_eq!(
            store.recover().unwrap().events,
            vec![first, restored, after]
        );
    }

    #[test]
    fn quarantines_checksum_version_and_utf8_failures_without_trusting_them() {
        let directory = Directory::new();
        let wal = directory.wal();
        let good = event("good");
        wal.append(std::slice::from_ref(&good)).unwrap();
        let mut bad: WalRecord = serde_json::from_slice(&encoded(event("bad checksum"))).unwrap();
        bad.checksum ^= 1;
        append_bytes(&wal, &serde_json::to_vec(&bad).unwrap());
        append_bytes(&wal, b"\n");
        let mut future: WalRecord =
            serde_json::from_slice(&encoded(event("future format"))).unwrap();
        future.version = 2;
        append_bytes(&wal, &serde_json::to_vec(&future).unwrap());
        append_bytes(&wal, b"\n\xff\xfe\n");
        let original = fs::read(wal.path()).unwrap();
        let recovery = wal.recover_with_repair().unwrap();
        assert_eq!(recovery.events, vec![good]);
        assert_eq!(recovery.quarantined_records, 3);
        assert_eq!(recovery.salvaged_records, 0);
        assert_eq!(wal.quarantine_stats().unwrap().corrupted_records, 3);
        let original_archive = fs::read_dir(wal.quarantine_directory())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|extension| extension == "wal"))
            .unwrap();
        assert_eq!(fs::read(original_archive).unwrap(), original);
    }

    #[test]
    fn budget_or_archive_failure_never_rewrites_the_original_wal() {
        let directory = Directory::new();
        let wal = directory.wal();
        wal.append(&[event("valid event")]).unwrap();
        append_bytes(&wal, b"broken record\n");
        let original = fs::read(wal.path()).unwrap();
        assert!(wal.recover_with_repair_limit(0).is_err());
        assert_eq!(fs::read(wal.path()).unwrap(), original);
        assert_eq!(wal.recover().unwrap().corrupted_records, 1);
        fs::remove_dir(wal.quarantine_directory()).unwrap();
        fs::write(wal.quarantine_directory(), b"archive unavailable").unwrap();
        assert!(wal.recover_with_repair().is_err());
        assert_eq!(fs::read(wal.path()).unwrap(), original);
    }

    #[test]
    fn ownership_survives_reset_and_is_released_after_the_last_clone() {
        let directory = Directory::new();
        let wal = directory.wal();
        let clone = wal.clone();
        assert_eq!(
            Wal::open(wal.path().into()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        wal.reset().unwrap();
        assert_eq!(
            Wal::open(wal.path().into()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(wal);
        assert!(Wal::open(clone.path().into()).is_err());
        drop(clone);
        assert!(Wal::open(directory.0.join("active.wal")).is_ok());
    }

    #[test]
    fn cloned_writers_do_not_interleave_records() {
        let directory = Directory::new();
        let wal = directory.wal();
        let writers: Vec<_> = (0..6)
            .map(|writer| {
                let wal = wal.clone();
                std::thread::spawn(move || {
                    let events: Vec<_> = (0..20)
                        .map(|record| event(&format!("writer-{writer}-{record}")))
                        .collect();
                    wal.append(&events).unwrap();
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        let recovery = wal.recover().unwrap();
        assert_eq!(recovery.events.len(), 120);
        assert_eq!(recovery.corrupted_records, 0);
        assert_eq!(
            recovery
                .events
                .iter()
                .map(|event| &event.uid)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            120
        );
    }
}
