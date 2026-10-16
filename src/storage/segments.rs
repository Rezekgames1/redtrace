use super::segment_index::{self, LoadedSegmentIndex, SegmentIndexMeta};
use crate::{
    index::{ExecutionLimits, QueryBudget, QueryMatches, QueryPage, SearchResult},
    model::Event,
    query::Expr,
    time_range::TimeRange,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const MANIFEST_VERSION: u16 = 1;
const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_RETENTION_DAYS: u64 = 7;
const DEFAULT_COMPACT_SEGMENTS: usize = 8;
const MAX_SEGMENT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SegmentMeta {
    pub id: u64,
    pub file: String,
    pub events: usize,
    pub bytes: u64,
    pub checksum: u64,
    #[serde(default)]
    pub index: Option<SegmentIndexMeta>,
    pub created_unix: u64,
    pub min_timestamp: String,
    pub max_timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_bounds: Option<SegmentTimeBounds>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SegmentTimeBounds {
    pub minimum: Option<String>,
    pub maximum: Option<String>,
}

fn timestamp_bounds<'a>(timestamps: impl IntoIterator<Item = &'a str>) -> SegmentTimeBounds {
    let mut minimum = None;
    let mut maximum = None;
    for timestamp in timestamps {
        let Ok(timestamp) = chrono::DateTime::parse_from_rfc3339(timestamp) else {
            // Unknown timestamps must never allow a segment to be excluded.
            return SegmentTimeBounds::default();
        };
        let timestamp = timestamp.with_timezone(&chrono::Utc);
        minimum = Some(minimum.map_or(timestamp, |previous| std::cmp::min(previous, timestamp)));
        maximum = Some(maximum.map_or(timestamp, |previous| std::cmp::max(previous, timestamp)));
    }
    SegmentTimeBounds {
        minimum: minimum.map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
        maximum: maximum.map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
    }
}

impl SegmentMeta {
    fn storage_bytes(&self) -> u64 {
        let mut bytes = self.bytes;
        if let Some(index) = &self.index {
            for sidecar in [&index.fields, &index.terms, &index.postings] {
                bytes = bytes.saturating_add(sidecar.bytes);
            }
            if let Some(offsets) = &index.offsets {
                bytes = bytes.saturating_add(offsets.bytes);
            }
        }
        bytes
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Manifest {
    version: u16,
    next_id: u64,
    segments: Vec<SegmentMeta>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            version: MANIFEST_VERSION,
            next_id: 1,
            segments: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct SegmentRecovery {
    pub events: Vec<Event>,
    pub corrupted_segments: usize,
    pub corrupted_indexes: usize,
    pub segment_count: usize,
    pub bytes: u64,
}

#[derive(Clone, Debug)]
pub struct SegmentStore {
    root: PathBuf,
    manifest_path: PathBuf,
    max_bytes: u64,
    retention_seconds: u64,
    max_segment_bytes: u64,
    max_temporary_bytes: u64,
    _ownership: Arc<File>,
    write_lock: Arc<Mutex<()>>,
    index_cache: Arc<Mutex<BTreeMap<u64, Arc<LoadedSegmentIndex>>>>,
    #[cfg(test)]
    failure: Arc<Mutex<Option<&'static str>>>,
    #[cfg(test)]
    clock: Option<u64>,
}

struct SegmentTransaction {
    directory: PathBuf,
    installed: Vec<PathBuf>,
    bytes: u64,
    existing_temporary_bytes: u64,
    next_id: u64,
    published: bool,
}

impl Drop for SegmentTransaction {
    fn drop(&mut self) {
        if !self.published {
            for path in &self.installed {
                let _ = fs::remove_file(path);
            }
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

impl SegmentStore {
    pub fn open_default() -> io::Result<Self> {
        Self::open(super::wal::data_directory())
    }

    pub fn open(root: PathBuf) -> io::Result<Self> {
        let max_bytes = environment_u64("REDTRACE_MAX_STORAGE_MB")
            .map(|value| value.saturating_mul(1024 * 1024))
            .unwrap_or(DEFAULT_MAX_BYTES);
        let max_segment_bytes = environment_u64("REDTRACE_SEGMENT_MB")
            .filter(|value| *value > 0)
            .map(|value| value.saturating_mul(1024 * 1024))
            .unwrap_or(MAX_SEGMENT_BYTES)
            .min(MAX_SEGMENT_BYTES)
            .min(max_bytes);
        Self::open_with_limits(
            root,
            max_bytes,
            environment_u64("REDTRACE_RETENTION_DAYS")
                .unwrap_or(DEFAULT_RETENTION_DAYS)
                .saturating_mul(24 * 60 * 60),
            max_segment_bytes,
            max_bytes
                .saturating_add(max_segment_bytes)
                .saturating_add(MAX_MANIFEST_BYTES),
        )
    }

    pub fn open_with_limits(
        root: PathBuf,
        max_bytes: u64,
        retention_seconds: u64,
        max_segment_bytes: u64,
        max_temporary_bytes: u64,
    ) -> io::Result<Self> {
        if max_bytes == 0 || max_segment_bytes == 0 || max_temporary_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "segment storage limits must be positive",
            ));
        }
        create_private_dir(&root)?;
        create_private_dir(&root.join("segments"))?;
        let ownership = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("catalog.lock"))?;
        ownership.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => io::Error::new(
                io::ErrorKind::WouldBlock,
                "another segment store owns this catalog",
            ),
            fs::TryLockError::Error(error) => error,
        })?;
        let store = Self {
            manifest_path: root.join("catalog.json"),
            root,
            max_bytes,
            retention_seconds,
            max_segment_bytes: max_segment_bytes.min(max_bytes).min(MAX_SEGMENT_BYTES),
            max_temporary_bytes,
            _ownership: Arc::new(ownership),
            write_lock: Arc::new(Mutex::new(())),
            index_cache: Arc::new(Mutex::new(BTreeMap::new())),
            #[cfg(test)]
            failure: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            clock: None,
        };
        if !store.manifest_path.exists() {
            let mut transaction = store.transaction()?;
            store.write_manifest(&Manifest::default(), &mut transaction)?;
        }
        Ok(store)
    }

    pub fn recover(&self) -> io::Result<SegmentRecovery> {
        let _guard = self.lock_writer()?;
        let manifest = self.read_manifest()?;
        let mut recovery = SegmentRecovery {
            segment_count: manifest.segments.len(),
            bytes: manifest
                .segments
                .iter()
                .map(SegmentMeta::storage_bytes)
                .fold(0_u64, u64::saturating_add),
            ..SegmentRecovery::default()
        };
        let mut seen = HashSet::new();
        for segment in &manifest.segments {
            if let Some(index) = &segment.index
                && segment_index::validate(&self.root.join("segments"), index).is_err()
            {
                recovery.corrupted_indexes += 1;
            }
            let path = self.root.join("segments").join(&segment.file);
            let Ok(actual_checksum) = checksum_file(&path) else {
                recovery.corrupted_segments += 1;
                continue;
            };
            if actual_checksum != segment.checksum || fs::metadata(&path)?.len() != segment.bytes {
                recovery.corrupted_segments += 1;
                continue;
            }
            let file = File::open(path)?;
            let mut valid = Vec::new();
            let mut corrupt = false;
            for line in BufReader::new(file).lines() {
                let Ok(line) = line else {
                    corrupt = true;
                    break;
                };
                match serde_json::from_str::<Event>(&line) {
                    Ok(event) => valid.push(event),
                    Err(_) => {
                        corrupt = true;
                        break;
                    }
                }
            }
            if corrupt || valid.len() != segment.events {
                recovery.corrupted_segments += 1;
                continue;
            }
            for event in valid {
                if seen.insert(event.uid.clone()) {
                    recovery.events.push(event);
                }
            }
        }
        Ok(recovery)
    }

    pub fn commit(&self, events: &[Event]) -> io::Result<Option<SegmentMeta>> {
        let _guard = self.lock_writer()?;
        let original = self.read_manifest()?;
        let mut seen = self.validate_segments(&original)?;
        let mut manifest = original.clone();
        let mut transaction = self.transaction()?;
        self.normalize_retention(&mut manifest, &mut transaction)?;
        let fresh: Vec<_> = events
            .iter()
            .filter(|event| seen.insert(event.uid.clone()))
            .cloned()
            .collect();
        self.stage_chunks(&mut manifest, &mut transaction, &fresh, self.now())?;
        self.publish(&original, &manifest, &mut transaction)?;
        if manifest.segments.len() >= compact_threshold() {
            self.rewrite_all(&manifest, false)?;
        }
        if fresh.is_empty() {
            return Ok(None);
        }
        Ok(self.read_manifest()?.segments.last().cloned())
    }

    pub fn ensure_indexes(&self) -> io::Result<bool> {
        let _guard = self.lock_writer()?;
        let manifest = self.read_manifest()?;
        let indexes_current = manifest.segments.iter().all(|segment| {
            segment
                .index
                .as_ref()
                .is_some_and(segment_index::is_current)
        });
        if !indexes_current {
            return self.rewrite_all(&manifest, true);
        }
        if manifest
            .segments
            .iter()
            .all(|segment| segment.time_bounds.is_some())
        {
            return Ok(false);
        }
        self.validate_segments(&manifest)?;
        let mut updated = manifest.clone();
        for segment in &mut updated.segments {
            if segment.time_bounds.is_some() {
                continue;
            }
            let path = self.root.join("segments").join(&segment.file);
            let timestamps = BufReader::new(File::open(path)?)
                .lines()
                .map(|line| {
                    serde_json::from_str::<Event>(&line?)
                        .map(|event| event.timestamp)
                        .map_err(io::Error::other)
                })
                .collect::<io::Result<Vec<_>>>()?;
            segment.time_bounds = Some(timestamp_bounds(timestamps.iter().map(String::as_str)));
        }
        let mut transaction = self.transaction()?;
        self.write_manifest(&updated, &mut transaction)?;
        Ok(true)
    }

    pub fn compact_all(&self) -> io::Result<bool> {
        let _guard = self.lock_writer()?;
        let manifest = self.read_manifest()?;
        self.rewrite_all(&manifest, false)
    }

    pub fn enforce_retention(&self) -> io::Result<bool> {
        let _guard = self.lock_writer()?;
        let original = self.read_manifest()?;
        self.validate_segments(&original)?;
        let mut manifest = original.clone();
        let mut transaction = self.transaction()?;
        self.normalize_retention(&mut manifest, &mut transaction)?;
        let changed = serde_json::to_vec(&original).map_err(io::Error::other)?
            != serde_json::to_vec(&manifest).map_err(io::Error::other)?;
        if changed {
            self.publish(&original, &manifest, &mut transaction)?;
        }
        Ok(changed)
    }

    pub fn stats(&self) -> io::Result<(usize, u64)> {
        let manifest = self.read_manifest()?;
        Ok((
            manifest.segments.len(),
            manifest
                .segments
                .iter()
                .map(SegmentMeta::storage_bytes)
                .fold(0_u64, u64::saturating_add),
        ))
    }

    pub fn search(&self, expression: &Expr, limit: usize) -> io::Result<SearchResult> {
        self.search_page(expression, limit, None)
    }

    pub fn search_page(
        &self,
        expression: &Expr,
        limit: usize,
        before: Option<(&str, &str)>,
    ) -> io::Result<SearchResult> {
        self.search_page_bounded(
            expression,
            limit,
            before,
            &mut QueryBudget::new(ExecutionLimits::default()),
        )
    }

    pub fn search_page_bounded(
        &self,
        expression: &Expr,
        limit: usize,
        before: Option<(&str, &str)>,
        budget: &mut QueryBudget,
    ) -> io::Result<SearchResult> {
        let started = Instant::now();
        let mut matches = QueryMatches::new();
        let mut page = QueryPage::new(
            limit,
            before.map(|(timestamp, uid)| (timestamp.to_owned(), uid.to_owned())),
            budget,
        )?;
        self.search_into(expression, budget, |event, budget| {
            if matches.accept(event, budget)? {
                page.offer(event, budget)?;
            }
            Ok(())
        })?;
        Ok(SearchResult {
            total: matches.total(),
            took_micros: started.elapsed().as_micros(),
            events: page.into_events(budget)?,
        })
    }

    pub fn search_into(
        &self,
        expression: &Expr,
        budget: &mut QueryBudget,
        visitor: impl FnMut(&Event, &mut QueryBudget) -> io::Result<()>,
    ) -> io::Result<()> {
        self.search_into_time_range(expression, budget, &TimeRange::default(), visitor)
    }

    pub fn search_into_time_range(
        &self,
        expression: &Expr,
        budget: &mut QueryBudget,
        range: &TimeRange,
        mut visitor: impl FnMut(&Event, &mut QueryBudget) -> io::Result<()>,
    ) -> io::Result<()> {
        let _guard = loop {
            budget.check()?;
            match self.write_lock.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::Poisoned(error)) => break error.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(std::time::Duration::from_millis(1))
                }
            }
        };
        let initial_memory = budget.usage.memory_bytes;
        let bytes = segment_index::read_bounded(&self.manifest_path, budget)?;
        budget.allocate(bytes.len().saturating_mul(16))?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        budget.release(bytes.len().saturating_mul(2));
        drop(bytes);
        let manifest_memory = budget.usage.memory_bytes.saturating_sub(initial_memory);
        if manifest.version != MANIFEST_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported query manifest version",
            ));
        }
        let directory = self.root.join("segments");
        let mut visitor = |event: &Event, budget: &mut QueryBudget| {
            if range.contains(&event.timestamp) {
                visitor(event, budget)?;
            }
            Ok(())
        };
        for segment in &manifest.segments {
            if let Some(bounds) = &segment.time_bounds
                && !range.overlaps(bounds.minimum.as_deref(), bounds.maximum.as_deref())
            {
                continue;
            }
            budget.segment()?;
            let path = directory.join(&segment.file);
            if let Some(meta) = &segment.index {
                let index = self.load_index(segment.id, meta, budget)?;
                read_matching_events(
                    &path,
                    Some((&index, expression, segment.events)),
                    budget,
                    &mut visitor,
                )?;
                budget.release(index.memory_bytes());
            } else {
                read_matching_events(&path, None, budget, &mut |event, budget| {
                    if crate::index::matches_event(expression, event, budget)? {
                        visitor(event, budget)?;
                    }
                    Ok(())
                })?;
            }
        }
        budget.release(manifest_memory);
        Ok(())
    }

    fn load_index(
        &self,
        segment_id: u64,
        meta: &SegmentIndexMeta,
        budget: &mut QueryBudget,
    ) -> io::Result<Arc<LoadedSegmentIndex>> {
        if let Ok(cache) = self.index_cache.try_lock()
            && let Some(index) = cache.get(&segment_id)
        {
            budget.allocate(index.memory_bytes())?;
            return Ok(Arc::clone(index));
        }
        let index = Arc::new(segment_index::load_bounded(
            &self.root.join("segments"),
            meta,
            budget,
        )?);
        if let Ok(mut cache) = self.index_cache.try_lock() {
            while cache.len() >= 4
                || cache
                    .values()
                    .map(|index| index.memory_bytes())
                    .sum::<usize>()
                    .saturating_add(index.memory_bytes())
                    > ExecutionLimits::default().max_memory_bytes
            {
                let Some(oldest) = cache.keys().next().copied() else {
                    break;
                };
                cache.remove(&oldest);
            }
            cache.insert(segment_id, Arc::clone(&index));
        }
        Ok(index)
    }

    fn rewrite_all(&self, original: &Manifest, force: bool) -> io::Result<bool> {
        self.validate_segments(original)?;
        if original.segments.is_empty() {
            return Ok(false);
        }
        let mut transaction = self.transaction()?;
        let mut manifest = Manifest {
            next_id: original.next_id,
            ..Manifest::default()
        };
        let mut groups = BTreeMap::<u64, Vec<&SegmentMeta>>::new();
        let oldest_allowed = self.now().saturating_sub(self.retention_seconds);
        let mut segments: Vec<_> = original.segments.iter().collect();
        segments.sort_by_key(|segment| (segment.created_unix, segment.id));
        for segment in segments {
            if segment.created_unix < oldest_allowed {
                continue;
            }
            groups
                .entry(segment.created_unix)
                .or_default()
                .push(segment);
        }
        if !force
            && original.segments.len() == 1
            && original.segments[0].storage_bytes() <= self.segment_limit()
            && original.segments[0].created_unix >= oldest_allowed
        {
            return Ok(false);
        }
        let mut seen = HashSet::new();
        for (created_unix, segments) in groups {
            self.stage_stored_segments(
                &mut manifest,
                &mut transaction,
                &segments,
                created_unix,
                &mut seen,
            )?;
        }
        self.publish(original, &manifest, &mut transaction)?;
        Ok(true)
    }

    fn stage_chunks(
        &self,
        manifest: &mut Manifest,
        transaction: &mut SegmentTransaction,
        events: &[Event],
        created_unix: u64,
    ) -> io::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let estimate = segment_output_bound(events)?;
        if estimate > self.segment_limit() && events.len() > 1 {
            let middle = events.len() / 2;
            self.stage_chunks(manifest, transaction, &events[..middle], created_unix)?;
            return self.stage_chunks(manifest, transaction, &events[middle..], created_unix);
        }
        let id = manifest.next_id.max(transaction.next_id);
        manifest.next_id = id.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "segment identifier exhausted")
        })?;
        transaction.next_id = manifest.next_id;
        let segment = self.write_segment_files(transaction, id, events, created_unix, estimate)?;
        if segment.storage_bytes() > self.segment_limit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "one event and its index exceed the segment storage limit; input preserved",
            ));
        }
        manifest.segments.push(segment);
        self.apply_retention(manifest);
        self.prune_staging(transaction, manifest)
    }

    fn stage_stored_segments(
        &self,
        manifest: &mut Manifest,
        transaction: &mut SegmentTransaction,
        segments: &[&SegmentMeta],
        created_unix: u64,
        seen: &mut HashSet<String>,
    ) -> io::Result<()> {
        let mut chunk = Vec::new();
        let mut bound = 26_u64;
        for segment in segments {
            let path = self.root.join("segments").join(&segment.file);
            for line in BufReader::new(File::open(path)?).lines() {
                let event: Event = serde_json::from_str(&line?).map_err(io::Error::other)?;
                if !seen.insert(event.uid.clone()) {
                    continue;
                }
                let additional =
                    segment_output_bound(std::slice::from_ref(&event))?.saturating_sub(26);
                if !chunk.is_empty() && bound.saturating_add(additional) > self.segment_limit() {
                    self.stage_chunks(manifest, transaction, &chunk, created_unix)?;
                    chunk.clear();
                    bound = 26;
                }
                bound = bound.saturating_add(additional);
                chunk.push(event);
            }
        }
        self.stage_chunks(manifest, transaction, &chunk, created_unix)
    }

    fn write_segment_files(
        &self,
        transaction: &mut SegmentTransaction,
        id: u64,
        events: &[Event],
        created_unix: u64,
        estimate: u64,
    ) -> io::Result<SegmentMeta> {
        self.check_temporary_space(transaction, estimate.saturating_add(MAX_MANIFEST_BYTES))?;
        self.fail_at("segment_write")?;
        let stem = format!("{id:016}");
        let filename = format!("{stem}.jsonl");
        let final_path = transaction.directory.join(&filename);
        let temp_path = transaction.directory.join(format!(".{filename}.tmp"));
        let mut file = BufWriter::with_capacity(64 * 1024, private_file(&temp_path)?);
        for event in events {
            serde_json::to_writer(&mut file, event).map_err(io::Error::other)?;
            file.write_all(b"\n")?;
            self.fail_at("segment_partial_write")?;
        }
        file.flush()?;
        self.fail_at("segment_sync")?;
        file.get_ref().sync_all()?;
        drop(file);
        fs::rename(&temp_path, &final_path)?;
        self.fail_at("index_write")?;
        let index = segment_index::write(&transaction.directory, &stem, events)?;
        self.fail_at("index_complete")?;
        let segment = SegmentMeta {
            id,
            file: filename,
            events: events.len(),
            bytes: fs::metadata(&final_path)?.len(),
            checksum: checksum_file(&final_path)?,
            index: Some(index),
            created_unix,
            min_timestamp: events
                .iter()
                .map(|event| event.timestamp.as_str())
                .min()
                .unwrap_or_default()
                .to_owned(),
            max_timestamp: events
                .iter()
                .map(|event| event.timestamp.as_str())
                .max()
                .unwrap_or_default()
                .to_owned(),
            time_bounds: Some(timestamp_bounds(
                events.iter().map(|event| event.timestamp.as_str()),
            )),
        };
        if segment.storage_bytes() > estimate {
            return Err(io::Error::other("segment output exceeded reserved space"));
        }
        transaction.bytes = transaction.bytes.saturating_add(segment.storage_bytes());
        Ok(segment)
    }

    fn read_manifest(&self) -> io::Result<Manifest> {
        if fs::metadata(&self.manifest_path)?.len() > MAX_MANIFEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "segment catalog exceeds limit",
            ));
        }
        let bytes = fs::read(&self.manifest_path)?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if manifest.version != MANIFEST_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported segment manifest version {}", manifest.version),
            ));
        }
        let mut ids = HashSet::new();
        for segment in &manifest.segments {
            let stem = format!("{:016}", segment.id);
            let expected = format!("{stem}.jsonl");
            if segment.file != expected || !ids.insert(segment.id) || segment.id >= manifest.next_id
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid segment catalog ownership",
                ));
            }
            if let Some(index) = &segment.index {
                let expected = [
                    format!("{stem}.fields.json"),
                    format!("{stem}.terms.json"),
                    format!("{stem}.postings.bin"),
                    format!("{stem}.offsets.bin"),
                ];
                let files = index.files();
                if files
                    .iter()
                    .zip(&expected)
                    .any(|(file, expected)| *file != expected)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid segment index ownership",
                    ));
                }
            }
        }
        Ok(manifest)
    }

    fn write_manifest(
        &self,
        manifest: &Manifest,
        transaction: &mut SegmentTransaction,
    ) -> io::Result<()> {
        let mut bytes = serde_json::to_vec_pretty(manifest).map_err(io::Error::other)?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(io::Error::other("segment catalog exceeds limit"));
        }
        self.check_temporary_space(transaction, bytes.len() as u64)?;
        let temp_path = transaction.directory.join("catalog.json");
        let mut file = private_file(&temp_path)?;
        self.fail_at("manifest_write")?;
        let middle = bytes.len() / 2;
        file.write_all(&bytes[..middle])?;
        self.fail_at("manifest_partial_write")?;
        file.write_all(&bytes[middle..])?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        self.fail_at("manifest_replace")?;
        if let Err(error) = replace_manifest(&temp_path, &self.manifest_path) {
            transaction.published =
                fs::read(&self.manifest_path).is_ok_and(|actual| actual == bytes);
            return Err(error);
        }
        transaction.published = true;
        self.fail_at("manifest_sync")?;
        sync_directory(&self.root)
    }

    fn apply_retention(&self, manifest: &mut Manifest) {
        let oldest_allowed = self.now().saturating_sub(self.retention_seconds);
        manifest
            .segments
            .retain(|segment| segment.created_unix >= oldest_allowed);
        manifest
            .segments
            .sort_by_key(|segment| (segment.created_unix, segment.id));
        let mut total: u64 = manifest
            .segments
            .iter()
            .map(SegmentMeta::storage_bytes)
            .fold(0_u64, u64::saturating_add);
        while total > self.max_bytes && !manifest.segments.is_empty() {
            let removed = manifest.segments.remove(0);
            total = total.saturating_sub(removed.storage_bytes());
        }
    }

    fn remove_unreferenced_segments(
        &self,
        original: &Manifest,
        manifest: &Manifest,
    ) -> io::Result<()> {
        let referenced: HashSet<_> = manifest.segments.iter().map(|segment| segment.id).collect();
        let directory = self.root.join("segments");
        for segment in &original.segments {
            if referenced.contains(&segment.id) {
                continue;
            }
            self.fail_at("cleanup")?;
            for name in segment_files(segment) {
                match fs::remove_file(directory.join(name)) {
                    Ok(()) => (),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                    Err(error) => return Err(error),
                }
                self.fail_at("cleanup_partial")?;
            }
        }
        sync_directory(&directory)
    }

    fn normalize_retention(
        &self,
        manifest: &mut Manifest,
        transaction: &mut SegmentTransaction,
    ) -> io::Result<()> {
        let oldest_allowed = self.now().saturating_sub(self.retention_seconds);
        manifest
            .segments
            .retain(|segment| segment.created_unix >= oldest_allowed);
        let oversized: Vec<_> = manifest
            .segments
            .iter()
            .filter(|segment| segment.storage_bytes() > self.segment_limit())
            .cloned()
            .collect();
        for segment in oversized {
            manifest
                .segments
                .retain(|existing| existing.id != segment.id);
            self.stage_stored_segments(
                manifest,
                transaction,
                &[&segment],
                segment.created_unix,
                &mut HashSet::new(),
            )?;
        }
        self.apply_retention(manifest);
        self.prune_staging(transaction, manifest)
    }

    fn validate_segments(&self, manifest: &Manifest) -> io::Result<HashSet<String>> {
        let mut seen = HashSet::new();
        for segment in &manifest.segments {
            if let Some(index) = &segment.index {
                let sidecars = [&index.fields, &index.terms, &index.postings];
                for meta in sidecars.into_iter().chain(index.offsets.iter()) {
                    let path = self.root.join("segments").join(&meta.file);
                    if fs::metadata(&path)?.len() != meta.bytes
                        || checksum_file(&path)? != meta.checksum
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "retention refused because an index is corrupted; original preserved",
                        ));
                    }
                }
                if segment_index::is_current(index) {
                    segment_index::validate(&self.root.join("segments"), index)?;
                }
            }
            let path = self.root.join("segments").join(&segment.file);
            if fs::metadata(&path)?.len() != segment.bytes
                || checksum_file(&path)? != segment.checksum
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "retention refused because an event segment is corrupted; original preserved",
                ));
            }
            let mut count = 0_usize;
            for line in BufReader::new(File::open(path)?).lines() {
                let event: Event = serde_json::from_str(&line?)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                count = count
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("segment event count overflow"))?;
                seen.insert(event.uid);
            }
            if count != segment.events {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "segment event count mismatch; original preserved",
                ));
            }
        }
        Ok(seen)
    }

    fn publish(
        &self,
        original: &Manifest,
        manifest: &Manifest,
        transaction: &mut SegmentTransaction,
    ) -> io::Result<()> {
        for segment in &manifest.segments {
            for name in segment_files(segment) {
                let source = transaction.directory.join(name);
                if !source.exists() {
                    continue;
                }
                let destination = self.root.join("segments").join(name);
                if destination.try_exists()? {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "segment output already exists; original preserved",
                    ));
                }
                self.fail_at("segment_install")?;
                fs::rename(source, &destination)?;
                transaction.installed.push(destination);
                self.fail_at("segment_partial_install")?;
            }
        }
        sync_directory(&self.root.join("segments"))?;
        self.write_manifest(manifest, transaction)?;
        self.clear_index_cache();
        self.remove_unreferenced_segments(original, manifest)
    }

    fn prune_staging(
        &self,
        transaction: &mut SegmentTransaction,
        manifest: &Manifest,
    ) -> io::Result<()> {
        let referenced: HashSet<_> = manifest.segments.iter().flat_map(segment_files).collect();
        transaction.bytes = 0;
        for entry in fs::read_dir(&transaction.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            if referenced.contains(name.to_string_lossy().as_ref()) {
                transaction.bytes = transaction.bytes.saturating_add(entry.metadata()?.len());
            } else {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    fn transaction(&self) -> io::Result<SegmentTransaction> {
        let manifest = if self.manifest_path.try_exists()? {
            self.read_manifest()?
        } else {
            Manifest::default()
        };
        let referenced: HashSet<_> = manifest.segments.iter().flat_map(segment_files).collect();
        let mut existing_temporary_bytes = 0_u64;
        let mut next_id = manifest.next_id;
        for entry in fs::read_dir(self.root.join("segments"))? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err(io::Error::other(
                    "unexpected entry in segment storage; original preserved",
                ));
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !referenced.contains(name.as_ref()) {
                existing_temporary_bytes =
                    existing_temporary_bytes.saturating_add(entry.metadata()?.len());
            }
            if let Some(id) = name
                .split('.')
                .next()
                .and_then(|stem| stem.parse::<u64>().ok())
            {
                next_id = next_id.max(
                    id.checked_add(1)
                        .ok_or_else(|| io::Error::other("segment identifier exhausted"))?,
                );
            }
        }
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".segments-") && name.ends_with(".tmp") {
                existing_temporary_bytes =
                    existing_temporary_bytes.saturating_add(directory_bytes(&entry.path())?);
            } else if name == ".catalog.json.tmp" {
                existing_temporary_bytes =
                    existing_temporary_bytes.saturating_add(entry.metadata()?.len());
            }
        }
        if existing_temporary_bytes > self.max_temporary_bytes {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "preserved segment files exhaust temporary budget",
            ));
        }
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
        let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = self.root.join(format!(".segments-{id}.tmp"));
        fs::create_dir(&directory)?;
        create_private_dir(&directory)?;
        Ok(SegmentTransaction {
            directory,
            installed: Vec::new(),
            bytes: 0,
            existing_temporary_bytes,
            next_id,
            published: false,
        })
    }

    fn check_temporary_space(
        &self,
        transaction: &SegmentTransaction,
        additional: u64,
    ) -> io::Result<()> {
        if transaction
            .existing_temporary_bytes
            .saturating_add(transaction.bytes)
            .saturating_add(additional)
            > self.max_temporary_bytes
        {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "segment temporary space budget exhausted; original preserved",
            ));
        }
        check_available_space(&self.root, additional)
    }

    fn segment_limit(&self) -> u64 {
        self.max_segment_bytes.min(self.max_bytes)
    }

    fn now(&self) -> u64 {
        #[cfg(test)]
        if let Some(now) = self.clock {
            return now;
        }
        now_unix()
    }

    fn lock_writer(&self) -> io::Result<std::sync::MutexGuard<'_, ()>> {
        self.write_lock
            .lock()
            .map_err(|_| io::Error::other("segment writer lock poisoned"))
    }

    fn fail_at(&self, stage: &'static str) -> io::Result<()> {
        #[cfg(test)]
        if *self.failure.lock().unwrap() == Some(stage) {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                format!("injected segment failure: {stage}"),
            ));
        }
        let _ = stage;
        Ok(())
    }

    fn clear_index_cache(&self) {
        self.index_cache
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
    }
}

fn segment_files(segment: &SegmentMeta) -> Vec<&str> {
    let mut files = vec![segment.file.as_str()];
    if let Some(index) = &segment.index {
        files.extend(index.files());
    }
    files
}

#[derive(Default)]
struct ByteCounter(u64);

impl Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("segment size overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_bytes(value: &impl Serialize) -> io::Result<u64> {
    let mut counter = ByteCounter::default();
    serde_json::to_writer(&mut counter, value).map_err(io::Error::other)?;
    Ok(counter.0)
}

fn segment_output_bound(events: &[Event]) -> io::Result<u64> {
    let mut bytes = 26_u64;
    for event in events {
        bytes = bytes.saturating_add(serialized_bytes(event)?.saturating_add(9));
        let fields = [
            ("uid", event.uid.as_str()),
            ("event.uid", event.uid.as_str()),
            ("@timestamp", event.timestamp.as_str()),
            ("source", event.source.as_str()),
            ("log.source", event.source.as_str()),
            ("level", event.level.as_str()),
            ("event.description", event.message.as_str()),
        ];
        for (field, value) in fields.into_iter().chain(
            event
                .fields
                .iter()
                .map(|(field, value)| (field.as_str(), value.as_str())),
        ) {
            bytes = bytes.saturating_add(
                serialized_bytes(&(field, value.to_lowercase()))?.saturating_add(10),
            );
        }
        for term in event
            .message
            .split(|c: char| !c.is_alphanumeric() && !matches!(c, '.' | '_' | '\\'))
            .filter(|term| !term.is_empty())
        {
            bytes =
                bytes.saturating_add(serialized_bytes(&term.to_lowercase())?.saturating_add(10));
        }
    }
    Ok(bytes)
}

fn directory_bytes(path: &Path) -> io::Result<u64> {
    if !fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(io::Error::other("unexpected preserved segment entry"));
    }
    let mut bytes = 0_u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(io::Error::other("unexpected preserved segment entry"));
        }
        bytes = bytes.saturating_add(entry.metadata()?.len());
    }
    Ok(bytes)
}

fn check_available_space(path: &Path, required: u64) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let path: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut available = 0_u64;
        let result = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                path.as_ptr(),
                &mut available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        if available < required {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "insufficient disk space for segment transaction; original preserved",
            ));
        }
    }
    let _ = (path, required);
    Ok(())
}

fn replace_manifest(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let source: Vec<_> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let destination: Vec<_> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let result = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::rename(source, destination)
    }
}

fn read_matching_events(
    path: &Path,
    indexed: Option<(&LoadedSegmentIndex, &Expr, usize)>,
    budget: &mut QueryBudget,
    visitor: &mut impl FnMut(&Event, &mut QueryBudget) -> io::Result<()>,
) -> io::Result<()> {
    fn read_query_line(
        reader: &mut impl BufRead,
        line: &mut Vec<u8>,
        budget: &mut QueryBudget,
    ) -> io::Result<usize> {
        loop {
            budget.work(1)?;
            let buffer = reader.fill_buf()?;
            if buffer.is_empty() {
                return Ok(line.len());
            }
            let end = buffer.iter().position(|byte| *byte == b'\n');
            let bytes = end.map_or(buffer.len(), |position| position + 1);
            if line.len().saturating_add(bytes) > budget.limits.max_record_bytes {
                return Err(io::Error::other(crate::index::QueryFailure::RecordBytes));
            }
            budget.scan(bytes as u64)?;
            line.extend_from_slice(&buffer[..bytes]);
            reader.consume(bytes);
            if end.is_some() {
                return Ok(line.len());
            }
        }
    }

    let initial_memory = budget.usage.memory_bytes;
    let prepared = indexed
        .map(|(index, expression, count)| {
            if index.event_count() != count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "segment event count mismatch",
                ));
            }
            index.prepare(expression, budget)
        })
        .transpose()?;
    let prepared_memory = budget.usage.memory_bytes.saturating_sub(initial_memory);
    let mut reader = BufReader::new(File::open(path)?);
    let line_memory = budget
        .limits
        .max_record_bytes
        .saturating_mul(2)
        .saturating_add(2);
    budget.allocate(line_memory)?;
    let mut line = Vec::with_capacity(budget.limits.max_record_bytes + 1);
    let count = indexed.map(|(_, _, count)| count).unwrap_or(usize::MAX);
    for document in 0..count {
        budget.check()?;
        if let Some((index, _, _)) = indexed {
            budget.document()?;
            let document = u32::try_from(document).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "segment document overflow")
            })?;
            if !prepared
                .as_ref()
                .expect("indexed query")
                .matches(&document, budget)?
            {
                continue;
            }
            let offset = index.offset(document).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "segment offset is missing")
            })?;
            reader.seek(SeekFrom::Start(offset))?;
        }
        line.clear();
        let read = read_query_line(&mut reader, &mut line, budget)?;
        if read == 0 {
            if indexed.is_none() {
                break;
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "segment offset points beyond end of file",
            ));
        }
        if indexed.is_none() {
            budget.document()?;
        }
        let temporary = line.len().saturating_mul(16);
        budget.allocate(temporary)?;
        let event: Event = serde_json::from_slice(&line).map_err(io::Error::other)?;
        budget.record(&event)?;
        visitor(&event, budget)?;
        budget.release(temporary);
    }
    budget.release(line_memory);
    budget.release(prepared_memory);
    Ok(())
}

fn private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn checksum_file(path: &Path) -> io::Result<u64> {
    let mut file = File::open(path)?;
    let mut hash = 0xcbf29ce484222325_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(hash);
        }
        for byte in &buffer[..read] {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
}

fn environment_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.parse().ok()
}

fn compact_threshold() -> usize {
    environment_u64("REDTRACE_COMPACT_SEGMENTS")
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value >= 2)
        .unwrap_or(DEFAULT_COMPACT_SEGMENTS)
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

    fn event(id: u64, message: &str) -> Event {
        Event::normalized(
            id,
            format!("2026-01-01T00:00:{id:02}Z"),
            "test.segment".into(),
            "low".into(),
            message.into(),
            BTreeMap::new(),
        )
    }

    fn directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "redtrace-segment-{name}-{}-{}",
            std::process::id(),
            now_unix()
        ))
    }

    #[test]
    fn commits_and_recovers_an_immutable_segment() {
        let root = directory("recover");
        let _ = fs::remove_dir_all(&root);
        let store = SegmentStore::open(root.clone()).unwrap();
        let meta = store
            .commit(&[event(1, "first"), event(2, "second")])
            .unwrap();
        assert_eq!(meta.unwrap().events, 2);
        let recovery = store.recover().unwrap();
        assert_eq!(recovery.events.len(), 2);
        assert_eq!(recovery.corrupted_segments, 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn buffered_segments_preserve_large_records_and_index_offsets() {
        let root = directory("buffered-large-records");
        let store = SegmentStore::open(root.clone()).unwrap();
        let mut first = event(1, &"large first record ".repeat(6000));
        first
            .fields
            .insert("payload".into(), "é\\\"\n".repeat(20000));
        let second = event(2, "short middle record");
        let third = event(
            3,
            &format!("{} final-marker", "длинная запись ".repeat(6000)),
        );
        let expected = vec![first, second, third];
        store.commit(&expected).unwrap();
        let recovery = store.recover().unwrap();
        assert_eq!(recovery.corrupted_segments, 0);
        assert_eq!(recovery.corrupted_indexes, 0);
        assert_eq!(recovery.events, expected);
        let query = crate::query::parse("message~final-marker").unwrap();
        let found = store.search(&query, 10).unwrap();
        assert_eq!(found.total, 1);
        assert_eq!(found.events, vec![expected[2].clone()]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn recent_queries_skip_historical_sidecars_before_scan_and_segment_budgets() {
        let root = directory("time-pruning-budget");
        let store = SegmentStore::open(root.clone()).unwrap();
        let mut old = event(1, &"historical payload ".repeat(12000));
        old.timestamp = "2020-01-01T00:00:00Z".into();
        let mut recent = event(2, "recent marker");
        recent.timestamp = "2026-10-16T10:00:00Z".into();
        store.commit(&[old]).unwrap();
        store.commit(std::slice::from_ref(&recent)).unwrap();
        let range = TimeRange::parse(&crate::time_range::TimeRangeParams {
            from: Some("2026-10-16T09:00:00Z".into()),
            to: None,
        })
        .unwrap();
        let limits = ExecutionLimits {
            max_scan_bytes: 32 * 1024,
            max_segments: 1,
            ..ExecutionLimits::default()
        };
        let mut budget = QueryBudget::new(limits);
        let mut found = Vec::new();
        store
            .search_into_time_range(&Expr::MatchAll, &mut budget, &range, |event, _| {
                found.push(event.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(found, vec![recent]);
        assert_eq!(budget.usage.segments, 1);
        assert!(
            store
                .search_into(
                    &Expr::MatchAll,
                    &mut QueryBudget::new(limits),
                    |_, _| Ok(())
                )
                .is_err()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_time_bounds_upgrade_is_chronological_metadata_only_and_idempotent() {
        let root = directory("legacy-time-bounds");
        let store = SegmentStore::open(root.clone()).unwrap();
        let mut first = event(1, "offset event");
        first.timestamp = "2026-10-12T10:30:00+02:00".into();
        let mut second = event(2, "UTC event");
        second.timestamp = "2026-10-12T09:00:00Z".into();
        store.commit(&[first, second.clone()]).unwrap();
        let mut manifest = store.read_manifest().unwrap();
        let original = manifest.segments[0].clone();
        let event_path = root.join("segments").join(&original.file);
        let bytes = fs::read(&event_path).unwrap();
        manifest.segments[0].time_bounds = None;
        fs::write(&store.manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(store.ensure_indexes().unwrap());
        assert!(!store.ensure_indexes().unwrap());
        let current = store.read_manifest().unwrap();
        assert_eq!(current.segments[0].file, original.file);
        assert_eq!(fs::read(&event_path).unwrap(), bytes);
        let bounds = current.segments[0].time_bounds.as_ref().unwrap();
        assert_eq!(
            bounds.minimum.as_deref(),
            Some("2026-10-12T08:30:00.000000000Z")
        );
        assert_eq!(
            bounds.maximum.as_deref(),
            Some("2026-10-12T09:00:00.000000000Z")
        );
        let range = TimeRange::parse(&crate::time_range::TimeRangeParams {
            from: Some("2026-10-12T09:00:00Z".into()),
            to: Some("2026-10-12T09:00:01Z".into()),
        })
        .unwrap();
        let mut found = Vec::new();
        store
            .search_into_time_range(
                &Expr::MatchAll,
                &mut QueryBudget::new(ExecutionLimits::default()),
                &range,
                |event, _| {
                    found.push(event.clone());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(found, vec![second]);
        let before = TimeRange::parse(&crate::time_range::TimeRangeParams {
            from: None,
            to: Some("2026-10-12T08:30:00Z".into()),
        })
        .unwrap();
        let mut budget = QueryBudget::new(ExecutionLimits::default());
        store
            .search_into_time_range(&Expr::MatchAll, &mut budget, &before, |_, _| {
                panic!("exclusive end must exclude the segment")
            })
            .unwrap();
        assert_eq!(budget.usage.segments, 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn invalid_event_time_disables_segment_pruning_without_hiding_valid_records() {
        let root = directory("invalid-time-bounds");
        let store = SegmentStore::open(root.clone()).unwrap();
        let mut invalid = event(1, "unknown time");
        invalid.timestamp = "invalid".into();
        let mut valid = event(2, "valid time");
        valid.timestamp = "2026-10-16T10:00:00Z".into();
        store.commit(&[invalid, valid.clone()]).unwrap();
        assert!(
            store.read_manifest().unwrap().segments[0]
                .time_bounds
                .as_ref()
                .unwrap()
                .minimum
                .is_none()
        );
        assert!(!store.ensure_indexes().unwrap());
        let range = TimeRange::parse(&crate::time_range::TimeRangeParams {
            from: Some("2026-10-16T00:00:00Z".into()),
            to: None,
        })
        .unwrap();
        let mut found = Vec::new();
        store
            .search_into_time_range(
                &Expr::MatchAll,
                &mut QueryBudget::new(ExecutionLimits::default()),
                &range,
                |event, _| {
                    found.push(event.clone());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(found, vec![valid]);
        assert_eq!(store.recover().unwrap().events.len(), 2);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn isolates_a_corrupted_segment() {
        let root = directory("corrupt");
        let _ = fs::remove_dir_all(&root);
        let store = SegmentStore::open(root.clone()).unwrap();
        let meta = store.commit(&[event(1, "first")]).unwrap().unwrap();
        OpenOptions::new()
            .append(true)
            .open(root.join("segments").join(meta.file))
            .unwrap()
            .write_all(b"corruption")
            .unwrap();
        let recovery = store.recover().unwrap();
        assert!(recovery.events.is_empty());
        assert_eq!(recovery.corrupted_segments, 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn retention_removes_oldest_segments_when_size_is_exceeded() {
        let root = directory("retention");
        let _ = fs::remove_dir_all(&root);
        let mut store = SegmentStore::open(root.clone()).unwrap();
        let first = store.commit(&[event(1, "first")]).unwrap().unwrap();
        store.max_bytes = first.storage_bytes().saturating_add(64);
        store.commit(&[event(2, "second")]).unwrap();
        let recovery = store.recover().unwrap();
        assert_eq!(recovery.segment_count, 1);
        assert_eq!(recovery.events.len(), 1);
        assert_eq!(recovery.events[0].message, "second");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn compaction_merges_segments_and_preserves_events() {
        let root = directory("compact");
        let _ = fs::remove_dir_all(&root);
        let mut store = SegmentStore::open(root.clone()).unwrap();
        store.clock = Some(now_unix());
        store.commit(&[event(1, "first")]).unwrap();
        store.commit(&[event(2, "second")]).unwrap();
        assert!(store.compact_all().unwrap());
        let recovery = store.recover().unwrap();
        assert_eq!(recovery.segment_count, 1);
        assert_eq!(recovery.events.len(), 2);
        assert_eq!(recovery.corrupted_indexes, 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corrupted_index_is_reported_without_losing_events() {
        let root = directory("index-corrupt");
        let _ = fs::remove_dir_all(&root);
        let store = SegmentStore::open(root.clone()).unwrap();
        let meta = store.commit(&[event(1, "first")]).unwrap().unwrap();
        let postings = meta.index.unwrap().postings.file;
        OpenOptions::new()
            .append(true)
            .open(root.join("segments").join(postings))
            .unwrap()
            .write_all(b"corruption")
            .unwrap();
        let recovery = store.recover().unwrap();
        assert_eq!(recovery.events.len(), 1);
        assert_eq!(recovery.corrupted_segments, 0);
        assert_eq!(recovery.corrupted_indexes, 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn searches_segment_postings_without_rebuilding_the_memory_index() {
        let root = directory("search");
        let _ = fs::remove_dir_all(&root);
        let store = SegmentStore::open(root.clone()).unwrap();
        let mut failed = event(1, "failed administrator login");
        failed.fields.insert("event.id".into(), "4625".into());
        let mut success = event(2, "accepted login");
        success.fields.insert("event.id".into(), "4624".into());
        store.commit(&[failed, success]).unwrap();
        let expression = crate::query::parse("event.id:4625 AND administrator").unwrap();
        let result = store.search(&expression, 10).unwrap();
        assert_eq!(result.total, 1);
        assert_eq!(result.events[0].fields["event.id"], "4625");
        let _ = fs::remove_dir_all(root);
    }
}

#[cfg(test)]
#[path = "retention_tests.rs"]
mod retention_tests;
