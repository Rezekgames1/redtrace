use crate::{
    index::{PreparedQuery, QueryBudget, QueryFailure},
    model::Event,
    query::Expr,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const POSTINGS_MAGIC: &[u8; 4] = b"RTP1";
const OFFSETS_MAGIC: &[u8; 4] = b"RTO1";
const INDEX_VERSION: u16 = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SidecarMeta {
    pub file: String,
    pub bytes: u64,
    pub checksum: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SegmentIndexMeta {
    #[serde(default = "legacy_index_version")]
    pub version: u16,
    pub fields: SidecarMeta,
    pub terms: SidecarMeta,
    pub postings: SidecarMeta,
    #[serde(default)]
    pub offsets: Option<SidecarMeta>,
}

#[derive(Debug)]
pub struct LoadedSegmentIndex {
    fields: Vec<(String, String)>,
    terms: Vec<String>,
    field_postings: Vec<BTreeSet<u32>>,
    term_postings: Vec<BTreeSet<u32>>,
    offsets: Vec<u64>,
    memory_bytes: usize,
}

impl SegmentIndexMeta {
    pub fn bytes(&self) -> u64 {
        self.fields.bytes
            + self.terms.bytes
            + self.postings.bytes
            + self.offsets.as_ref().map(|meta| meta.bytes).unwrap_or(0)
    }

    pub fn files(&self) -> Vec<&str> {
        let mut files = vec![
            self.fields.file.as_str(),
            self.terms.file.as_str(),
            self.postings.file.as_str(),
        ];
        if let Some(offsets) = &self.offsets {
            files.push(&offsets.file);
        }
        files
    }
}

pub fn write(directory: &Path, stem: &str, events: &[Event]) -> io::Result<SegmentIndexMeta> {
    let mut fields: BTreeMap<(String, String), BTreeSet<u32>> = BTreeMap::new();
    let mut terms: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    for (document, event) in events.iter().enumerate() {
        let document = u32::try_from(document)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "segment is too large"))?;
        for (field, value) in searchable_fields(event) {
            fields
                .entry((field, value.to_lowercase()))
                .or_default()
                .insert(document);
        }
        for term in tokenize(&event.message) {
            terms.entry(term).or_default().insert(document);
        }
    }

    let field_dictionary: Vec<_> = fields.keys().cloned().collect();
    let term_dictionary: Vec<_> = terms.keys().cloned().collect();
    let field_file = format!("{stem}.fields.json");
    let term_file = format!("{stem}.terms.json");
    let postings_file = format!("{stem}.postings.bin");
    let offsets_file = format!("{stem}.offsets.bin");
    let field_path = directory.join(&field_file);
    let term_path = directory.join(&term_file);
    let postings_path = directory.join(&postings_file);
    let offsets_path = directory.join(&offsets_file);

    write_json_atomic(&field_path, &field_dictionary)?;
    write_json_atomic(&term_path, &term_dictionary)?;
    write_postings_atomic(
        &postings_path,
        fields.values().map(|ids| ids.iter().copied()),
        terms.values().map(|ids| ids.iter().copied()),
    )?;
    write_offsets_atomic(&offsets_path, events)?;

    Ok(SegmentIndexMeta {
        version: INDEX_VERSION,
        fields: sidecar(field_file, &field_path)?,
        terms: sidecar(term_file, &term_path)?,
        postings: sidecar(postings_file, &postings_path)?,
        offsets: Some(sidecar(offsets_file, &offsets_path)?),
    })
}

pub fn validate(directory: &Path, index: &SegmentIndexMeta) -> io::Result<()> {
    if index.version != INDEX_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "outdated segment index version",
        ));
    }
    let offsets = index
        .offsets
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "segment offsets are missing"))?;
    for meta in [&index.fields, &index.terms, &index.postings, offsets] {
        let path = directory.join(&meta.file);
        if fs::metadata(&path)?.len() != meta.bytes || checksum_file(&path)? != meta.checksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("segment index checksum mismatch: {}", meta.file),
            ));
        }
    }
    let mut postings = File::open(directory.join(&index.postings.file))?;
    let mut magic = [0_u8; 4];
    postings.read_exact(&mut magic)?;
    if &magic != POSTINGS_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid postings header",
        ));
    }
    let mut offsets_file = File::open(directory.join(&offsets.file))?;
    offsets_file.read_exact(&mut magic)?;
    if &magic != OFFSETS_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid offsets header",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub fn load(directory: &Path, index: &SegmentIndexMeta) -> io::Result<LoadedSegmentIndex> {
    validate(directory, index)?;
    let fields: Vec<(String, String)> =
        serde_json::from_slice(&fs::read(directory.join(&index.fields.file))?)
            .map_err(io::Error::other)?;
    let terms: Vec<String> = serde_json::from_slice(&fs::read(directory.join(&index.terms.file))?)
        .map_err(io::Error::other)?;
    let (field_postings, term_postings) = read_postings(&directory.join(&index.postings.file))?;
    let offsets_meta = index
        .offsets
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "segment offsets are missing"))?;
    let offsets = read_offsets(&directory.join(&offsets_meta.file))?;
    if fields.len() != field_postings.len() || terms.len() != term_postings.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dictionary and postings lengths differ",
        ));
    }
    Ok(LoadedSegmentIndex {
        fields,
        terms,
        field_postings,
        term_postings,
        offsets,
        memory_bytes: 0,
    })
}

pub(crate) fn read_bounded(path: &Path, budget: &mut QueryBudget) -> io::Result<Vec<u8>> {
    budget.check()?;
    let mut file = File::open(path)?;
    let bytes = usize::try_from(file.metadata()?.len())
        .map_err(|_| io::Error::other(QueryFailure::SidecarBytes))?;
    if bytes > budget.limits.max_sidecar_bytes {
        return Err(io::Error::other(QueryFailure::SidecarBytes));
    }
    budget.scan(bytes as u64)?;
    budget.allocate(bytes.saturating_mul(2))?;
    let mut data = Vec::with_capacity(bytes);
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        budget.work(1)?;
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if data.len().saturating_add(read) > bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "query file changed while reading",
            ));
        }
        data.extend_from_slice(&buffer[..read]);
    }
    Ok(data)
}

fn read_sidecar(
    directory: &Path,
    meta: &SidecarMeta,
    budget: &mut QueryBudget,
) -> io::Result<Vec<u8>> {
    let bytes = read_bounded(&directory.join(&meta.file), budget)?;
    if bytes.len() as u64 != meta.bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "segment index size mismatch",
        ));
    }
    let mut hash = 0xcbf29ce484222325_u64;
    for chunk in bytes.chunks(16 * 1024) {
        budget.work((chunk.len() as u64).div_ceil(64))?;
        for byte in chunk {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    if hash != meta.checksum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "segment index checksum mismatch",
        ));
    }
    Ok(bytes)
}

pub fn load_bounded(
    directory: &Path,
    index: &SegmentIndexMeta,
    budget: &mut QueryBudget,
) -> io::Result<LoadedSegmentIndex> {
    if index.version != INDEX_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "outdated segment index version",
        ));
    }
    let initial_memory = budget.usage.memory_bytes;
    let fields_bytes = read_sidecar(directory, &index.fields, budget)?;
    budget.allocate(fields_bytes.len().saturating_mul(16))?;
    let fields: Vec<(String, String)> =
        serde_json::from_slice(&fields_bytes).map_err(io::Error::other)?;
    budget.check()?;
    budget.release(fields_bytes.len().saturating_mul(2));
    drop(fields_bytes);
    let terms_bytes = read_sidecar(directory, &index.terms, budget)?;
    budget.allocate(terms_bytes.len().saturating_mul(16))?;
    let terms: Vec<String> = serde_json::from_slice(&terms_bytes).map_err(io::Error::other)?;
    budget.check()?;
    budget.release(terms_bytes.len().saturating_mul(2));
    drop(terms_bytes);
    let offsets_meta = index
        .offsets
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "segment offsets are missing"))?;
    let offsets_bytes = read_sidecar(directory, offsets_meta, budget)?;
    let mut reader = io::Cursor::new(&offsets_bytes);
    let mut magic = [0; 4];
    reader.read_exact(&mut magic)?;
    if &magic != OFFSETS_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid offsets header",
        ));
    }
    let count = read_u32(&mut reader)? as usize;
    if count > budget.limits.max_documents {
        return Err(io::Error::other(QueryFailure::Documents));
    }
    if count.saturating_mul(8).saturating_add(8) != offsets_bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid offsets count",
        ));
    }
    budget.allocate(count.saturating_mul(8))?;
    let mut offsets = Vec::with_capacity(count);
    for _ in 0..count {
        budget.work(1)?;
        let mut bytes = [0; 8];
        reader.read_exact(&mut bytes)?;
        let offset = u64::from_le_bytes(bytes);
        if offsets.last().is_some_and(|last| *last >= offset) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid offset order",
            ));
        }
        offsets.push(offset);
    }
    budget.release(offsets_bytes.len().saturating_mul(2));
    drop(offsets_bytes);
    let postings_bytes = read_sidecar(directory, &index.postings, budget)?;
    let mut reader = io::Cursor::new(&postings_bytes);
    reader.read_exact(&mut magic)?;
    if &magic != POSTINGS_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid postings header",
        ));
    }
    let field_count = read_u32(&mut reader)? as usize;
    let term_count = read_u32(&mut reader)? as usize;
    if field_count != fields.len() || term_count != terms.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dictionary and postings lengths differ",
        ));
    }
    budget.allocate((field_count + term_count).saturating_mul(64))?;
    let mut all = Vec::with_capacity(field_count + term_count);
    for _ in 0..field_count + term_count {
        budget.work(1)?;
        let count = read_u32(&mut reader)? as usize;
        if count > offsets.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid posting count",
            ));
        }
        budget.allocate(count.saturating_mul(64))?;
        let mut posting = BTreeSet::new();
        let mut document = 0_u32;
        for entry in 0..count {
            budget.work(1)?;
            let delta = read_varint(&mut reader)?;
            if entry > 0 && delta == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate posting",
                ));
            }
            document = document.checked_add(delta).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "posting delta overflow")
            })?;
            if document as usize >= offsets.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "posting outside segment",
                ));
            }
            posting.insert(document);
        }
        all.push(posting);
    }
    if reader.position() != postings_bytes.len() as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing postings bytes",
        ));
    }
    budget.release(postings_bytes.len().saturating_mul(2));
    let term_postings = all.split_off(field_count);
    Ok(LoadedSegmentIndex {
        fields,
        terms,
        field_postings: all,
        term_postings,
        offsets,
        memory_bytes: budget.usage.memory_bytes - initial_memory,
    })
}

impl LoadedSegmentIndex {
    pub(crate) fn memory_bytes(&self) -> usize {
        self.memory_bytes
    }

    pub(crate) fn prepare<'a>(
        &'a self,
        expression: &Expr,
        budget: &mut QueryBudget,
    ) -> io::Result<PreparedQuery<'a, u32>> {
        PreparedQuery::prepare(
            expression,
            &|| {
                self.fields
                    .iter()
                    .zip(&self.field_postings)
                    .map(|((name, value), posting)| (name.as_str(), value.as_str(), posting))
            },
            &|| {
                self.terms
                    .iter()
                    .zip(&self.term_postings)
                    .map(|(term, posting)| (term.as_str(), posting))
            },
            budget,
        )
    }

    pub(crate) fn event_count(&self) -> usize {
        self.offsets.len()
    }
    pub fn offset(&self, document: u32) -> Option<u64> {
        self.offsets.get(document as usize).copied()
    }
    #[cfg(test)]
    pub fn evaluate(&self, expression: &Expr, event_count: usize) -> BTreeSet<u32> {
        match expression {
            Expr::MatchAll => (0..event_count)
                .filter_map(|value| u32::try_from(value).ok())
                .collect(),
            Expr::Exists(field) => self.match_values(Some(field), "", false),
            Expr::Value {
                field,
                value,
                exact,
            } => self.match_values(field.as_deref(), value, *exact),
            Expr::And(left, right) => {
                &self.evaluate(left, event_count) & &self.evaluate(right, event_count)
            }
            Expr::Or(left, right) => {
                &self.evaluate(left, event_count) | &self.evaluate(right, event_count)
            }
            Expr::Not(inner) => {
                &self.evaluate(&Expr::MatchAll, event_count) - &self.evaluate(inner, event_count)
            }
            Expr::Term {
                field: None,
                value,
                prefix,
            } => self.match_text(value, *prefix),
            Expr::Term {
                field: Some(field),
                value,
                prefix,
            } if field == "message" => self.match_text(value, *prefix),
            Expr::Term {
                field: Some(field),
                value,
                prefix,
            } => self.match_field(field, value, *prefix),
        }
    }

    #[cfg(test)]
    fn match_field(&self, field: &str, value: &str, prefix: bool) -> BTreeSet<u32> {
        self.fields
            .iter()
            .zip(&self.field_postings)
            .filter(|((candidate_field, candidate_value), _)| {
                candidate_field == crate::index::canonical_field(field)
                    && if prefix {
                        candidate_value.starts_with(value)
                    } else {
                        candidate_value == value
                    }
            })
            .fold(BTreeSet::new(), |matches, (_, posting)| &matches | posting)
    }

    #[cfg(test)]
    fn match_values(&self, field: Option<&str>, value: &str, exact: bool) -> BTreeSet<u32> {
        self.fields
            .iter()
            .zip(&self.field_postings)
            .filter(|((name, candidate), _)| {
                field.is_none_or(|field| name == crate::index::canonical_field(field))
                    && if exact {
                        candidate == value
                    } else {
                        candidate.contains(value)
                    }
            })
            .fold(BTreeSet::new(), |matches, (_, posting)| &matches | posting)
    }

    #[cfg(test)]
    fn match_text(&self, value: &str, prefix: bool) -> BTreeSet<u32> {
        let mut groups = tokenize(value).into_iter().map(|token| {
            self.terms
                .iter()
                .zip(&self.term_postings)
                .filter(|(candidate, _)| {
                    if prefix {
                        candidate.starts_with(&token)
                    } else {
                        *candidate == &token
                    }
                })
                .fold(BTreeSet::new(), |matches, (_, posting)| &matches | posting)
        });
        let Some(first) = groups.next() else {
            return BTreeSet::new();
        };
        groups.fold(first, |matches, posting| &matches & &posting)
    }
}

#[cfg(test)]
type PostingGroups = (Vec<BTreeSet<u32>>, Vec<BTreeSet<u32>>);

#[cfg(test)]
fn read_postings(path: &Path) -> io::Result<PostingGroups> {
    let mut file = File::open(path)?;
    let mut magic = [0_u8; 4];
    file.read_exact(&mut magic)?;
    if &magic != POSTINGS_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid postings header",
        ));
    }
    let field_count = read_u32(&mut file)? as usize;
    let term_count = read_u32(&mut file)? as usize;
    let mut all = Vec::with_capacity(field_count + term_count);
    for _ in 0..field_count + term_count {
        let count = read_u32(&mut file)? as usize;
        let mut posting = BTreeSet::new();
        let mut document = 0_u32;
        for index in 0..count {
            let delta = read_varint(&mut file)?;
            document = if index == 0 {
                delta
            } else {
                document.checked_add(delta).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "posting delta overflow")
                })?
            };
            posting.insert(document);
        }
        all.push(posting);
    }
    let terms = all.split_off(field_count);
    Ok((all, terms))
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
fn read_offsets(path: &Path) -> io::Result<Vec<u64>> {
    let mut file = File::open(path)?;
    let mut magic = [0_u8; 4];
    file.read_exact(&mut magic)?;
    if &magic != OFFSETS_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid offsets header",
        ));
    }
    let count = read_u32(&mut file)? as usize;
    let mut offsets = Vec::with_capacity(count);
    for _ in 0..count {
        let mut bytes = [0_u8; 8];
        file.read_exact(&mut bytes)?;
        offsets.push(u64::from_le_bytes(bytes));
    }
    Ok(offsets)
}

fn read_varint(reader: &mut impl Read) -> io::Result<u32> {
    let mut value = 0_u32;
    for shift in (0..35).step_by(7) {
        let mut byte = [0_u8; 1];
        reader.read_exact(&mut byte)?;
        value |= u32::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "varint is too long",
    ))
}

fn searchable_fields(event: &Event) -> Vec<(String, String)> {
    let mut values = vec![
        ("uid".into(), event.uid.clone()),
        ("event.uid".into(), event.uid.clone()),
        ("@timestamp".into(), event.timestamp.clone()),
        ("source".into(), event.source.clone()),
        ("log.source".into(), event.source.clone()),
        ("level".into(), event.level.clone()),
        ("event.description".into(), event.message.clone()),
    ];
    values.extend(
        event
            .fields
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    values
}

pub fn is_current(index: &SegmentIndexMeta) -> bool {
    index.version == INDEX_VERSION
}

fn legacy_index_version() -> u16 {
    1
}

fn tokenize(value: &str) -> BTreeSet<String> {
    value
        .split(|c: char| !c.is_alphanumeric() && !matches!(c, '.' | '_' | '\\'))
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let temp = temporary_path(path)?;
    let mut file = private_file(&temp)?;
    serde_json::to_writer(&mut file, value).map_err(io::Error::other)?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.sync_all()?;
    fs::rename(temp, path)
}

fn write_offsets_atomic(path: &Path, events: &[Event]) -> io::Result<()> {
    let temp = temporary_path(path)?;
    let mut file = private_file(&temp)?;
    file.write_all(OFFSETS_MAGIC)?;
    file.write_all(&(events.len() as u32).to_le_bytes())?;
    let mut offset = 0_u64;
    for event in events {
        file.write_all(&offset.to_le_bytes())?;
        let bytes = serde_json::to_vec(event).map_err(io::Error::other)?;
        offset = offset.saturating_add(bytes.len() as u64 + 1);
    }
    file.flush()?;
    file.sync_all()?;
    fs::rename(temp, path)
}

fn write_postings_atomic<FI, TI, FP, TP>(
    path: &Path,
    field_postings: FI,
    term_postings: TI,
) -> io::Result<()>
where
    FI: IntoIterator<Item = FP>,
    TI: IntoIterator<Item = TP>,
    FP: IntoIterator<Item = u32>,
    TP: IntoIterator<Item = u32>,
{
    let field_postings: Vec<Vec<u32>> = field_postings
        .into_iter()
        .map(|posting| posting.into_iter().collect())
        .collect();
    let term_postings: Vec<Vec<u32>> = term_postings
        .into_iter()
        .map(|posting| posting.into_iter().collect())
        .collect();
    let temp = temporary_path(path)?;
    let mut file = private_file(&temp)?;
    file.write_all(POSTINGS_MAGIC)?;
    file.write_all(&(field_postings.len() as u32).to_le_bytes())?;
    file.write_all(&(term_postings.len() as u32).to_le_bytes())?;
    for posting in field_postings.iter().chain(term_postings.iter()) {
        file.write_all(&(posting.len() as u32).to_le_bytes())?;
        let mut previous = 0_u32;
        for (index, document) in posting.iter().copied().enumerate() {
            let delta = if index == 0 {
                document
            } else {
                document - previous
            };
            write_varint(&mut file, delta)?;
            previous = document;
        }
    }
    file.flush()?;
    file.sync_all()?;
    fs::rename(temp, path)
}

fn write_varint(writer: &mut impl Write, mut value: u32) -> io::Result<()> {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        writer.write_all(&[byte])?;
        if value == 0 {
            return Ok(());
        }
    }
}

fn temporary_path(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing filename"))?
        .to_string_lossy();
    Ok(path.with_file_name(format!(".{name}.tmp")))
}

fn sidecar(file: String, path: &Path) -> io::Result<SidecarMeta> {
    Ok(SidecarMeta {
        file,
        bytes: fs::metadata(path)?.len(),
        checksum: checksum_file(path)?,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn query_fixture(name: &str) -> (PathBuf, crate::storage::SegmentStore, Vec<Event>) {
        let root = std::env::temp_dir().join("opencode").join(format!(
            "redtrace-query-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = crate::storage::SegmentStore::open(root.clone()).unwrap();
        let events: Vec<_> = (0..120)
            .map(|id| {
                Event::normalized(
                    id,
                    format!("2026-10-12T10:{:02}:{:02}Z", id / 60, id % 60),
                    "test.query".into(),
                    "low".into(),
                    format!("event {id} login"),
                    BTreeMap::from([(
                        "event.id".into(),
                        if id % 2 == 0 { "4625" } else { "4624" }.into(),
                    )]),
                )
            })
            .collect();
        store.commit(&events[..60]).unwrap();
        store.commit(&events[60..]).unwrap();
        (root, store, events)
    }

    #[test]
    fn bounded_disk_queries_page_and_count_across_segments() {
        let (root, store, events) = query_fixture("pages");
        let memory = crate::index::EventIndex::from_events(events);
        for raw in [
            "*",
            "NOT event.id=4625",
            "event.id:4625 OR message~119",
            "event.id:* AND login",
            "source:test.*",
        ] {
            let expression = crate::query::parse(raw).unwrap();
            let mut budget = QueryBudget::new(crate::index::ExecutionLimits::default());
            let disk = store
                .search_page_bounded(&expression, 9, None, &mut budget)
                .unwrap();
            let expected = memory
                .search_page_bounded(
                    &expression,
                    9,
                    None,
                    &mut QueryBudget::new(crate::index::ExecutionLimits::default()),
                )
                .unwrap();
            assert_eq!(disk.total, expected.total, "{raw}");
            assert_eq!(disk.events, expected.events, "{raw}");
            let last = disk.events.last().unwrap();
            let next = store
                .search_page(&expression, 9, Some((&last.timestamp, &last.uid)))
                .unwrap();
            assert_eq!(next.total, disk.total);
            assert!(next.events.iter().all(|event| !disk.events.contains(event)));
        }
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_disk_work_memory_io_and_segment_limits_fail_closed() {
        let (root, store, _) = query_fixture("limits");
        for (limits, expected) in [
            (
                crate::index::ExecutionLimits {
                    max_segments: 1,
                    ..Default::default()
                },
                QueryFailure::Segments,
            ),
            (
                crate::index::ExecutionLimits {
                    max_scan_bytes: 1,
                    ..Default::default()
                },
                QueryFailure::ScanBytes,
            ),
            (
                crate::index::ExecutionLimits {
                    max_sidecar_bytes: 1,
                    ..Default::default()
                },
                QueryFailure::SidecarBytes,
            ),
            (
                crate::index::ExecutionLimits {
                    max_record_bytes: 1,
                    ..Default::default()
                },
                QueryFailure::RecordBytes,
            ),
            (
                crate::index::ExecutionLimits {
                    max_documents: 1,
                    ..Default::default()
                },
                QueryFailure::Documents,
            ),
        ] {
            let error = store
                .search_page_bounded(&Expr::MatchAll, 3, None, &mut QueryBudget::new(limits))
                .unwrap_err();
            assert_eq!(
                crate::index::query_failure(&error),
                Some(expected),
                "{expected:?}"
            );
        }
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn disk_scan_cancellation_stops_before_next_record() {
        let (root, store, _) = query_fixture("cancel");
        let mut budget = QueryBudget::new(crate::index::ExecutionLimits::default());
        let cancellation = budget.cancellation();
        let mut visited = 0;
        let error = store
            .search_into(&Expr::MatchAll, &mut budget, |_, _| {
                visited += 1;
                cancellation.cancel();
                Ok(())
            })
            .unwrap_err();
        assert_eq!(visited, 1);
        assert_eq!(
            crate::index::query_failure(&error),
            Some(QueryFailure::Cancelled)
        );
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn writes_dictionaries_and_delta_encoded_postings() {
        let directory =
            std::env::temp_dir().join(format!("redtrace-postings-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let events = vec![
            Event::normalized(
                1,
                "2026-01-01T00:00:00Z".into(),
                "test".into(),
                "low".into(),
                "failed login".into(),
                BTreeMap::from([("event.id".into(), "4625".into())]),
            ),
            Event::normalized(
                2,
                "2026-01-01T00:00:01Z".into(),
                "test".into(),
                "low".into(),
                "login accepted".into(),
                BTreeMap::from([("event.id".into(), "4624".into())]),
            ),
        ];
        let meta = write(&directory, "0001", &events).unwrap();
        validate(&directory, &meta).unwrap();
        let loaded = load(&directory, &meta).unwrap();
        let memory = crate::index::EventIndex::from_events(events.clone());
        for query in [
            "login",
            "\"login accepted\"",
            "source=test",
            "source~es",
            "event.id:*",
            "NOT event.id=4625",
            "event.id:4625 OR message~accepted",
            "timestamp~2026",
            "event.level=low",
        ] {
            let expression = crate::query::parse(query).unwrap();
            assert_eq!(
                loaded.evaluate(&expression, events.len()).len(),
                memory.search(&expression, 20).unwrap().total,
                "{query}"
            );
        }
        let terms: Vec<String> =
            serde_json::from_slice(&fs::read(directory.join(meta.terms.file)).unwrap()).unwrap();
        assert!(terms.contains(&"login".into()));
        let _ = fs::remove_dir_all(directory);
    }
}
