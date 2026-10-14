//! Direct auditd log ingestion. Event groups share node/timestamp/serial; checkpoints
//! always point before the first group which has not been emitted durably.
use super::{BoundedLine, BoundedLines, CollectionBatch, SourceStatus};
use crate::{config::Resources, model::Event, storage::CheckpointStore};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{self, BufReader, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug)]
struct Record {
    key: String,
    timestamp: String,
    kind: String,
    values: BTreeMap<String, String>,
    raw: String,
}

/// Audit quoted values are not shell strings; unquoted path/argv strings may be hex.
fn values(line: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let bytes = line.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() && out.len() < 256 {
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        let start = pos;
        while pos < bytes.len() && !matches!(bytes[pos], b'=' | b' ' | b'\n' | b'\t') {
            pos += 1;
        }
        if pos >= bytes.len() || bytes[pos] != b'=' {
            pos += usize::from(pos < bytes.len());
            continue;
        }
        let key = &line[start..pos];
        pos += 1;
        let quote = bytes
            .get(pos)
            .copied()
            .filter(|b| matches!(b, b'"' | b'\''));
        if quote.is_some() {
            pos += 1;
        }
        let start = pos;
        while pos < bytes.len()
            && quote.map_or(!bytes[pos].is_ascii_whitespace(), |q| bytes[pos] != q)
        {
            pos += 1;
        }
        if !key.is_empty() && key.len() <= 64 {
            out.insert(
                key.into(),
                if let Some(q) = quote {
                    format!("{}{}{}", q as char, &line[start..pos], q as char)
                } else {
                    line[start..pos].into()
                },
            );
        }
        if quote.is_some() && pos < bytes.len() {
            pos += 1;
        }
    }
    out
}

fn decode(value: &str) -> String {
    if value.len() >= 2
        && (value.starts_with('"') && value.ends_with('"')
            || value.starts_with('\'') && value.ends_with('\''))
    {
        return value[1..value.len() - 1].into();
    }
    if value.len() >= 2
        && value.len().is_multiple_of(2)
        && value.bytes().all(|b| b.is_ascii_hexdigit())
    {
        let bytes: Vec<u8> = value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).unwrap_or(""), 16).unwrap_or(0)
            })
            .collect();
        if let Ok(text) = String::from_utf8(bytes) {
            return text;
        }
    }
    value.into()
}

fn parse(line: &str) -> io::Result<Record> {
    let values = values(line);
    let kind = values
        .get("type")
        .filter(|v| v.len() < 64)
        .ok_or_else(|| io::Error::other("audit record has no type"))?
        .clone();
    let at = line
        .find("msg=audit(")
        .ok_or_else(|| io::Error::other("audit record has no event identity"))?
        + 10;
    let end = line[at..]
        .find(')')
        .ok_or_else(|| io::Error::other("incomplete audit identity"))?
        + at;
    let identity = &line[at..end];
    let (seconds, serial) = identity
        .split_once(':')
        .ok_or_else(|| io::Error::other("invalid audit identity"))?;
    if serial.is_empty() || !serial.bytes().all(|b| b.is_ascii_digit()) {
        return Err(io::Error::other("invalid audit serial"));
    }
    let (seconds, fraction) = seconds.split_once('.').unwrap_or((seconds, "0"));
    let seconds = seconds.parse::<i64>().map_err(io::Error::other)?;
    if fraction.is_empty() || fraction.len() > 9 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err(io::Error::other("invalid audit timestamp"));
    }
    let nanos = format!("{fraction:0<9}")
        .parse::<u32>()
        .map_err(io::Error::other)?;
    let timestamp = DateTime::from_timestamp(seconds, nanos)
        .ok_or_else(|| io::Error::other("invalid audit timestamp"))?
        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let node = values.get("node").map(String::as_str).unwrap_or("local");
    Ok(Record {
        key: format!("{node}:{identity}"),
        timestamp,
        kind,
        values,
        raw: line.trim_end().into(),
    })
}

struct Group {
    start: u64,
    records: Vec<Record>,
    bytes: usize,
    complete: bool,
    partial: bool,
}

fn event(group: Group, cursor: &str) -> Event {
    let first = &group.records[0];
    let mut fields = BTreeMap::from([
        ("audit.event_id".into(), first.key.clone()),
        ("collector.cursor".into(), cursor.into()),
        ("collector.cursor_kind".into(), "file".into()),
        (
            "event.original".into(),
            group
                .records
                .iter()
                .map(|r| r.raw.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        ("audit.partial".into(), group.partial.to_string()),
        ("parser.version".into(), "1".into()),
    ]);
    let mut args = BTreeMap::<usize, String>::new();
    let mut fragments = BTreeMap::<usize, BTreeMap<usize, String>>::new();
    let mut paths = BTreeMap::<usize, String>::new();
    for record in &group.records {
        match record.kind.as_str() {
            "SYSCALL" => {
                for (from, to) in [
                    ("pid", "process.pid"),
                    ("ppid", "process.parent.pid"),
                    ("uid", "user.id"),
                    ("auid", "user.audit.id"),
                    ("euid", "user.effective.id"),
                    ("gid", "group.id"),
                    ("ses", "session.id"),
                    ("syscall", "audit.syscall"),
                    ("arch", "audit.arch"),
                    ("exit", "event.code"),
                    ("key", "audit.key"),
                ] {
                    if let Some(value) = record.values.get(from) {
                        fields.insert(to.into(), value.clone());
                    }
                }
                for (from, to) in [("exe", "process.executable"), ("comm", "process.name")] {
                    if let Some(value) = record.values.get(from) {
                        fields.insert(to.into(), decode(value));
                    }
                }
                fields.insert(
                    "event.outcome".into(),
                    if record.values.get("success").is_some_and(|v| v == "yes") {
                        "success"
                    } else {
                        "failure"
                    }
                    .into(),
                );
            }
            "EXECVE" => {
                for (key, value) in &record.values {
                    if let Some(arg) = key.strip_prefix('a') {
                        if let Ok(index) = arg.parse::<usize>() {
                            if index < 256 {
                                args.insert(index, decode(value));
                            }
                        } else if let Some((index, part)) = arg.split_once('[')
                            && let (Ok(index), Ok(part)) = (
                                index.parse::<usize>(),
                                part.trim_end_matches(']').parse::<usize>(),
                            )
                            && index < 256
                            && part < 256
                        {
                            fragments
                                .entry(index)
                                .or_default()
                                .insert(part, value.clone());
                        }
                    }
                }
            }
            "CWD" => {
                if let Some(value) = record.values.get("cwd") {
                    fields.insert("process.working_directory".into(), decode(value));
                }
            }
            "PATH" => {
                if let Some(value) = record.values.get("name") {
                    let item = record
                        .values
                        .get("item")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(paths.len());
                    if item < 64 {
                        paths.insert(item, decode(value));
                    }
                }
            }
            "PROCTITLE" => {
                if let Some(value) = record.values.get("proctitle") {
                    fields.insert(
                        "process.command_line".into(),
                        decode(value).replace('\0', " "),
                    );
                }
            }
            "SOCKADDR" => {
                if let Some(address) = record.values.get("saddr") {
                    socket_address(address, &mut fields);
                }
            }
            _ => {}
        }
    }
    for (index, parts) in fragments {
        args.entry(index).or_insert_with(|| {
            // Audit splits long arguments by bytes. Decode after reassembly so a UTF-8
            // character split between two hex fragments keeps its original bytes.
            if parts.values().all(|part| !part.starts_with(['\"', '\''])) {
                decode(&parts.into_values().collect::<String>())
            } else {
                parts.into_values().map(|part| decode(&part)).collect()
            }
        });
    }
    if !args.is_empty() {
        fields.insert(
            "process.args".into(),
            serde_json::to_string(&args.values().collect::<Vec<_>>()).unwrap_or_default(),
        );
        fields.insert(
            "process.command_line".into(),
            args.into_values()
                .map(|v| {
                    if v.contains(char::is_whitespace) {
                        format!("{v:?}")
                    } else {
                        v
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    if let Some(path) = paths.values().next() {
        fields.insert("file.path".into(), path.clone());
    }
    if !paths.is_empty() {
        fields.insert(
            "file.paths".into(),
            serde_json::to_string(&paths.into_values().collect::<Vec<_>>()).unwrap_or_default(),
        );
    }
    let exec = group.records.iter().any(|r| r.kind == "EXECVE");
    let network = fields.contains_key("destination.ip") || fields.contains_key("unix.socket.path");
    fields.insert(
        "event.category".into(),
        if exec {
            "process"
        } else if network {
            "network"
        } else if fields.contains_key("file.path") {
            "file"
        } else {
            "system"
        }
        .into(),
    );
    fields.insert(
        "event.id".into(),
        if exec {
            "process.exec"
        } else if network {
            "network.socket"
        } else {
            "audit.syscall"
        }
        .into(),
    );
    fields.insert(
        "event.action".into(),
        if exec { "exec" } else { "syscall" }.into(),
    );
    fields.insert(
        "audit.record_types".into(),
        group
            .records
            .iter()
            .map(|r| r.kind.as_str())
            .collect::<Vec<_>>()
            .join(","),
    );
    let description = fields
        .get("process.command_line")
        .or_else(|| fields.get("process.executable"))
        .cloned()
        .unwrap_or_else(|| first.kind.clone());
    let mut event = Event::normalized(
        0,
        first.timestamp.clone(),
        "linux.audit".into(),
        "low".into(),
        format!("audit: {description}"),
        fields,
    );
    event.identify(&first.key);
    crate::modules::normalize(&mut event);
    event
}

fn socket_address(value: &str, fields: &mut BTreeMap<String, String>) {
    if value.len() > 8192
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return;
    }
    let bytes: Vec<u8> = value
        .as_bytes()
        .chunks_exact(2)
        .filter_map(|v| u8::from_str_radix(std::str::from_utf8(v).ok()?, 16).ok())
        .collect();
    if bytes.len() < 2 {
        return;
    }
    let family_bytes = [bytes[0], bytes[1]];
    let little = u16::from_le_bytes(family_bytes);
    let family = if matches!(little, 1 | 2 | 10) {
        little
    } else {
        u16::from_be_bytes(family_bytes)
    };
    match family {
        2 if bytes.len() >= 8 => {
            fields.insert(
                "destination.ip".into(),
                std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]).to_string(),
            );
            fields.insert(
                "destination.port".into(),
                u16::from_be_bytes([bytes[2], bytes[3]]).to_string(),
            );
            fields.insert("network.type".into(), "ipv4".into());
        }
        10 if bytes.len() >= 24 => {
            if let Ok(address) = <[u8; 16]>::try_from(&bytes[8..24]) {
                fields.insert(
                    "destination.ip".into(),
                    std::net::Ipv6Addr::from(address).to_string(),
                );
                fields.insert(
                    "destination.port".into(),
                    u16::from_be_bytes([bytes[2], bytes[3]]).to_string(),
                );
                fields.insert("network.type".into(), "ipv6".into());
            }
        }
        1 => {
            fields.insert(
                "unix.socket.path".into(),
                String::from_utf8_lossy(&bytes[2..])
                    .trim_end_matches('\0')
                    .into(),
            );
            fields.insert("network.type".into(), "unix".into());
        }
        _ => {}
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct FileCursor {
    pub identity: String,
    pub offset: u64,
}
pub(crate) fn file_identity(file: &File) -> io::Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata()?;
        Ok(format!("{}:{}", m.dev(), m.ino()))
    }
    #[cfg(not(unix))]
    {
        let m = file.metadata()?;
        Ok(format!("{:?}", m.created()?))
    }
}

fn locate(path: &Path, cursor: Option<&FileCursor>) -> io::Result<(File, bool)> {
    let file = File::open(path)?;
    if let Some(cursor) = cursor {
        if file_identity(&file)? == cursor.identity && file.metadata()?.len() >= cursor.offset {
            return Ok((file, false));
        }
        // auditd's numeric rotations, newest to oldest. Never skip a still-present old inode.
        for suffix in 1..=20 {
            let rotated = PathBuf::from(format!("{}.{suffix}", path.display()));
            if let Ok(old) = File::open(rotated)
                && file_identity(&old)? == cursor.identity
                && old.metadata()?.len() >= cursor.offset
            {
                return Ok((old, true));
            }
        }
        return Err(io::Error::other(
            "audit checkpoint file disappeared or was truncated; source history gap detected; reset the source explicitly to continue",
        ));
    }
    Ok((file, false))
}

pub fn collect(path: &Path, checkpoints: &CheckpointStore, limits: &Resources) -> CollectionBatch {
    match read(path, checkpoints, limits) {
        Ok((events, warning)) => CollectionBatch {
            status: SourceStatus {
                name: "linux.audit".into(),
                platform: "linux".into(),
                state: if warning.is_some() {
                    "degraded"
                } else {
                    "ready"
                }
                .into(),
                events_collected: events.len(),
                lookback: "durable audit file cursor".into(),
                last_error: warning,
            },
            events,
        },
        Err(error) => CollectionBatch {
            events: Vec::new(),
            status: SourceStatus {
                name: "linux.audit".into(),
                platform: "linux".into(),
                state: "error".into(),
                events_collected: 0,
                lookback: "audit file".into(),
                last_error: Some(error.to_string()),
            },
        },
    }
}

fn read(
    path: &Path,
    checkpoints: &CheckpointStore,
    limits: &Resources,
) -> io::Result<(Vec<Event>, Option<String>)> {
    let checkpoint = checkpoints.get("linux.audit");
    let cursor = checkpoint
        .as_ref()
        .map(|cp| serde_json::from_str::<FileCursor>(&cp.cursor))
        .transpose()
        .map_err(io::Error::other)?;
    let (mut file, rotated) = locate(path, cursor.as_ref())?;
    let identity = file_identity(&file)?;
    let metadata = file.metadata()?;
    let offset = cursor.as_ref().map(|cp| cp.offset).unwrap_or(0);
    // When a fully consumed rotated log is still present, start the next newer file.
    if rotated && offset == metadata.len() {
        for suffix in 1..=20 {
            if let Ok(old) = File::open(format!("{}.{suffix}", path.display()))
                && file_identity(&old)? == identity
            {
                let next = if suffix == 1 {
                    path.to_path_buf()
                } else {
                    PathBuf::from(format!("{}.{suffix}", path.display(), suffix = suffix - 1))
                };
                return read_file(File::open(next)?, 0, limits, suffix > 1);
            }
        }
    }
    file.seek(SeekFrom::Start(offset))?;
    read_file(file, offset, limits, rotated)
}

fn read_file(
    file: File,
    offset: u64,
    limits: &Resources,
    closed: bool,
) -> io::Result<(Vec<Event>, Option<String>)> {
    let identity = file_identity(&file)?;
    let stable = closed
        || file.metadata()?.modified()?.elapsed().unwrap_or_default() >= Duration::from_secs(2);
    let mut lines = BoundedLines::new(BufReader::new(file), limits.max_record_bytes);
    let mut position = offset;
    let mut groups = BTreeMap::<u64, Group>::new();
    let mut keys = HashMap::<String, u64>::new();
    let mut bytes = 0;
    let mut warning = None;
    let mut eof = false;
    loop {
        if groups.len() >= limits.max_aggregation_events
            || bytes >= limits.max_aggregation_bytes
            || position - offset >= limits.max_batch_bytes as u64
        {
            break;
        }
        let raw = match lines.read_line()? {
            BoundedLine::Complete(raw) => raw,
            BoundedLine::End => {
                eof = true;
                break;
            }
            BoundedLine::Incomplete => {
                warning = Some("incomplete audit line; durable cursor held".into());
                break;
            }
            BoundedLine::Oversized => {
                warning = Some("oversized audit line; durable cursor held".into());
                break;
            }
        };
        let start = position;
        position += raw.len() as u64;
        let line = match std::str::from_utf8(&raw) {
            Ok(line) => line,
            Err(_) => {
                warning = Some("audit log contains invalid UTF-8; durable cursor held".into());
                position = start;
                break;
            }
        };
        let record = match parse(line) {
            Ok(record) => record,
            Err(error) => {
                warning = Some(format!("{error}; durable cursor held"));
                position = start;
                break;
            }
        };
        let key = record.key.clone();
        let start = *keys.entry(key).or_insert(start);
        let group = groups.entry(start).or_insert_with(|| Group {
            start,
            records: Vec::new(),
            bytes: 0,
            complete: false,
            partial: false,
        });
        if group.complete {
            group.complete = false;
            position = start;
            warning = Some("audit event received records after EOE; cursor held".into());
            break;
        }
        if group.bytes + raw.len() > 60 * 1024 || group.records.len() >= 128 {
            group.complete = false;
            position = start;
            warning = Some("audit event aggregation cap reached; cursor held".into());
            break;
        }
        group.bytes += raw.len();
        bytes += raw.len();
        group.complete = record.kind == "EOE";
        group.records.push(record);
    }
    if eof && stable {
        for group in groups.values_mut() {
            if !group.complete {
                group.complete = true;
                group.partial = true;
            }
        }
    }
    let mut events = Vec::new();
    while let Some((&start, group)) = groups.first_key_value() {
        if !group.complete || events.len() >= limits.max_batch_events {
            break;
        }
        let group = groups
            .remove(&start)
            .ok_or_else(|| io::Error::other("audit aggregation changed"))?;
        let boundary = groups
            .first_key_value()
            .map(|(_, g)| g.start)
            .unwrap_or(position);
        let cursor = serde_json::to_string(&FileCursor {
            identity: identity.clone(),
            offset: boundary,
        })
        .map_err(io::Error::other)?;
        events.push(event(group, &cursor));
    }
    if !groups.is_empty() && warning.is_none() && !eof {
        warning =
            Some("audit aggregation budget reached; remaining source records retained".into());
    }
    Ok((events, warning))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn argument_fragments_decode_after_reassembling_utf8_bytes() {
        let record =
            parse("type=EXECVE msg=audit(1700000000.123:42): argc=1 a0_len=3 a0[0]=E2 a0[1]=82AC")
                .unwrap();
        let result = event(
            Group {
                start: 0,
                records: vec![record],
                bytes: 0,
                complete: true,
                partial: false,
            },
            "cursor",
        );
        assert_eq!(result.fields["process.args"], "[\"€\"]");
    }

    #[test]
    fn socket_families_accept_both_linux_byte_orders() {
        for address in [
            "02000050C00002010000000000000000",
            "00020050C00002010000000000000000",
        ] {
            let mut fields = BTreeMap::new();
            socket_address(address, &mut fields);
            assert_eq!(fields["destination.ip"], "192.0.2.1");
            assert_eq!(fields["destination.port"], "80");
        }
    }
    #[test]
    fn aggregates_exec_and_decodes_hex_without_losing_argument_boundaries() {
        let raw = [
            "type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=59 success=yes pid=12 ppid=1 uid=1000 exe=2F62696E2F7368 comm=7368",
            "type=EXECVE msg=audit(1700000000.123:42): argc=2 a0=2F62696E2F7368 a1=68656C6C6F20776F726C64",
            "type=CWD msg=audit(1700000000.123:42): cwd=2F746D70",
            "type=PATH msg=audit(1700000000.123:42): item=0 name=2F62696E2F7368",
            "type=EOE msg=audit(1700000000.123:42):",
        ];
        let records = raw.iter().map(|r| parse(r).unwrap()).collect();
        let e = event(
            Group {
                start: 0,
                records,
                bytes: 0,
                complete: true,
                partial: false,
            },
            "cursor",
        );
        assert_eq!(e.fields["process.executable"], "/bin/sh");
        assert_eq!(e.fields["process.args"], "[\"/bin/sh\",\"hello world\"]");
        assert_eq!(e.fields["process.working_directory"], "/tmp");
        assert_eq!(e.fields["event.id"], "process.exec");
        assert_eq!(e.fields["file.path"], "/bin/sh");
    }
}
