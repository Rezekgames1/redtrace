//! Streaming backups: bounded buffers, checksummed entries and fresh-directory restore.
use crate::{
    ingest::hex,
    service::{self, invalid},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
const MAGIC: &[u8] = b"REDTRACE-BACKUP-1\n";
const MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_FILES: usize = 100_000;
const MAX_DEPTH: usize = 64;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u16,
    pub data_version: u16,
    pub application: String,
    pub created_at: String,
    pub files: Vec<Entry>,
    pub total_bytes: u64,
    #[serde(default)]
    pub source_root: Option<String>,
}

fn compatibility(root: &Path) -> io::Result<()> {
    let path = root.join("data-version.json");
    if path.exists() {
        let value: serde_json::Value = serde_json::from_slice(&service::read_private(&path, 4096)?)
            .map_err(io::Error::other)?;
        if value["version"] != 1
            || value["minimum_reader"] != 1
            || value
                .get("config_version")
                .is_some_and(|version| version != crate::config::VERSION)
        {
            return Err(invalid(
                "database requires a newer reader; use the matching REDTRACE version or restore a compatible backup",
            ));
        }
    }
    // Refuse future or invalid configuration before either backup activation or
    // migration writes a compatibility marker into a legacy directory.
    crate::config::Config::load(&root.join("config.json"))?;
    if root.join("rules.json").exists() || root.join("rules-state.json").exists() {
        crate::rules::Manager::open(root.join("rules.json"))?;
    }
    Ok(())
}
pub fn migrate(root: &Path) -> io::Result<()> {
    service::private_directory(root)?;
    compatibility(root)?;
    let path = root.join("data-version.json");
    if path.exists() {
        return Ok(());
    }
    // Existing WAL/catalog formats are unchanged; migration adds the compatibility marker.
    service::write_private(&path,b"{\"version\":1,\"minimum_reader\":1,\"config_version\":1,\"migration\":\"legacy-v1-compatible\"}\n")
}
fn entries(
    root: &Path,
    path: &Path,
    files: &mut Vec<PathBuf>,
    directories: &mut usize,
    depth: usize,
) -> io::Result<()> {
    if depth > MAX_DEPTH || *directories >= MAX_FILES {
        return Err(invalid("backup directory traversal cap reached"));
    }
    *directories += 1;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(invalid("backup filenames must be UTF-8"));
        };
        if name.starts_with('.')
            || name.ends_with(".tmp")
            || name.ends_with(".lock")
            || matches!(
                name,
                "session.json" | "session.key" | "backups" | "restore-staging"
            )
        {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("backup refuses redirected files"));
        }
        if metadata.is_dir() {
            entries(root, &entry.path(), files, directories, depth + 1)?;
        } else if metadata.is_file() {
            if files.len() >= MAX_FILES {
                return Err(invalid("backup file cap reached"));
            }
            if entry.path().strip_prefix(root).is_err() {
                return Err(invalid("backup file escaped source root"));
            }
            files.push(entry.path());
        }
    }
    Ok(())
}
fn checksum(path: &Path) -> io::Result<(u64, String)> {
    let mut file = File::open(path)?;
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0u8; 65536];
    let mut total = 0;
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        total += size as u64;
        if total > MAX_BYTES {
            return Err(invalid("backup byte cap reached"));
        }
        digest.update(&buffer[..size]);
    }
    Ok((total, hex(digest.finish().as_ref())))
}
fn new_file(path: &Path) -> io::Result<File> {
    service::create_private_file(path)
}
struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        if self.0.is_dir() {
            let _ = fs::remove_dir_all(&self.0);
        } else {
            let _ = fs::remove_file(&self.0);
        }
    }
}
fn copy_verified(source: &mut impl Read, output: &mut impl Write, entry: &Entry) -> io::Result<()> {
    let mut remaining = entry.bytes;
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = [0u8; 65536];
    while remaining > 0 {
        let limit = remaining.min(buffer.len() as u64) as usize;
        let count = source.read(&mut buffer[..limit])?;
        if count == 0 {
            return Err(invalid("backup truncated; target was not activated"));
        }
        output.write_all(&buffer[..count])?;
        digest.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if hex(digest.finish().as_ref()) != entry.sha256 {
        return Err(invalid(
            "backup checksum mismatch; target was not activated",
        ));
    }
    Ok(())
}
fn verify_tail(source: &mut impl Read) -> io::Result<()> {
    let mut tail = [0u8; 1];
    if source.read(&mut tail)? != 0 {
        return Err(invalid("unexpected bytes after backup"));
    }
    Ok(())
}
pub fn create(root: &Path, destination: &Path) -> io::Result<Manifest> {
    service::absolute_path(root)?;
    service::absolute_path(destination)?;
    if !root.is_dir() {
        return Err(invalid("backup source directory does not exist"));
    }
    service::private_directory(root)?;
    compatibility(root)?;
    if destination.exists() {
        return Err(invalid("backup destination already exists"));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("backup destination has no parent"))?;
    service::private_directory(parent)?;
    let mut paths = Vec::new();
    let mut directories = 0;
    entries(root, root, &mut paths, &mut directories, 0)?;
    paths.sort();
    let mut files = Vec::new();
    let mut total_bytes = 0;
    for path in &paths {
        let (bytes, sha256) = checksum(path)?;
        total_bytes += bytes;
        if total_bytes > MAX_BYTES {
            return Err(invalid("backup byte cap reached"));
        }
        files.push(Entry {
            path: path
                .strip_prefix(root)
                .map_err(io::Error::other)?
                .components()
                .map(|part| {
                    part.as_os_str()
                        .to_str()
                        .ok_or_else(|| invalid("backup path not UTF-8"))
                })
                .collect::<io::Result<Vec<_>>>()?
                .join("/"),
            bytes,
            sha256,
        });
    }
    let manifest = Manifest {
        format: 1,
        data_version: 1,
        application: env!("CARGO_PKG_VERSION").into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        files,
        total_bytes,
        source_root: Some(root.to_string_lossy().into_owned()),
    };
    validate_manifest(&manifest)?;
    let metadata = serde_json::to_vec(&manifest).map_err(io::Error::other)?;
    if metadata.len() > 16 * 1024 * 1024 {
        return Err(invalid("backup manifest cap reached"));
    }
    let staging = Staging(parent.join(format!(".backup-{}.partial", service::random_secret()?)));
    let mut output = new_file(&staging.0)?;
    output.write_all(MAGIC)?;
    output.write_all(&(metadata.len() as u64).to_le_bytes())?;
    output.write_all(&metadata)?;
    for (path, entry) in paths.iter().zip(&manifest.files) {
        let mut file = File::open(path)?;
        if let Err(error) =
            copy_verified(&mut file, &mut output, entry).and_then(|()| verify_tail(&mut file))
        {
            if error.kind() != io::ErrorKind::InvalidInput {
                return Err(error);
            }
            return Err(io::Error::other(
                "source changed during backup; stop the collector or use the online snapshot API",
            ));
        }
    }
    output.sync_all()?;
    drop(output);
    // Both files share a directory/filesystem. A link atomically refuses an
    // already-created destination instead of replacing another backup.
    fs::hard_link(&staging.0, destination)?;
    fs::remove_file(&staging.0)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(manifest)
}
fn manifest(file: &mut File) -> io::Result<Manifest> {
    let mut magic = vec![0u8; MAGIC.len()];
    file.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(invalid("unsupported backup format"));
    }
    let mut bytes = [0u8; 8];
    file.read_exact(&mut bytes)?;
    let len = u64::from_le_bytes(bytes);
    if len > 16 * 1024 * 1024 {
        return Err(invalid("backup manifest cap exceeded"));
    }
    let mut metadata = vec![0u8; len as usize];
    file.read_exact(&mut metadata)?;
    let manifest: Manifest = serde_json::from_slice(&metadata).map_err(io::Error::other)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}
fn validate_manifest(manifest: &Manifest) -> io::Result<()> {
    if manifest.format != 1
        || manifest.data_version != 1
        || manifest.files.len() > MAX_FILES
        || manifest.total_bytes > MAX_BYTES
        || manifest
            .files
            .iter()
            .map(|f| f.bytes)
            .try_fold(0u64, |a, b| a.checked_add(b))
            != Some(manifest.total_bytes)
    {
        return Err(invalid(
            "unsupported data version or invalid backup budgets",
        ));
    }
    let mut names = std::collections::HashSet::new();
    for entry in &manifest.files {
        let path = Path::new(&entry.path);
        if entry.path.is_empty()
            || entry.path.len() > 4096
            || entry.path.contains(['\\', ':'])
            || entry.path.chars().any(char::is_control)
            || entry.path.split('/').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.ends_with(['.', ' '])
                    || matches!(
                        part.split('.')
                            .next()
                            .unwrap_or("")
                            .to_ascii_uppercase()
                            .as_str(),
                        "CON"
                            | "PRN"
                            | "AUX"
                            | "NUL"
                            | "COM1"
                            | "COM2"
                            | "COM3"
                            | "COM4"
                            | "COM5"
                            | "COM6"
                            | "COM7"
                            | "COM8"
                            | "COM9"
                            | "LPT1"
                            | "LPT2"
                            | "LPT3"
                            | "LPT4"
                            | "LPT5"
                            | "LPT6"
                            | "LPT7"
                            | "LPT8"
                            | "LPT9"
                    )
            })
            || path.is_absolute()
            || path
                .components()
                .any(|p| !matches!(p, std::path::Component::Normal(_)))
            || entry.path.split('/').count() > MAX_DEPTH + 1
            || !names.insert(entry.path.to_ascii_lowercase())
            || entry.sha256.len() != 64
            || !entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid("invalid backup file path or checksum"));
        }
    }
    Ok(())
}
pub fn inspect(path: &Path) -> io::Result<Manifest> {
    let mut file = File::open(path)?;
    let manifest = manifest(&mut file)?;
    for entry in &manifest.files {
        copy_verified(&mut file, &mut io::sink(), entry)?;
    }
    verify_tail(&mut file)?;
    Ok(manifest)
}
pub fn restore(archive: &Path, target: &Path) -> io::Result<Manifest> {
    service::absolute_path(target)?;
    if target.exists() {
        return Err(invalid(
            "restore requires a new data directory; existing database remains unchanged",
        ));
    }
    let mut source = File::open(archive)?;
    let manifest = manifest(&mut source)?;
    let parent = target
        .parent()
        .ok_or_else(|| invalid("restore target has no parent"))?;
    service::private_directory(parent)?;
    let staging = Staging(parent.join(format!(".restore-{}", service::random_secret()?)));
    service::private_directory(&staging.0)?;
    for entry in &manifest.files {
        let path = staging.0.join(&entry.path);
        service::private_directory(
            path.parent()
                .ok_or_else(|| invalid("restore file has no parent"))?,
        )?;
        let mut output = new_file(&path)?;
        copy_verified(&mut source, &mut output, entry)?;
        output.sync_all()?;
    }
    verify_tail(&mut source)?;
    if let Some(original) = &manifest.source_root {
        for name in ["service.json", "desktop-service.json", "config.json"] {
            let path = staging.0.join(name);
            if path.exists() {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&service::read_private(&path, 1024 * 1024)?)
                        .map_err(io::Error::other)?;
                rebase(&mut value, original, &target.to_string_lossy());
                service::write_private(
                    &path,
                    &serde_json::to_vec_pretty(&value).map_err(io::Error::other)?,
                )?;
            }
        }
    }
    migrate(&staging.0)?;
    fs::rename(&staging.0, target)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(manifest)
}

fn rebase(value: &mut serde_json::Value, old: &str, new: &str) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                rebase(value, old, new);
            }
        }
        serde_json::Value::Object(values) => {
            for (name, value) in values {
                if matches!(
                    name.as_str(),
                    "data_dir"
                        | "session_file"
                        | "audit_path"
                        | "path"
                        | "REDTRACE_AGENT_TOKEN_FILE"
                        | "REDTRACE_INGEST_KEY"
                        | "REDTRACE_AGENT_CA"
                        | "REDTRACE_INGEST_CERT"
                        | "REDTRACE_AGENT_STATE_DIR"
                        | "REDTRACE_SOURCE_CONFIG"
                ) && let serde_json::Value::String(path) = value
                    && (path == old
                        || path
                            .strip_prefix(old)
                            .is_some_and(|tail| tail.starts_with(['/', '\\'])))
                {
                    let relative = path[old.len()..].trim_start_matches(['/', '\\']);
                    let mut target = PathBuf::from(new);
                    for component in relative.split(['/', '\\']).filter(|part| !part.is_empty()) {
                        target.push(component);
                    }
                    *path = target.to_string_lossy().into_owned();
                } else {
                    rebase(value, old, new);
                }
            }
        }
        _ => {}
    }
}
pub fn offline_lock(root: &Path) -> io::Result<Vec<File>> {
    let mut locks = Vec::new();
    for name in ["active.lock", "catalog.lock"] {
        let path = root.join(name);
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        file.try_lock()
            .map_err(|_| invalid("collector is running; stop it or use the online backup"))?;
        locks.push(file);
    }
    Ok(locks)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backup_restore_verifies_bytes_and_keeps_existing_target() {
        let base = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "redtrace-backup-{}",
                service::random_secret().unwrap()
            ));
        service::private_directory(&base).unwrap();
        let data = base.join("data");
        service::private_directory(&data).unwrap();
        service::write_private(&data.join("fixture.json"), b"{\"fixture\":true}").unwrap();
        let archive = base.join("fixture.rtbackup");
        create(&data, &archive).unwrap();
        let restored = base.join("restored");
        restore(&archive, &restored).unwrap();
        assert_eq!(
            fs::read(restored.join("fixture.json")).unwrap(),
            b"{\"fixture\":true}"
        );
        assert!(restore(&archive, &restored).is_err());
        fs::remove_dir_all(base).unwrap();
    }
}
