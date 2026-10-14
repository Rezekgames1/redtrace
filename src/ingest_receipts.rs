use super::{
    hex, now_unix, private_registry_create, private_registry_open, private_registry_replace,
    reject_registry_link, sha256,
};
use std::{
    collections::{HashSet, VecDeque},
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const HEADER: &[u8; 8] = b"RTACK001";
const RECORD_BYTES: usize = 32;
const MAX_RECEIPTS: usize = 65_536;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const TTL_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug)]
pub(super) struct ReceiptStore {
    path: PathBuf,
    entries: VecDeque<(String, u64)>,
    known: HashSet<String>,
    repair_needed: bool,
}

impl ReceiptStore {
    pub fn open(path: PathBuf) -> io::Result<Self> {
        let mut store = Self {
            path,
            entries: VecDeque::new(),
            known: HashSet::new(),
            repair_needed: false,
        };
        if store.path.exists() {
            let mut file = private_registry_open(&store.path)?;
            if file.metadata()?.len() > MAX_FILE_BYTES {
                return Err(invalid("durable receipt log exceeds cap"));
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            if bytes.get(..HEADER.len()) != Some(HEADER.as_slice()) {
                return Err(invalid("invalid durable receipt version"));
            }
            let records = &bytes[HEADER.len()..];
            for record in records.chunks_exact(RECORD_BYTES) {
                if record[24..] != sha256(&record[..24])[..8]
                    || !record[..16].iter().all(u8::is_ascii_hexdigit)
                {
                    return Err(invalid(
                        "durable receipt checksum mismatch; original preserved",
                    ));
                }
                let uid = std::str::from_utf8(&record[..16])
                    .map_err(|_| invalid("invalid durable receipt UID"))?
                    .to_owned();
                let at = u64::from_le_bytes(record[16..24].try_into().unwrap());
                if store.known.insert(uid.clone()) {
                    store.entries.push_back((uid, at));
                }
            }
            drop(file);
            store.prune(now_unix());
            if !records.len().is_multiple_of(RECORD_BYTES) {
                let archive = store.path.with_extension("torn-original");
                let mut original = private_registry_create(&archive)?;
                original.write_all(&bytes)?;
                original.sync_all()?;
                drop(original);
                store.replace_log()?;
            }
        } else {
            store.replace_log()?;
        }
        Ok(store)
    }

    pub fn contains(&mut self, uid: &str) -> bool {
        self.prune(now_unix());
        self.known.contains(uid)
    }

    pub fn confirm(&mut self, uids: impl IntoIterator<Item = String>) -> io::Result<()> {
        let now = now_unix();
        self.prune(now);
        let fresh: Vec<_> = uids
            .into_iter()
            .filter(|uid| !self.known.contains(uid))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        if fresh.is_empty() {
            return Ok(());
        }
        let mut bytes = Vec::with_capacity(fresh.len() * RECORD_BYTES);
        for uid in &fresh {
            if uid.len() != 16 || !uid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(invalid("invalid durable receipt UID"));
            }
            encode(uid, now, &mut bytes);
        }
        if self.repair_needed
            || fs::metadata(&self.path)?
                .len()
                .saturating_add(bytes.len() as u64)
                > MAX_FILE_BYTES
        {
            self.replace_log()?;
            self.repair_needed = false;
        }
        reject_registry_link(&self.path)?;
        let mut options = OpenOptions::new();
        options.append(true);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(0x20000);
        }
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(0x100);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x00200000);
        }
        let result = (|| {
            let mut file = options.open(&self.path)?;
            file.write_all(&bytes)?;
            file.sync_data()
        })();
        if result.is_err() {
            self.repair_needed = true;
            return result;
        }
        for uid in fresh {
            self.known.insert(uid.clone());
            self.entries.push_back((uid, now));
        }
        self.prune(now);
        Ok(())
    }

    fn prune(&mut self, now: u64) {
        while self
            .entries
            .front()
            .is_some_and(|(_, at)| now.saturating_sub(*at) > TTL_SECONDS)
            || self.entries.len() > MAX_RECEIPTS
        {
            if let Some((uid, _)) = self.entries.pop_front() {
                self.known.remove(&uid);
            }
        }
    }

    fn replace_log(&self) -> io::Result<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let temporary = parent.join(format!(".receipts-{}.tmp", hex(&super::random_bytes(16)?)));
        let result = (|| {
            let mut file = private_registry_create(&temporary)?;
            file.write_all(HEADER)?;
            let mut bytes = Vec::with_capacity(self.entries.len() * RECORD_BYTES);
            for (uid, at) in &self.entries {
                encode(uid, *at, &mut bytes);
            }
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            reject_registry_link(&self.path)?;
            private_registry_replace(&temporary, &self.path)?;
            #[cfg(unix)]
            std::fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

fn encode(uid: &str, at: u64, bytes: &mut Vec<u8>) {
    let start = bytes.len();
    bytes.extend_from_slice(uid.as_bytes());
    bytes.extend_from_slice(&at.to_le_bytes());
    bytes.extend_from_slice(&sha256(&bytes[start..])[..8]);
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path() -> PathBuf {
        let directory = std::env::temp_dir().join("opencode").join(format!(
            "receipts-{}",
            hex(&super::super::random_bytes(16).unwrap())
        ));
        fs::create_dir_all(&directory).unwrap();
        directory.join("receipts.bin")
    }

    #[test]
    fn receipt_restart_and_torn_tail_preserve_durable_prefix_and_original() {
        let path = path();
        let mut store = ReceiptStore::open(path.clone()).unwrap();
        store.confirm(["1111111111111111".into()]).unwrap();
        drop(store);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"torn")
            .unwrap();
        let original = fs::read(&path).unwrap();
        let mut reopened = ReceiptStore::open(path.clone()).unwrap();
        assert!(reopened.contains("1111111111111111"));
        assert_eq!(
            fs::read(path.with_extension("torn-original")).unwrap(),
            original
        );
        reopened.confirm(["2222222222222222".into()]).unwrap();
        drop(reopened);
        assert!(
            ReceiptStore::open(path.clone())
                .unwrap()
                .contains("2222222222222222")
        );
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn checksum_corruption_fails_closed_without_modifying_original() {
        let path = path();
        let mut store = ReceiptStore::open(path.clone()).unwrap();
        store.confirm(["1111111111111111".into()]).unwrap();
        drop(store);
        let mut bytes = fs::read(&path).unwrap();
        bytes[10] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert!(ReceiptStore::open(path.clone()).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn receipt_history_is_count_age_and_disk_bounded() {
        let path = path();
        let mut store = ReceiptStore::open(path.clone()).unwrap();
        for index in 0..=MAX_RECEIPTS {
            let uid = format!("{index:016x}");
            store.known.insert(uid.clone());
            store.entries.push_back((uid, now_unix()));
        }
        store.prune(now_unix());
        assert_eq!(store.entries.len(), MAX_RECEIPTS);
        assert!(!store.contains("0000000000000000"));
        store.replace_log().unwrap();
        assert!(fs::metadata(&path).unwrap().len() <= MAX_FILE_BYTES);
        store.prune(now_unix() + TTL_SECONDS + 1);
        assert!(store.known.is_empty());
        assert!(store.entries.is_empty());
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
