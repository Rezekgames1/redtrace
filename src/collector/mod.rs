pub mod audit_file;
pub mod endpoint_security;
pub mod extended;
mod linux;
mod macos;
mod windows;

use crate::model::Event;
use crate::storage::CheckpointStore;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};

#[derive(Clone, Debug, Serialize)]
pub struct SourceStatus {
    pub name: String,
    pub platform: String,
    pub state: String,
    pub events_collected: usize,
    pub lookback: String,
    pub last_error: Option<String>,
}

#[derive(Debug)]
pub struct CollectionBatch {
    pub events: Vec<Event>,
    pub status: SourceStatus,
}

pub fn collect_platform_events(checkpoints: &CheckpointStore) -> CollectionBatch {
    #[cfg(target_os = "macos")]
    {
        return macos::collect(checkpoints);
    }
    #[cfg(target_os = "linux")]
    {
        return linux::collect(checkpoints);
    }
    #[cfg(target_os = "windows")]
    {
        return windows::collect(checkpoints);
    }

    #[allow(unreachable_code)]
    CollectionBatch {
        events: Vec::new(),
        status: SourceStatus {
            name: "unsupported".into(),
            platform: std::env::consts::OS.into(),
            state: "unsupported".into(),
            events_collected: 0,
            lookback: "none".into(),
            last_error: Some("native collector is not implemented for this platform".into()),
        },
    }
}

pub async fn stream_platform_events(
    tx: mpsc::Sender<Event>,
    status: Arc<RwLock<SourceStatus>>,
    checkpoints: Arc<CheckpointStore>,
) {
    #[cfg(target_os = "macos")]
    {
        macos::stream_unified_log(tx, status, checkpoints).await;
    }
    #[cfg(target_os = "linux")]
    {
        linux::stream_journal(tx, status, checkpoints).await;
    }
    #[cfg(target_os = "windows")]
    {
        windows::poll_event_log(tx, status, checkpoints).await;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        drop((tx, status, checkpoints));
    }
}

pub fn initial_status() -> SourceStatus {
    let name = if cfg!(target_os = "macos") {
        "macos.unified_log"
    } else if cfg!(target_os = "linux") {
        "linux.journald"
    } else if cfg!(target_os = "windows") {
        "windows.eventlog"
    } else {
        "unsupported"
    };
    SourceStatus {
        name: name.into(),
        platform: std::env::consts::OS.into(),
        state: "backfilling".into(),
        events_collected: 0,
        lookback: if name == "unsupported" {
            "none".into()
        } else {
            format!("{} + stream", configured_lookback_for_platform())
        },
        last_error: (name == "unsupported")
            .then(|| "native collector is not implemented for this platform".into()),
    }
}

fn configured_lookback_for_platform() -> String {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        return configured_lookback();
    }
    #[allow(unreachable_code)]
    "none".into()
}

pub fn configured_lookback() -> String {
    #[cfg(target_os = "macos")]
    {
        return macos::configured_lookback();
    }
    #[cfg(target_os = "linux")]
    {
        return linux::configured_lookback();
    }
    #[cfg(target_os = "windows")]
    {
        return windows::configured_lookback();
    }
    #[allow(unreachable_code)]
    "none".into()
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum BoundedLine {
    End,
    Complete(Vec<u8>),
    Oversized,
    Incomplete,
}

pub(super) struct BoundedLines<R> {
    reader: R,
    limit: usize,
    discarding: bool,
}

impl<R> BoundedLines<R> {
    pub(super) fn new(reader: R, limit: usize) -> Self {
        Self {
            reader,
            limit,
            discarding: false,
        }
    }

    fn consume_chunk(
        limit: usize,
        discarding: &mut bool,
        available: &[u8],
        bytes: &mut Vec<u8>,
    ) -> (usize, Option<BoundedLine>) {
        if available.is_empty() {
            return (
                0,
                Some(if bytes.is_empty() {
                    BoundedLine::End
                } else {
                    BoundedLine::Incomplete
                }),
            );
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let amount = newline.map_or(available.len(), |index| index + 1);
        if *discarding {
            if newline.is_some() {
                *discarding = false;
            }
            return (amount, None);
        }
        let remaining = limit.saturating_sub(bytes.len());
        if amount > remaining {
            let consumed = remaining + 1;
            *discarding = available[consumed - 1] != b'\n';
            return (consumed, Some(BoundedLine::Oversized));
        }
        bytes.extend_from_slice(&available[..amount]);
        (
            amount,
            newline.map(|_| BoundedLine::Complete(std::mem::take(bytes))),
        )
    }
}

impl<R: std::io::BufRead> BoundedLines<R> {
    pub(super) fn read_line(&mut self) -> std::io::Result<BoundedLine> {
        let mut bytes = Vec::new();
        loop {
            let available = self.reader.fill_buf()?;
            let (consumed, line) =
                Self::consume_chunk(self.limit, &mut self.discarding, available, &mut bytes);
            self.reader.consume(consumed);
            if let Some(line) = line {
                return Ok(line);
            }
        }
    }
}

impl<R: tokio::io::AsyncBufRead + Unpin> BoundedLines<R> {
    pub(super) async fn next_line(&mut self) -> std::io::Result<BoundedLine> {
        use tokio::io::AsyncBufReadExt;
        let mut bytes = Vec::new();
        loop {
            let available = self.reader.fill_buf().await?;
            let (consumed, line) =
                Self::consume_chunk(self.limit, &mut self.discarding, available, &mut bytes);
            self.reader.consume(consumed);
            if let Some(line) = line {
                return Ok(line);
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::path::PathBuf;

    pub(super) struct CheckpointFixture {
        pub(super) directory: PathBuf,
        pub(super) store: CheckpointStore,
    }

    impl CheckpointFixture {
        pub(super) fn new() -> Self {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).unwrap();
            let directory = std::env::temp_dir().join("opencode").join(format!(
                "redtrace-collector-{}-{:016x}",
                std::process::id(),
                u64::from_le_bytes(random),
            ));
            let store = CheckpointStore::open(directory.join("checkpoints.json")).unwrap();
            Self { directory, store }
        }
    }

    impl Drop for CheckpointFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn synchronous_reader_handles_boundaries_eof_and_oversized_resynchronization() {
        for capacity in [1, 3, 16] {
            let input = b"abc\n1234\nx\nunfinished";
            let mut lines =
                BoundedLines::new(std::io::BufReader::with_capacity(capacity, &input[..]), 4);
            assert_eq!(
                lines.read_line().unwrap(),
                BoundedLine::Complete(b"abc\n".to_vec())
            );
            assert_eq!(lines.read_line().unwrap(), BoundedLine::Oversized);
            assert_eq!(
                lines.read_line().unwrap(),
                BoundedLine::Complete(b"x\n".to_vec())
            );
            assert_eq!(lines.read_line().unwrap(), BoundedLine::Oversized);
            assert_eq!(lines.read_line().unwrap(), BoundedLine::End);
            let mut lines =
                BoundedLines::new(std::io::BufReader::with_capacity(capacity, &b"abc"[..]), 4);
            assert_eq!(lines.read_line().unwrap(), BoundedLine::Incomplete);
            assert_eq!(lines.read_line().unwrap(), BoundedLine::End);
        }
    }

    #[tokio::test]
    async fn asynchronous_reader_matches_sync_framing_and_stops_before_newline_for_oversize() {
        for capacity in [1, 3, 16] {
            let mut lines = BoundedLines::new(
                tokio::io::BufReader::with_capacity(capacity, &b"abc\n1234\nx\nabc"[..]),
                4,
            );
            assert_eq!(
                lines.next_line().await.unwrap(),
                BoundedLine::Complete(b"abc\n".to_vec())
            );
            assert_eq!(lines.next_line().await.unwrap(), BoundedLine::Oversized);
            assert_eq!(
                lines.next_line().await.unwrap(),
                BoundedLine::Complete(b"x\n".to_vec())
            );
            assert_eq!(lines.next_line().await.unwrap(), BoundedLine::Incomplete);
            assert_eq!(lines.next_line().await.unwrap(), BoundedLine::End);
        }
        use tokio::io::AsyncWriteExt;
        let (mut writer, reader) = tokio::io::duplex(16);
        writer.write_all(b"12345").await.unwrap();
        let mut lines = BoundedLines::new(tokio::io::BufReader::new(reader), 4);
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), lines.next_line())
                .await
                .unwrap()
                .unwrap(),
            BoundedLine::Oversized
        );
    }

    #[test]
    fn framing_never_retains_more_than_the_record_budget() {
        for limit in [0, 1, 4, 1024] {
            let mut bytes = Vec::new();
            let mut discarding = false;
            for _ in 0..10000 {
                let (_, _) =
                    BoundedLines::<()>::consume_chunk(limit, &mut discarding, b"xxx", &mut bytes);
                assert!(bytes.len() <= limit);
            }
        }
    }
}
