use super::{CollectionBatch, SourceStatus, configured_lookback, parse_events};
use crate::{
    model::Event,
    storage::{CheckpointStore, SourceCheckpoint},
};
use std::{collections::BTreeMap, ffi::c_void, ptr, sync::Arc, time::Duration};
use tokio::sync::{RwLock, mpsc};

type Handle = isize;

#[link(name = "wevtapi")]
unsafe extern "system" {
    fn EvtQuery(session: Handle, path: *const u16, query: *const u16, flags: u32) -> Handle;
    fn EvtSubscribe(
        session: Handle,
        signal: *mut c_void,
        channel: *const u16,
        query: *const u16,
        bookmark: Handle,
        context: *const c_void,
        callback: *const c_void,
        flags: u32,
    ) -> Handle;
    fn EvtNext(
        result: Handle,
        count: u32,
        events: *mut Handle,
        timeout: u32,
        flags: u32,
        returned: *mut u32,
    ) -> i32;
    fn EvtRender(
        context: Handle,
        fragment: Handle,
        flags: u32,
        size: u32,
        buffer: *mut c_void,
        used: *mut u32,
        properties: *mut u32,
    ) -> i32;
    fn EvtCreateBookmark(xml: *const u16) -> Handle;
    fn EvtUpdateBookmark(bookmark: Handle, event: Handle) -> i32;
    fn EvtClose(handle: Handle) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateEventW(
        attributes: *const c_void,
        manual: i32,
        initial: i32,
        name: *const u16,
    ) -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    fn ResetEvent(handle: *mut c_void) -> i32;
}

const CHANNELS: [(&str, &str, &str); 4] = [
    (
        "System",
        "windows.system",
        "EventID=7036 or EventID=7045 or EventID=6005 or EventID=6006 or EventID=104",
    ),
    (
        "Security",
        "windows.security",
        "EventID=4624 or EventID=4625 or EventID=4688 or EventID=4740",
    ),
    (
        "Microsoft-Windows-Sysmon/Operational",
        "windows.sysmon",
        "EventID=1 or EventID=3 or EventID=7 or EventID=11 or EventID=12 or EventID=13 or EventID=22",
    ),
    (
        "Microsoft-Windows-PowerShell/Operational",
        "windows.powershell",
        "EventID=4104",
    ),
];

struct EventHandle(Handle);

impl Drop for EventHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                EvtClose(self.0);
            }
        }
    }
}

struct Signal(*mut c_void);

impl Drop for Signal {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

fn render(handle: Handle, flags: u32) -> Result<String, String> {
    let mut used = 0;
    let mut properties = 0;
    unsafe {
        EvtRender(
            0,
            handle,
            flags,
            0,
            ptr::null_mut(),
            &mut used,
            &mut properties,
        );
    }
    if used == 0 || used > 2 * 1024 * 1024 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut buffer = vec![0u16; (used as usize).div_ceil(2)];
    if unsafe {
        EvtRender(
            0,
            handle,
            flags,
            used,
            buffer.as_mut_ptr().cast(),
            &mut used,
            &mut properties,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..length]).map_err(|error| error.to_string())
}

fn normalize(handle: Handle, source: &str) -> Result<Vec<Event>, String> {
    let xml = render(handle, 1)?;
    let bookmark = EventHandle(unsafe { EvtCreateBookmark(ptr::null()) });
    if bookmark.0 == 0 || unsafe { EvtUpdateBookmark(bookmark.0, handle) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let cursor = render(bookmark.0, 2)?;
    let mut events = parse_events(&xml, source);
    if events.len() != 1 || !events[0].fields.contains_key("event.record_id") {
        return Err("event cannot be normalized; checkpoint held before unconfirmed record".into());
    }
    for event in &mut events {
        event
            .fields
            .insert("collector.cursor".into(), cursor.clone());
        event
            .fields
            .insert("collector.mode".into(), "native".into());
    }
    Ok(events)
}

fn next_is_idle(code: Option<i32>) -> bool {
    matches!(code, Some(259 | 1460))
}

fn next_handle(result: Handle) -> Result<Option<EventHandle>, String> {
    let mut handle = 0;
    let mut returned = 0;
    if unsafe { EvtNext(result, 1, &mut handle, 0, 0, &mut returned) } == 0 {
        let error = std::io::Error::last_os_error();
        if next_is_idle(error.raw_os_error()) {
            return Ok(None);
        }
        return Err(format!("EvtNext: {error}"));
    }
    let handle = EventHandle(handle);
    if returned != 1 || handle.0 == 0 {
        return Err("EvtNext returned an invalid event count or handle".into());
    }
    Ok(Some(handle))
}

fn current_record(channel: &str) -> Result<Option<u64>, String> {
    let channel = wide(channel);
    let query = wide("*");
    let result = EventHandle(unsafe { EvtQuery(0, channel.as_ptr(), query.as_ptr(), 1 | 0x200) });
    if result.0 == 0 {
        return Err(format!(
            "EvtQuery latest record: {}",
            std::io::Error::last_os_error()
        ));
    }
    let Some(handle) = next_handle(result.0)? else {
        return Ok(None);
    };
    let xml = render(handle.0, 1)?;
    super::tag_text(&xml, "EventRecordID")
        .and_then(|value| value.parse().ok())
        .map(Some)
        .ok_or_else(|| "latest event has no valid record ID".into())
}

struct ResumePlan {
    query: String,
    bookmark: Option<String>,
    warning: Option<String>,
}

fn resume_plan(
    channel: &str,
    ids: &str,
    stored: Option<&SourceCheckpoint>,
    current: Option<u64>,
    initial_since: &str,
    use_bookmark: bool,
) -> ResumePlan {
    let filter = format!("*[System[({ids})]]");
    let Some(stored) = stored else {
        return ResumePlan {
            query: format!("*[System[({ids}) and TimeCreated[@SystemTime >= '{initial_since}']]]"),
            bookmark: None,
            warning: None,
        };
    };
    let record = super::checkpoint_record_id(&stored.cursor);
    if let Some(record) = record.filter(|record| current.is_some_and(|last| *record <= last)) {
        let is_bookmark = stored.cursor.starts_with('<');
        let matching_channel =
            super::attribute(&stored.cursor, "Channel").as_deref() == Some(channel);
        if use_bookmark && is_bookmark && matching_channel {
            return ResumePlan {
                query: filter,
                bookmark: Some(stored.cursor.clone()),
                warning: None,
            };
        }
        return ResumePlan {
            query: format!("*[System[({ids}) and EventRecordID > {record}]]"),
            bookmark: None,
            warning: (is_bookmark && !matching_channel)
                .then(|| "bookmark channel mismatch; replaying from durable record ID".into()),
        };
    }
    ResumePlan {
        query: filter,
        bookmark: None,
        warning: Some("durable bookmark is invalid or log record IDs reset; replaying all retained matching records".into()),
    }
}

fn initial_since() -> String {
    let millis = super::lookback_millis(&configured_lookback());
    (chrono::Utc::now() - chrono::Duration::milliseconds(millis as i64))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn plan_for_source(
    channel: &str,
    source: &str,
    ids: &str,
    checkpoints: &CheckpointStore,
    since: &str,
    use_bookmark: bool,
) -> Result<ResumePlan, String> {
    let stored = checkpoints.get(source);
    let current = if stored.is_some() {
        current_record(channel)?
    } else {
        None
    };
    Ok(resume_plan(
        channel,
        ids,
        stored.as_ref(),
        current,
        since,
        use_bookmark,
    ))
}

pub fn collect(checkpoints: &CheckpointStore) -> CollectionBatch {
    let mut events = Vec::new();
    let mut errors = Vec::new();
    let since = initial_since();
    for (channel, source, ids) in CHANNELS {
        let plan = match plan_for_source(channel, source, ids, checkpoints, &since, false) {
            Ok(plan) => plan,
            Err(error) => {
                errors.push(format!("{channel}: {error}"));
                continue;
            }
        };
        if let Some(warning) = plan.warning {
            errors.push(format!("{channel}: {warning}"));
        }
        let channel_wide = wide(channel);
        let query_wide = wide(&plan.query);
        let result = EventHandle(unsafe {
            EvtQuery(0, channel_wide.as_ptr(), query_wide.as_ptr(), 1 | 0x100)
        });
        if result.0 == 0 {
            errors.push(format!(
                "{channel}: EvtQuery: {}",
                std::io::Error::last_os_error()
            ));
            continue;
        }
        for _ in 0..2000 {
            let handle = match next_handle(result.0) {
                Ok(Some(handle)) => handle,
                Ok(None) => break,
                Err(error) => {
                    errors.push(format!("{channel}: {error}"));
                    break;
                }
            };
            match normalize(handle.0, source) {
                Ok(batch) => events.extend(batch),
                Err(error) => {
                    errors.push(format!("{channel}: {error}"));
                    break;
                }
            }
        }
    }
    CollectionBatch {
        status: SourceStatus {
            name: "windows.eventlog.native".into(),
            platform: "windows".into(),
            state: if errors.is_empty() {
                "ready"
            } else if events.is_empty() {
                "error"
            } else {
                "degraded"
            }
            .into(),
            events_collected: events.len(),
            lookback: configured_lookback(),
            last_error: (!errors.is_empty()).then(|| errors.join("; ")),
        },
        events,
    }
}

struct PullSubscription {
    result: EventHandle,
    _bookmark: EventHandle,
    signal: Signal,
    warning: Option<String>,
}

impl PullSubscription {
    fn open(
        channel: &str,
        source: &str,
        ids: &str,
        checkpoints: &CheckpointStore,
        since: &str,
    ) -> Result<Self, String> {
        let signal = Signal(unsafe { CreateEventW(ptr::null(), 1, 1, ptr::null()) });
        if signal.0.is_null() {
            return Err(format!("CreateEventW: {}", std::io::Error::last_os_error()));
        }
        let mut plan = plan_for_source(channel, source, ids, checkpoints, since, true)?;
        let cursor = plan.bookmark.as_deref().map(wide);
        let bookmark = EventHandle(if let Some(cursor) = &cursor {
            unsafe { EvtCreateBookmark(cursor.as_ptr()) }
        } else {
            0
        });
        if cursor.is_some() && bookmark.0 == 0 {
            return Err(format!(
                "EvtCreateBookmark: {}",
                std::io::Error::last_os_error()
            ));
        }
        let channel_wide = wide(channel);
        let open = |query: &str, bookmark: Handle| {
            let query_wide = wide(query);
            EventHandle(unsafe {
                EvtSubscribe(
                    0,
                    signal.0,
                    channel_wide.as_ptr(),
                    query_wide.as_ptr(),
                    bookmark,
                    ptr::null(),
                    ptr::null(),
                    if bookmark == 0 { 2 } else { 3 | 0x10000 },
                )
            })
        };
        let mut result = open(&plan.query, bookmark.0);
        if result.0 == 0 {
            let error = std::io::Error::last_os_error();
            if bookmark.0 != 0 && matches!(error.raw_os_error(), Some(15011 | 15012)) {
                plan = plan_for_source(channel, source, ids, checkpoints, since, false)?;
                plan.warning = Some(format!(
                    "bookmark no longer retained ({error}); replaying available records from durable checkpoint"
                ));
                result = open(&plan.query, 0);
            } else {
                return Err(format!("EvtSubscribe: {error}"));
            }
        }
        if result.0 == 0 {
            return Err(format!(
                "EvtSubscribe recovery: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            result,
            _bookmark: bookmark,
            signal,
            warning: plan.warning,
        })
    }

    fn wait_for_events(&self, backlog: bool) -> Result<bool, String> {
        if backlog {
            return Ok(true);
        }
        match unsafe { WaitForSingleObject(self.signal.0, 250) } {
            0 => {
                if unsafe { ResetEvent(self.signal.0) } == 0 {
                    return Err(format!("ResetEvent: {}", std::io::Error::last_os_error()));
                }
                Ok(true)
            }
            258 => Ok(false),
            _ => Err(format!(
                "WaitForSingleObject: {}",
                std::io::Error::last_os_error()
            )),
        }
    }

    fn next_event(&self, source: &str) -> Result<Option<Event>, String> {
        let Some(handle) = next_handle(self.result.0)? else {
            return Ok(None);
        };
        Ok(normalize(handle.0, source)?.pop())
    }
}

fn drain_events(
    tx: &mpsc::Sender<Event>,
    mut next: impl FnMut() -> Result<Option<Event>, String>,
) -> Result<bool, String> {
    for _ in 0..256 {
        if tx.is_closed() {
            return Ok(false);
        }
        let Some(event) = next()? else {
            return Ok(false);
        };
        if tx.blocking_send(event).is_err() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn drain_if_ready(
    tx: &mpsc::Sender<Event>,
    ready: bool,
    next: impl FnMut() -> Result<Option<Event>, String>,
) -> Result<Option<bool>, String> {
    if !ready {
        return Ok(None);
    }
    drain_events(tx, next).map(Some)
}

fn subscribe(
    channel: &'static str,
    source: &str,
    ids: &str,
    tx: mpsc::Sender<Event>,
    checkpoints: Arc<CheckpointStore>,
    since: &str,
    health: mpsc::Sender<(&'static str, Option<String>)>,
) -> Result<(), String> {
    let subscription = PullSubscription::open(channel, source, ids, &checkpoints, since)?;
    let mut full = false;
    let mut reported = false;
    while !tx.is_closed() {
        let ready = subscription.wait_for_events(full)?;
        let Some(backlog) = drain_if_ready(&tx, ready, || subscription.next_event(source))? else {
            continue;
        };
        full = backlog;
        if !reported {
            if health
                .blocking_send((channel, subscription.warning.clone()))
                .is_err()
            {
                return Ok(());
            }
            reported = true;
        }
    }
    Ok(())
}

struct ChannelHealth {
    errors: BTreeMap<&'static str, Option<String>>,
}

impl ChannelHealth {
    fn new() -> Self {
        Self {
            errors: CHANNELS
                .iter()
                .map(|(channel, _, _)| (*channel, Some("initializing subscription".into())))
                .collect(),
        }
    }

    fn update(&mut self, channel: &'static str, error: Option<String>, status: &mut SourceStatus) {
        self.errors.insert(channel, error);
        let errors: Vec<_> = self
            .errors
            .iter()
            .filter_map(|(channel, error)| {
                error.as_ref().map(|error| format!("{channel}: {error}"))
            })
            .collect();
        status.state = if errors.is_empty() {
            "streaming"
        } else {
            "degraded"
        }
        .into();
        status.last_error = (!errors.is_empty()).then(|| errors.join("; "));
    }
}

pub async fn stream(
    tx: mpsc::Sender<Event>,
    status: Arc<RwLock<SourceStatus>>,
    checkpoints: Arc<CheckpointStore>,
) {
    let since = initial_since();
    let (health_tx, mut health_rx) = mpsc::channel(16);
    let mut health = ChannelHealth::new();
    health.update(
        CHANNELS[0].0,
        Some("initializing subscription".into()),
        &mut *status.write().await,
    );
    let mut tasks = Vec::new();
    for (channel, source, ids) in CHANNELS {
        let tx = tx.clone();
        let checkpoints = checkpoints.clone();
        let health_tx = health_tx.clone();
        let since = since.clone();
        tasks.push(tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            loop {
                if tx.is_closed() {
                    break;
                }
                let sender = tx.clone();
                let store = checkpoints.clone();
                let attempt_since = since.clone();
                let reporter = health_tx.clone();
                let started = std::time::Instant::now();
                let result = tokio::task::spawn_blocking(move || {
                    subscribe(
                        channel,
                        source,
                        ids,
                        sender,
                        store,
                        &attempt_since,
                        reporter,
                    )
                })
                .await;
                let error = match result {
                    Ok(Ok(())) => break,
                    Ok(Err(error)) => error,
                    Err(error) => format!("subscription worker failed: {error}"),
                };
                if health_tx.send((channel, Some(error))).await.is_err() {
                    break;
                }
                if started.elapsed() >= Duration::from_secs(30) {
                    backoff = Duration::from_secs(1);
                }
                tokio::select! {
                    _ = tx.closed() => break,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }));
    }
    drop(health_tx);
    while let Some((channel, error)) = health_rx.recv().await {
        health.update(channel, error, &mut *status.write().await);
    }
    for task in tasks {
        let _ = task.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::tests::CheckpointFixture;

    fn checkpoint(cursor: &str) -> SourceCheckpoint {
        SourceCheckpoint {
            cursor: cursor.into(),
            timestamp: "2026-10-01T00:00:00Z".into(),
            event_uid: "fixture".into(),
            updated_unix: 0,
            sequence: 0,
        }
    }

    fn event(record: u64) -> Event {
        Event::normalized(
            0,
            format!("2026-10-01T00:00:{record:02}Z"),
            "windows.sysmon".into(),
            "low".into(),
            "fixture".into(),
            BTreeMap::from([(
                "collector.cursor".into(),
                format!(
                    "<BookmarkList><Bookmark Channel='Microsoft-Windows-Sysmon/Operational' RecordId='{record}' IsCurrent='true'/></BookmarkList>"
                ),
            )]),
        )
    }

    #[test]
    fn only_empty_and_timeout_are_idle_not_invalid_operation_or_stale_subscription() {
        assert!(next_is_idle(Some(259)));
        assert!(next_is_idle(Some(1460)));
        for code in [None, Some(4317), Some(15011), Some(5), Some(6)] {
            assert!(!next_is_idle(code));
        }
    }

    #[test]
    fn bookmark_resume_uses_stable_filter_and_numeric_resume_uses_durable_record() {
        let channel = CHANNELS[2].0;
        let stored = checkpoint(
            "<BookmarkList><Bookmark Channel='Microsoft-Windows-Sysmon/Operational' RecordId='42'/></BookmarkList>",
        );
        let plan = resume_plan(
            channel,
            "EventID=1",
            Some(&stored),
            Some(50),
            "initial",
            true,
        );
        assert_eq!(plan.query, "*[System[(EventID=1)]]");
        assert_eq!(plan.bookmark, Some(stored.cursor.clone()));
        assert!(plan.warning.is_none());
        let plan = resume_plan(
            channel,
            "EventID=1",
            Some(&stored),
            Some(50),
            "initial",
            false,
        );
        assert_eq!(plan.query, "*[System[(EventID=1) and EventRecordID > 42]]");
        assert!(plan.bookmark.is_none());
        let numeric = checkpoint("42");
        let plan = resume_plan(
            channel,
            "EventID=1",
            Some(&numeric),
            Some(50),
            "initial",
            true,
        );
        assert_eq!(plan.query, "*[System[(EventID=1) and EventRecordID > 42]]");
        assert!(plan.bookmark.is_none());
    }

    #[test]
    fn invalid_or_reset_checkpoint_replays_retained_events_instead_of_moving_lookback() {
        for stored in [checkpoint("42"), checkpoint("broken bookmark")] {
            for current in [None, Some(1)] {
                let plan = resume_plan(
                    CHANNELS[2].0,
                    "EventID=1",
                    Some(&stored),
                    current,
                    "2026-10-01T00:00:00Z",
                    true,
                );
                assert_eq!(plan.query, "*[System[(EventID=1)]]");
                assert!(plan.bookmark.is_none());
                assert!(plan.warning.is_some());
            }
        }
        let stored = checkpoint("<Bookmark Channel='Security' RecordId='42'/>");
        let plan = resume_plan(
            CHANNELS[2].0,
            "EventID=1",
            Some(&stored),
            Some(50),
            "initial",
            true,
        );
        assert!(plan.bookmark.is_none());
        assert!(plan.warning.as_ref().unwrap().contains("channel mismatch"));
        let plan = resume_plan(
            CHANNELS[2].0,
            "EventID=1",
            None,
            None,
            "2026-10-01T00:00:00Z",
            true,
        );
        assert!(plan.query.contains("@SystemTime >= '2026-10-01T00:00:00Z'"));
        assert!(!plan.query.contains("timediff"));
    }

    #[test]
    fn one_channel_recovery_does_not_clear_another_channel_error() {
        let mut status = crate::collector::initial_status();
        let mut health = ChannelHealth::new();
        for (channel, _, _) in CHANNELS {
            health.update(channel, None, &mut status);
        }
        assert_eq!(status.state, "streaming");
        assert!(status.last_error.is_none());
        health.update(
            CHANNELS[2].0,
            Some("EvtNext: os error 4317".into()),
            &mut status,
        );
        health.update(CHANNELS[1].0, Some("access denied".into()), &mut status);
        health.update(CHANNELS[2].0, None, &mut status);
        assert_eq!(status.state, "degraded");
        assert!(!status.last_error.as_ref().unwrap().contains("4317"));
        assert!(
            status
                .last_error
                .as_ref()
                .unwrap()
                .contains("Security: access denied")
        );
        health.update(CHANNELS[1].0, None, &mut status);
        assert_eq!(status.state, "streaming");
        assert!(status.last_error.is_none());
    }

    #[test]
    fn pull_failure_stops_delivery_and_reconnect_uses_only_confirmed_bookmark() {
        let fixture = CheckpointFixture::new();
        let confirmed = event(10);
        let wal = crate::storage::Wal::open(fixture.directory.join("fixture.wal")).unwrap();
        wal.append(std::slice::from_ref(&confirmed)).unwrap();
        fixture.store.update_events(&[confirmed]).unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        let mut results = [
            Ok(Some(event(11))),
            Err("EvtNext: os error 4317".into()),
            Ok(Some(event(12))),
        ]
        .into_iter();
        let mut calls = 0;
        assert_eq!(
            drain_events(&tx, || {
                calls += 1;
                results.next().unwrap()
            })
            .unwrap_err(),
            "EvtNext: os error 4317"
        );
        assert_eq!(calls, 2);
        let unconfirmed = rx.try_recv().unwrap();
        assert!(rx.try_recv().is_err());
        let stored = fixture.store.get("windows.sysmon").unwrap();
        assert_eq!(super::super::checkpoint_record_id(&stored.cursor), Some(10));
        let plan = resume_plan(
            CHANNELS[2].0,
            "EventID=1",
            Some(&stored),
            Some(50),
            "initial",
            true,
        );
        assert_eq!(plan.bookmark, Some(stored.cursor));
        wal.append(std::slice::from_ref(&unconfirmed)).unwrap();
        fixture.store.update_events(&[unconfirmed]).unwrap();
        let reopened = CheckpointStore::open(fixture.directory.join("checkpoints.json")).unwrap();
        assert_eq!(
            super::super::checkpoint_record_id(&reopened.get("windows.sysmon").unwrap().cursor),
            Some(11)
        );
        assert_eq!(wal.recover().unwrap().events.len(), 2);
    }

    #[test]
    fn bounded_pull_drain_continues_backlog_and_stops_cleanly_on_empty_or_closed_receiver() {
        let (tx, mut rx) = mpsc::channel(512);
        let mut remaining = (1..=300).map(event);
        assert!(drain_events(&tx, || Ok(remaining.next())).unwrap());
        assert!(!drain_events(&tx, || Ok(remaining.next())).unwrap());
        for record in 1..=300 {
            let received = rx.try_recv().unwrap();
            assert_eq!(
                super::super::checkpoint_record_id(&received.fields["collector.cursor"]),
                Some(record)
            );
        }
        assert!(rx.try_recv().is_err());
        assert!(!drain_events(&tx, || Ok(None)).unwrap());
        drop(rx);
        assert!(!drain_events(&tx, || panic!("closed receiver must not enumerate")).unwrap());
    }

    #[test]
    fn exhausted_pull_wait_timeout_does_not_reenumerate_or_deliver_a_cursor() {
        let (tx, mut rx) = mpsc::channel(8);
        assert_eq!(drain_if_ready(&tx, true, || Ok(None)).unwrap(), Some(false));
        assert_eq!(
            drain_if_ready(&tx, false, || panic!("timeout must not call EvtNext")).unwrap(),
            None
        );
        assert!(rx.try_recv().is_err());
        let mut results = [Some(event(11)), None].into_iter();
        assert_eq!(
            drain_if_ready(&tx, true, || Ok(results.next().unwrap())).unwrap(),
            Some(false)
        );
        assert_eq!(
            super::super::checkpoint_record_id(&rx.try_recv().unwrap().fields["collector.cursor"]),
            Some(11)
        );
    }

    #[test]
    #[ignore = "read-only native exhausted-subscription regression evidence"]
    fn native_exhausted_pull_reenumeration_reproduces_invalid_operation() {
        let channel = wide(CHANNELS[2].0);
        let query = wide("*[System[EventID=65535]]");
        let signal = Signal(unsafe { CreateEventW(ptr::null(), 1, 1, ptr::null()) });
        assert!(!signal.0.is_null());
        let subscription = EventHandle(unsafe {
            EvtSubscribe(
                0,
                signal.0,
                channel.as_ptr(),
                query.as_ptr(),
                0,
                ptr::null(),
                ptr::null(),
                2,
            )
        });
        assert_ne!(subscription.0, 0);
        assert!(next_handle(subscription.0).unwrap().is_none());
        let error = next_handle(subscription.0)
            .err()
            .expect("exhausted pull enumeration unexpectedly accepted");
        assert!(error.contains("4317"), "{error}");
        println!(
            "read-only native defect reproduced: EvtNext NO_MORE_ITEMS followed by unsolicited EvtNext -> {error}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "read-only native multi-channel subscription verification"]
    async fn native_channel_stream_clears_old_errors_and_stops_after_receiver_closes() {
        let fixture = CheckpointFixture::new();
        let checkpoints = Arc::new(
            CheckpointStore::open(fixture.directory.join("stream-checkpoints.json")).unwrap(),
        );
        let mut initial = crate::collector::initial_status();
        initial.state = "degraded".into();
        initial.last_error = Some("Sysmon: EvtNext: os error 4317 from prior attempt".into());
        let status = Arc::new(RwLock::new(initial));
        let (tx, mut rx) = mpsc::channel(512);
        let task = tokio::spawn(stream(tx, status.clone(), checkpoints.clone()));
        let mut received = 0;
        let deadline = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => {
                    let current = status.read().await.clone();
                    drop(rx);
                    tokio::time::timeout(Duration::from_secs(3), task).await.unwrap().unwrap();
                    panic!("native channels did not recover: {current:?}");
                }
                event = rx.recv() => {
                    let event = event.expect("native stream stopped unexpectedly");
                    assert_eq!(event.fields["collector.mode"], "native");
                    assert!(event.fields.contains_key("collector.cursor"));
                    received += 1;
                }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {
                    let current = status.read().await;
                    if current.state == "streaming" && current.last_error.is_none() {
                        break;
                    }
                }
            }
        }
        assert!(checkpoints.is_empty());
        drop(rx);
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert!(checkpoints.is_empty());
        println!(
            "read-only native four-channel stream recovered from old 4317, delivered {received} records without checkpoint advancement, then shut down"
        );
    }

    #[test]
    #[ignore = "read-only native Event Log verification"]
    fn native_sysmon_bookmark_reopen_and_empty_enumeration_are_read_only() {
        let fixture = CheckpointFixture::new();
        let (channel, source, ids) = CHANNELS[2];
        let channel_wide = wide(channel);
        let query_wide = wide("*");
        let result = EventHandle(unsafe {
            EvtQuery(0, channel_wide.as_ptr(), query_wide.as_ptr(), 1 | 0x200)
        });
        assert_ne!(
            result.0,
            0,
            "Sysmon read query failed: {}",
            std::io::Error::last_os_error()
        );
        let handle = next_handle(result.0)
            .unwrap()
            .expect("Sysmon has no existing records");
        let events = normalize(handle.0, source).unwrap();
        let record = events[0].fields["event.record_id"].parse::<u64>().unwrap();
        let wal = crate::storage::Wal::open(fixture.directory.join("fixture.wal")).unwrap();
        wal.append(&events).unwrap();
        fixture.store.update_events(&events).unwrap();
        let saved = fixture.store.get(source).unwrap();
        let since = initial_since();
        for _ in 0..2 {
            let subscription =
                PullSubscription::open(channel, source, ids, &fixture.store, &since).unwrap();
            assert!(subscription.warning.is_none());
            let (tx, mut rx) = mpsc::channel(512);
            let mut backlog = false;
            for _ in 0..4 {
                let ready = subscription.wait_for_events(backlog).unwrap();
                if let Some(full) =
                    drain_if_ready(&tx, ready, || subscription.next_event(source)).unwrap()
                {
                    backlog = full;
                }
                while let Ok(event) = rx.try_recv() {
                    assert!(event.fields["event.record_id"].parse::<u64>().unwrap() > record);
                    assert_eq!(event.fields["collector.mode"], "native");
                }
                assert_eq!(fixture.store.get(source).unwrap(), saved);
            }
        }
        let empty_query = wide("*[System[EventID=65535]]");
        let empty = EventHandle(unsafe {
            EvtQuery(0, channel_wide.as_ptr(), empty_query.as_ptr(), 1 | 0x100)
        });
        assert_ne!(empty.0, 0);
        assert!(next_handle(empty.0).unwrap().is_none());
        println!(
            "read-only Sysmon native bookmark reopen verified at record {record}; durable cursor unchanged during delivery; empty query handled"
        );
    }
}
