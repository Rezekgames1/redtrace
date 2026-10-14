#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use super::{CollectionBatch, SourceStatus};
use crate::model::Event;
use crate::storage::CheckpointStore;
use std::{collections::BTreeMap, process::Command, sync::Arc, time::Duration};
use tokio::sync::{RwLock, mpsc};

#[cfg(target_os = "windows")]
mod native;

const POLL_INTERVAL: Duration = Duration::from_secs(5);

pub fn configured_lookback() -> String {
    let value = std::env::var("REDTRACE_LOOKBACK").unwrap_or_else(|_| "15m".into());
    if valid_lookback(&value) {
        value
    } else {
        "15m".into()
    }
}

pub fn collect(checkpoints: &CheckpointStore) -> CollectionBatch {
    #[cfg(target_os = "windows")]
    if std::env::var("REDTRACE_WINDOWS_COLLECTOR").as_deref() != Ok("wevtutil") {
        return native::collect(checkpoints);
    }
    let lookback = configured_lookback();
    let millis = lookback_millis(&lookback);
    match collect_window(millis, checkpoints) {
        Ok(events) => CollectionBatch {
            status: SourceStatus {
                name: "windows.eventlog".into(),
                platform: "windows".into(),
                state: "ready".into(),
                events_collected: events.len(),
                lookback,
                last_error: None,
            },
            events,
        },
        Err(error) => CollectionBatch {
            events: Vec::new(),
            status: SourceStatus {
                name: "windows.eventlog".into(),
                platform: "windows".into(),
                state: "error".into(),
                events_collected: 0,
                lookback,
                last_error: Some(error),
            },
        },
    }
}

pub async fn poll_event_log(
    tx: mpsc::Sender<Event>,
    status: Arc<RwLock<SourceStatus>>,
    checkpoints: Arc<CheckpointStore>,
) {
    #[cfg(target_os = "windows")]
    if std::env::var("REDTRACE_WINDOWS_COLLECTOR").as_deref() != Ok("wevtutil") {
        native::stream(tx, status, checkpoints).await;
        return;
    }
    loop {
        let store = checkpoints.clone();
        match tokio::task::spawn_blocking(move || collect_window(10_000, &store)).await {
            Ok(Ok(events)) => {
                set_state(&status, "streaming", None).await;
                for event in events {
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
            Ok(Err(error)) => set_state(&status, "error", Some(error)).await,
            Err(error) => set_state(&status, "error", Some(error.to_string())).await,
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn collect_window(millis: u64, checkpoints: &CheckpointStore) -> Result<Vec<Event>, String> {
    let sources = [
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
    let mut events = Vec::new();
    let mut errors = Vec::new();
    for (channel, source, ids) in sources {
        let query = checkpoints
            .get(source)
            .and_then(|checkpoint| checkpoint_record_id(&checkpoint.cursor))
            .map(|record| format!("*[System[({ids}) and EventRecordID > {record}]]"))
            .unwrap_or_else(|| {
                format!("*[System[({ids}) and TimeCreated[timediff(@SystemTime) <= {millis}]]]")
            });
        let output = Command::new("wevtutil.exe")
            .args([
                "qe",
                channel,
                &format!("/q:{query}"),
                "/f:xml",
                "/rd:false",
                "/c:2000",
            ])
            .output();
        match output {
            Ok(output) if output.status.success() => {
                let xml = String::from_utf8_lossy(&output.stdout);
                events.extend(parse_events(&xml, source));
            }
            Ok(output) => errors.push(format!(
                "{channel}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            Err(error) => errors.push(format!("{channel}: {error}")),
        }
    }
    if events.is_empty() && !errors.is_empty() {
        Err(errors.join("; "))
    } else {
        Ok(events)
    }
}

fn checkpoint_record_id(cursor: &str) -> Option<u64> {
    cursor.parse::<u64>().ok().or_else(|| {
        ["RecordId='", "RecordId=\""].iter().find_map(|prefix| {
            cursor
                .split(prefix)
                .nth(1)
                .and_then(|value| value.split(['\'', '"']).next())
                .and_then(|value| value.parse().ok())
        })
    })
}

fn parse_events(xml: &str, source: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let mut cursor = xml;
    while let Some(start) = cursor.find("<Event") {
        let candidate = &cursor[start..];
        let Some(open_end) = candidate.find('>') else {
            break;
        };
        let opening = &candidate[..=open_end];
        if !opening.starts_with("<Event ") && opening != "<Event>" {
            cursor = &candidate[open_end + 1..];
            continue;
        }
        let Some(end) = candidate.find("</Event>") else {
            break;
        };
        let block = &candidate[..end + "</Event>".len()];
        if let Some(event) = parse_event(block, source) {
            events.push(event);
        }
        cursor = &candidate[end + "</Event>".len()..];
    }
    events
}

fn parse_event(xml: &str, source: &str) -> Option<Event> {
    let event_id = tag_text(xml, "EventID")?;
    let timestamp = attribute_from_element(xml, "TimeCreated", "SystemTime")?;
    let provider = attribute_from_element(xml, "Provider", "Name").unwrap_or_default();
    let computer = tag_text(xml, "Computer").unwrap_or_default();
    let record_id = tag_text(xml, "EventRecordID");
    let data = event_data(xml);
    let (title, level, outcome) = describe(&event_id, &data);
    let mut fields = BTreeMap::from([
        ("event.id".into(), event_id.clone()),
        ("event.outcome".into(), outcome.into()),
        ("event.provider".into(), provider),
        ("host.name".into(), computer),
    ]);
    if let Some(record_id) = &record_id {
        fields.insert("collector.cursor".into(), record_id.clone());
        fields.insert("event.record_id".into(), record_id.clone());
    }
    map_first(
        &data,
        &["TargetUserName", "SubjectUserName", "User"],
        "user.name",
        &mut fields,
    );
    map_first(&data, &["IpAddress", "SourceIp"], "source.ip", &mut fields);
    map_first(&data, &["IpPort", "SourcePort"], "source.port", &mut fields);
    map_first(&data, &["DestinationIp"], "destination.ip", &mut fields);
    map_first(&data, &["DestinationPort"], "destination.port", &mut fields);
    map_first(&data, &["ImageLoaded"], "dll.path", &mut fields);
    map_first(&data, &["TargetObject"], "registry.path", &mut fields);
    map_first(&data, &["Details"], "registry.value_data", &mut fields);
    map_first(
        &data,
        &["NewProcessId", "ProcessId", "ProcessID"],
        "process.pid",
        &mut fields,
    );
    map_first(
        &data,
        &["ProcessName", "NewProcessName", "Image"],
        "process.executable",
        &mut fields,
    );
    if let Some(executable) = fields.get("process.executable").cloned() {
        let process_name = executable
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&executable)
            .to_owned();
        fields.insert("process.name".into(), process_name);
    }
    map_first(
        &data,
        &["CommandLine", "ProcessCommandLine", "ScriptBlockText"],
        "process.command_line",
        &mut fields,
    );
    map_first(
        &data,
        &["ParentProcessId", "ParentProcessID"],
        "process.parent.pid",
        &mut fields,
    );
    map_first(
        &data,
        &["ParentImage", "ParentProcessName"],
        "parent.name",
        &mut fields,
    );
    map_first(&data, &["Hashes", "Hash"], "file.hash", &mut fields);
    map_first(&data, &["TargetFilename"], "file.path", &mut fields);
    let mut event = Event::normalized(0, timestamp, source.into(), level.into(), title, fields);
    if let Some(record) = record_id {
        event.identify(&format!("{}:{record}", event.fields["host.name"]));
    }
    Some(event)
}

fn describe(
    event_id: &str,
    data: &BTreeMap<String, String>,
) -> (String, &'static str, &'static str) {
    match event_id {
        "4624" => (
            format!(
                "Успешный вход пользователя {}",
                value(data, "TargetUserName")
            ),
            "low",
            "success",
        ),
        "4625" => (
            format!(
                "Неуспешный вход пользователя {}",
                value(data, "TargetUserName")
            ),
            "medium",
            "failure",
        ),
        "4740" => (
            format!(
                "Учётная запись {} заблокирована",
                value(data, "TargetUserName")
            ),
            "high",
            "failure",
        ),
        "4688" | "1" => (
            format!(
                "Запущен процесс {}",
                data.get("NewProcessName")
                    .or_else(|| data.get("Image"))
                    .map(String::as_str)
                    .unwrap_or("н/д")
            ),
            "medium",
            "success",
        ),
        "3" => (
            "Создано сетевое соединение процессом".into(),
            "medium",
            "unknown",
        ),
        "11" => (
            format!("Создан файл {}", value(data, "TargetFilename")),
            "medium",
            "success",
        ),
        "7" => (
            format!("Загружен модуль {}", value(data, "ImageLoaded")),
            "medium",
            "success",
        ),
        "12" | "13" => (
            format!("Изменён реестр {}", value(data, "TargetObject")),
            "medium",
            "success",
        ),
        "22" => (
            format!("DNS-запрос {}", value(data, "QueryName")),
            "medium",
            "unknown",
        ),
        "4104" => ("Выполнен блок PowerShell".into(), "high", "success"),
        _ => (format!("Windows Event {event_id}"), "low", "unknown"),
    }
}

fn event_data(xml: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut cursor = xml;
    while let Some(start) = cursor.find("<Data") {
        let candidate = &cursor[start..];
        let Some(open_end) = candidate.find('>') else {
            break;
        };
        let open = &candidate[..=open_end];
        let Some(name) = attribute(open, "Name") else {
            cursor = &candidate[open_end + 1..];
            continue;
        };
        let Some(close) = candidate[open_end + 1..].find("</Data>") else {
            break;
        };
        let value = &candidate[open_end + 1..open_end + 1 + close];
        out.insert(name, xml_unescape(value.trim()));
        cursor = &candidate[open_end + 1 + close + "</Data>".len()..];
    }
    out
}

fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let start = xml.find(&format!("<{tag}"))?;
    let body = &xml[start..];
    let open_end = body.find('>')?;
    let close = body[open_end + 1..].find(&format!("</{tag}>"))?;
    Some(xml_unescape(
        body[open_end + 1..open_end + 1 + close].trim(),
    ))
}

fn attribute_from_element(xml: &str, element: &str, name: &str) -> Option<String> {
    let start = xml.find(&format!("<{element}"))?;
    let end = xml[start..].find('>')?;
    attribute(&xml[start..=start + end], name)
}

fn attribute(element: &str, name: &str) -> Option<String> {
    for quote in ['\'', '"'] {
        let needle = format!("{name}={quote}");
        if let Some(start) = element.find(&needle) {
            let value = &element[start + needle.len()..];
            return value.find(quote).map(|end| xml_unescape(&value[..end]));
        }
    }
    None
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn map_first(
    data: &BTreeMap<String, String>,
    candidates: &[&str],
    target: &str,
    fields: &mut BTreeMap<String, String>,
) {
    if let Some(value) = candidates
        .iter()
        .find_map(|name| data.get(*name))
        .filter(|value| !value.is_empty() && value.as_str() != "-")
    {
        fields.insert(target.into(), value.clone());
    }
}

fn value<'a>(data: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    data.get(key).map(String::as_str).unwrap_or("н/д")
}

fn valid_lookback(value: &str) -> bool {
    value.strip_suffix(['m', 'h', 'd']).is_some_and(|number| {
        !number.is_empty()
            && number.bytes().all(|byte| byte.is_ascii_digit())
            && number
                .parse::<u32>()
                .is_ok_and(|number| number > 0 && number <= 10080)
    })
}

fn lookback_millis(value: &str) -> u64 {
    let amount = value[..value.len() - 1].parse::<u64>().unwrap_or(15);
    match value.chars().last() {
        Some('d') => amount * 86_400_000,
        Some('h') => amount * 3_600_000,
        _ => amount * 60_000,
    }
}

async fn set_state(status: &Arc<RwLock<SourceStatus>>, state: &str, error: Option<String>) {
    let mut status = status.write().await;
    status.state = state.into();
    status.last_error = error;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookback_rejects_unicode_zero_and_overflow_without_panicking() {
        for invalid in [
            "\u{e9}",
            "0m",
            "999999999999999999999999h",
            "10081d",
            "1h;id",
        ] {
            assert!(!valid_lookback(invalid));
        }
        assert!(valid_lookback("15m"));
        assert!(valid_lookback("10080d"));
    }

    #[test]
    fn parses_security_event_xml() {
        let xml = r#"<Events><Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2026-09-29T10:00:00.0000000Z'/><Computer>HOST</Computer></System><EventData><Data Name='TargetUserName'>admin</Data><Data Name='IpAddress'>10.0.0.9</Data></EventData></Event></Events>"#;
        let events = parse_events(xml, "windows.security");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].fields["event.id"], "4625");
        assert_eq!(events[0].fields["source.ip"], "10.0.0.9");
    }

    #[test]
    fn bookmark_and_polling_record_ids_are_compatible() {
        assert_eq!(checkpoint_record_id("42"), Some(42));
        assert_eq!(
            checkpoint_record_id(
                "<BookmarkList><Bookmark Channel='Security' RecordId='42' IsCurrent='true'/></BookmarkList>"
            ),
            Some(42)
        );
        assert_eq!(checkpoint_record_id("invalid"), None);
    }

    #[test]
    fn records_with_identical_descriptions_are_distinct() {
        let xml = "<Event><System><EventID>4625</EventID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><EventRecordID>42</EventRecordID><Computer>HOST</Computer></System><EventData><Data Name='TargetUserName'>admin</Data></EventData></Event>";
        let first = parse_events(xml, "windows.security").remove(0);
        let second = parse_events(
            &xml.replace("<EventRecordID>42", "<EventRecordID>43"),
            "windows.security",
        )
        .remove(0);
        assert_eq!(first.message, second.message);
        assert_ne!(first.uid, second.uid);
        assert_eq!(first.uid, parse_events(xml, "windows.security")[0].uid);
    }
}
