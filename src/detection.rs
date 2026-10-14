use crate::model::Event;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    path::PathBuf,
    time::Instant,
};

const WINDOW_SECONDS: i64 = 5 * 60;
const SUPPRESSION_SECONDS: i64 = 10 * 60;
const MAX_WINDOW_EVENTS: usize = 128;
const MAX_STATE_KEYS: usize = 2048;
const MAX_SCOPE_KEYS: usize = 256;
const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SCOPE_BYTES: usize = 512 * 1024;
const ENTRY_BYTES: usize = 96;
const DEFAULT_MAX_ALERT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Alert {
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub confidence: u8,
    pub risk_score: u8,
    pub mitre_technique: String,
    pub timestamp: String,
    pub group_key: String,
    pub evidence: Vec<String>,
    pub description: String,
}

pub struct DetectionEngine {
    failures: HashMap<String, VecDeque<(i64, String)>>,
    suppressed_until: HashMap<String, i64>,
    started: Instant,
    clock: i64,
    refused_total: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DetectionHealth {
    pub failure_keys: usize,
    pub suppression_keys: usize,
    pub state_bytes: usize,
    pub max_state_keys: usize,
    pub max_scope_keys: usize,
    pub max_state_bytes: usize,
    pub max_scope_bytes: usize,
    pub refused_total: u64,
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self {
            failures: HashMap::new(),
            suppressed_until: HashMap::new(),
            started: Instant::now(),
            clock: 0,
            refused_total: 0,
        }
    }
}

impl DetectionEngine {
    pub fn evaluate(&mut self, event: &Event) -> Vec<Alert> {
        self.evaluate_at(event, self.started.elapsed().as_secs())
    }

    pub fn evaluate_at(&mut self, event: &Event, received_seconds: u64) -> Vec<Alert> {
        self.clock = self.clock.max(received_seconds.min(i64::MAX as u64) as i64);
        let timestamp = self.clock;
        self.expire(timestamp);
        let mut alerts = Vec::new();
        let event_id = event.field("event.id").unwrap_or_default();
        let scope = event
            .field("agent.id")
            .filter(|id| id.len() == 16 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .map(|id| format!("agent:{id}|"))
            .unwrap_or_else(|| "local|".into());

        if matches!(event_id, "ssh.login.failure" | "4625") {
            let key = bounded_group(
                event
                    .field("source.ip")
                    .or_else(|| event.field("user.name"))
                    .unwrap_or("unknown"),
            );
            let state_key = format!("{scope}auth:{}", fingerprint(&key));
            let evidence = if self.admit(&scope, &state_key, ENTRY_BYTES) {
                let window = self.failures.entry(state_key).or_default();
                if !window.iter().any(|(_, uid)| uid == &event.uid) {
                    window.push_back((timestamp, bounded_uid(&event.uid)));
                }
                while window
                    .front()
                    .is_some_and(|(at, _)| timestamp.saturating_sub(*at) > WINDOW_SECONDS)
                {
                    window.pop_front();
                }
                while window.len() > MAX_WINDOW_EVENTS {
                    window.pop_front();
                }
                (window.len() >= 5).then(|| {
                    window
                        .iter()
                        .map(|(_, uid)| uid.clone())
                        .collect::<Vec<_>>()
                })
            } else {
                None
            };
            let suppression_key = format!("{scope}auth.bruteforce:{}", fingerprint(&key));
            if let Some(evidence) = evidence.filter(|_| self.can_emit(&suppression_key, timestamp))
            {
                alerts.push(alert(
                    "auth.bruteforce",
                    "Множественные неуспешные попытки входа",
                    "high",
                    85,
                    78,
                    "T1110",
                    event,
                    key,
                    evidence,
                    "За пять минут зафиксировано не менее пяти отказов аутентификации.",
                ));
                self.suppress(&scope, suppression_key, timestamp);
            }
        }

        if event_id == "4740" {
            alerts.push(alert(
                "account.lockout",
                "Учётная запись заблокирована",
                "high",
                98,
                82,
                "T1110",
                event,
                bounded_group(event.field("user.name").unwrap_or("unknown")),
                vec![event.uid.clone()],
                "Windows зарегистрировала блокировку учётной записи.",
            ));
        }

        if matches!(event_id, "4104" | "powershell.script_block") {
            alerts.push(alert(
                "powershell.script_block",
                "Выполнен PowerShell Script Block",
                "medium",
                65,
                55,
                "T1059.001",
                event,
                bounded_group(event.field("user.name").unwrap_or("local")),
                vec![event.uid.clone()],
                "Зафиксировано выполнение блока PowerShell; требуется анализ содержимого.",
            ));
        }

        if let Some(command) = event.field("process.command_line") {
            let lower = command.to_ascii_lowercase();
            let indicators = [
                "encodedcommand",
                " -enc ",
                "frombase64string",
                "rundll32 javascript:",
                "curl | sh",
                "curl|sh",
                "wget | sh",
                "/dev/tcp/",
                "chmod +s",
            ];
            if indicators.iter().any(|indicator| lower.contains(indicator)) {
                let key = bounded_group(event.field("process.name").unwrap_or("unknown"));
                let suppression_key =
                    format!("{scope}process.suspicious_command:{}", fingerprint(&key));
                if self.can_emit(&suppression_key, timestamp) {
                    alerts.push(alert(
                        "process.suspicious_command",
                        "Подозрительная командная строка",
                        "critical",
                        90,
                        92,
                        "T1059",
                        event,
                        key,
                        vec![event.uid.clone()],
                        "Командная строка содержит технику кодирования или исполнения через shell.",
                    ));
                    self.suppress(&scope, suppression_key, timestamp);
                }
            }
        }

        if event_id == "sudo.command.failure" {
            alerts.push(alert(
                "privilege.sudo_failure",
                "Отказ повышения привилегий",
                "medium",
                80,
                58,
                "T1548.003",
                event,
                bounded_group(event.field("user.name").unwrap_or("unknown")),
                vec![event.uid.clone()],
                "sudo отклонил попытку выполнения команды с повышенными привилегиями.",
            ));
        }

        alerts
    }

    fn can_emit(&self, key: &str, timestamp: i64) -> bool {
        self.suppressed_until
            .get(key)
            .is_none_or(|until| timestamp >= *until)
    }

    fn expire(&mut self, timestamp: i64) {
        self.failures.retain(|_, window| {
            while window
                .front()
                .is_some_and(|(at, _)| timestamp.saturating_sub(*at) > WINDOW_SECONDS)
            {
                window.pop_front();
            }
            !window.is_empty()
        });
        self.suppressed_until.retain(|_, until| timestamp < *until);
    }

    fn usage(&self, scope: Option<&str>) -> (usize, usize) {
        let included = |key: &str| scope.is_none_or(|scope| key.starts_with(scope));
        let failures = self.failures.iter().filter(|(key, _)| included(key));
        let mut keys = 0;
        let mut bytes = 0;
        for (key, window) in failures {
            keys += 1;
            bytes += key.len() + 128 + window.len() * ENTRY_BYTES;
        }
        for key in self.suppressed_until.keys().filter(|key| included(key)) {
            keys += 1;
            bytes += key.len() + 128;
        }
        (keys, bytes)
    }

    fn admit(&mut self, scope: &str, key: &str, extra: usize) -> bool {
        let exists = self.failures.contains_key(key) || self.suppressed_until.contains_key(key);
        let charge = extra + if exists { 0 } else { key.len() + 128 };
        let (keys, bytes) = self.usage(None);
        let (scope_keys, scope_bytes) = self.usage(Some(scope));
        let allowed = (exists || (keys < MAX_STATE_KEYS && scope_keys < MAX_SCOPE_KEYS))
            && bytes.saturating_add(charge) <= MAX_STATE_BYTES
            && scope_bytes.saturating_add(charge) <= MAX_SCOPE_BYTES;
        if !allowed {
            self.refused_total = self.refused_total.saturating_add(1);
        }
        allowed
    }

    fn suppress(&mut self, scope: &str, key: String, timestamp: i64) {
        if self.admit(scope, &key, 0) {
            self.suppressed_until
                .insert(key, timestamp.saturating_add(SUPPRESSION_SECONDS));
        }
    }

    pub fn health(&self) -> DetectionHealth {
        DetectionHealth {
            failure_keys: self.failures.len(),
            suppression_keys: self.suppressed_until.len(),
            state_bytes: self.usage(None).1,
            max_state_keys: MAX_STATE_KEYS,
            max_scope_keys: MAX_SCOPE_KEYS,
            max_state_bytes: MAX_STATE_BYTES,
            max_scope_bytes: MAX_SCOPE_BYTES,
            refused_total: self.refused_total,
        }
    }
}

fn bounded_group(value: &str) -> String {
    if value.len() <= 128 && !value.chars().any(char::is_control) {
        value.into()
    } else {
        format!("bounded:{}", fingerprint(value))
    }
}

fn bounded_uid(value: &str) -> String {
    if value.len() <= 64 {
        value.into()
    } else {
        fingerprint(value)
    }
}

#[allow(clippy::too_many_arguments)]
fn alert(
    rule_id: &str,
    title: &str,
    severity: &str,
    confidence: u8,
    risk_score: u8,
    technique: &str,
    event: &Event,
    group_key: String,
    evidence: Vec<String>,
    description: &str,
) -> Alert {
    let id = fingerprint(&format!("{rule_id}|{}|{group_key}", event.uid));
    Alert {
        id,
        rule_id: rule_id.into(),
        title: title.into(),
        severity: severity.into(),
        confidence,
        risk_score,
        mitre_technique: technique.into(),
        timestamp: event.timestamp.clone(),
        group_key,
        evidence,
        description: description.into(),
    }
}

fn fingerprint(value: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in value.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

#[derive(Serialize, Deserialize)]
struct AlertRecord {
    checksum: u64,
    alert: Alert,
}

#[derive(Debug)]
pub struct AlertLog {
    path: PathBuf,
    max_bytes: u64,
}

impl AlertLog {
    pub fn open_default() -> io::Result<Self> {
        Self::open(crate::storage::data_directory().join("alerts.jsonl"))
    }

    pub fn open(path: PathBuf) -> io::Result<Self> {
        Self::open_with_limit(path, alert_log_limit())
    }

    fn open_with_limit(path: PathBuf, max_bytes: u64) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
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
        Ok(Self { path, max_bytes })
    }

    pub fn append(&self, alerts: &[Alert]) -> io::Result<()> {
        if alerts.is_empty() {
            return Ok(());
        }
        let mut file = OpenOptions::new().append(true).open(&self.path)?;
        for alert in alerts {
            let bytes = serde_json::to_vec(alert).map_err(io::Error::other)?;
            serde_json::to_writer(
                &mut file,
                &AlertRecord {
                    checksum: checksum(&bytes),
                    alert: alert.clone(),
                },
            )
            .map_err(io::Error::other)?;
            file.write_all(b"\n")?;
        }
        file.flush()?;
        file.sync_data()?;
        if file.metadata()?.len() > self.max_bytes {
            self.compact()?;
        }
        Ok(())
    }

    pub fn recover(&self) -> io::Result<(Vec<Alert>, usize)> {
        let mut alerts = Vec::new();
        let mut corrupt = 0;
        let mut seen = HashSet::new();
        for line in BufReader::new(File::open(&self.path)?).lines() {
            let Ok(line) = line else {
                corrupt += 1;
                continue;
            };
            let Ok(record) = serde_json::from_str::<AlertRecord>(&line) else {
                corrupt += 1;
                continue;
            };
            let Ok(bytes) = serde_json::to_vec(&record.alert) else {
                corrupt += 1;
                continue;
            };
            if checksum(&bytes) != record.checksum {
                corrupt += 1;
            } else if seen.insert(record.alert.id.clone()) {
                alerts.push(record.alert);
            }
        }
        Ok((alerts, corrupt))
    }

    fn compact(&self) -> io::Result<()> {
        let (alerts, _) = self.recover()?;
        let mut retained = Vec::new();
        let target = self.max_bytes / 2;
        let mut bytes = 0_u64;
        for alert in alerts.into_iter().rev() {
            let encoded = encode_record(&alert)?;
            let record_bytes = encoded.len() as u64 + 1;
            if !retained.is_empty() && bytes.saturating_add(record_bytes) > target {
                break;
            }
            bytes = bytes.saturating_add(record_bytes);
            retained.push(encoded);
        }
        retained.reverse();
        let parent = self
            .path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let temp = parent.join(".alerts.jsonl.tmp");
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        for record in retained {
            file.write_all(&record)?;
            file.write_all(b"\n")?;
        }
        file.sync_all()?;
        fs::rename(&temp, &self.path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

fn encode_record(alert: &Alert) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(alert).map_err(io::Error::other)?;
    serde_json::to_vec(&AlertRecord {
        checksum: checksum(&bytes),
        alert: alert.clone(),
    })
    .map_err(io::Error::other)
}

fn alert_log_limit() -> u64 {
    std::env::var("REDTRACE_MAX_ALERT_MB")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.saturating_mul(1024 * 1024))
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_ALERT_BYTES)
}

fn checksum(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn failed_login(index: usize) -> Event {
        Event::normalized(
            index as u64,
            format!("2026-01-01T00:00:{index:02}Z"),
            "windows.security".into(),
            "medium".into(),
            "failed login".into(),
            BTreeMap::from([
                ("event.id".into(), "4625".into()),
                ("source.ip".into(), "10.0.0.9".into()),
            ]),
        )
    }

    #[test]
    fn emits_threshold_alert_and_suppresses_duplicates() {
        let mut engine = DetectionEngine::default();
        let mut alerts = Vec::new();
        for index in 0..6 {
            alerts.extend(engine.evaluate(&failed_login(index)));
        }
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "auth.bruteforce");
        assert_eq!(alerts[0].evidence.len(), 5);
    }

    #[test]
    fn alert_log_recovers_valid_records() {
        let path =
            std::env::temp_dir().join(format!("redtrace-alerts-{}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);
        let log = AlertLog::open(path.clone()).unwrap();
        let alert = DetectionEngine::default()
            .evaluate(&Event::normalized(
                1,
                "2026-01-01T00:00:00Z".into(),
                "linux.sudo".into(),
                "high".into(),
                "denied".into(),
                BTreeMap::from([("event.id".into(), "sudo.command.failure".into())]),
            ))
            .remove(0);
        log.append(std::slice::from_ref(&alert)).unwrap();
        let (recovered, corrupt) = log.recover().unwrap();
        assert_eq!(corrupt, 0);
        assert_eq!(recovered, vec![alert]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn alert_log_compacts_to_a_bounded_file() {
        let path =
            std::env::temp_dir().join(format!("redtrace-alert-limit-{}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);
        let log = AlertLog::open_with_limit(path.clone(), 1_024).unwrap();
        for index in 0..40 {
            let alert = DetectionEngine::default()
                .evaluate(&Event::normalized(
                    index,
                    format!("2026-01-01T00:00:{:02}Z", index % 60),
                    "linux.sudo".into(),
                    "high".into(),
                    format!("denied {index}"),
                    BTreeMap::from([("event.id".into(), "sudo.command.failure".into())]),
                ))
                .remove(0);
            log.append(&[alert]).unwrap();
        }
        let (recovered, corrupt) = log.recover().unwrap();
        assert_eq!(corrupt, 0);
        assert!(!recovered.is_empty());
        assert!(recovered.len() < 40);
        assert!(fs::metadata(&path).unwrap().len() <= 1_024);
        let _ = fs::remove_file(path);
    }
}
