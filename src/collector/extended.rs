use super::{BoundedLine, BoundedLines, audit_file, endpoint_security::EsSession};
use crate::{
    config::{Config, EventFilter},
    model::Event,
    modules::ModuleHealth,
    storage::CheckpointStore,
};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, BufReader, Seek, SeekFrom},
    path::Path,
};

pub struct ExtendedCollectors {
    config: Config,
    filter: EventFilter,
    es: Option<EsSession>,
    es_retry: std::time::Instant,
    next_source: usize,
    pub health: BTreeMap<String, ModuleHealth>,
}
impl ExtendedCollectors {
    pub fn new(config: Config) -> io::Result<Self> {
        config.validate()?;
        Ok(Self {
            filter: EventFilter::new(&config)?,
            config,
            es: None,
            es_retry: std::time::Instant::now(),
            next_source: 0,
            health: BTreeMap::new(),
        })
    }
    pub fn reconfigure(&mut self, config: Config) -> io::Result<()> {
        config.validate()?;
        self.filter = EventFilter::new(&config)?;
        self.es = None;
        self.es_retry = std::time::Instant::now();
        self.next_source = 0;
        self.config = config;
        self.health.clear();
        Ok(())
    }
    pub fn collect(&mut self, checkpoints: &CheckpointStore) -> Vec<Event> {
        let mut events = Vec::new();
        let mut bytes = 0;
        let mut sources = Vec::new();
        if self.config.sources.linux_audit && cfg!(target_os = "linux") {
            sources.push("linux.audit".to_owned());
        }
        if self.config.sources.macos_endpoint_security && cfg!(target_os = "macos") {
            sources.push("macos.endpoint_security".to_owned());
        }
        sources.extend(
            self.config
                .sources
                .module_inputs
                .iter()
                .map(|input| format!("module.{}", input.id)),
        );
        if sources.is_empty() {
            return events;
        }
        let start = self.next_source % sources.len();
        // Rotate the first source so a busy audit stream cannot starve optional inputs.
        self.next_source = (start + 1) % sources.len();
        for index in 0..sources.len() {
            let source = &sources[(start + index) % sources.len()];
            let mut limits = self.config.resources.clone();
            limits.max_batch_events = limits.max_batch_events.saturating_sub(events.len());
            limits.max_batch_bytes = limits.max_batch_bytes.saturating_sub(bytes);
            if limits.max_batch_events == 0 || limits.max_batch_bytes == 0 {
                break;
            }
            let (batch, warning, health_id, permissions) = if source == "linux.audit" {
                let batch = audit_file::collect(
                    Path::new(&self.config.sources.audit_path),
                    checkpoints,
                    &limits,
                );
                let denied = batch
                    .status
                    .last_error
                    .as_ref()
                    .is_some_and(|e| e.contains("Permission denied"));
                (
                    batch.events,
                    batch.status.last_error,
                    source.clone(),
                    if denied { "denied" } else { "read-only" },
                )
            } else if source == "macos.endpoint_security" {
                if self.es.is_none() && std::time::Instant::now() >= self.es_retry {
                    match EsSession::start(
                        &self.config.sources.es_events,
                        self.config.resources.max_record_bytes,
                    ) {
                        Ok(es) => self.es = Some(es),
                        Err(error) => {
                            self.es_retry =
                                std::time::Instant::now() + std::time::Duration::from_secs(60);
                            let health = self.health.entry(source.clone()).or_default();
                            health.id = source.clone();
                            health.state = "error".into();
                            health.permissions = "root + Full Disk Access + ES entitlement".into();
                            health.errors += 1;
                            health.error = Some(error.to_string());
                        }
                    }
                }
                if let Some(es) = &mut self.es {
                    let batch = es.drain_bounded(limits.max_batch_events, limits.max_batch_bytes);
                    self.health.insert(es.health.id.clone(), es.health.clone());
                    for event in batch {
                        let event = self.filter_event(event);
                        bytes +=
                            crate::ingest::normalized_event_bytes(&event, usize::MAX).unwrap_or(0);
                        events.push(event);
                    }
                    if es_health_failed(&self.health, source) {
                        self.es = None;
                        self.es_retry =
                            std::time::Instant::now() + std::time::Duration::from_secs(60);
                    }
                }
                continue;
            } else {
                let input = self
                    .config
                    .sources
                    .module_inputs
                    .iter()
                    .find(|input| source == &format!("module.{}", input.id))
                    .expect("configured module source");
                let mut config = self.config.clone();
                config.resources = limits.clone();
                match module_file(input, checkpoints, &config) {
                    Ok(batch) => (
                        batch.events,
                        batch.warning,
                        input.id.clone(),
                        "read-only module input",
                    ),
                    Err(error) => (
                        Vec::new(),
                        Some(error.to_string()),
                        input.id.clone(),
                        "read-only module input",
                    ),
                }
            };
            let mut warning = warning;
            let mut accepted = 0;
            let mut filtered = 0;
            let mut last_event_at = None;
            for event in batch {
                let event = self.filter_event(event);
                match crate::ingest::normalized_event_bytes(
                    &event,
                    self.config.resources.max_batch_bytes.saturating_sub(bytes),
                ) {
                    Ok(size) if events.len() < self.config.resources.max_batch_events => {
                        bytes += size;
                        accepted += 1;
                        filtered += u64::from(event.fields.contains_key("event.filtered"));
                        last_event_at = Some(event.timestamp.clone());
                        events.push(event);
                    }
                    _ => {
                        warning = Some("collection batch budget reached; source cursor held for remaining records".into());
                        break;
                    }
                }
            }
            let health = self.health.entry(health_id.clone()).or_default();
            health.id = health_id;
            health.state = if warning.is_some() {
                if accepted == 0 { "error" } else { "degraded" }
            } else {
                "ready"
            }
            .into();
            health.permissions = permissions.into();
            health.events += accepted;
            health.filtered += filtered;
            health.errors += u64::from(warning.is_some());
            if last_event_at.is_some() {
                health.last_event_at = last_event_at;
            }
            health.error = warning;
        }
        events
    }

    fn filter_event(&self, mut event: Event) -> Event {
        if event.fields.contains_key("event.filtered") || !self.filter.accepts(&event) {
            event.fields.insert("event.filtered".into(), "true".into());
            event.message = "Event excluded by collection policy".into();
            event
                .fields
                .retain(|key, _| key.starts_with("collector.") || key == "event.filtered");
        }
        event
    }
}

fn es_health_failed(health: &BTreeMap<String, ModuleHealth>, source: &str) -> bool {
    health
        .get(source)
        .is_some_and(|health| health.state == "error")
}

struct ModuleBatch {
    events: Vec<Event>,
    warning: Option<String>,
}

fn module_file(
    input: &crate::config::ModuleInput,
    checkpoints: &CheckpointStore,
    config: &Config,
) -> io::Result<ModuleBatch> {
    let mut file = File::open(&input.path)?;
    let identity = audit_file::file_identity(&file)?;
    let source = format!("module.{}", input.id);
    let cursor = checkpoints
        .get(&source)
        .map(|cp| serde_json::from_str::<audit_file::FileCursor>(&cp.cursor))
        .transpose()
        .map_err(io::Error::other)?;
    let offset = if let Some(cp) = cursor {
        if cp.identity != identity || file.metadata()?.len() < cp.offset {
            return Err(io::Error::other(
                "module input rotated or truncated; reset its cursor explicitly",
            ));
        }
        cp.offset
    } else {
        0
    };
    file.seek(SeekFrom::Start(offset))?;
    let mut position = offset;
    let mut reader = BoundedLines::new(BufReader::new(file), config.resources.max_record_bytes);
    let mut events = Vec::new();
    let mut warning = None;
    let filter = EventFilter::new(&Config {
        include: input.query.clone(),
        exclude: String::new(),
        ..config.clone()
    })?;
    for _ in 0..config.resources.max_batch_events {
        let raw = match reader.read_line() {
            Err(error) => {
                warning = Some(error.to_string());
                break;
            }
            Ok(line) => match line {
                BoundedLine::Complete(raw) => raw,
                BoundedLine::End => break,
                BoundedLine::Incomplete => {
                    warning = Some("incomplete module record; cursor held".into());
                    break;
                }
                BoundedLine::Oversized => {
                    warning = Some("module record exceeds configured limit; cursor held".into());
                    break;
                }
            },
        };
        if position - offset + raw.len() as u64 > config.resources.max_batch_bytes as u64 {
            warning = Some("module batch byte budget reached; cursor held".into());
            break;
        }
        let mut record: crate::modules::ModuleEvent = match serde_json::from_slice(&raw) {
            Ok(record) => record,
            Err(error) => {
                warning = Some(format!("invalid module record: {error}; cursor held"));
                break;
            }
        };
        if let Err(error) = record.validate(&input.id) {
            warning = Some(format!("{error}; cursor held"));
            break;
        }
        position += raw.len() as u64;
        record.event.source = source.clone();
        record.event.fields.retain(|k, _| {
            !k.starts_with("collector.") && !k.starts_with("agent.") && k != "event.filtered"
        });
        record.event.timestamp = chrono::DateTime::parse_from_rfc3339(&record.event.timestamp)
            .map_err(io::Error::other)?
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        record.event.id = 0;
        crate::modules::normalize(&mut record.event);
        record.event.identify(&format!("{identity}:{position}"));
        record.event.fields.insert(
            "collector.cursor".into(),
            serde_json::to_string(&audit_file::FileCursor {
                identity: identity.clone(),
                offset: position,
            })
            .map_err(io::Error::other)?,
        );
        record
            .event
            .fields
            .insert("collector.cursor_kind".into(), "file".into());
        if !filter.accepts(&record.event) {
            record
                .event
                .fields
                .insert("event.filtered".into(), "true".into());
        }
        events.push(record.event);
    }
    Ok(ModuleBatch { events, warning })
}
