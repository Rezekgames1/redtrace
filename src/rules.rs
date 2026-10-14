//! Declarative, bounded rule evaluation; live and replay share the same engine.
use crate::{
    detection::Alert,
    index::{ExecutionLimits, QueryBudget, matches_event},
    model::Event,
    query::{self, Expr},
    service::{self, invalid},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::IpAddr,
    path::{Path, PathBuf},
};

const MAX_RULES: usize = 128;
const MAX_KEYS: usize = 2048;
const MAX_STATE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    Match,
    Threshold,
    Sequence,
    Absence,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "operator", rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    Number {
        field: String,
        min: Option<f64>,
        max: Option<f64>,
    },
    Cidr {
        field: String,
        network: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub revision: u32,
    pub enabled: bool,
    pub title: String,
    pub severity: String,
    pub confidence: u8,
    pub risk_score: u8,
    pub mitre_technique: String,
    pub description: String,
    pub kind: Kind,
    pub query: String,
    pub conditions: Vec<Condition>,
    pub exceptions: Vec<String>,
    pub group_by: Vec<String>,
    pub window_seconds: u64,
    pub threshold: usize,
    pub sequence: Vec<String>,
    pub suppression_seconds: u64,
}
impl Default for Rule {
    fn default() -> Self {
        Self {
            id: "custom.rule".into(),
            revision: 1,
            enabled: true,
            title: "Custom detection".into(),
            severity: "medium".into(),
            confidence: 70,
            risk_score: 50,
            mitre_technique: String::new(),
            description: String::new(),
            kind: Kind::Match,
            query: "*".into(),
            conditions: Vec::new(),
            exceptions: Vec::new(),
            group_by: Vec::new(),
            window_seconds: 300,
            threshold: 5,
            sequence: Vec::new(),
            suppression_seconds: 60,
        }
    }
}

struct Compiled {
    rule: Rule,
    query: Expr,
    exceptions: Vec<Expr>,
    sequence: Vec<Expr>,
}
impl Compiled {
    fn new(rule: Rule) -> io::Result<Self> {
        if rule.id.is_empty()
            || rule.id.len() > 64
            || !rule
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            || rule.revision == 0
            || rule.title.is_empty()
            || rule.title.len() > 256
            || rule.description.len() > 2048
            || rule.mitre_technique.len() > 64
            || !matches!(
                rule.severity.as_str(),
                "low" | "medium" | "high" | "critical"
            )
            || rule.risk_score > 100
            || rule.confidence > 100
            || !(1..=86400).contains(&rule.window_seconds)
            || !(1..=128).contains(&rule.threshold)
            || rule.suppression_seconds > 86400
            || rule.group_by.len() > 4
            || rule.group_by.iter().any(|f| f.is_empty() || f.len() > 64)
            || rule.exceptions.len() > 16
            || rule.conditions.len() > 16
            || rule.sequence.len() > 8
        {
            return Err(invalid("invalid rule fields or limits"));
        }
        if matches!(rule.kind, Kind::Sequence | Kind::Absence) && rule.sequence.len() < 2 {
            return Err(invalid(
                "sequence and absence rules require 2–8 predicates (absence: trigger then expected event)",
            ));
        }
        if rule.kind == Kind::Absence && rule.sequence.len() != 2 {
            return Err(invalid(
                "absence rule requires exactly trigger and expected predicates",
            ));
        }
        for condition in &rule.conditions {
            match condition {
                Condition::Number { field, min, max } => {
                    if field.is_empty()
                        || field.len() > 64
                        || min.is_none() && max.is_none()
                        || min.is_some_and(|n| !n.is_finite())
                        || max.is_some_and(|n| !n.is_finite())
                        || min.zip(*max).is_some_and(|(a, b)| a > b)
                    {
                        return Err(invalid("invalid numeric rule condition"));
                    }
                }
                Condition::Cidr { field, network } => {
                    if field.is_empty() || field.len() > 64 || parse_cidr(network).is_none() {
                        return Err(invalid("invalid CIDR rule condition"));
                    }
                }
            }
        }
        let query = query::parse(&rule.query).map_err(io::Error::other)?;
        let exceptions = rule
            .exceptions
            .iter()
            .map(|q| query::parse(q).map_err(io::Error::other))
            .collect::<io::Result<Vec<_>>>()?;
        let sequence = rule
            .sequence
            .iter()
            .map(|q| query::parse(q).map_err(io::Error::other))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            rule,
            query,
            exceptions,
            sequence,
        })
    }
}

fn parse_cidr(value: &str) -> Option<(IpAddr, u32)> {
    let (ip, prefix) = value.split_once('/')?;
    let ip = ip.parse().ok()?;
    let prefix = prefix.parse().ok()?;
    if prefix > if matches!(ip, IpAddr::V4(_)) { 32 } else { 128 } {
        return None;
    }
    Some((ip, prefix))
}
fn within(ip: IpAddr, network: IpAddr, prefix: u32) -> bool {
    match (ip, network) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            prefix == 0 || u32::from(a) >> (32 - prefix) == u32::from(b) >> (32 - prefix)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            prefix == 0 || u128::from(a) >> (128 - prefix) == u128::from(b) >> (128 - prefix)
        }
        _ => false,
    }
}
fn condition_matches(condition: &Condition, event: &Event) -> bool {
    match condition {
        Condition::Number { field, min, max } => event
            .field(field)
            .and_then(|v| v.parse::<f64>().ok())
            .is_some_and(|v| {
                v.is_finite() && min.is_none_or(|m| v >= m) && max.is_none_or(|m| v <= m)
            }),
        Condition::Cidr { field, network } => event
            .field(field)
            .and_then(|v| v.parse().ok())
            .zip(parse_cidr(network))
            .is_some_and(|(ip, (net, prefix))| within(ip, net, prefix)),
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct State {
    seen: VecDeque<(u64, String)>,
    step: usize,
    start: u64,
    last: u64,
    suppressed_until: u64,
    evidence: Vec<String>,
    anchor: Option<Event>,
}
impl State {
    fn bytes(&self) -> usize {
        // Include state, tree/key overhead and string slots, not just payloads.
        std::mem::size_of::<Self>()
            + 256
            + self.seen.iter().map(|(_, s)| s.len() + 32).sum::<usize>()
            + self
                .evidence
                .iter()
                .map(|uid| uid.len() + std::mem::size_of::<String>())
                .sum::<usize>()
            + self
                .anchor
                .as_ref()
                .map(crate::index::event_memory_bytes)
                .unwrap_or(0)
    }
}

pub struct Engine {
    rules: Vec<Compiled>,
    states: BTreeMap<String, State>,
    pub refused: u64,
    clock: u64,
    last_tick: Option<u64>,
    state_bytes: usize,
}
impl Engine {
    pub fn new(rules: Vec<Rule>) -> io::Result<Self> {
        if rules.len() > MAX_RULES {
            return Err(invalid("at most 128 custom rules are supported"));
        }
        let mut ids = std::collections::HashSet::new();
        for r in &rules {
            if !ids.insert(&r.id) {
                return Err(invalid("duplicate rule ID"));
            }
        }
        Ok(Self {
            rules: rules
                .into_iter()
                .map(Compiled::new)
                .collect::<io::Result<_>>()?,
            states: BTreeMap::new(),
            refused: 0,
            clock: 0,
            last_tick: None,
            state_bytes: 0,
        })
    }
    pub fn evaluate(&mut self, event: &Event, now: u64) -> Vec<Alert> {
        self.clock = self.clock.max(now);
        let now = self.clock;
        let mut alerts = self.tick(now);
        // UIDs enter several bounded evidence collections and persisted snapshots.
        if event.uid.is_empty() || event.uid.len() > 256 {
            self.refused = self.refused.saturating_add(1);
            return alerts;
        }
        if event
            .fields
            .get("event.filtered")
            .is_some_and(|v| v == "true")
        {
            return alerts;
        }
        let mut budget = QueryBudget::new(ExecutionLimits {
            max_work: 100_000,
            ..ExecutionLimits::default()
        });
        for compiled in &self.rules {
            let rule = &compiled.rule;
            if !rule.enabled {
                continue;
            }
            let match_expr = |expr: &Expr, budget: &mut QueryBudget| {
                matches_event(expr, event, budget).unwrap_or(false)
            };
            if compiled
                .exceptions
                .iter()
                .any(|e| match_expr(e, &mut budget))
                || !rule.conditions.iter().all(|c| condition_matches(c, event))
            {
                continue;
            }
            let scope = event
                .field("agent.id")
                .or_else(|| event.field("host.name"))
                .unwrap_or("local");
            let group = rule
                .group_by
                .iter()
                .map(|f| event.field(f).unwrap_or("<absent>"))
                .collect::<Vec<_>>()
                .join("|");
            let group = format!("{scope}|{group}");
            let hash = crate::ingest::hex(&crate::ingest::sha256(group.as_bytes()));
            let key = format!("{}:{hash}", rule.id);
            let eligible = if matches!(rule.kind, Kind::Sequence | Kind::Absence) {
                compiled.sequence.iter().any(|q| match_expr(q, &mut budget))
            } else {
                match_expr(&compiled.query, &mut budget)
            };
            if !eligible {
                continue;
            }
            let existing = self.states.contains_key(&key);
            let growth = if existing {
                0
            } else {
                State::default().bytes()
            } + event.uid.len()
                + 32
                + match rule.kind {
                    Kind::Sequence => event.uid.len() + std::mem::size_of::<String>(),
                    Kind::Absence => {
                        crate::index::event_memory_bytes(event)
                            + event.uid.len()
                            + std::mem::size_of::<String>()
                    }
                    Kind::Match | Kind::Threshold => 0,
                };
            if self.states.len() >= MAX_KEYS && !existing
                || self.state_bytes.saturating_add(growth) > MAX_STATE_BYTES
            {
                self.refused = self.refused.saturating_add(1);
                continue;
            }
            let state = self.states.entry(key).or_default();
            state.last = now;
            if now < state.suppressed_until || state.seen.iter().any(|(_, uid)| uid == &event.uid) {
                continue;
            }
            let before = if existing { state.bytes() } else { 0 };
            while state
                .seen
                .front()
                .is_some_and(|(at, _)| now.saturating_sub(*at) > rule.window_seconds)
            {
                state.seen.pop_front();
            }
            if state.seen.len() >= 128 {
                state.seen.pop_front();
            }
            state.seen.push_back((now, event.uid.clone()));
            let emit = match rule.kind {
                Kind::Match => true,
                Kind::Threshold => state.seen.len() >= rule.threshold,
                Kind::Sequence => {
                    if state.step > 0 && now.saturating_sub(state.start) > rule.window_seconds {
                        state.step = 0;
                        state.evidence.clear();
                    }
                    if match_expr(&compiled.sequence[state.step], &mut budget) {
                        if state.step == 0 {
                            state.start = now;
                        }
                        state.evidence.push(event.uid.clone());
                        state.step += 1;
                    }
                    state.step == compiled.sequence.len()
                }
                Kind::Absence => {
                    if state.anchor.is_some() && match_expr(&compiled.sequence[1], &mut budget) {
                        state.anchor = None;
                        state.evidence.clear();
                    } else if state.anchor.is_none()
                        && match_expr(&compiled.sequence[0], &mut budget)
                    {
                        state.anchor = Some(event.clone());
                        state.start = now;
                        state.evidence = vec![event.uid.clone()];
                    }
                    false
                }
            };
            if emit {
                let evidence = if rule.kind == Kind::Threshold {
                    state.seen.iter().map(|(_, uid)| uid.clone()).collect()
                } else if rule.kind == Kind::Sequence {
                    state.evidence.clone()
                } else {
                    vec![event.uid.clone()]
                };
                alerts.push(make_alert(rule, event, &group, evidence));
                state.suppressed_until = now.saturating_add(rule.suppression_seconds);
                state.step = 0;
                state.evidence.clear();
            }
            self.state_bytes = self
                .state_bytes
                .saturating_sub(before)
                .saturating_add(state.bytes());
        }
        alerts
    }
    pub fn tick(&mut self, now: u64) -> Vec<Alert> {
        self.clock = self.clock.max(now);
        let now = self.clock;
        let mut out = Vec::new();
        if self.last_tick == Some(now) {
            return out;
        }
        self.last_tick = Some(now);
        for compiled in &self.rules {
            let r = &compiled.rule;
            if !r.enabled {
                continue;
            }
            let prefix = format!("{}:", r.id);
            for (key, state) in self
                .states
                .iter_mut()
                .filter(|(key, _)| key.starts_with(&prefix))
            {
                if r.kind == Kind::Absence
                    && state.anchor.is_some()
                    && now.saturating_sub(state.start) >= r.window_seconds
                {
                    if now >= state.suppressed_until {
                        if let Some(event) = state.anchor.take() {
                            let mut alert = make_alert(r, &event, key, state.evidence.clone());
                            alert.timestamp = i64::try_from(now)
                                .ok()
                                .and_then(|now| chrono::DateTime::from_timestamp(now, 0))
                                .map(|t| t.to_rfc3339())
                                .unwrap_or(event.timestamp);
                            out.push(alert);
                        }
                        state.suppressed_until = now.saturating_add(r.suppression_seconds);
                    } else {
                        state.anchor = None;
                    }
                }
            }
        }
        self.states.retain(|key, s| {
            let window = self
                .rules
                .iter()
                .find(|r| key.starts_with(&format!("{}:", r.rule.id)))
                .map(|r| r.rule.window_seconds)
                .unwrap_or(1);
            s.anchor.is_some() || now.saturating_sub(s.last) <= window || s.suppressed_until > now
        });
        self.state_bytes = self.states.values().map(State::bytes).sum();
        out
    }
    pub fn health(&self) -> serde_json::Value {
        serde_json::json!({"rules":self.rules.len(),"state_keys":self.states.len(),"state_bytes":self.states.values().map(State::bytes).sum::<usize>(),"max_state_bytes":MAX_STATE_BYTES,"refused_total":self.refused})
    }
}
fn make_alert(rule: &Rule, event: &Event, group: &str, evidence: Vec<String>) -> Alert {
    let id = crate::ingest::hex(&crate::ingest::sha256(
        format!("{}:{}:{}:{group}", rule.id, rule.revision, event.uid).as_bytes(),
    ));
    Alert {
        id: id[..16].into(),
        rule_id: rule.id.clone(),
        title: rule.title.clone(),
        severity: rule.severity.clone(),
        confidence: rule.confidence,
        risk_score: rule.risk_score,
        mitre_technique: rule.mitre_technique.clone(),
        timestamp: event.timestamp.clone(),
        group_key: group.chars().take(256).collect(),
        evidence,
        description: format!(
            "Rule {} revision {}: {}",
            rule.id, rule.revision, rule.description
        ),
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    pub version: u16,
    pub generation: u64,
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub history: Vec<Rule>,
}
impl Default for RuleFile {
    fn default() -> Self {
        Self {
            version: 1,
            generation: 0,
            rules: Vec::new(),
            history: Vec::new(),
        }
    }
}
pub struct Manager {
    path: PathBuf,
    pub file: RuleFile,
    pub engine: Engine,
}
impl Manager {
    pub fn open(path: PathBuf) -> io::Result<Self> {
        let file: RuleFile = if path.exists() {
            serde_json::from_slice(&service::read_private(&path, 4 * 1024 * 1024)?)
                .map_err(io::Error::other)?
        } else {
            RuleFile::default()
        };
        if file.version != 1 || file.history.len() > 256 {
            return Err(invalid("unsupported rule file version or history cap"));
        }
        for previous in &file.history {
            Compiled::new(previous.clone())?;
        }
        if file.rules.iter().any(|rule| {
            file.history
                .iter()
                .any(|previous| previous.id == rule.id && previous.revision >= rule.revision)
        }) {
            return Err(invalid(
                "active rule revision must exceed its stored history",
            ));
        }
        let mut engine = Engine::new(file.rules.clone())?;
        let snapshot = path.with_file_name("rules-state.json");
        if snapshot.exists() {
            let state: Snapshot =
                serde_json::from_slice(&service::read_private(&snapshot, 8 * 1024 * 1024)?)
                    .map_err(io::Error::other)?;
            if state.version != 1
                || state.states.len() > MAX_KEYS
                || state.states.values().any(|s| {
                    s.seen.len() > 128
                        || s.evidence.len() > 128
                        || s.step > 8
                        || s.seen
                            .iter()
                            .any(|(_, uid)| uid.is_empty() || uid.len() > 256)
                        || s.evidence
                            .iter()
                            .any(|uid| uid.is_empty() || uid.len() > 256)
                        || s.anchor
                            .as_ref()
                            .is_some_and(|event| event.uid.is_empty() || event.uid.len() > 256)
                        || s.last > state.clock
                        || s.start > state.clock
                        || s.seen.iter().any(|(at, _)| *at > state.clock)
                        || s.suppressed_until > state.clock.saturating_add(86400)
                })
                || state.states.keys().any(|key| {
                    key.split_once(':').is_none_or(|(id, hash)| {
                        id.is_empty()
                            || id.len() > 64
                            || hash.len() != 64
                            || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                })
                || state.states.values().map(State::bytes).sum::<usize>() > MAX_STATE_BYTES
            {
                return Err(invalid("invalid or unbounded detection state snapshot"));
            }
            if state.generation == file.generation {
                for (key, value) in &state.states {
                    if let Some(rule) = engine
                        .rules
                        .iter()
                        .find(|r| key.starts_with(&format!("{}:", r.rule.id)))
                    {
                        let valid = match rule.rule.kind {
                            Kind::Sequence => {
                                value.anchor.is_none()
                                    && value.step < rule.sequence.len()
                                    && value.evidence.len() == value.step
                            }
                            Kind::Absence => {
                                value.step == 0
                                    && value.evidence.len() <= 1
                                    && value.anchor.as_ref().is_none_or(|anchor| {
                                        value.evidence.first() == Some(&anchor.uid)
                                    })
                            }
                            Kind::Match | Kind::Threshold => {
                                value.anchor.is_none()
                                    && value.step == 0
                                    && value.evidence.is_empty()
                            }
                        };
                        if !valid {
                            return Err(invalid("invalid persisted rule progress"));
                        }
                    } else {
                        return Err(invalid("unknown rule in persisted state"));
                    }
                }
                engine.states = state.states;
                engine.clock = state.clock;
                engine.state_bytes = engine.states.values().map(State::bytes).sum();
            }
        }
        Ok(Self { path, file, engine })
    }
    pub fn replace(&mut self, generation: u64, rules: Vec<Rule>) -> io::Result<()> {
        if generation != self.file.generation {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "rules changed; reload before saving",
            ));
        }
        let mut engine = Engine::new(rules.clone())?;
        for rule in &rules {
            if let Some(previous) = self.file.rules.iter().find(|r| r.id == rule.id)
                && rule != previous
                && rule.revision <= previous.revision
            {
                return Err(invalid("rule revision must increase on replacement"));
            }
            if !self
                .file
                .rules
                .iter()
                .any(|previous| previous.id == rule.id)
                && self
                    .file
                    .history
                    .iter()
                    .any(|previous| previous.id == rule.id && rule.revision <= previous.revision)
            {
                return Err(invalid(
                    "recreated rule revision must exceed its stored history",
                ));
            }
        }
        let mut history = self.file.history.clone();
        history.extend(
            self.file
                .rules
                .iter()
                .filter(|old| !rules.iter().any(|new| new == *old))
                .cloned(),
        );
        engine.states = self
            .engine
            .states
            .iter()
            .filter(|(key, _)| {
                rules.iter().any(|new| {
                    key.starts_with(&format!("{}:", new.id))
                        && self.file.rules.iter().any(|old| old == new)
                })
            })
            .map(|(key, state)| (key.clone(), state.clone()))
            .collect();
        engine.clock = self.engine.clock;
        engine.state_bytes = engine.states.values().map(State::bytes).sum();
        if history.len() > 256 {
            history.drain(..history.len() - 256);
        }
        let file = RuleFile {
            version: 1,
            generation: generation
                .checked_add(1)
                .ok_or_else(|| invalid("rule generation limit reached"))?,
            rules,
            history,
        };
        let bytes = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(invalid("rules and history exceed storage limit"));
        }
        service::write_private(&self.path, &bytes)?;
        self.file = file;
        self.engine = engine;
        Ok(())
    }
    pub fn checkpoint(&self) -> io::Result<()> {
        if self.file.rules.is_empty() {
            return Ok(());
        }
        let state = Snapshot {
            version: 1,
            generation: self.file.generation,
            clock: self.engine.clock,
            states: self
                .engine
                .states
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        State {
                            seen: v.seen.clone(),
                            step: v.step,
                            start: v.start,
                            last: v.last,
                            suppressed_until: v.suppressed_until,
                            evidence: v.evidence.clone(),
                            anchor: v.anchor.clone(),
                        },
                    )
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&state).map_err(io::Error::other)?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(invalid("detection snapshot exceeds byte budget"));
        }
        service::write_private(&self.path.with_file_name("rules-state.json"), &bytes)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u16,
    generation: u64,
    clock: u64,
    states: BTreeMap<String, State>,
}

pub fn replay(rules: Vec<Rule>, events: Vec<Event>) -> io::Result<serde_json::Value> {
    if events.len() > 10_000
        || events
            .iter()
            .map(crate::index::event_memory_bytes)
            .sum::<usize>()
            > 16 * 1024 * 1024
    {
        return Err(invalid("replay input exceeds budget"));
    }
    // RFC3339 strings with different offsets do not sort by event time. A stable
    // sort also preserves collection order when two events have the same time.
    let mut events = events
        .into_iter()
        .map(|event| {
            chrono::DateTime::parse_from_rfc3339(&event.timestamp)
                .map(|time| (time, event))
                .map_err(io::Error::other)
        })
        .collect::<io::Result<Vec<_>>>()?;
    events.sort_by_key(|(at, _)| *at);
    let mut engine = Engine::new(rules)?;
    let mut alerts = Vec::new();
    let mut last = 0;
    for (time, event) in &events {
        let now = time.timestamp().max(0) as u64;
        last = now;
        alerts.extend(engine.evaluate(event, now));
        if alerts.len() > 10_000 {
            return Err(invalid("replay alert cap exceeded"));
        }
    }
    let tail = engine
        .rules
        .iter()
        .map(|r| r.rule.window_seconds)
        .max()
        .unwrap_or(0);
    alerts.extend(engine.tick(last.saturating_add(tail)));
    if alerts.len() > 10_000 {
        return Err(invalid("replay alert cap exceeded"));
    }
    Ok(
        serde_json::json!({"events":events.len(),"alerts":alerts,"health":engine.health(),"clock":"event time; absence evaluated through final window"}),
    )
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub title: String,
    pub status: String,
    pub alert_ids: Vec<String>,
    pub evidence: Vec<String>,
    pub notes: String,
    pub updated_at: String,
}
pub fn save_cases(path: &Path, cases: &[Case]) -> io::Result<()> {
    if cases.len() > 512
        || cases.iter().any(|c| {
            c.id.is_empty()
                || c.id.len() > 64
                || c.title.len() > 256
                || c.notes.len() > 8192
                || c.alert_ids.len() > 128
                || c.evidence.len() > 512
                || !matches!(
                    c.status.as_str(),
                    "open" | "investigating" | "resolved" | "false_positive"
                )
        })
    {
        return Err(invalid("invalid case or case storage limit"));
    }
    let mut ids = std::collections::HashSet::new();
    if cases.iter().any(|case| {
        !ids.insert(&case.id)
            || !case
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || case
                .alert_ids
                .iter()
                .chain(&case.evidence)
                .any(|id| id.is_empty() || id.len() > 256)
    }) {
        return Err(invalid("invalid or duplicate case identity or evidence"));
    }
    let bytes = serde_json::to_vec_pretty(cases).map_err(io::Error::other)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(invalid("case storage limit reached"));
    }
    service::write_private(path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn e(id: &str, agent: &str, seq: u64) -> Event {
        Event::normalized(
            0,
            format!("2026-10-13T10:00:{seq:02}Z"),
            "test".into(),
            "low".into(),
            seq.to_string(),
            BTreeMap::from([
                ("event.id".into(), id.into()),
                ("agent.id".into(), agent.into()),
            ]),
        )
    }
    #[test]
    fn threshold_scope_exception_and_suppression() {
        let r = Rule {
            kind: Kind::Threshold,
            query: "event.id=fail".into(),
            threshold: 2,
            exceptions: vec!["agent.id=excluded".into()],
            ..Rule::default()
        };
        let mut engine = Engine::new(vec![r]).unwrap();
        assert!(engine.evaluate(&e("fail", "a", 1), 1).is_empty());
        assert!(engine.evaluate(&e("fail", "b", 2), 2).is_empty());
        assert_eq!(engine.evaluate(&e("fail", "a", 3), 3).len(), 1);
        assert!(engine.evaluate(&e("fail", "a", 4), 4).is_empty());
        assert!(engine.evaluate(&e("fail", "excluded", 5), 5).is_empty());
    }
    #[test]
    fn sequence_and_absence_share_replay_semantics() {
        let seq = Rule {
            kind: Kind::Sequence,
            sequence: vec!["event.id=start".into(), "event.id=end".into()],
            ..Rule::default()
        };
        assert_eq!(
            replay(vec![seq], vec![e("start", "a", 1), e("end", "a", 2)]).unwrap()["alerts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let r = Rule {
            kind: Kind::Absence,
            sequence: vec!["event.id=start".into(), "event.id=end".into()],
            ..Rule::default()
        };
        assert_eq!(
            replay(vec![r.clone()], vec![e("start", "a", 1)]).unwrap()["alerts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            replay(vec![r], vec![e("start", "a", 1), e("end", "a", 2)]).unwrap()["alerts"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }
    #[test]
    fn numeric_and_cidr_conditions_are_typed() {
        let mut event = e("x", "a", 1);
        event.fields.insert("source.ip".into(), "10.1.2.3".into());
        assert!(condition_matches(
            &Condition::Cidr {
                field: "source.ip".into(),
                network: "10.0.0.0/8".into()
            },
            &event
        ));
        assert!(!condition_matches(
            &Condition::Number {
                field: "event.id".into(),
                min: Some(1.0),
                max: None
            },
            &event
        ));
    }
}
