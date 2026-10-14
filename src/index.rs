use crate::{model::Event, query::Expr};
use serde::Serialize;
use std::{
    cmp::Ordering,
    collections::{BTreeSet, BinaryHeap, HashMap, HashSet},
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering as AtomicOrdering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ExecutionLimits {
    pub max_work: u64,
    pub max_scan_bytes: u64,
    pub max_memory_bytes: usize,
    pub max_documents: usize,
    pub max_segments: usize,
    pub max_record_bytes: usize,
    pub max_sidecar_bytes: usize,
    pub max_results: usize,
    pub max_aggregate_buckets: usize,
    pub max_concurrent: usize,
    pub deadline_ms: u64,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            max_work: 20_000_000,
            max_scan_bytes: 256 * 1024 * 1024,
            max_memory_bytes: 64 * 1024 * 1024,
            max_documents: 500_000,
            max_segments: 256,
            max_record_bytes: 1024 * 1024,
            max_sidecar_bytes: 8 * 1024 * 1024,
            max_results: 10_000,
            max_aggregate_buckets: 4096,
            max_concurrent: 2,
            deadline_ms: 3000,
        }
    }
}

impl ExecutionLimits {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| match std::env::var(name) {
            Ok(raw) => Ok(Some(raw)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(format!("{name} must be UTF-8")),
        })
    }

    fn from_lookup(
        mut lookup: impl FnMut(&str) -> Result<Option<String>, String>,
    ) -> Result<Self, String> {
        let mut limits = Self::default();
        let mut tightened = |name: &str, ceiling: u64| -> Result<u64, String> {
            match lookup(name)? {
                Some(raw) => raw
                    .parse::<u64>()
                    .ok()
                    .filter(|value| (1..=ceiling).contains(value))
                    .ok_or_else(|| format!("{name} must be an integer between 1 and {ceiling}")),
                None => Ok(ceiling),
            }
        };
        limits.max_work = tightened("REDTRACE_EXEC_MAX_WORK", limits.max_work)?;
        limits.max_scan_bytes = tightened("REDTRACE_EXEC_MAX_SCAN_BYTES", limits.max_scan_bytes)?;
        limits.deadline_ms = tightened("REDTRACE_EXEC_DEADLINE_MS", limits.deadline_ms)?;
        for (name, value) in [
            (
                "REDTRACE_EXEC_MAX_MEMORY_BYTES",
                &mut limits.max_memory_bytes,
            ),
            ("REDTRACE_EXEC_MAX_DOCUMENTS", &mut limits.max_documents),
            ("REDTRACE_EXEC_MAX_SEGMENTS", &mut limits.max_segments),
            (
                "REDTRACE_EXEC_MAX_RECORD_BYTES",
                &mut limits.max_record_bytes,
            ),
            (
                "REDTRACE_EXEC_MAX_SIDECAR_BYTES",
                &mut limits.max_sidecar_bytes,
            ),
            ("REDTRACE_EXEC_MAX_RESULTS", &mut limits.max_results),
            (
                "REDTRACE_EXEC_MAX_AGGREGATE_BUCKETS",
                &mut limits.max_aggregate_buckets,
            ),
            ("REDTRACE_EXEC_MAX_CONCURRENT", &mut limits.max_concurrent),
        ] {
            *value = tightened(name, *value as u64)? as usize;
        }
        Ok(limits)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryFailure {
    Deadline,
    Cancelled,
    Work,
    ScanBytes,
    Memory,
    Documents,
    Segments,
    RecordBytes,
    SidecarBytes,
    Results,
    AggregateBuckets,
}

impl std::fmt::Display for QueryFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "query execution limit: {self:?}")
    }
}

impl std::error::Error for QueryFailure {}

pub fn query_failure(error: &io::Error) -> Option<QueryFailure> {
    error.get_ref()?.downcast_ref::<QueryFailure>().copied()
}

#[derive(Clone)]
pub struct QueryCancellation {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

impl QueryCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, AtomicOrdering::Relaxed);
    }

    pub fn check(&self) -> io::Result<()> {
        if self.cancelled.load(AtomicOrdering::Relaxed) {
            return Err(io::Error::other(QueryFailure::Cancelled));
        }
        if Instant::now() >= self.deadline {
            return Err(io::Error::other(QueryFailure::Deadline));
        }
        Ok(())
    }
}

#[derive(Default, Clone, Copy, Debug, Serialize)]
pub struct QueryUsage {
    pub work: u64,
    pub scan_bytes: u64,
    pub memory_bytes: usize,
    pub peak_memory_bytes: usize,
    pub documents: usize,
    pub segments: usize,
}

pub struct QueryBudget {
    pub limits: ExecutionLimits,
    pub usage: QueryUsage,
    cancellation: QueryCancellation,
}

impl QueryBudget {
    pub fn new(limits: ExecutionLimits) -> Self {
        Self {
            limits,
            usage: QueryUsage::default(),
            cancellation: QueryCancellation {
                cancelled: Arc::new(AtomicBool::new(false)),
                deadline: Instant::now() + Duration::from_millis(limits.deadline_ms),
            },
        }
    }

    pub fn cancellation(&self) -> QueryCancellation {
        self.cancellation.clone()
    }

    pub fn check(&self) -> io::Result<()> {
        self.cancellation.check()
    }

    pub fn work(&mut self, count: u64) -> io::Result<()> {
        self.check()?;
        if count > self.limits.max_work.saturating_sub(self.usage.work) {
            return Err(io::Error::other(QueryFailure::Work));
        }
        self.usage.work += count;
        Ok(())
    }

    pub fn scan(&mut self, bytes: u64) -> io::Result<()> {
        self.check()?;
        if bytes
            > self
                .limits
                .max_scan_bytes
                .saturating_sub(self.usage.scan_bytes)
        {
            return Err(io::Error::other(QueryFailure::ScanBytes));
        }
        self.usage.scan_bytes += bytes;
        Ok(())
    }

    pub fn allocate(&mut self, bytes: usize) -> io::Result<()> {
        self.check()?;
        if bytes
            > self
                .limits
                .max_memory_bytes
                .saturating_sub(self.usage.memory_bytes)
        {
            return Err(io::Error::other(QueryFailure::Memory));
        }
        self.usage.memory_bytes += bytes;
        self.usage.peak_memory_bytes = self.usage.peak_memory_bytes.max(self.usage.memory_bytes);
        Ok(())
    }

    pub fn release(&mut self, bytes: usize) {
        self.usage.memory_bytes = self.usage.memory_bytes.saturating_sub(bytes);
    }

    pub fn document(&mut self) -> io::Result<()> {
        self.work(1)?;
        if self.usage.documents >= self.limits.max_documents {
            return Err(io::Error::other(QueryFailure::Documents));
        }
        self.usage.documents += 1;
        Ok(())
    }

    pub fn segment(&mut self) -> io::Result<()> {
        self.work(1)?;
        if self.usage.segments >= self.limits.max_segments {
            return Err(io::Error::other(QueryFailure::Segments));
        }
        self.usage.segments += 1;
        Ok(())
    }

    pub fn record(&mut self, event: &Event) -> io::Result<usize> {
        for _ in &event.fields {
            self.work(1)?;
        }
        let bytes = event_memory_bytes(event);
        if bytes > self.limits.max_record_bytes {
            return Err(io::Error::other(QueryFailure::RecordBytes));
        }
        self.scan(bytes as u64)?;
        Ok(bytes)
    }
}

pub fn event_memory_bytes(event: &Event) -> usize {
    std::mem::size_of::<Event>()
        + event.uid.len()
        + event.timestamp.len()
        + event.source.len()
        + event.level.len()
        + event.message.len()
        + event
            .fields
            .iter()
            .map(|(name, value)| name.len() + value.len() + 128)
            .sum::<usize>()
}

#[derive(Eq)]
struct RankedEvent(Event);

impl PartialEq for RankedEvent {
    fn eq(&self, other: &Self) -> bool {
        (&self.0.timestamp, &self.0.uid) == (&other.0.timestamp, &other.0.uid)
    }
}

impl Ord for RankedEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        (&other.0.timestamp, &other.0.uid).cmp(&(&self.0.timestamp, &self.0.uid))
    }
}

impl PartialOrd for RankedEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct QueryMatches {
    seen: HashSet<String>,
    total: usize,
}

impl Default for QueryMatches {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryMatches {
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            total: 0,
        }
    }

    pub fn accept(&mut self, event: &Event, budget: &mut QueryBudget) -> io::Result<bool> {
        budget.work(1)?;
        if self.seen.contains(&event.uid) {
            return Ok(false);
        }
        budget.allocate(event.uid.len() + 128)?;
        self.seen.insert(event.uid.clone());
        self.total += 1;
        Ok(true)
    }

    pub fn total(&self) -> usize {
        self.total
    }
}

pub struct QueryPage {
    limit: usize,
    before: Option<(String, String)>,
    events: BinaryHeap<RankedEvent>,
}

impl QueryPage {
    pub fn new(
        limit: usize,
        before: Option<(String, String)>,
        budget: &mut QueryBudget,
    ) -> io::Result<Self> {
        if limit > budget.limits.max_results {
            return Err(io::Error::other(QueryFailure::Results));
        }
        budget.allocate(limit.saturating_mul(std::mem::size_of::<RankedEvent>() * 2))?;
        Ok(Self {
            limit,
            before,
            events: BinaryHeap::with_capacity(limit),
        })
    }

    pub fn offer(&mut self, event: &Event, budget: &mut QueryBudget) -> io::Result<()> {
        budget.work(1)?;
        if self.limit == 0
            || self
                .before
                .as_ref()
                .is_some_and(|(timestamp, uid)| (&event.timestamp, &event.uid) >= (timestamp, uid))
        {
            return Ok(());
        }
        if self.events.len() == self.limit {
            let oldest = &self.events.peek().expect("nonempty query page").0;
            if (&event.timestamp, &event.uid) <= (&oldest.timestamp, &oldest.uid) {
                return Ok(());
            }
            budget.release(event_memory_bytes(
                &self.events.pop().expect("nonempty query page").0,
            ));
        }
        budget.allocate(event_memory_bytes(event))?;
        self.events.push(RankedEvent(event.clone()));
        Ok(())
    }

    pub fn into_events(mut self, budget: &mut QueryBudget) -> io::Result<Vec<Event>> {
        budget.allocate(
            self.events
                .len()
                .saturating_mul(std::mem::size_of::<Event>()),
        )?;
        let mut events = Vec::with_capacity(self.events.len());
        while let Some(event) = self.events.pop() {
            budget.work(1 + self.limit.checked_ilog2().unwrap_or(0) as u64)?;
            events.push(event.0);
        }
        events.reverse();
        Ok(events)
    }
}

pub struct EventSnapshot {
    events: Vec<Arc<Event>>,
}

impl EventSnapshot {
    pub fn visit(
        &self,
        expression: &Expr,
        budget: &mut QueryBudget,
        mut visitor: impl FnMut(&Event, &mut QueryBudget) -> io::Result<()>,
    ) -> io::Result<()> {
        for event in &self.events {
            budget.document()?;
            budget.record(event)?;
            if matches_event(expression, event, budget)? {
                visitor(event, budget)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn matches_event(
    expression: &Expr,
    event: &Event,
    budget: &mut QueryBudget,
) -> io::Result<bool> {
    budget.work(1)?;
    match expression {
        Expr::MatchAll => Ok(true),
        Expr::And(left, right) => {
            Ok(matches_event(left, event, budget)? && matches_event(right, event, budget)?)
        }
        Expr::Or(left, right) => {
            Ok(matches_event(left, event, budget)? || matches_event(right, event, budget)?)
        }
        Expr::Not(inner) => Ok(!matches_event(inner, event, budget)?),
        Expr::Exists(field) => match_event_values(event, Some(field), "", false, false, budget),
        Expr::Value {
            field,
            value,
            exact,
        } => match_event_values(event, field.as_deref(), value, *exact, false, budget),
        Expr::Term {
            field,
            value,
            prefix,
        } => {
            if field.as_deref().is_none_or(|name| name == "message") {
                let temporary_bytes =
                    event.message.len().saturating_mul(40) + value.len().saturating_mul(40);
                budget.allocate(temporary_bytes)?;
                let tokens = tokenize(&event.message);
                let wanted = tokenize(value);
                budget.work((tokens.len() * wanted.len()) as u64)?;
                let matched = !wanted.is_empty()
                    && wanted.iter().all(|wanted| {
                        tokens.iter().any(|token| {
                            if *prefix {
                                token.starts_with(wanted)
                            } else {
                                token == wanted
                            }
                        })
                    });
                budget.release(temporary_bytes);
                Ok(matched)
            } else {
                match_event_values(event, field.as_deref(), value, true, *prefix, budget)
            }
        }
    }
}

fn match_event_values(
    event: &Event,
    field: Option<&str>,
    value: &str,
    exact: bool,
    prefix: bool,
    budget: &mut QueryBudget,
) -> io::Result<bool> {
    let builtins = [
        ("uid", event.uid.as_str()),
        ("event.uid", event.uid.as_str()),
        ("@timestamp", event.timestamp.as_str()),
        ("source", event.source.as_str()),
        ("log.source", event.source.as_str()),
        ("level", event.level.as_str()),
        ("event.description", event.message.as_str()),
    ];
    for (name, candidate) in builtins.into_iter().chain(
        event
            .fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    ) {
        budget.work(1)?;
        if field.is_some_and(|field| canonical_field(field) != name) {
            continue;
        }
        budget.scan(candidate.len() as u64)?;
        let temporary_bytes = candidate.len().saturating_mul(4);
        budget.allocate(temporary_bytes)?;
        let candidate = candidate.to_lowercase();
        let matched = if prefix {
            candidate.starts_with(value)
        } else if exact {
            candidate == value
        } else {
            candidate.contains(value)
        };
        budget.release(temporary_bytes);
        if matched {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) enum PreparedQuery<'a, T> {
    All,
    Any(Vec<&'a BTreeSet<T>>),
    And(Vec<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),
}

impl<'a, T: Ord> PreparedQuery<'a, T> {
    pub(crate) fn prepare<F, FI, R, RI>(
        expression: &Expr,
        fields: &F,
        terms: &R,
        budget: &mut QueryBudget,
    ) -> io::Result<Self>
    where
        F: Fn() -> FI,
        FI: Iterator<Item = (&'a str, &'a str, &'a BTreeSet<T>)>,
        R: Fn() -> RI,
        RI: Iterator<Item = (&'a str, &'a BTreeSet<T>)>,
    {
        budget.work(1)?;
        budget.allocate(128)?;
        match expression {
            Expr::MatchAll => Ok(Self::All),
            Expr::And(left, right) => Ok(Self::And(vec![
                Self::prepare(left, fields, terms, budget)?,
                Self::prepare(right, fields, terms, budget)?,
            ])),
            Expr::Or(left, right) => Ok(Self::Or(
                Box::new(Self::prepare(left, fields, terms, budget)?),
                Box::new(Self::prepare(right, fields, terms, budget)?),
            )),
            Expr::Not(inner) => Ok(Self::Not(Box::new(Self::prepare(
                inner, fields, terms, budget,
            )?))),
            Expr::Term {
                field,
                value,
                prefix,
            } if field.as_deref().is_none_or(|name| name == "message") => {
                let mut groups = Vec::new();
                let temporary = value.len().saturating_mul(40);
                budget.allocate(temporary)?;
                for token in tokenize(value) {
                    let mut postings = Vec::new();
                    for (candidate, posting) in terms() {
                        budget.work(1)?;
                        budget.scan(candidate.len() as u64)?;
                        if if *prefix {
                            candidate.starts_with(&token)
                        } else {
                            candidate == token
                        } {
                            budget.allocate(32)?;
                            postings.push(posting);
                        }
                    }
                    budget.allocate(128)?;
                    groups.push(Self::Any(postings));
                }
                budget.release(temporary);
                if groups.is_empty() {
                    Ok(Self::Any(Vec::new()))
                } else {
                    Ok(Self::And(groups))
                }
            }
            _ => {
                let (field, value, exact, prefix) = match expression {
                    Expr::Exists(field) => (Some(field.as_str()), "", false, false),
                    Expr::Value {
                        field,
                        value,
                        exact,
                    } => (field.as_deref(), value.as_str(), *exact, false),
                    Expr::Term {
                        field,
                        value,
                        prefix,
                    } => (field.as_deref(), value.as_str(), true, *prefix),
                    _ => unreachable!(),
                };
                let mut postings = Vec::new();
                for (name, candidate, posting) in fields() {
                    budget.work(1)?;
                    if field.is_some_and(|field| canonical_field(field) != name) {
                        continue;
                    }
                    budget.scan(candidate.len() as u64)?;
                    if if prefix {
                        candidate.starts_with(value)
                    } else if exact {
                        candidate == value
                    } else {
                        candidate.contains(value)
                    } {
                        budget.allocate(32)?;
                        postings.push(posting);
                    }
                }
                Ok(Self::Any(postings))
            }
        }
    }

    pub(crate) fn matches(&self, document: &T, budget: &mut QueryBudget) -> io::Result<bool> {
        budget.work(1)?;
        match self {
            Self::All => Ok(true),
            Self::Any(postings) => {
                for posting in postings {
                    budget.work(1 + posting.len().checked_ilog2().unwrap_or(0) as u64)?;
                    if posting.contains(document) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Self::And(groups) => {
                for group in groups {
                    if !group.matches(document, budget)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Self::Or(left, right) => {
                Ok(left.matches(document, budget)? || right.matches(document, budget)?)
            }
            Self::Not(inner) => Ok(!inner.matches(document, budget)?),
        }
    }
}

#[derive(Default)]
pub struct EventIndex {
    events: Vec<Arc<Event>>,
    uids: HashSet<String>,
    fields: HashMap<String, HashMap<String, BTreeSet<usize>>>,
    terms: HashMap<String, BTreeSet<usize>>,
}

#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub total: usize,
    pub took_micros: u128,
    pub events: Vec<Event>,
}

impl EventIndex {
    pub fn from_events(events: Vec<Event>) -> Self {
        let mut index = Self::default();
        for event in events {
            index.push(event);
        }
        index
    }

    pub fn push(&mut self, event: Event) -> bool {
        if !self.uids.insert(event.uid.clone()) {
            return false;
        }
        let document = self.events.len();
        for (field, value) in searchable_fields(&event) {
            self.fields
                .entry(field)
                .or_default()
                .entry(value.to_lowercase())
                .or_default()
                .insert(document);
        }
        for token in tokenize(&event.message) {
            self.terms.entry(token).or_default().insert(document);
        }
        self.events.push(Arc::new(event));
        true
    }

    pub fn search(&self, expression: &Expr, limit: usize) -> io::Result<SearchResult> {
        self.search_page_bounded(
            expression,
            limit,
            None,
            &mut QueryBudget::new(ExecutionLimits::default()),
        )
    }

    #[cfg(test)]
    fn search_unbounded(&self, expression: &Expr, limit: usize) -> SearchResult {
        let started = Instant::now();
        let matches = self.evaluate(expression);
        let total = matches.len();
        let events = matches
            .into_iter()
            .rev()
            .take(limit)
            .filter_map(|id| self.events.get(id).map(|event| event.as_ref().clone()))
            .collect();
        SearchResult {
            total,
            took_micros: started.elapsed().as_micros(),
            events,
        }
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn contains_uid(&self, uid: &str) -> bool {
        self.uids.contains(uid)
    }

    pub fn snapshot(&self, budget: &mut QueryBudget) -> io::Result<EventSnapshot> {
        if self.events.len() > budget.limits.max_documents {
            return Err(io::Error::other(QueryFailure::Documents));
        }
        budget.allocate(
            self.events
                .len()
                .saturating_mul(std::mem::size_of::<Arc<Event>>()),
        )?;
        let mut events = Vec::with_capacity(self.events.len());
        for event in &self.events {
            budget.work(1)?;
            events.push(event.clone());
        }
        Ok(EventSnapshot { events })
    }

    pub fn search_page_bounded(
        &self,
        expression: &Expr,
        limit: usize,
        before: Option<(String, String)>,
        budget: &mut QueryBudget,
    ) -> io::Result<SearchResult> {
        let started = Instant::now();
        let snapshot = self.snapshot(budget)?;
        let mut matches = QueryMatches::new();
        let mut page = QueryPage::new(limit, before, budget)?;
        snapshot.visit(expression, budget, |event, budget| {
            if matches.accept(event, budget)? {
                page.offer(event, budget)?;
            }
            Ok(())
        })?;
        Ok(SearchResult {
            total: matches.total(),
            took_micros: started.elapsed().as_micros(),
            events: page.into_events(budget)?,
        })
    }

    #[cfg(test)]
    fn evaluate(&self, expression: &Expr) -> BTreeSet<usize> {
        match expression {
            Expr::MatchAll => self.all(),
            Expr::Exists(field) => self.match_values(Some(field), "", false),
            Expr::Value {
                field,
                value,
                exact,
            } => self.match_values(field.as_deref(), value, *exact),
            Expr::And(left, right) => &self.evaluate(left) & &self.evaluate(right),
            Expr::Or(left, right) => &self.evaluate(left) | &self.evaluate(right),
            Expr::Not(inner) => &self.all() - &self.evaluate(inner),
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
    fn all(&self) -> BTreeSet<usize> {
        (0..self.events.len()).collect()
    }

    #[cfg(test)]
    fn match_values(&self, field: Option<&str>, value: &str, exact: bool) -> BTreeSet<usize> {
        self.fields
            .iter()
            .filter(|(name, _)| field.is_none_or(|field| *name == canonical_field(field)))
            .flat_map(|(_, values)| values.iter())
            .filter(|(candidate, _)| {
                if exact {
                    candidate.as_str() == value
                } else {
                    candidate.contains(value)
                }
            })
            .fold(BTreeSet::new(), |set, (_, ids)| &set | ids)
    }

    #[cfg(test)]
    fn match_field(&self, field: &str, value: &str, prefix: bool) -> BTreeSet<usize> {
        let Some(values) = self.fields.get(canonical_field(field)) else {
            return BTreeSet::new();
        };
        if !prefix {
            return values.get(value).cloned().unwrap_or_default();
        }
        values
            .iter()
            .filter(|(candidate, _)| candidate.starts_with(value))
            .fold(BTreeSet::new(), |set, (_, ids)| &set | ids)
    }

    #[cfg(test)]
    fn match_text(&self, value: &str, prefix: bool) -> BTreeSet<usize> {
        let tokens = tokenize(value);
        let mut groups = tokens.into_iter().map(|token| {
            if prefix {
                self.terms
                    .iter()
                    .filter(|(candidate, _)| candidate.starts_with(&token))
                    .fold(BTreeSet::new(), |set, (_, ids)| &set | ids)
            } else {
                self.terms.get(&token).cloned().unwrap_or_default()
            }
        });
        let Some(first) = groups.next() else {
            return BTreeSet::new();
        };
        groups.fold(first, |set, ids| &set & &ids)
    }
}

pub(crate) fn canonical_field(field: &str) -> &str {
    match field {
        "message" => "event.description",
        "timestamp" => "@timestamp",
        "event.level" => "level",
        _ => field,
    }
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

fn tokenize(value: &str) -> Vec<String> {
    value
        .split(|c: char| !c.is_alphanumeric() && !matches!(c, '.' | '_' | '\\'))
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse;

    fn fixture_events() -> Vec<Event> {
        vec![
            Event::normalized(
                1,
                "2026-01-01T10:00:00Z".into(),
                "test.security".into(),
                "medium".into(),
                "An account failed to log on".into(),
                std::collections::BTreeMap::from([
                    ("event.id".into(), "4625".into()),
                    ("user.name".into(), "administrator".into()),
                ]),
            ),
            Event::normalized(
                2,
                "2026-01-01T10:01:00Z".into(),
                "test.process".into(),
                "high".into(),
                "New process with EncodedCommand".into(),
                std::collections::BTreeMap::from([
                    ("event.id".into(), "4688".into()),
                    ("process.name".into(), "powershell.exe".into()),
                ]),
            ),
        ]
    }

    #[test]
    fn executor_configuration_can_only_tighten_each_limit() {
        let limits = ExecutionLimits::from_lookup(|_| Ok(Some("1".into()))).unwrap();
        assert_eq!(limits.max_concurrent, 1);
        assert_eq!(limits.max_work, 1);
        assert_eq!(limits.max_scan_bytes, 1);
        assert_eq!(limits.deadline_ms, 1);
        assert_eq!(limits.max_record_bytes, 1);
        assert_eq!(limits.max_aggregate_buckets, 1);
        for value in ["0", "-1", "invalid", "18446744073709551615"] {
            assert!(ExecutionLimits::from_lookup(|_| Ok(Some(value.into()))).is_err());
        }
        assert!(
            ExecutionLimits::from_lookup(|name| {
                Ok((name == "REDTRACE_EXEC_MAX_CONCURRENT").then(|| "3".into()))
            })
            .is_err()
        );
        assert!(ExecutionLimits::from_lookup(|_| Err("invalid encoding".into())).is_err());
    }

    #[test]
    fn bounded_ram_results_match_existing_query_semantics() {
        let index = EventIndex::from_events(fixture_events());
        for raw in [
            "*",
            "ministr",
            "message:enc*",
            "event.id:4625 OR process.name~shell",
            "NOT user.name:*",
            "source=test.security",
            "event.level=high",
            "*~account",
        ] {
            let expression = parse(raw).unwrap();
            let mut budget = QueryBudget::new(ExecutionLimits::default());
            let result = index
                .search_page_bounded(&expression, 20, None, &mut budget)
                .unwrap();
            assert_eq!(
                result.total,
                index.search_unbounded(&expression, 20).total,
                "{raw}"
            );
        }
    }

    #[test]
    fn top_k_and_cursor_use_uid_order_for_equal_timestamps() {
        let mut events = Vec::new();
        for id in 0..200 {
            let mut event = fixture_events().remove(0);
            event.id = 200 - id;
            event.uid = format!("{id:016x}");
            events.push(event);
        }
        let index = EventIndex::from_events(events);
        let mut budget = QueryBudget::new(ExecutionLimits::default());
        let first = index
            .search_page_bounded(&Expr::MatchAll, 7, None, &mut budget)
            .unwrap();
        assert_eq!(first.total, 200);
        assert_eq!(first.events.len(), 7);
        assert_eq!(first.events[0].uid, format!("{:016x}", 199));
        let last = first.events.last().unwrap();
        let mut budget = QueryBudget::new(ExecutionLimits::default());
        let second = index
            .search_page_bounded(
                &Expr::MatchAll,
                7,
                Some((last.timestamp.clone(), last.uid.clone())),
                &mut budget,
            )
            .unwrap();
        assert_eq!(second.total, 200);
        assert_eq!(second.events[0].uid, format!("{:016x}", 192));
        assert!(
            second
                .events
                .iter()
                .all(|event| !first.events.contains(event))
        );
        assert!(budget.usage.peak_memory_bytes < 100_000);
    }

    #[test]
    fn ram_snapshot_survives_rotation_and_new_ingestion() {
        let mut index = EventIndex::from_events(fixture_events());
        let mut budget = QueryBudget::new(ExecutionLimits::default());
        let snapshot = index.snapshot(&mut budget).unwrap();
        index = EventIndex::default();
        let mut fresh = fixture_events().remove(0);
        fresh.uid = "00000000000000ff".into();
        index.push(fresh);
        let mut found = Vec::new();
        snapshot
            .visit(&Expr::MatchAll, &mut budget, |event, _| {
                found.push(event.uid.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(found.len(), 2);
        assert!(!found.contains(&"00000000000000ff".into()));
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn ram_execution_rejects_each_resource_limit_without_partial_results() {
        let index = EventIndex::from_events(fixture_events());
        for (limits, expected) in [
            (
                ExecutionLimits {
                    max_work: 1,
                    ..ExecutionLimits::default()
                },
                QueryFailure::Work,
            ),
            (
                ExecutionLimits {
                    max_scan_bytes: 1,
                    ..ExecutionLimits::default()
                },
                QueryFailure::ScanBytes,
            ),
            (
                ExecutionLimits {
                    max_memory_bytes: 1,
                    ..ExecutionLimits::default()
                },
                QueryFailure::Memory,
            ),
            (
                ExecutionLimits {
                    max_documents: 1,
                    ..ExecutionLimits::default()
                },
                QueryFailure::Documents,
            ),
            (
                ExecutionLimits {
                    max_record_bytes: 1,
                    ..ExecutionLimits::default()
                },
                QueryFailure::RecordBytes,
            ),
            (
                ExecutionLimits {
                    max_results: 1,
                    ..ExecutionLimits::default()
                },
                QueryFailure::Results,
            ),
        ] {
            let error = index
                .search_page_bounded(&Expr::MatchAll, 2, None, &mut QueryBudget::new(limits))
                .unwrap_err();
            assert_eq!(query_failure(&error), Some(expected));
        }
    }

    #[test]
    fn cancellation_and_deadline_stop_real_scan_visitors() {
        let index = EventIndex::from_events(fixture_events());
        let mut budget = QueryBudget::new(ExecutionLimits::default());
        let snapshot = index.snapshot(&mut budget).unwrap();
        let cancellation = budget.cancellation();
        let mut visited = 0;
        let error = snapshot
            .visit(&Expr::MatchAll, &mut budget, |_, _| {
                visited += 1;
                cancellation.cancel();
                Ok(())
            })
            .unwrap_err();
        assert_eq!(visited, 1);
        assert_eq!(query_failure(&error), Some(QueryFailure::Cancelled));
        let mut budget = QueryBudget::new(ExecutionLimits {
            deadline_ms: 0,
            ..ExecutionLimits::default()
        });
        assert_eq!(
            query_failure(
                &snapshot
                    .visit(&Expr::MatchAll, &mut budget, |_, _| panic!(
                        "expired scan visited a record"
                    ))
                    .unwrap_err()
            ),
            Some(QueryFailure::Deadline)
        );
    }

    #[test]
    fn searches_fields_and_boolean_expressions() {
        let index = EventIndex::from_events(fixture_events());
        let result = index
            .search(
                &parse("event.id:4625 OR process.name:powershell.exe").unwrap(),
                20,
            )
            .unwrap();
        assert_eq!(result.total, 2);
    }

    #[test]
    fn searches_message_terms() {
        let index = EventIndex::from_events(fixture_events());
        assert_eq!(
            index
                .search(&parse("encodedcommand").unwrap(), 20)
                .unwrap()
                .total,
            1
        );
    }

    #[test]
    fn searches_substrings_across_values_and_exact_fields() {
        let index = EventIndex::from_events(fixture_events());
        for (query, total) in [
            ("ministr", 1),
            ("shell.ex", 1),
            ("user.name=administrator", 1),
            ("user.name=admin", 0),
            ("user.name~admin", 1),
            ("process.name:*", 1),
            ("NOT user.name:*", 1),
            ("\"failed to log\"", 1),
            ("\"account log\"", 0),
            ("*=\"powershell.exe\"", 1),
            ("event.id:4625 OR process.name~shell", 2),
        ] {
            assert_eq!(
                index.search(&parse(query).unwrap(), 20).unwrap().total,
                total,
                "{query}"
            );
        }
    }
}
