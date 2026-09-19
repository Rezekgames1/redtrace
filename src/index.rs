use crate::{model::Event, query::Expr};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Instant;

#[derive(Default)]
pub struct EventIndex {
    events: Vec<Event>,
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
        self.events.push(event);
        true
    }

    pub fn search(&self, expression: &Expr, limit: usize) -> SearchResult {
        let started = Instant::now();
        let matches = self.evaluate(expression);
        let total = matches.len();
        let events = matches
            .into_iter()
            .rev()
            .take(limit)
            .filter_map(|id| self.events.get(id).cloned())
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

    fn evaluate(&self, expression: &Expr) -> BTreeSet<usize> {
        match expression {
            Expr::MatchAll => self.all(),
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

    fn all(&self) -> BTreeSet<usize> {
        (0..self.events.len()).collect()
    }

    fn match_field(&self, field: &str, value: &str, prefix: bool) -> BTreeSet<usize> {
        let Some(values) = self.fields.get(field) else {
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

fn searchable_fields(event: &Event) -> Vec<(String, String)> {
    let mut values = vec![
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
    fn searches_fields_and_boolean_expressions() {
        let index = EventIndex::from_events(fixture_events());
        let result = index.search(
            &parse("event.id:4625 OR process.name:powershell.exe").unwrap(),
            20,
        );
        assert_eq!(result.total, 2);
    }

    #[test]
    fn searches_message_terms() {
        let index = EventIndex::from_events(fixture_events());
        assert_eq!(index.search(&parse("encodedcommand").unwrap(), 20).total, 1);
    }
}
