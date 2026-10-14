use serde::Serialize;
use std::{
    collections::{BTreeMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Notify;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct IngestLimits {
    pub max_body_bytes: usize,
    pub max_event_bytes: usize,
    pub max_batch_bytes: usize,
    pub global_concurrency: usize,
    pub agent_concurrency: usize,
    pub global_inflight_bytes: usize,
    pub agent_inflight_bytes: usize,
    pub global_waiters: usize,
    pub agent_waiters: usize,
    pub global_waiting_bytes: usize,
    pub agent_waiting_bytes: usize,
    pub global_pending_events: usize,
    pub agent_pending_events: usize,
    pub global_pending_bytes: usize,
    pub agent_pending_bytes: usize,
    pub queue_wait_ms: u64,
    pub request_timeout_ms: u64,
    pub retry_after_seconds: u64,
}

impl Default for IngestLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 8 * 1024 * 1024,
            max_event_bytes: 256 * 1024,
            max_batch_bytes: 8 * 1024 * 1024,
            global_concurrency: 8,
            agent_concurrency: 2,
            global_inflight_bytes: 128 * 1024 * 1024,
            agent_inflight_bytes: 32 * 1024 * 1024,
            global_waiters: 16,
            agent_waiters: 2,
            global_waiting_bytes: 256 * 1024 * 1024,
            agent_waiting_bytes: 32 * 1024 * 1024,
            global_pending_events: 4096,
            agent_pending_events: 1024,
            global_pending_bytes: 32 * 1024 * 1024,
            agent_pending_bytes: 8 * 1024 * 1024,
            queue_wait_ms: 250,
            request_timeout_ms: 10_000,
            retry_after_seconds: 1,
        }
    }
}

impl IngestLimits {
    pub fn from_env() -> Result<Self, String> {
        let mut limits = Self::default();
        macro_rules! read_limit {
            ($field:ident) => {
                let name = format!(
                    "REDTRACE_INGEST_{}",
                    stringify!($field).to_ascii_uppercase()
                );
                if let Some(value) = std::env::var_os(&name) {
                    limits.$field = value
                        .to_str()
                        .and_then(|value| value.parse().ok())
                        .ok_or_else(|| format!("{name} must be a positive integer"))?;
                }
            };
        }
        read_limit!(max_body_bytes);
        read_limit!(max_event_bytes);
        read_limit!(max_batch_bytes);
        read_limit!(global_concurrency);
        read_limit!(agent_concurrency);
        read_limit!(global_inflight_bytes);
        read_limit!(agent_inflight_bytes);
        read_limit!(global_waiters);
        read_limit!(agent_waiters);
        read_limit!(global_waiting_bytes);
        read_limit!(agent_waiting_bytes);
        read_limit!(global_pending_events);
        read_limit!(agent_pending_events);
        read_limit!(global_pending_bytes);
        read_limit!(agent_pending_bytes);
        read_limit!(queue_wait_ms);
        read_limit!(request_timeout_ms);
        read_limit!(retry_after_seconds);
        limits.validate()?;
        Ok(limits)
    }

    pub fn validate(&self) -> Result<(), String> {
        let ceilings = Self::default();
        macro_rules! check_limit {
            ($field:ident) => {
                if self.$field == 0 || self.$field > ceilings.$field {
                    return Err(format!(
                        "{} must be between 1 and {}",
                        stringify!($field),
                        ceilings.$field
                    ));
                }
            };
        }
        check_limit!(max_body_bytes);
        check_limit!(max_event_bytes);
        check_limit!(max_batch_bytes);
        check_limit!(global_concurrency);
        check_limit!(agent_concurrency);
        check_limit!(global_inflight_bytes);
        check_limit!(agent_inflight_bytes);
        check_limit!(global_waiters);
        check_limit!(agent_waiters);
        check_limit!(global_waiting_bytes);
        check_limit!(agent_waiting_bytes);
        check_limit!(global_pending_events);
        check_limit!(agent_pending_events);
        check_limit!(global_pending_bytes);
        check_limit!(agent_pending_bytes);
        check_limit!(queue_wait_ms);
        check_limit!(request_timeout_ms);
        check_limit!(retry_after_seconds);
        let charge = self.request_charge();
        if self.max_event_bytes > self.max_batch_bytes
            || charge > self.agent_inflight_bytes
            || self.agent_inflight_bytes > self.global_inflight_bytes
            || charge > self.agent_waiting_bytes
            || self.agent_waiting_bytes > self.global_waiting_bytes
            || self.agent_concurrency > self.global_concurrency
            || self.agent_waiters > self.global_waiters
            || self.agent_pending_events > self.global_pending_events
            || self.max_batch_bytes > self.agent_pending_bytes
            || self.agent_pending_bytes > self.global_pending_bytes
        {
            return Err("inconsistent ingest limits".into());
        }
        Ok(())
    }

    fn request_charge(&self) -> usize {
        self.max_body_bytes + self.max_batch_bytes
    }
}

#[derive(Clone, Default, Debug, Serialize)]
pub struct BudgetUsage {
    pub active_requests: usize,
    pub inflight_bytes: usize,
    pub waiting_requests: usize,
    pub waiting_bytes: usize,
    pub pending_events: usize,
    pub pending_bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct IngestBudgetHealth {
    pub limits: IngestLimits,
    pub usage: BudgetUsage,
    pub agents: BTreeMap<String, BudgetUsage>,
    pub throttled_total: u64,
    pub unauthorized_total: u64,
    pub request_timeouts_total: u64,
    pub suppressed_logs_total: u64,
}

#[derive(Default, Debug)]
struct BudgetState {
    usage: BudgetUsage,
    agents: BTreeMap<String, BudgetUsage>,
    pending: BTreeMap<String, (String, usize)>,
    throttled_total: u64,
    unauthorized_total: u64,
    request_timeouts_total: u64,
    suppressed_logs_total: u64,
    last_log: Option<Instant>,
}

#[derive(Debug)]
pub(super) struct IngestBudget {
    pub limits: IngestLimits,
    state: Mutex<BudgetState>,
    changed: Notify,
}

impl IngestBudget {
    pub fn new(limits: IngestLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(BudgetState::default()),
            changed: Notify::new(),
        }
    }

    pub fn snapshot(&self) -> IngestBudgetHealth {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        IngestBudgetHealth {
            limits: self.limits.clone(),
            usage: state.usage.clone(),
            agents: state.agents.clone(),
            throttled_total: state.throttled_total,
            unauthorized_total: state.unauthorized_total,
            request_timeouts_total: state.request_timeouts_total,
            suppressed_logs_total: state.suppressed_logs_total,
        }
    }

    pub fn log(&self, reason: &'static str) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        match reason {
            "unauthorized" => state.unauthorized_total = state.unauthorized_total.saturating_add(1),
            "request_timeout" => {
                state.request_timeouts_total = state.request_timeouts_total.saturating_add(1)
            }
            "throttled" => state.throttled_total = state.throttled_total.saturating_add(1),
            _ => {}
        }
        if state
            .last_log
            .is_some_and(|last| last.elapsed() < Duration::from_secs(30))
        {
            state.suppressed_logs_total = state.suppressed_logs_total.saturating_add(1);
            return;
        }
        state.last_log = Some(Instant::now());
        tracing::warn!(reason, "ingest request limited or rejected");
    }

    fn activate(&self, id: &str) -> Option<RequestPermit> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let agent = state.agents.get(id).cloned().unwrap_or_default();
        let charge = self.limits.request_charge();
        if state.usage.active_requests >= self.limits.global_concurrency
            || agent.active_requests >= self.limits.agent_concurrency
            || state.usage.inflight_bytes + charge > self.limits.global_inflight_bytes
            || agent.inflight_bytes + charge > self.limits.agent_inflight_bytes
        {
            return None;
        }
        state.usage.active_requests += 1;
        state.usage.inflight_bytes += charge;
        let agent = state.agents.entry(id.into()).or_default();
        agent.active_requests += 1;
        agent.inflight_bytes += charge;
        Some(RequestPermit {
            id: id.into(),
            waiting: false,
        })
    }

    pub async fn acquire(self: &Arc<Self>, id: &str) -> Result<BudgetGuard, ()> {
        if let Some(permit) = self.activate(id) {
            return Ok(BudgetGuard {
                budget: self.clone(),
                permit,
            });
        }
        {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            let agent = state.agents.get(id).cloned().unwrap_or_default();
            let charge = self.limits.request_charge();
            if state.usage.waiting_requests >= self.limits.global_waiters
                || agent.waiting_requests >= self.limits.agent_waiters
                || state.usage.waiting_bytes + charge > self.limits.global_waiting_bytes
                || agent.waiting_bytes + charge > self.limits.agent_waiting_bytes
            {
                return Err(());
            }
            state.usage.waiting_requests += 1;
            state.usage.waiting_bytes += charge;
            let agent = state.agents.entry(id.into()).or_default();
            agent.waiting_requests += 1;
            agent.waiting_bytes += charge;
        }
        let _waiting = BudgetGuard {
            budget: self.clone(),
            permit: RequestPermit {
                id: id.into(),
                waiting: true,
            },
        };
        tokio::time::timeout(Duration::from_millis(self.limits.queue_wait_ms), async {
            loop {
                let notified = self.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if let Some(permit) = self.activate(id) {
                    return BudgetGuard {
                        budget: self.clone(),
                        permit,
                    };
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| ())
    }

    pub fn reap(&self, known: &HashSet<String>) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let completed: Vec<_> = state
            .pending
            .keys()
            .filter(|uid| known.contains(*uid))
            .cloned()
            .collect();
        for uid in completed {
            remove_pending(&mut state, &uid);
        }
        prune_agents(&mut state);
    }

    pub fn reserve_pending(
        self: &Arc<Self>,
        id: &str,
        events: &[(String, usize)],
    ) -> Result<PendingGuard, ()> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let events: Vec<_> = events
            .iter()
            .filter(|(uid, _)| !state.pending.contains_key(uid))
            .collect();
        let bytes: usize = events.iter().map(|(_, bytes)| *bytes).sum();
        let agent = state.agents.get(id).cloned().unwrap_or_default();
        if state.usage.pending_events + events.len() > self.limits.global_pending_events
            || agent.pending_events + events.len() > self.limits.agent_pending_events
            || state.usage.pending_bytes + bytes > self.limits.global_pending_bytes
            || agent.pending_bytes + bytes > self.limits.agent_pending_bytes
        {
            return Err(());
        }
        let mut unsent = HashSet::new();
        for (uid, bytes) in events {
            state.pending.insert(uid.clone(), (id.into(), *bytes));
            unsent.insert(uid.clone());
        }
        state.usage.pending_events += unsent.len();
        state.usage.pending_bytes += bytes;
        let agent = state.agents.entry(id.into()).or_default();
        agent.pending_events += unsent.len();
        agent.pending_bytes += bytes;
        Ok(PendingGuard {
            budget: self.clone(),
            unsent,
        })
    }
}

fn remove_pending(state: &mut BudgetState, uid: &str) {
    if let Some((id, bytes)) = state.pending.remove(uid) {
        state.usage.pending_events -= 1;
        state.usage.pending_bytes -= bytes;
        if let Some(agent) = state.agents.get_mut(&id) {
            agent.pending_events -= 1;
            agent.pending_bytes -= bytes;
        }
    }
}

fn prune_agents(state: &mut BudgetState) {
    state.agents.retain(|_, agent| {
        agent.active_requests + agent.waiting_requests + agent.pending_events > 0
    });
}

struct RequestPermit {
    id: String,
    waiting: bool,
}

pub(super) struct BudgetGuard {
    budget: Arc<IngestBudget>,
    permit: RequestPermit,
}

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        let mut state = self
            .budget
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let charge = self.budget.limits.request_charge();
        if self.permit.waiting {
            state.usage.waiting_requests -= 1;
            state.usage.waiting_bytes -= charge;
        } else {
            state.usage.active_requests -= 1;
            state.usage.inflight_bytes -= charge;
        }
        if let Some(agent) = state.agents.get_mut(&self.permit.id) {
            if self.permit.waiting {
                agent.waiting_requests -= 1;
                agent.waiting_bytes -= charge;
            } else {
                agent.active_requests -= 1;
                agent.inflight_bytes -= charge;
            }
        }
        prune_agents(&mut state);
        drop(state);
        self.budget.changed.notify_waiters();
    }
}

pub(super) struct PendingGuard {
    budget: Arc<IngestBudget>,
    unsent: HashSet<String>,
}

impl PendingGuard {
    pub fn owns(&self, uid: &str) -> bool {
        self.unsent.contains(uid)
    }

    pub fn sent(&mut self, uid: &str) {
        self.unsent.remove(uid);
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        let mut state = self
            .budget
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for uid in &self.unsent {
            remove_pending(&mut state, uid);
        }
        prune_agents(&mut state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> IngestLimits {
        IngestLimits {
            max_body_bytes: 4096,
            max_event_bytes: 1024,
            max_batch_bytes: 4096,
            global_concurrency: 2,
            agent_concurrency: 1,
            global_inflight_bytes: 16384,
            agent_inflight_bytes: 8192,
            global_waiters: 2,
            agent_waiters: 1,
            global_waiting_bytes: 16384,
            agent_waiting_bytes: 8192,
            global_pending_events: 3,
            agent_pending_events: 2,
            global_pending_bytes: 8192,
            agent_pending_bytes: 4096,
            ..IngestLimits::default()
        }
    }

    #[test]
    fn validates_limits_and_rejects_unsafe_combinations() {
        assert!(limits().validate().is_ok());
        let mut invalid = limits();
        invalid.max_body_bytes = 0;
        assert!(invalid.validate().is_err());
        invalid = limits();
        invalid.global_concurrency = 9;
        assert!(invalid.validate().is_err());
        invalid = limits();
        invalid.agent_inflight_bytes = 8191;
        assert!(invalid.validate().is_err());
        invalid = limits();
        invalid.agent_waiting_bytes = 8191;
        assert!(invalid.validate().is_err());
        invalid = limits();
        invalid.agent_pending_bytes = 4095;
        assert!(invalid.validate().is_err());
    }

    #[tokio::test]
    async fn concurrency_waiter_bounds_and_cancellation_release_permits() {
        let budget = Arc::new(IngestBudget::new(limits()));
        let first = budget.acquire("a").await.unwrap();
        let second = budget.acquire("b").await.unwrap();
        let waiting_budget = budget.clone();
        let waiter = tokio::spawn(async move { waiting_budget.acquire("a").await });
        tokio::task::yield_now().await;
        assert_eq!(budget.snapshot().usage.waiting_requests, 1);
        assert!(budget.acquire("a").await.is_err());
        waiter.abort();
        let _ = waiter.await;
        assert_eq!(budget.snapshot().usage.waiting_bytes, 0);
        drop(first);
        let next = budget.acquire("a").await.unwrap();
        drop(next);
        drop(second);
        let snapshot = budget.snapshot();
        assert_eq!(snapshot.usage.active_requests, 0);
        assert_eq!(snapshot.usage.inflight_bytes, 0);
        assert!(snapshot.agents.is_empty());
    }

    #[tokio::test]
    async fn byte_budget_applies_even_when_concurrency_has_capacity() {
        let mut config = limits();
        config.global_concurrency = 8;
        config.agent_concurrency = 2;
        let budget = Arc::new(IngestBudget::new(config));
        let first = budget.acquire("a").await.unwrap();
        assert!(budget.acquire("a").await.is_err());
        let second = budget.acquire("b").await.unwrap();
        assert!(budget.acquire("c").await.is_err());
        drop(first);
        drop(second);
        assert_eq!(budget.snapshot().usage.waiting_requests, 0);
    }

    #[test]
    fn pending_events_remain_charged_until_durable_even_after_guard_drop() {
        let budget = Arc::new(IngestBudget::new(limits()));
        let events = vec![("1".into(), 2000), ("2".into(), 2000)];
        let mut batch = budget.reserve_pending("a", &events).unwrap();
        batch.sent("1");
        drop(batch);
        assert_eq!(budget.snapshot().usage.pending_events, 1);
        assert_eq!(budget.snapshot().usage.pending_bytes, 2000);
        let retry = budget.reserve_pending("a", &[("1".into(), 2000)]).unwrap();
        assert!(!retry.owns("1"));
        drop(retry);
        assert_eq!(budget.snapshot().usage.pending_bytes, 2000);
        budget.reap(&HashSet::from(["1".into()]));
        assert_eq!(budget.snapshot().usage.pending_bytes, 0);
        assert!(budget.snapshot().agents.is_empty());
    }

    #[test]
    fn pending_agent_global_counts_and_bytes_are_enforced_atomically() {
        let budget = Arc::new(IngestBudget::new(limits()));
        let first = budget
            .reserve_pending("a", &[("1".into(), 2000), ("2".into(), 2000)])
            .unwrap();
        assert!(budget.reserve_pending("a", &[("3".into(), 1)]).is_err());
        assert!(
            budget
                .reserve_pending("b", &[("3".into(), 1), ("4".into(), 1)])
                .is_err()
        );
        let second = budget.reserve_pending("b", &[("3".into(), 2000)]).unwrap();
        assert_eq!(budget.snapshot().usage.pending_events, 3);
        drop(first);
        drop(second);
        let bytes = budget.reserve_pending("a", &[("1".into(), 4096)]).unwrap();
        assert!(budget.reserve_pending("a", &[("2".into(), 1)]).is_err());
        let more = budget.reserve_pending("b", &[("2".into(), 4096)]).unwrap();
        assert!(budget.reserve_pending("c", &[("3".into(), 1)]).is_err());
        drop(bytes);
        drop(more);
        assert_eq!(budget.snapshot().usage.pending_bytes, 0);
    }

    #[test]
    fn logs_are_globally_bounded_without_secret_or_agent_labels() {
        let budget = IngestBudget::new(limits());
        budget.log("unauthorized");
        for _ in 0..100 {
            budget.log("throttled");
        }
        let snapshot = budget.snapshot();
        assert_eq!(snapshot.unauthorized_total, 1);
        assert_eq!(snapshot.throttled_total, 100);
        assert_eq!(snapshot.suppressed_logs_total, 100);
    }
}
