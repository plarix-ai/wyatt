//! State that outlives one call: session labels and counters, and per-agent
//! rate windows.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

/// What one agent connection has done so far. Labels only grow: once a
/// session has read a secret it stays a session that has read a secret.
#[derive(Debug, Clone, Default)]
pub struct Session {
    pub labels: BTreeSet<String>,
    pub calls: u64,
    pub tools: BTreeSet<String>,
    pub limit_calls: BTreeMap<String, u64>,
    /// Labels from the agent's other sessions since the daemon started.
    /// Rules see this together with `labels` as `history.labels`, so an
    /// agent cannot shed a label by opening a new session.
    pub history: BTreeSet<String>,
}

impl Session {
    pub fn record_success(&mut self, tool: &str, labels: &BTreeSet<String>, limits: &[String]) {
        self.calls += 1;
        self.tools.insert(tool.to_string());
        self.labels.extend(labels.iter().cloned());
        for id in limits {
            *self.limit_calls.entry(id.clone()).or_default() += 1;
        }
    }
}

/// Sliding windows keyed by (limit id, agent). Shared by all sessions of an
/// agent, so reconnecting does not reset a rate limit.
#[derive(Debug, Default)]
pub struct RateState {
    windows: HashMap<(String, String), VecDeque<u64>>,
}

impl RateState {
    pub fn would_exceed(&self, limit: &str, agent: &str, count: u32, window_ms: u64, now_ms: u64) -> bool {
        let key = (limit.to_string(), agent.to_string());
        let Some(w) = self.windows.get(&key) else { return false };
        w.iter().filter(|t| now_ms.saturating_sub(**t) < window_ms).count() >= count as usize
    }

    pub fn record(&mut self, limit: &str, agent: &str, window_ms: u64, now_ms: u64) {
        let w = self.windows.entry((limit.to_string(), agent.to_string())).or_default();
        while w.front().is_some_and(|t| now_ms.saturating_sub(*t) >= window_ms) {
            w.pop_front();
        }
        w.push_back(now_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_slides() {
        let mut r = RateState::default();
        for t in [0, 10, 20] {
            assert!(!r.would_exceed("l", "a", 3, 100, t));
            r.record("l", "a", 100, t);
        }
        assert!(r.would_exceed("l", "a", 3, 100, 50));
        assert!(!r.would_exceed("l", "b", 3, 100, 50));
        assert!(!r.would_exceed("l", "a", 3, 100, 101));
    }
}
