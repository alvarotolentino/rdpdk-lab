use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::Instant;

/// Tracks per-IP packet rates using a sliding time window.
///
/// Each IP has a queue of timestamps. When queried, timestamps older
/// than the window are evicted and the remaining count is the rate.
#[derive(Debug)]
pub struct RateTracker {
    window_secs: u64,
    /// Per-IP queue of packet arrival instants.
    buckets: HashMap<Ipv4Addr, VecDeque<Instant>>,
}

impl RateTracker {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            buckets: HashMap::new(),
        }
    }

    /// Record a packet arrival from the given source IP.
    pub fn record(&mut self, ip: Ipv4Addr, now: Instant) {
        let deque = self.buckets.entry(ip).or_default();
        deque.push_back(now);
        self.evict(ip, now);
    }

    /// Return the current packets-per-second rate for a source IP.
    pub fn rate_pps(&mut self, ip: Ipv4Addr, now: Instant) -> f64 {
        self.evict(ip, now);
        let count = self
            .buckets
            .get(&ip)
            .map(VecDeque::len)
            .unwrap_or(0);
        count as f64 / self.window_secs.max(1) as f64
    }

    /// Return all IPs and their current pps, sorted descending.
    pub fn all_rates(&mut self, now: Instant) -> Vec<(Ipv4Addr, f64)> {
        let ips: Vec<Ipv4Addr> = self.buckets.keys().copied().collect();
        for ip in &ips {
            self.evict(*ip, now);
        }
        let mut rates: Vec<(Ipv4Addr, f64)> = self
            .buckets
            .iter()
            .map(|(ip, deque)| {
                let pps = deque.len() as f64 / self.window_secs.max(1) as f64;
                (*ip, pps)
            })
            .filter(|(_, pps)| *pps > 0.0)
            .collect();
        rates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        rates
    }

    /// Remove timestamps outside the sliding window for a given IP.
    fn evict(&mut self, ip: Ipv4Addr, now: Instant) {
        if let Some(deque) = self.buckets.get_mut(&ip) {
            let cutoff = now - std::time::Duration::from_secs(self.window_secs);
            while deque.front().is_some_and(|t| *t < cutoff) {
                deque.pop_front();
            }
            if deque.is_empty() {
                self.buckets.remove(&ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn records_and_counts() {
        let mut tracker = RateTracker::new(10);
        let now = Instant::now();
        let ip = Ipv4Addr::new(10, 0, 0, 1);

        for i in 0..100 {
            tracker.record(ip, now + Duration::from_millis(i * 10));
        }

        // 100 packets in a 10-second window = 10 pps
        let pps = tracker.rate_pps(ip, now + Duration::from_millis(999));
        assert!((pps - 10.0).abs() < 0.01);
    }

    #[test]
    fn evicts_old_entries() {
        let mut tracker = RateTracker::new(5);
        let now = Instant::now();
        let ip = Ipv4Addr::new(10, 0, 0, 2);

        // Record 10 packets at time 0
        for _ in 0..10 {
            tracker.record(ip, now);
        }

        // After 6 seconds, all should be evicted
        let pps = tracker.rate_pps(ip, now + Duration::from_secs(6));
        assert!(pps < f64::EPSILON);
    }

    #[test]
    fn all_rates_sorted_descending() {
        let mut tracker = RateTracker::new(10);
        let now = Instant::now();
        let ip1 = Ipv4Addr::new(10, 0, 0, 1);
        let ip2 = Ipv4Addr::new(10, 0, 0, 2);

        for _ in 0..50 {
            tracker.record(ip1, now);
        }
        for _ in 0..100 {
            tracker.record(ip2, now);
        }

        let rates = tracker.all_rates(now);
        assert_eq!(rates[0].0, ip2); // ip2 has more packets
        assert!(rates[0].1 > rates[1].1);
    }
}
