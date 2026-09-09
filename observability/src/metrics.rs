use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// Simple Prometheus-style metrics collector
pub struct MetricsCollector {
    counters: RwLock<HashMap<String, AtomicU64>>,
    gauges: RwLock<HashMap<String, AtomicU64>>,
    histograms: RwLock<HashMap<String, Vec<f64>>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
        }
    }

    pub fn increment_counter(&self, name: &str) {
        if let Ok(mut counters) = self.counters.write() {
            counters
                .entry(name.to_string())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn increment_counter_by(&self, name: &str, value: u64) {
        if let Ok(mut counters) = self.counters.write() {
            counters
                .entry(name.to_string())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(value, Ordering::Relaxed);
        }
    }

    pub fn set_gauge(&self, name: &str, value: u64) {
        if let Ok(mut gauges) = self.gauges.write() {
            gauges
                .entry(name.to_string())
                .or_insert_with(|| AtomicU64::new(0))
                .store(value, Ordering::Relaxed);
        }
    }

    pub fn record_histogram(&self, name: &str, value: f64) {
        if let Ok(mut histograms) = self.histograms.write() {
            histograms.entry(name.to_string()).or_default().push(value);
        }
    }

    pub fn get_counter(&self, name: &str) -> u64 {
        self.counters
            .read()
            .ok()
            .and_then(|counters| counters.get(name).map(|c| c.load(Ordering::Relaxed)))
            .unwrap_or(0)
    }

    pub fn get_gauge(&self, name: &str) -> u64 {
        self.gauges
            .read()
            .ok()
            .and_then(|gauges| gauges.get(name).map(|g| g.load(Ordering::Relaxed)))
            .unwrap_or(0)
    }

    pub fn render_prometheus(&self) -> String {
        let mut output = String::new();
        if let Ok(counters) = self.counters.read() {
            for (name, value) in counters.iter() {
                output.push_str(&format!(
                    "# HELP {} counter\n# TYPE {} counter\n{} {}\n",
                    name,
                    name,
                    name,
                    value.load(Ordering::Relaxed)
                ));
            }
        }
        if let Ok(gauges) = self.gauges.read() {
            for (name, value) in gauges.iter() {
                output.push_str(&format!(
                    "# HELP {} gauge\n# TYPE {} gauge\n{} {}\n",
                    name,
                    name,
                    name,
                    value.load(Ordering::Relaxed)
                ));
            }
        }
        output
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let mc = MetricsCollector::new();
        mc.increment_counter("requests_total");
        mc.increment_counter("requests_total");
        assert_eq!(mc.get_counter("requests_total"), 2);
    }

    #[test]
    fn test_gauge() {
        let mc = MetricsCollector::new();
        mc.set_gauge("active_connections", 42);
        assert_eq!(mc.get_gauge("active_connections"), 42);
    }

    #[test]
    fn test_histogram() {
        let mc = MetricsCollector::new();
        mc.record_histogram("request_duration_ms", 100.0);
        mc.record_histogram("request_duration_ms", 200.0);
    }
}
