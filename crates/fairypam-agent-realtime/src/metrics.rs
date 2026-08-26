#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct RealtimeMetrics {
    pub sample_count: u64,
    pub transition_count: u64,
    pub missed_deadlines: u64,
    pub stale_events: u64,
    pub queue_overflows: u64,
    pub sample_intervals_us: Vec<u64>,
    pub scheduler_lateness_us: Vec<u64>,
    pub detection_to_input_us: Vec<u64>,
    pub chord_skew_us: Vec<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct RealtimeMetricsSummary {
    pub sample_count: u64,
    pub transition_count: u64,
    pub missed_deadlines: u64,
    pub stale_events: u64,
    pub queue_overflows: u64,
    pub sample_interval_p50_us: u64,
    pub sample_interval_p95_us: u64,
    pub sample_interval_p99_us: u64,
    pub scheduler_lateness_p99_us: u64,
    pub detection_to_input_p99_us: u64,
    pub chord_skew_p99_us: u64,
}

impl RealtimeMetrics {
    pub fn percentile(values: &mut [u64], percentile: u8) -> u64 {
        if values.is_empty() {
            return 0;
        }
        values.sort_unstable();
        let index = (values.len() - 1) * usize::from(percentile) / 100;
        values[index]
    }

    pub fn summary(&self) -> RealtimeMetricsSummary {
        let mut sample_intervals = self.sample_intervals_us.clone();
        let mut scheduler_lateness = self.scheduler_lateness_us.clone();
        let mut detection_to_input = self.detection_to_input_us.clone();
        let mut chord_skew = self.chord_skew_us.clone();
        RealtimeMetricsSummary {
            sample_count: self.sample_count,
            transition_count: self.transition_count,
            missed_deadlines: self.missed_deadlines,
            stale_events: self.stale_events,
            queue_overflows: self.queue_overflows,
            sample_interval_p50_us: Self::percentile(&mut sample_intervals, 50),
            sample_interval_p95_us: Self::percentile(&mut sample_intervals, 95),
            sample_interval_p99_us: Self::percentile(&mut sample_intervals, 99),
            scheduler_lateness_p99_us: Self::percentile(&mut scheduler_lateness, 99),
            detection_to_input_p99_us: Self::percentile(&mut detection_to_input, 99),
            chord_skew_p99_us: Self::percentile(&mut chord_skew, 99),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_is_stable_and_does_not_mutate_raw_samples() {
        let metrics = RealtimeMetrics {
            sample_count: 3,
            transition_count: 2,
            sample_intervals_us: vec![30, 10, 20],
            scheduler_lateness_us: vec![3, 1, 2],
            detection_to_input_us: vec![300, 100, 200],
            chord_skew_us: vec![9, 7, 8],
            ..RealtimeMetrics::default()
        };

        let summary = metrics.summary();

        assert_eq!(summary.sample_interval_p50_us, 20);
        assert_eq!(summary.sample_interval_p99_us, 20);
        assert_eq!(summary.scheduler_lateness_p99_us, 2);
        assert_eq!(summary.detection_to_input_p99_us, 200);
        assert_eq!(summary.chord_skew_p99_us, 8);
        assert_eq!(metrics.sample_intervals_us, vec![30, 10, 20]);
    }
}
