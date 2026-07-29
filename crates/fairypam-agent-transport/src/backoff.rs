use std::time::Duration;

use crate::TransportError;

#[derive(Clone, Debug)]
pub struct CappedBackoff {
    base: Duration,
    maximum: Duration,
    attempt: u32,
    rng: fastrand::Rng,
}

impl CappedBackoff {
    pub fn new(base: Duration, maximum: Duration) -> Result<Self, TransportError> {
        Self::with_seed(base, maximum, fastrand::u64(..))
    }

    fn with_seed(base: Duration, maximum: Duration, seed: u64) -> Result<Self, TransportError> {
        if base.is_zero() || maximum < base {
            return Err(TransportError::new(
                "transport.backoff_invalid",
                "backoff base must be non-zero and not exceed its cap",
            ));
        }
        Ok(Self {
            base,
            maximum,
            attempt: 0,
            rng: fastrand::Rng::with_seed(seed),
        })
    }

    pub fn next_delay(&mut self) -> Duration {
        let multiplier = 1_u32.checked_shl(self.attempt.min(30)).unwrap_or(u32::MAX);
        let ceiling = self.base.saturating_mul(multiplier).min(self.maximum);
        self.attempt = self.attempt.saturating_add(1);
        // Equal jitter: retain exponential growth while ensuring independent
        // processes do not synchronize at the cap after a Hub restart.
        ceiling.mul_f64(self.rng.f64() * 0.5 + 0.5)
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_is_exponential_jittered_and_capped() {
        let mut backoff =
            CappedBackoff::with_seed(Duration::from_millis(10), Duration::from_millis(25), 7)
                .unwrap();

        let first = backoff.next_delay();
        let second = backoff.next_delay();
        let capped = backoff.next_delay();
        assert!((Duration::from_millis(5)..=Duration::from_millis(10)).contains(&first));
        assert!((Duration::from_millis(10)..=Duration::from_millis(20)).contains(&second));
        assert!((Duration::from_micros(12_500)..=Duration::from_millis(25)).contains(&capped));
        assert_ne!(capped, Duration::from_millis(25));
        backoff.reset();
        assert!(
            (Duration::from_millis(5)..=Duration::from_millis(10)).contains(&backoff.next_delay())
        );
    }

    #[test]
    fn independent_instances_do_not_share_a_fixed_jitter_sequence() {
        let mut first =
            CappedBackoff::with_seed(Duration::from_secs(1), Duration::from_secs(30), 1).unwrap();
        let mut second =
            CappedBackoff::with_seed(Duration::from_secs(1), Duration::from_secs(30), 2).unwrap();

        assert_ne!(first.next_delay(), second.next_delay());
    }
}
