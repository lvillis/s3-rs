use std::time::Duration;

#[cfg(feature = "async")]
pub(crate) mod async_transport;
#[cfg(feature = "blocking")]
pub(crate) mod blocking_transport;
#[cfg(feature = "rustls")]
pub(crate) mod tls;

#[derive(Clone, Copy, Debug)]
pub(crate) struct RetryConfig {
    pub(crate) max_attempts: u32,
    pub(crate) base_delay: Duration,
    pub(crate) max_delay: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(2),
        }
    }
}

pub(crate) fn backoff_delay(config: RetryConfig, attempt: u32) -> Duration {
    let attempt = attempt.saturating_sub(1);
    let factor = 1u32 << attempt.min(16);
    let millis = config
        .base_delay
        .as_millis()
        .saturating_mul(u128::from(factor));
    let capped = millis.min(config.max_delay.as_millis());

    let jitter = jitter_millis(capped);
    Duration::from_millis(jitter as u64)
}

fn jitter_millis(max_millis: u128) -> u128 {
    if max_millis <= 1 {
        return max_millis;
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u128)
        .unwrap_or(0);

    nanos % max_millis
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_delay_is_capped_and_non_negative() {
        let cfg = RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(2),
        };

        let d1 = backoff_delay(cfg, 1);
        let d2 = backoff_delay(cfg, 2);
        let d3 = backoff_delay(cfg, 3);
        let d99 = backoff_delay(cfg, 99);

        assert!(d1 < Duration::from_millis(200));
        assert!(d2 < Duration::from_millis(400));
        assert!(d3 < Duration::from_millis(800));
        assert!(d99 < cfg.max_delay);
    }

    #[test]
    fn backoff_delay_zero_base_is_zero() {
        let cfg = RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_secs(2),
        };

        assert_eq!(backoff_delay(cfg, 1), Duration::from_millis(0));
        assert_eq!(backoff_delay(cfg, 10), Duration::from_millis(0));
    }
}
