//! Bounded per-token fixed-window rate limiting for the scan API adapter.
//!
//! Token values are never stored. Buckets are keyed by a non-cryptographic
//! fingerprint, and the number of retained buckets is capped so rotating
//! credentials cannot grow the limiter without bound. A fingerprint collision
//! can only make two callers share a budget; it cannot disclose a token.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default maximum number of token buckets the limiter retains.
pub const DEFAULT_MAX_TRACKED_TOKENS: usize = 1024;

/// Fixed-window rate limit settings for one API adapter.
///
/// Rate limiting is disabled unless the adapter is built with
/// [`ScanApi::with_rate_limit`](crate::service::ScanApi::with_rate_limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Requests allowed per token within one window. Zero denies every request.
    pub requests_per_window: u32,
    /// Length of the fixed window. Zero denies every request.
    pub window: Duration,
    /// Maximum number of token buckets retained. Zero denies every request.
    pub max_tracked_tokens: usize,
}

impl RateLimitConfig {
    /// Builds a config with the default bound on tracked tokens.
    pub fn per_window(requests_per_window: u32, window: Duration) -> Self {
        Self {
            requests_per_window,
            window,
            max_tracked_tokens: DEFAULT_MAX_TRACKED_TOKENS,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self::per_window(60, Duration::from_secs(60))
    }
}

/// Outcome of one limiter check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RateLimitDecision {
    /// Whether the request may proceed.
    pub allowed: bool,
    /// Configured requests per window.
    pub limit: u32,
    /// Requests left in the current window, after this one when allowed.
    pub remaining: u32,
    /// Whole seconds until the current window resets.
    pub reset_seconds: u64,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    window_start: Duration,
    used: u32,
}

/// Thread-safe, bounded fixed-window limiter.
pub(crate) struct RateLimiter {
    config: RateLimitConfig,
    buckets: Mutex<BTreeMap<u64, Bucket>>,
}

impl RateLimiter {
    pub(crate) fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn check(&self, token: &str, now: SystemTime) -> RateLimitDecision {
        let config = self.config;
        if config.requests_per_window == 0
            || config.window.is_zero()
            || config.max_tracked_tokens == 0
        {
            return RateLimitDecision {
                allowed: false,
                limit: config.requests_per_window,
                remaining: 0,
                reset_seconds: config.window.as_secs(),
            };
        }

        let now = now.duration_since(UNIX_EPOCH).unwrap_or_default();
        let key = fingerprint(token);
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);

        if !buckets.contains_key(&key) && buckets.len() >= config.max_tracked_tokens {
            // Evict the bucket with the oldest window; it is closest to freeing
            // a slot, and the cap keeps memory independent of token count.
            if let Some(oldest) = buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.window_start)
                .map(|(key, _)| *key)
            {
                buckets.remove(&oldest);
            }
        }

        let bucket = buckets.entry(key).or_insert(Bucket {
            window_start: now,
            used: 0,
        });
        if now.saturating_sub(bucket.window_start) >= config.window {
            bucket.window_start = now;
            bucket.used = 0;
        }
        let allowed = bucket.used < config.requests_per_window;
        if allowed {
            bucket.used += 1;
        }
        let left = config
            .window
            .saturating_sub(now.saturating_sub(bucket.window_start));
        RateLimitDecision {
            allowed,
            limit: config.requests_per_window,
            remaining: config.requests_per_window.saturating_sub(bucket.used),
            reset_seconds: left.as_secs() + u64::from(left.subsec_nanos() > 0),
        }
    }

    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.buckets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// FNV-1a fingerprint. Not cryptographic: the limiter only needs a stable key
/// and never exposes it.
fn fingerprint(token: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in token.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn limiter(requests: u32, window_seconds: u64, max_tracked_tokens: usize) -> RateLimiter {
        RateLimiter::new(RateLimitConfig {
            requests_per_window: requests,
            window: Duration::from_secs(window_seconds),
            max_tracked_tokens,
        })
    }

    #[test]
    fn a_burst_is_allowed_then_denied_until_the_window_resets() {
        let limiter = limiter(2, 10, 8);
        for _ in 0..2 {
            assert!(limiter.check("token", at(0)).allowed);
        }
        let denied = limiter.check("token", at(0));
        assert!(!denied.allowed);
        assert_eq!(denied.remaining, 0);
        assert_eq!(denied.reset_seconds, 10);

        let refilled = limiter.check("token", at(10));
        assert!(refilled.allowed);
        assert_eq!(refilled.remaining, 1);
    }

    #[test]
    fn sustained_requests_refill_with_the_window_without_sleeping() {
        let limiter = limiter(1, 10, 8);
        assert!(limiter.check("token", at(0)).allowed);
        assert!(!limiter.check("token", at(9)).allowed);
        assert!(limiter.check("token", at(10)).allowed);
        assert!(!limiter.check("token", at(19)).allowed);
        assert!(limiter.check("token", at(20)).allowed);
    }

    #[test]
    fn buckets_are_isolated_per_token_and_bounded() {
        let limiter = limiter(1, 60, 2);
        assert!(limiter.check("first", at(0)).allowed);
        assert!(limiter.check("second", at(0)).allowed);
        assert!(!limiter.check("first", at(0)).allowed);

        assert!(limiter.check("third", at(0)).allowed);
        assert_eq!(limiter.tracked(), 2);
        assert!(limiter.check("fourth", at(0)).allowed);
        assert_eq!(limiter.tracked(), 2);
    }

    #[test]
    fn an_unbounded_or_empty_configuration_denies_everything() {
        for config in [
            RateLimitConfig {
                requests_per_window: 0,
                window: Duration::from_secs(60),
                max_tracked_tokens: 8,
            },
            RateLimitConfig {
                requests_per_window: 8,
                window: Duration::ZERO,
                max_tracked_tokens: 8,
            },
            RateLimitConfig {
                requests_per_window: 8,
                window: Duration::from_secs(60),
                max_tracked_tokens: 0,
            },
        ] {
            assert!(!RateLimiter::new(config).check("token", at(0)).allowed);
        }
    }
}
