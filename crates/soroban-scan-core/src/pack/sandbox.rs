//! Bounded in-process execution for rule packs.
//!
//! Packs are untrusted community input. This module runs a pack's work on a
//! worker thread and fails closed when it exceeds the configured wall-clock,
//! output, or rule-count limits. A panic in pack code is reported as a
//! diagnostic ([`PackLimitError::PackFailed`]) instead of crashing the scanner.
//!
//! Rust cannot forcibly cancel a running thread, so a timeout detaches the
//! worker. Callers must treat a timeout as terminal and never wait for the
//! abandoned work.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

/// Default wall-clock limit for one pack run.
pub const DEFAULT_MAX_DURATION: Duration = Duration::from_secs(5);
/// Default maximum number of bytes a pack may emit (1 MiB).
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Default maximum number of rules a pack may declare.
pub const DEFAULT_MAX_RULES: usize = 10_000;

/// Hard resource limits applied to a pack run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackLimits {
    /// Maximum wall-clock time the pack may run.
    pub max_duration: Duration,
    /// Maximum UTF-8 byte length of the pack's output.
    pub max_output_bytes: usize,
    /// Maximum number of rules the pack may declare.
    pub max_rules: usize,
}

impl Default for PackLimits {
    fn default() -> Self {
        Self {
            max_duration: DEFAULT_MAX_DURATION,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_rules: DEFAULT_MAX_RULES,
        }
    }
}

/// A pack limit violation or execution failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackLimitError {
    /// The pack did not finish within the time limit.
    #[error("pack exceeded the {0:?} time limit")]
    Timeout(Duration),
    /// The pack emitted more output than allowed.
    #[error("pack output exceeds {limit} bytes")]
    OutputTooLarge {
        /// Configured maximum byte length.
        limit: usize,
    },
    /// The pack declared more rules than allowed.
    #[error("pack declares {count} rules; the limit is {limit}")]
    TooManyRules {
        /// Number of rules the pack declared.
        count: usize,
        /// Configured maximum rule count.
        limit: usize,
    },
    /// The pack panicked or its worker stopped without producing output.
    #[error("pack execution failed")]
    PackFailed,
}

/// Successful, bounded pack output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackOutcome {
    /// Output produced by the pack.
    pub output: String,
    /// Wall-clock time spent running the pack.
    pub elapsed: Duration,
}

/// Runs `run` under `limits`, returning bounded output or a diagnostic error.
///
/// The rule count is checked before any work starts. Output is checked after
/// the worker finishes, and a panic is converted to [`PackLimitError::PackFailed`].
pub fn run_bounded<F>(
    limits: PackLimits,
    rule_count: usize,
    run: F,
) -> Result<PackOutcome, PackLimitError>
where
    F: FnOnce() -> String + Send + 'static,
{
    if rule_count > limits.max_rules {
        return Err(PackLimitError::TooManyRules {
            count: rule_count,
            limit: limits.max_rules,
        });
    }

    let (sender, receiver) = mpsc::channel();
    let start = Instant::now();
    let _worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));
        let _ = sender.send(result);
    });

    match receiver.recv_timeout(limits.max_duration) {
        Ok(Ok(output)) => {
            let elapsed = start.elapsed();
            if output.len() > limits.max_output_bytes {
                return Err(PackLimitError::OutputTooLarge {
                    limit: limits.max_output_bytes,
                });
            }
            Ok(PackOutcome { output, elapsed })
        }
        Ok(Err(_)) => Err(PackLimitError::PackFailed),
        Err(RecvTimeoutError::Timeout) => Err(PackLimitError::Timeout(limits.max_duration)),
        Err(RecvTimeoutError::Disconnected) => Err(PackLimitError::PackFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_duration: Duration, max_output_bytes: usize, max_rules: usize) -> PackLimits {
        PackLimits {
            max_duration,
            max_output_bytes,
            max_rules,
        }
    }

    #[test]
    fn successful_pack_returns_bounded_output() {
        let outcome = run_bounded(limits(Duration::from_secs(1), 8, 2), 2, || {
            "findings".to_string()
        })
        .unwrap();
        assert_eq!(outcome.output, "findings");
    }

    #[test]
    fn oversized_output_fails_closed() {
        let error = run_bounded(limits(Duration::from_secs(1), 4, 2), 0, || {
            "too long".to_string()
        })
        .unwrap_err();
        assert_eq!(error, PackLimitError::OutputTooLarge { limit: 4 });
    }

    #[test]
    fn too_many_rules_are_rejected_before_execution() {
        let error = run_bounded(limits(Duration::from_secs(1), 8, 2), 3, || {
            "never runs".to_string()
        })
        .unwrap_err();
        assert_eq!(error, PackLimitError::TooManyRules { count: 3, limit: 2 });
    }

    #[test]
    fn panics_become_diagnostics() {
        let error = run_bounded(PackLimits::default(), 0, || panic!("pack blew up")).unwrap_err();
        assert_eq!(error, PackLimitError::PackFailed);
    }

    #[test]
    fn timeouts_fail_closed() {
        let error = run_bounded(limits(Duration::from_millis(20), 8, 2), 0, || {
            std::thread::sleep(Duration::from_millis(500));
            "late".to_string()
        })
        .unwrap_err();
        assert_eq!(error, PackLimitError::Timeout(Duration::from_millis(20)));
    }
}
