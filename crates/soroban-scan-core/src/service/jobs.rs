//! In-process scan job storage with hard memory and retention bounds.
//!
//! The store keeps a fixed maximum number of jobs, rejects oversized payloads
//! and reports, and expires only finished jobs. Queued and running jobs are
//! never evicted or silently dropped: when the store is full, new work is
//! rejected with [`JobStoreError::StoreFull`] until a job finishes and expires.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use serde::Serialize;

/// Default maximum number of retained jobs.
pub const DEFAULT_MAX_JOBS: usize = 128;
/// Default maximum size of one submitted payload or completed report (1 MiB).
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Default retention for finished jobs (24 hours).
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

/// Hard bounds for a job store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobLimits {
    /// Maximum number of jobs held in any state.
    pub max_jobs: usize,
    /// Maximum UTF-8 byte length of a payload, report, or error message.
    pub max_payload_bytes: usize,
    /// How long a finished job is retained before it can be pruned.
    pub retention: Duration,
}

impl Default for JobLimits {
    fn default() -> Self {
        Self {
            max_jobs: DEFAULT_MAX_JOBS,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            retention: DEFAULT_RETENTION,
        }
    }
}

/// Lifecycle state of a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    /// Accepted but not started.
    Queued,
    /// Currently being processed.
    Running,
    /// Finished successfully; the report is available.
    Completed,
    /// Finished with an error; the bounded message is available.
    Failed,
}

impl JobStatus {
    /// True when the job will not change state again.
    pub fn is_terminal(self) -> bool {
        matches!(self, JobStatus::Completed | JobStatus::Failed)
    }
}

/// Snapshot of one job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Stable job identifier.
    pub id: String,
    /// Current lifecycle state.
    pub status: JobStatus,
    /// Submitted payload while queued or running.
    pub payload: Option<String>,
    /// Rendered report after completion.
    pub output: Option<String>,
    /// Bounded error message after failure.
    pub error: Option<String>,
    /// When the job was accepted.
    pub created_at: SystemTime,
    /// When the job reached a terminal state.
    pub finished_at: Option<SystemTime>,
}

/// Job store rejection. Variants are structured so an API can map them to
/// status codes and stable error codes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JobStoreError {
    /// A payload or report exceeded the configured byte limit.
    #[error("job payload or report exceeds {limit} bytes")]
    PayloadTooLarge {
        /// Configured maximum byte length.
        limit: usize,
    },
    /// The store already holds the maximum number of jobs.
    #[error("job store is full ({limit} jobs); retry after a job finishes and expires")]
    StoreFull {
        /// Configured maximum job count.
        limit: usize,
    },
    /// No job has the requested identifier.
    #[error("unknown job id")]
    NotFound,
    /// The job finished and its retention window has elapsed.
    #[error("job expired after {} seconds of retention", retention.as_secs())]
    Expired {
        /// Configured retention for finished jobs.
        retention: Duration,
    },
    /// The requested state transition is not allowed.
    #[error("job is in state {status:?}; expected {expected:?}")]
    InvalidTransition {
        /// Current state.
        status: JobStatus,
        /// Required state.
        expected: JobStatus,
    },
}

impl JobStoreError {
    /// Stable machine-readable error code.
    pub fn code(&self) -> &'static str {
        match self {
            JobStoreError::PayloadTooLarge { .. } => "payload_too_large",
            JobStoreError::StoreFull { .. } => "store_full",
            JobStoreError::NotFound => "job_not_found",
            JobStoreError::Expired { .. } => "job_expired",
            JobStoreError::InvalidTransition { .. } => "invalid_job_transition",
        }
    }
}

struct State {
    next_id: u64,
    jobs: BTreeMap<String, Job>,
    order: VecDeque<String>,
}

/// Thread-safe bounded job store.
pub struct JobStore {
    limits: JobLimits,
    state: Mutex<State>,
}

impl JobStore {
    /// Creates an empty store with the given limits.
    pub fn new(limits: JobLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(State {
                next_id: 1,
                jobs: BTreeMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    /// Configured bounds.
    pub fn limits(&self) -> JobLimits {
        self.limits
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A panic while holding the lock must not make the store unusable.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Accepts a payload, pruning expired finished jobs first.
    pub fn submit(&self, payload: impl Into<String>) -> Result<String, JobStoreError> {
        self.submit_at(payload, SystemTime::now())
    }

    /// Accepts a payload at an explicit time; used by tests and schedulers.
    pub fn submit_at(
        &self,
        payload: impl Into<String>,
        now: SystemTime,
    ) -> Result<String, JobStoreError> {
        let payload = payload.into();
        self.check_size(&payload)?;
        let mut state = self.lock();
        remove_expired(&mut state, now, self.limits.retention);
        if state.jobs.len() >= self.limits.max_jobs {
            return Err(JobStoreError::StoreFull {
                limit: self.limits.max_jobs,
            });
        }

        let id = format!("job-{}", state.next_id);
        state.next_id = state.next_id.saturating_add(1);
        state.jobs.insert(
            id.clone(),
            Job {
                id: id.clone(),
                status: JobStatus::Queued,
                payload: Some(payload),
                output: None,
                error: None,
                created_at: now,
                finished_at: None,
            },
        );
        state.order.push_back(id.clone());
        Ok(id)
    }

    /// Returns a snapshot of one job.
    pub fn get(&self, id: &str) -> Result<Job, JobStoreError> {
        self.lock()
            .jobs
            .get(id)
            .cloned()
            .ok_or(JobStoreError::NotFound)
    }

    /// Returns a snapshot of one job, reporting a finished job whose retention
    /// elapsed as [`JobStoreError::Expired`] instead of a generic not-found.
    pub fn get_at(&self, id: &str, now: SystemTime) -> Result<Job, JobStoreError> {
        let job = self.get(id)?;
        if job.status.is_terminal() {
            let elapsed = job
                .finished_at
                .and_then(|finished| now.duration_since(finished).ok());
            if elapsed.is_some_and(|elapsed| elapsed >= self.limits.retention) {
                return Err(JobStoreError::Expired {
                    retention: self.limits.retention,
                });
            }
        }
        Ok(job)
    }

    /// Oldest queued job id, if any.
    pub fn next_queued(&self) -> Option<String> {
        let state = self.lock();
        state
            .order
            .iter()
            .find(|id| {
                state
                    .jobs
                    .get(*id)
                    .is_some_and(|job| job.status == JobStatus::Queued)
            })
            .cloned()
    }

    /// Moves a queued job to running.
    pub fn start(&self, id: &str) -> Result<(), JobStoreError> {
        let mut state = self.lock();
        let job = state.jobs.get_mut(id).ok_or(JobStoreError::NotFound)?;
        if job.status != JobStatus::Queued {
            return Err(JobStoreError::InvalidTransition {
                status: job.status,
                expected: JobStatus::Queued,
            });
        }
        job.status = JobStatus::Running;
        Ok(())
    }

    /// Completes a running job and stores its report.
    pub fn complete(&self, id: &str, report: impl Into<String>) -> Result<(), JobStoreError> {
        self.complete_at(id, report, SystemTime::now())
    }

    /// Completes a running job at an explicit time.
    pub fn complete_at(
        &self,
        id: &str,
        report: impl Into<String>,
        now: SystemTime,
    ) -> Result<(), JobStoreError> {
        let report = report.into();
        self.check_size(&report)?;
        let mut state = self.lock();
        let job = state.jobs.get_mut(id).ok_or(JobStoreError::NotFound)?;
        if job.status != JobStatus::Running {
            return Err(JobStoreError::InvalidTransition {
                status: job.status,
                expected: JobStatus::Running,
            });
        }
        job.status = JobStatus::Completed;
        job.payload = None;
        job.output = Some(report);
        job.finished_at = Some(now);
        Ok(())
    }

    /// Fails a running job with a bounded message.
    pub fn fail(&self, id: &str, message: impl Into<String>) -> Result<(), JobStoreError> {
        self.fail_at(id, message, SystemTime::now())
    }

    /// Fails a running job at an explicit time.
    pub fn fail_at(
        &self,
        id: &str,
        message: impl Into<String>,
        now: SystemTime,
    ) -> Result<(), JobStoreError> {
        let mut message = message.into();
        if message.len() > self.limits.max_payload_bytes {
            message.truncate_floor(self.limits.max_payload_bytes);
        }
        let mut state = self.lock();
        let job = state.jobs.get_mut(id).ok_or(JobStoreError::NotFound)?;
        if job.status != JobStatus::Running {
            return Err(JobStoreError::InvalidTransition {
                status: job.status,
                expected: JobStatus::Running,
            });
        }
        job.status = JobStatus::Failed;
        job.payload = None;
        job.output = None;
        job.error = Some(message);
        job.finished_at = Some(now);
        Ok(())
    }

    /// Removes finished jobs whose retention elapsed. Returns the count.
    ///
    /// Queued and running jobs are untouched even when they are older than
    /// the retention window.
    pub fn remove_expired(&self, now: SystemTime) -> usize {
        remove_expired(&mut self.lock(), now, self.limits.retention)
    }

    /// Number of retained jobs in every state.
    pub fn len(&self) -> usize {
        self.lock().jobs.len()
    }

    /// True when the store holds no jobs.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn check_size(&self, text: &str) -> Result<(), JobStoreError> {
        if text.len() > self.limits.max_payload_bytes {
            return Err(JobStoreError::PayloadTooLarge {
                limit: self.limits.max_payload_bytes,
            });
        }
        Ok(())
    }
}

fn remove_expired(state: &mut State, now: SystemTime, retention: Duration) -> usize {
    let before = state.jobs.len();
    let expired: Vec<String> = state
        .jobs
        .values()
        .filter(|job| {
            job.status.is_terminal()
                && job.finished_at.is_some_and(|finished| {
                    now.duration_since(finished)
                        .map(|elapsed| elapsed >= retention)
                        .unwrap_or(false)
                })
        })
        .map(|job| job.id.clone())
        .collect();
    for id in &expired {
        state.jobs.remove(id);
    }
    if !expired.is_empty() {
        state.order.retain(|id| state.jobs.contains_key(id));
    }
    before - state.jobs.len()
}

trait TruncateFloor {
    fn truncate_floor(&mut self, max_bytes: usize);
}

impl TruncateFloor for String {
    fn truncate_floor(&mut self, max_bytes: usize) {
        if self.len() <= max_bytes {
            return;
        }
        let mut end = max_bytes;
        while end > 0 && !self.is_char_boundary(end) {
            end -= 1;
        }
        self.truncate(end);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn limits(max_jobs: usize, max_payload_bytes: usize) -> JobLimits {
        JobLimits {
            max_jobs,
            max_payload_bytes,
            retention: Duration::from_secs(60),
        }
    }

    #[test]
    fn jobs_move_through_the_lifecycle() {
        let store = JobStore::new(limits(4, 64));
        let id = store.submit_at("contract source", at(0)).unwrap();
        assert_eq!(store.get(&id).unwrap().status, JobStatus::Queued);
        assert_eq!(store.next_queued().as_deref(), Some(id.as_str()));

        store.start(&id).unwrap();
        assert_eq!(store.get(&id).unwrap().status, JobStatus::Running);
        assert!(store.next_queued().is_none());

        store.complete_at(&id, "{\"findings\":[]}", at(10)).unwrap();
        let job = store.get(&id).unwrap();
        assert_eq!(job.status, JobStatus::Completed);
        assert_eq!(job.output.as_deref(), Some("{\"findings\":[]}"));
        assert_eq!(job.payload, None);
        assert_eq!(job.finished_at, Some(at(10)));
    }

    #[test]
    fn oversized_payloads_and_reports_are_rejected() {
        let store = JobStore::new(limits(4, 8));
        assert_eq!(
            store.submit_at("123456789", at(0)),
            Err(JobStoreError::PayloadTooLarge { limit: 8 })
        );
        let id = store.submit_at("12345678", at(0)).unwrap();
        store.start(&id).unwrap();
        assert_eq!(
            store.complete_at(&id, "123456789", at(1)),
            Err(JobStoreError::PayloadTooLarge { limit: 8 })
        );
        assert_eq!(store.get(&id).unwrap().status, JobStatus::Running);
    }

    #[test]
    fn full_store_rejects_new_work_without_dropping_existing_jobs() {
        let store = JobStore::new(limits(2, 64));
        let first = store.submit_at("one", at(0)).unwrap();
        let second = store.submit_at("two", at(0)).unwrap();
        assert_eq!(
            store.submit_at("three", at(0)),
            Err(JobStoreError::StoreFull { limit: 2 })
        );
        store.start(&first).unwrap();
        assert_eq!(
            store.submit_at("three", at(0)),
            Err(JobStoreError::StoreFull { limit: 2 })
        );
        assert_eq!(store.len(), 2);
        assert_eq!(store.get(&first).unwrap().status, JobStatus::Running);
        assert_eq!(store.get(&second).unwrap().status, JobStatus::Queued);
    }

    #[test]
    fn retention_prunes_only_finished_jobs() {
        let store = JobStore::new(limits(4, 64));
        let finished = store.submit_at("finished", at(0)).unwrap();
        store.start(&finished).unwrap();
        store.complete_at(&finished, "report", at(10)).unwrap();

        let running = store.submit_at("running", at(20)).unwrap();
        store.start(&running).unwrap();
        let queued = store.submit_at("queued", at(20)).unwrap();

        assert_eq!(store.remove_expired(at(69)), 0);
        assert_eq!(store.remove_expired(at(70)), 1);
        assert_eq!(store.get(&finished).unwrap_err(), JobStoreError::NotFound);
        assert_eq!(store.get(&running).unwrap().status, JobStatus::Running);
        assert_eq!(store.get(&queued).unwrap().status, JobStatus::Queued);
    }

    #[test]
    fn invalid_transitions_are_rejected() {
        let store = JobStore::new(limits(2, 64));
        let id = store.submit_at("source", at(0)).unwrap();
        assert!(matches!(
            store.complete(&id, "report"),
            Err(JobStoreError::InvalidTransition {
                status: JobStatus::Queued,
                expected: JobStatus::Running
            })
        ));
        store.start(&id).unwrap();
        assert!(matches!(
            store.start(&id),
            Err(JobStoreError::InvalidTransition {
                status: JobStatus::Running,
                expected: JobStatus::Queued
            })
        ));
        assert_eq!(store.get("missing").unwrap_err(), JobStoreError::NotFound);
    }

    #[test]
    fn a_full_load_stays_within_the_job_cap() {
        let store = JobStore::new(limits(1_000, 64));
        for index in 0..1_000 {
            store.submit(format!("job-{index}")).unwrap();
        }
        assert_eq!(store.len(), 1_000);
        for index in 0..1_000 {
            assert_eq!(
                store.submit(format!("overflow-{index}")),
                Err(JobStoreError::StoreFull { limit: 1_000 })
            );
        }
        assert_eq!(store.len(), 1_000);
    }

    #[test]
    fn failure_messages_are_bounded() {
        let store = JobStore::new(limits(2, 4));
        let id = store.submit_at("x", at(0)).unwrap();
        store.start(&id).unwrap();
        store.fail_at(&id, "a long failure message", at(1)).unwrap();
        assert_eq!(store.get(&id).unwrap().error.as_deref(), Some("a lo"));
    }

    #[test]
    fn expired_jobs_return_a_clear_error() {
        let store = JobStore::new(limits(4, 64));
        let id = store.submit_at("done", at(0)).unwrap();
        store.start(&id).unwrap();
        store.complete_at(&id, "report", at(10)).unwrap();

        assert_eq!(
            store.get_at(&id, at(69)).unwrap().status,
            JobStatus::Completed
        );
        assert_eq!(
            store.get_at(&id, at(70)),
            Err(JobStoreError::Expired {
                retention: Duration::from_secs(60)
            })
        );

        let queued = store.submit_at("pending", at(0)).unwrap();
        assert_eq!(
            store.get_at(&queued, at(10_000)).unwrap().status,
            JobStatus::Queued,
            "queued work is never reported as expired"
        );
    }
}
