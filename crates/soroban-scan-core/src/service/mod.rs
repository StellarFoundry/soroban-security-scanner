//! In-process service building blocks for an opt-in scan API adapter.
//!
//! This module deliberately contains no HTTP listener and no network access.
//! A deployment supplies its own transport and drives the adapter.

pub mod api;
pub mod jobs;

pub use api::{ApiRequest, ApiResponse, ScanApi, MAX_FILE_NAME_BYTES};
pub use jobs::{
    Job, JobLimits, JobStatus, JobStore, JobStoreError, DEFAULT_MAX_JOBS,
    DEFAULT_MAX_PAYLOAD_BYTES, DEFAULT_RETENTION,
};
