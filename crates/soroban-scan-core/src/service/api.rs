//! Transport-agnostic, in-process scan API adapter.
//!
//! The adapter maps plain request values to responses; it does not open a
//! socket. A deployment parses HTTP (or any other protocol) into [`ApiRequest`]
//! and writes [`ApiResponse`] back. Every request requires bearer
//! authentication before routing or body parsing.

use std::time::SystemTime;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::api_auth::{ApiAuthConfig, ApiAuthError};
use crate::config::ScanConfig;
use crate::engine::scan_source_str;
use crate::registry::RuleRegistry;
use crate::report;

use super::jobs::{JobLimits, JobStatus, JobStore, JobStoreError};

/// Maximum accepted synthetic file name length.
pub const MAX_FILE_NAME_BYTES: usize = 128;

/// One transport-independent request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiRequest {
    /// HTTP method, matched case-insensitively.
    pub method: String,
    /// Request path, for example `/v1/scans`.
    pub path: String,
    /// Raw `Authorization` header value.
    pub authorization: Option<String>,
    /// Raw request body.
    pub body: Vec<u8>,
}

impl ApiRequest {
    /// Builds a request with no authorization header.
    pub fn new(
        method: impl Into<String>,
        path: impl Into<String>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            authorization: None,
            body: body.into(),
        }
    }

    /// Adds an `Authorization` header value.
    pub fn with_authorization(mut self, header: impl Into<String>) -> Self {
        self.authorization = Some(header.into());
        self
    }
}

/// One transport-independent response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiResponse {
    /// Suggested HTTP status code.
    pub status: u16,
    /// JSON response body.
    pub body: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanSubmission {
    source: String,
    #[serde(default = "default_file_name")]
    file: String,
}

fn default_file_name() -> String {
    "input.rs".to_string()
}

/// In-process API adapter over a bounded job store.
pub struct ScanApi {
    auth: ApiAuthConfig,
    jobs: JobStore,
    config: ScanConfig,
    registry: RuleRegistry,
}

impl ScanApi {
    /// Builds an adapter with default scan settings and the given auth/limits.
    pub fn new(auth: ApiAuthConfig, limits: JobLimits) -> Self {
        Self::with_scan(
            auth,
            limits,
            ScanConfig::default(),
            RuleRegistry::with_default_rules(),
        )
    }

    /// Builds an adapter with explicit scan settings.
    pub fn with_scan(
        auth: ApiAuthConfig,
        limits: JobLimits,
        config: ScanConfig,
        registry: RuleRegistry,
    ) -> Self {
        Self {
            auth,
            jobs: JobStore::new(limits),
            config,
            registry,
        }
    }

    /// The backing job store.
    pub fn jobs(&self) -> &JobStore {
        &self.jobs
    }

    /// Handles one request. Authentication is checked before routing.
    pub fn handle(&self, request: &ApiRequest) -> ApiResponse {
        if let Err(error) = self.auth.authenticate(request.authorization.as_deref()) {
            return auth_response(error);
        }

        match (request.method.as_str(), request.path.as_str()) {
            (method, "/v1/scans") if method.eq_ignore_ascii_case("POST") => {
                self.submit(&request.body)
            }
            (method, path) if method.eq_ignore_ascii_case("GET") => {
                match path.strip_prefix("/v1/jobs/") {
                    Some(id) if !id.is_empty() && !id.contains('/') => self.job(id),
                    _ => not_found(),
                }
            }
            _ => not_found(),
        }
    }

    /// Processes the oldest queued job synchronously.
    ///
    /// Returns the job id when a job was processed and `None` when the queue is
    /// empty. A worker loop calls this repeatedly.
    pub fn run_next(&self) -> Result<Option<String>, JobStoreError> {
        let Some(id) = self.jobs.next_queued() else {
            return Ok(None);
        };
        self.jobs.start(&id)?;
        let payload = self.jobs.get(&id)?.payload.unwrap_or_default();

        match self.process(&payload) {
            Ok(report) => {
                if let Err(error) = self.jobs.complete(&id, report) {
                    let message = format!("cannot store report: {error}");
                    let _ = self.jobs.fail(&id, message);
                }
            }
            Err(message) => {
                let _ = self.jobs.fail(&id, message);
            }
        }
        Ok(Some(id))
    }

    fn submit(&self, body: &[u8]) -> ApiResponse {
        if body.len() > self.jobs.limits().max_payload_bytes {
            return error_response(
                413,
                "payload_too_large",
                &format!(
                    "request body exceeds {} bytes",
                    self.jobs.limits().max_payload_bytes
                ),
            );
        }
        let text = match std::str::from_utf8(body) {
            Ok(text) => text,
            Err(_) => return error_response(400, "invalid_request", "body must be UTF-8 JSON"),
        };
        let submission: ScanSubmission = match serde_json::from_str(text) {
            Ok(submission) => submission,
            Err(_) => return error_response(400, "invalid_request", "invalid scan submission"),
        };
        if submission.source.len() > self.jobs.limits().max_payload_bytes {
            return error_response(
                413,
                "payload_too_large",
                &format!(
                    "source exceeds {} bytes",
                    self.jobs.limits().max_payload_bytes
                ),
            );
        }
        if !safe_file_name(&submission.file) {
            return error_response(
                400,
                "invalid_request",
                "file must be a plain .rs file name without directories",
            );
        }

        match self.jobs.submit(text) {
            Ok(id) => ApiResponse {
                status: 202,
                body: json!({ "job_id": id, "status": "queued" }).to_string(),
            },
            Err(error) => job_error_response(&error),
        }
    }

    fn job(&self, id: &str) -> ApiResponse {
        let job = match self.jobs.get_at(id, SystemTime::now()) {
            Ok(job) => job,
            Err(error) => return job_error_response(&error),
        };
        let status = match job.status {
            JobStatus::Queued => "queued",
            JobStatus::Running => "running",
            JobStatus::Completed => "completed",
            JobStatus::Failed => "failed",
        };
        if job.status == JobStatus::Completed {
            let report: Value = job
                .output
                .as_deref()
                .and_then(|text| serde_json::from_str(text).ok())
                .unwrap_or(Value::Null);
            return ApiResponse {
                status: 200,
                body: json!({ "job_id": job.id, "status": status, "report": report }).to_string(),
            };
        }
        if job.status == JobStatus::Failed {
            return ApiResponse {
                status: 200,
                body: json!({
                    "job_id": job.id,
                    "status": status,
                    "error": {
                        "code": "scan_failed",
                        "message": job.error.unwrap_or_default(),
                    }
                })
                .to_string(),
            };
        }
        ApiResponse {
            status: 202,
            body: json!({ "job_id": job.id, "status": status }).to_string(),
        }
    }

    fn process(&self, payload: &str) -> Result<String, String> {
        let submission: ScanSubmission =
            serde_json::from_str(payload).map_err(|_| "invalid scan submission".to_string())?;
        let outcome = scan_source_str(
            &submission.source,
            &submission.file,
            &self.config,
            &self.registry,
        );
        report::render_json(&outcome).map_err(|_| "cannot render report".to_string())
    }
}

fn safe_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_FILE_NAME_BYTES
        && name.ends_with(".rs")
        && name != ".rs"
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn auth_response(error: ApiAuthError) -> ApiResponse {
    match error {
        ApiAuthError::NotConfigured => error_response(
            503,
            "authentication_not_configured",
            "API authentication is not configured",
        ),
        ApiAuthError::InvalidConfiguration => error_response(
            503,
            "authentication_not_configured",
            "API authentication is not configured",
        ),
        ApiAuthError::Unauthorized => {
            error_response(401, "unauthorized", "missing or invalid bearer token")
        }
    }
}

fn job_error_response(error: &JobStoreError) -> ApiResponse {
    match error {
        JobStoreError::PayloadTooLarge { .. } => {
            error_response(413, error.code(), &error.to_string())
        }
        JobStoreError::StoreFull { .. } => error_response(503, error.code(), &error.to_string()),
        JobStoreError::NotFound => error_response(404, error.code(), "unknown job id"),
        JobStoreError::Expired { .. } => error_response(410, error.code(), &error.to_string()),
        JobStoreError::InvalidTransition { .. } => {
            error_response(409, error.code(), "invalid job transition")
        }
    }
}

fn not_found() -> ApiResponse {
    error_response(404, "not_found", "unknown route")
}

fn error_response(status: u16, code: &str, message: &str) -> ApiResponse {
    ApiResponse {
        status,
        body: json!({ "error": { "code": code, "message": message } }).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::jobs::JobLimits;

    fn api() -> ScanApi {
        ScanApi::new(
            ApiAuthConfig {
                bearer_token: Some("test-token_123".to_string()),
            },
            JobLimits::default(),
        )
    }

    fn submit(api: &ScanApi, body: &str) -> ApiResponse {
        api.handle(
            &ApiRequest::new("POST", "/v1/scans", body).with_authorization("Bearer test-token_123"),
        )
    }

    fn body(value: &ApiResponse) -> Value {
        serde_json::from_str(&value.body).unwrap()
    }

    #[test]
    fn authentication_failures_are_rejected_before_routing() {
        let api = api();
        for header in [None, Some("Bearer wrong")] {
            let mut request = ApiRequest::new("POST", "/v1/scans", "{}");
            request.authorization = header.map(str::to_string);
            let response = api.handle(&request);
            assert_eq!(response.status, 401);
            assert_eq!(body(&response)["error"]["code"], "unauthorized");
            assert!(!response.body.contains("test-token_123"));
        }
        assert_eq!(
            api.handle(&ApiRequest::new("POST", "/v1/scans", "{}"))
                .status,
            401
        );
    }

    #[test]
    fn unconfigured_authentication_fails_closed() {
        let api = ScanApi::new(ApiAuthConfig::default(), JobLimits::default());
        let response = api.handle(&ApiRequest::new("GET", "/v1/jobs/job-1", ""));
        assert_eq!(response.status, 503);
        assert_eq!(
            body(&response)["error"]["code"],
            "authentication_not_configured"
        );
    }

    #[test]
    fn submit_poll_and_complete_a_job() {
        let api = api();
        let response = submit(&api, r#"{"source":"pub fn f() {}","file":"lib.rs"}"#);
        assert_eq!(response.status, 202);
        let id = body(&response)["job_id"].as_str().unwrap().to_string();
        assert_eq!(body(&response)["status"], "queued");

        let poll = api.handle(
            &ApiRequest::new("GET", format!("/v1/jobs/{id}"), "")
                .with_authorization("Bearer test-token_123"),
        );
        assert_eq!(poll.status, 202);
        assert_eq!(body(&poll)["status"], "queued");

        assert_eq!(api.run_next().unwrap().as_deref(), Some(id.as_str()));

        let done = api.handle(
            &ApiRequest::new("GET", format!("/v1/jobs/{id}"), "")
                .with_authorization("Bearer test-token_123"),
        );
        assert_eq!(done.status, 200);
        assert_eq!(body(&done)["status"], "completed");
        assert!(body(&done)["report"]["findings"].is_array());
    }

    #[test]
    fn oversized_bodies_are_rejected_before_json_parsing() {
        let api = ScanApi::new(
            ApiAuthConfig {
                bearer_token: Some("test-token_123".to_string()),
            },
            JobLimits {
                max_jobs: 4,
                max_payload_bytes: 16,
                ..JobLimits::default()
            },
        );
        let response = submit(&api, &"x".repeat(17));
        assert_eq!(response.status, 413);
        assert_eq!(body(&response)["error"]["code"], "payload_too_large");
    }

    #[test]
    fn invalid_submissions_and_file_names_are_rejected() {
        let api = api();
        for body_text in [
            "not json",
            r#"{"source":"x","file":"../lib.rs"}"#,
            r#"{"source":"x","file":"lib.txt"}"#,
            r#"{"source":"x","file":".rs"}"#,
            r#"{"source":"x","unexpected":true}"#,
        ] {
            let response = submit(&api, body_text);
            assert_eq!(response.status, 400, "{body_text}");
            assert_eq!(body(&response)["error"]["code"], "invalid_request");
        }
    }

    #[test]
    fn a_full_store_returns_a_structured_error() {
        let api = ScanApi::new(
            ApiAuthConfig {
                bearer_token: Some("test-token_123".to_string()),
            },
            JobLimits {
                max_jobs: 1,
                ..JobLimits::default()
            },
        );
        assert_eq!(
            submit(&api, r#"{"source":"x","file":"lib.rs"}"#).status,
            202
        );
        let response = submit(&api, r#"{"source":"y","file":"lib.rs"}"#);
        assert_eq!(response.status, 503);
        assert_eq!(body(&response)["error"]["code"], "store_full");
        assert_eq!(api.jobs().len(), 1);
    }

    #[test]
    fn unknown_routes_and_jobs_return_structured_errors() {
        let api = api();
        let unknown = api.handle(
            &ApiRequest::new("DELETE", "/v1/scans", "").with_authorization("Bearer test-token_123"),
        );
        assert_eq!(unknown.status, 404);
        assert_eq!(body(&unknown)["error"]["code"], "not_found");

        let missing = api.handle(
            &ApiRequest::new("GET", "/v1/jobs/job-999", "")
                .with_authorization("Bearer test-token_123"),
        );
        assert_eq!(missing.status, 404);
        assert_eq!(body(&missing)["error"]["code"], "job_not_found");
    }
}
