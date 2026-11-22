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
use super::rate_limit::{RateLimitConfig, RateLimitDecision, RateLimiter};

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
    /// Response headers, as `(name, value)` pairs. Rate-limit fields contain
    /// counters only; the bearer token never appears here.
    pub headers: Vec<(String, String)>,
}

impl ApiResponse {
    fn with_rate_limit(mut self, decision: &RateLimitDecision) -> Self {
        self.headers = vec![
            ("RateLimit-Limit".to_string(), decision.limit.to_string()),
            (
                "RateLimit-Remaining".to_string(),
                decision.remaining.to_string(),
            ),
            (
                "RateLimit-Reset".to_string(),
                decision.reset_seconds.to_string(),
            ),
        ];
        if !decision.allowed {
            self.headers.push((
                "Retry-After".to_string(),
                decision.reset_seconds.to_string(),
            ));
        }
        self
    }
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
    rate_limit: Option<RateLimiter>,
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
            rate_limit: None,
        }
    }

    /// Enables a bounded per-token rate limit for this adapter.
    ///
    /// Rate limiting is opt-in; without this call the adapter enforces none.
    pub fn with_rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit = Some(RateLimiter::new(config));
        self
    }

    /// The backing job store.
    pub fn jobs(&self) -> &JobStore {
        &self.jobs
    }

    /// Handles one request. Authentication is checked before routing and
    /// before the rate limit, so only valid credentials consume a budget.
    pub fn handle(&self, request: &ApiRequest) -> ApiResponse {
        self.handle_at(request, SystemTime::now())
    }

    /// Handles one request at an explicit time; used by tests and schedulers
    /// that supply their own clock.
    pub fn handle_at(&self, request: &ApiRequest, now: SystemTime) -> ApiResponse {
        if let Err(error) = self.auth.authenticate(request.authorization.as_deref()) {
            return auth_response(error);
        }

        let Some(limiter) = &self.rate_limit else {
            return self.route(request);
        };
        // Authentication succeeded, so the header is a well-formed bearer value.
        let token = request
            .authorization
            .as_deref()
            .and_then(|header| header.split_once(' '))
            .map(|(_, token)| token)
            .unwrap_or_default();
        let decision = limiter.check(token, now);
        let response = if decision.allowed {
            self.route(request)
        } else {
            error_response(
                429,
                "rate_limited",
                "rate limit exceeded; retry after the current window resets",
            )
        };
        response.with_rate_limit(&decision)
    }

    fn route(&self, request: &ApiRequest) -> ApiResponse {
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
                headers: Vec::new(),
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
                headers: Vec::new(),
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
                headers: Vec::new(),
            };
        }
        ApiResponse {
            status: 202,
            body: json!({ "job_id": job.id, "status": status }).to_string(),
            headers: Vec::new(),
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
        headers: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

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

    fn limited(requests: u32, window_seconds: u64) -> ScanApi {
        api().with_rate_limit(RateLimitConfig::per_window(
            requests,
            Duration::from_secs(window_seconds),
        ))
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn handle_at(api: &ScanApi, body: &str, seconds: u64) -> ApiResponse {
        api.handle_at(
            &ApiRequest::new("POST", "/v1/scans", body).with_authorization("Bearer test-token_123"),
            at(seconds),
        )
    }

    fn header<'a>(response: &'a ApiResponse, name: &str) -> Option<&'a str> {
        response
            .headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn rate_limit_denies_a_burst_and_returns_standard_headers() {
        let api = limited(2, 60);
        let submission = r#"{"source":"x","file":"lib.rs"}"#;
        for remaining in ["1", "0"] {
            let response = handle_at(&api, submission, 0);
            assert_eq!(response.status, 202);
            assert_eq!(header(&response, "RateLimit-Limit"), Some("2"));
            assert_eq!(header(&response, "RateLimit-Remaining"), Some(remaining));
            assert_eq!(header(&response, "RateLimit-Reset"), Some("60"));
            assert_eq!(header(&response, "Retry-After"), None);
        }

        let denied = handle_at(&api, submission, 0);
        assert_eq!(denied.status, 429);
        assert_eq!(body(&denied)["error"]["code"], "rate_limited");
        assert_eq!(header(&denied, "RateLimit-Remaining"), Some("0"));
        assert_eq!(header(&denied, "Retry-After"), Some("60"));
        assert_eq!(api.jobs().len(), 2);
        for (name, value) in &denied.headers {
            assert!(!name.contains("test-token"));
            assert!(!value.contains("test-token"));
        }
    }

    #[test]
    fn rate_limit_refills_with_the_window_without_sleeping() {
        let api = limited(1, 10);
        let submission = r#"{"source":"x","file":"lib.rs"}"#;
        assert_eq!(handle_at(&api, submission, 0).status, 202);

        let denied = handle_at(&api, submission, 6);
        assert_eq!(denied.status, 429);
        assert_eq!(header(&denied, "RateLimit-Reset"), Some("4"));
        assert_eq!(header(&denied, "Retry-After"), Some("4"));

        let refilled = handle_at(&api, submission, 10);
        assert_eq!(refilled.status, 202);
        assert_eq!(header(&refilled, "RateLimit-Remaining"), Some("0"));
        assert_eq!(header(&refilled, "RateLimit-Reset"), Some("10"));
    }

    #[test]
    fn rate_limit_is_opt_in_and_authentication_does_not_consume_budget() {
        let plain = api();
        let response = submit(&plain, r#"{"source":"x","file":"lib.rs"}"#);
        assert!(response.headers.is_empty());

        let api = limited(1, 60);
        for _ in 0..5 {
            let unauthorized = api.handle(&ApiRequest::new("POST", "/v1/scans", "{}"));
            assert_eq!(unauthorized.status, 401);
            assert!(unauthorized.headers.is_empty());
        }
        assert_eq!(
            handle_at(&api, r#"{"source":"x","file":"lib.rs"}"#, 0).status,
            202
        );
        assert_eq!(
            handle_at(&api, r#"{"source":"x","file":"lib.rs"}"#, 0).status,
            429
        );
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
