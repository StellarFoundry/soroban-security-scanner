//! End-to-end tests for the in-process scan API adapter.
//!
//! The adapter performs no network I/O, so these tests need no server
//! credentials and no live GitHub or scan service.

use serde_json::{json, Value};
use soroban_scan_core::api_auth::ApiAuthConfig;
use soroban_scan_core::service::jobs::JobLimits;
use soroban_scan_core::service::{ApiRequest, ApiResponse, ScanApi};

const TOKEN: &str = "e2e-token_123";
const FIXTURE: &str = include_str!("../../../fixtures/must-trigger/SS-001.rs");

fn api(max_payload_bytes: usize) -> ScanApi {
    ScanApi::new(
        ApiAuthConfig {
            bearer_token: Some(TOKEN.to_string()),
        },
        JobLimits {
            max_jobs: 8,
            max_payload_bytes,
            ..JobLimits::default()
        },
    )
}

fn post(api: &ScanApi, body: &str) -> ApiResponse {
    api.handle(
        &ApiRequest::new("POST", "/v1/scans", body).with_authorization(format!("Bearer {TOKEN}")),
    )
}

fn get(api: &ScanApi, id: &str) -> ApiResponse {
    api.handle(
        &ApiRequest::new("GET", format!("/v1/jobs/{id}"), "")
            .with_authorization(format!("Bearer {TOKEN}")),
    )
}

fn body(response: &ApiResponse) -> Value {
    serde_json::from_str(&response.body)
        .unwrap_or_else(|error| panic!("invalid JSON {}: {error}", response.body))
}

#[test]
fn submit_poll_and_validate_a_fixture_report() {
    let api = api(JobLimits::default().max_payload_bytes);
    let submission = json!({ "source": FIXTURE, "file": "vault.rs" }).to_string();

    let accepted = post(&api, &submission);
    assert_eq!(accepted.status, 202);
    let accepted = body(&accepted);
    assert_eq!(accepted["status"], "queued");
    let id = accepted["job_id"].as_str().expect("job id").to_string();

    let queued = get(&api, &id);
    assert_eq!(queued.status, 202);
    assert_eq!(body(&queued)["status"], "queued");

    assert_eq!(api.run_next().unwrap().as_deref(), Some(id.as_str()));

    let completed = get(&api, &id);
    assert_eq!(completed.status, 200);
    let completed = body(&completed);
    assert_eq!(completed["status"], "completed");
    assert_eq!(completed["job_id"], id);

    let report = &completed["report"];
    assert_eq!(report["schema_version"], "1");
    let findings = report["findings"].as_array().expect("findings array");
    assert!(
        !findings.is_empty(),
        "the SS-001 fixture must report findings"
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding["rule_id"] == "SS-001"),
        "expected SS-001 in {findings:?}"
    );
    assert!(report["project"].is_object());
}

#[test]
fn missing_and_wrong_credentials_are_rejected() {
    for header in [None, Some("Bearer wrong-token")] {
        let mut request = ApiRequest::new("POST", "/v1/scans", "{}");
        request.authorization = header.map(str::to_string);
        let response = api(1024).handle(&request);
        assert_eq!(response.status, 401);
        let response = body(&response);
        assert_eq!(response["error"]["code"], "unauthorized");
        assert!(!response.to_string().contains(TOKEN));
    }
}

#[test]
fn oversized_input_is_rejected_without_creating_a_job() {
    let api = api(64);
    let response = post(&api, &"x".repeat(65));
    assert_eq!(response.status, 413);
    assert_eq!(body(&response)["error"]["code"], "payload_too_large");
    assert!(api.jobs().is_empty());

    let source = "x".repeat(65);
    let submission = json!({ "source": source, "file": "lib.rs" }).to_string();
    let response = post(&api, &submission);
    assert_eq!(response.status, 413);
    assert_eq!(body(&response)["error"]["code"], "payload_too_large");
    assert!(api.jobs().is_empty());
}
