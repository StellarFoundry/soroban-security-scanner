//! Deterministic OpenAPI 3.1.0 specification generator and validator (`#355`).
//!
//! Generates the machine-readable HTTP API contract directly from the route
//! table, excluding internal operator endpoints. The feature is offline,
//! bounded, and free of secrets: no network calls are made, no environment
//! variables or credentials are read, and internal routes (`/internal/*`,
//! `/_internal/*`, `/debug/*`, `/metrics`) are never emitted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::error::ScanError;
use crate::{TOOL_NAME, VERSION};

/// Supported OpenAPI specification version.
pub const OPENAPI_VERSION: &str = "3.1.0";

/// Maximum number of routes accepted by the generator.
pub const MAX_ROUTES: usize = 64;

/// Maximum length (in bytes) of a single route path.
pub const MAX_PATH_LEN: usize = 128;

/// Maximum size (in bytes) of the rendered OpenAPI JSON document.
pub const MAX_OPENAPI_BYTES: usize = 256 * 1024;

/// Maximum source files accepted in a single HTTP scan request payload.
pub const MAX_REQUEST_FILES: usize = 64;

/// Maximum UTF-8 byte length of a single source file in an HTTP scan request.
pub const MAX_REQUEST_FILE_BYTES: usize = 256 * 1024;

/// Secret-like substrings that must never appear in a generated OpenAPI document.
const FORBIDDEN_SECRET_PATTERNS: &[&str] = &[
    "ghp_",
    "github_pat_",
    "sk-",
    "AKIA",
    "-----BEGIN",
    "PRIVATE KEY",
    "secret_key",
    "client_secret",
];

/// HTTP method for an API route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl HttpMethod {
    /// Lowercase OpenAPI path-item key for this HTTP method.
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "get",
            HttpMethod::Post => "post",
            HttpMethod::Put => "put",
            HttpMethod::Delete => "delete",
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Path parameter metadata for a parameterized route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteParam {
    /// Parameter name matching `{name}` in the route path.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Regular expression constraining the parameter value.
    pub pattern: String,
}

/// Definition of an implemented HTTP endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiRoute {
    /// HTTP verb.
    pub method: HttpMethod,
    /// URL path template (for example `/v1/jobs/{job_id}`).
    pub path: String,
    /// Unique OpenAPI `operationId`.
    pub operation_id: String,
    /// Logical OpenAPI tag grouping related operations.
    pub tag: String,
    /// Short summary of the endpoint.
    pub summary: String,
    /// Detailed behavioral description.
    pub description: String,
    /// Whether the endpoint requires bearer token authentication.
    pub authenticated: bool,
    /// Whether the endpoint is internal-only and must be omitted from OpenAPI.
    pub internal: bool,
    /// Path parameters required by the route template.
    pub path_params: Vec<RouteParam>,
    /// Component schema name for the JSON request body, if any.
    pub request_schema: Option<String>,
    /// Primary HTTP success status code (`200` or `202`).
    pub response_status: u16,
    /// Component schema name for the primary JSON response body.
    pub response_schema: String,
}

/// Returns `true` when `path` is reserved for internal operator endpoints.
pub fn is_internal_path(path: &str) -> bool {
    let normalized = path.trim();
    normalized == "/internal"
        || normalized.starts_with("/internal/")
        || normalized == "/_internal"
        || normalized.starts_with("/_internal/")
        || normalized == "/debug"
        || normalized.starts_with("/debug/")
        || normalized == "/metrics"
        || normalized.starts_with("/metrics/")
}

/// Returns the complete route table implemented by the scanner API service,
/// including internal endpoints that are filtered out during OpenAPI generation.
pub fn implemented_routes() -> Vec<ApiRoute> {
    vec![
        ApiRoute {
            method: HttpMethod::Get,
            path: "/v1/health".to_string(),
            operation_id: "getHealth".to_string(),
            tag: "system".to_string(),
            summary: "Check service health and scanner version".to_string(),
            description: "Returns service readiness and the deterministic scanner version. \
                Does not require authentication and performs no disk or network I/O."
                .to_string(),
            authenticated: false,
            internal: false,
            path_params: Vec::new(),
            request_schema: None,
            response_status: 200,
            response_schema: "HealthResponse".to_string(),
        },
        ApiRoute {
            method: HttpMethod::Post,
            path: "/v1/scan".to_string(),
            operation_id: "runScan".to_string(),
            tag: "scans".to_string(),
            summary: "Run a synchronous security scan".to_string(),
            description: "Analyzes a bounded set of in-memory Rust/Soroban source files \
                with the deterministic rule engine and returns a JSON report conforming \
                to the stable report schema. Scanned code is never compiled or executed."
                .to_string(),
            authenticated: true,
            internal: false,
            path_params: Vec::new(),
            request_schema: Some("ScanRequest".to_string()),
            response_status: 200,
            response_schema: "ScanReport".to_string(),
        },
        ApiRoute {
            method: HttpMethod::Post,
            path: "/v1/jobs".to_string(),
            operation_id: "submitScanJob".to_string(),
            tag: "jobs".to_string(),
            summary: "Submit an asynchronous scan job".to_string(),
            description: "Enqueues a bounded scan request in the job store and returns \
                a job identifier and initial status (`queued`). Rejects new submissions \
                with HTTP 503 when the bounded job store is at capacity."
                .to_string(),
            authenticated: true,
            internal: false,
            path_params: Vec::new(),
            request_schema: Some("ScanJobRequest".to_string()),
            response_status: 202,
            response_schema: "ScanJobStatus".to_string(),
        },
        ApiRoute {
            method: HttpMethod::Get,
            path: "/v1/jobs/{job_id}".to_string(),
            operation_id: "getScanJob".to_string(),
            tag: "jobs".to_string(),
            summary: "Get scan job status".to_string(),
            description: "Returns the current lifecycle status (`queued`, `running`, \
                `done`, or `failed`) and timestamps for a submitted scan job. Expired \
                or unknown jobs return HTTP 404."
                .to_string(),
            authenticated: true,
            internal: false,
            path_params: vec![RouteParam {
                name: "job_id".to_string(),
                description: "Bounded job identifier returned by `POST /v1/jobs`.".to_string(),
                pattern: "^[a-z0-9-]{8,64}$".to_string(),
            }],
            request_schema: None,
            response_status: 200,
            response_schema: "ScanJobStatus".to_string(),
        },
        ApiRoute {
            method: HttpMethod::Get,
            path: "/v1/jobs/{job_id}/report".to_string(),
            operation_id: "getScanJobReport".to_string(),
            tag: "jobs".to_string(),
            summary: "Fetch the report for a completed scan job".to_string(),
            description: "Returns the deterministic JSON scan report once the job reaches \
                the `done` state. Jobs that are still running, failed, or expired return \
                a structured `ApiError`."
                .to_string(),
            authenticated: true,
            internal: false,
            path_params: vec![RouteParam {
                name: "job_id".to_string(),
                description: "Bounded job identifier returned by `POST /v1/jobs`.".to_string(),
                pattern: "^[a-z0-9-]{8,64}$".to_string(),
            }],
            request_schema: None,
            response_status: 200,
            response_schema: "ScanReport".to_string(),
        },
        ApiRoute {
            method: HttpMethod::Get,
            path: "/v1/rules".to_string(),
            operation_id: "listRules".to_string(),
            tag: "rules".to_string(),
            summary: "List available security rules".to_string(),
            description: "Returns all registered security detectors ordered by rule ID, \
                including default severity, confidence, and category."
                .to_string(),
            authenticated: true,
            internal: false,
            path_params: Vec::new(),
            request_schema: None,
            response_status: 200,
            response_schema: "RuleListResponse".to_string(),
        },
        ApiRoute {
            method: HttpMethod::Get,
            path: "/v1/rules/{rule_id}".to_string(),
            operation_id: "getRule".to_string(),
            tag: "rules".to_string(),
            summary: "Explain a security rule by ID".to_string(),
            description: "Returns full rule metadata, description, remediation guidance, \
                and reference URLs for a single detector (`SS-###`)."
                .to_string(),
            authenticated: true,
            internal: false,
            path_params: vec![RouteParam {
                name: "rule_id".to_string(),
                description: "Stable rule identifier (for example `SS-001`).".to_string(),
                pattern: "^SS-[0-9]{3}$".to_string(),
            }],
            request_schema: None,
            response_status: 200,
            response_schema: "RuleDetail".to_string(),
        },
        // Internal operator routes — must always be excluded from public OpenAPI output.
        ApiRoute {
            method: HttpMethod::Get,
            path: "/internal/metrics".to_string(),
            operation_id: "internalMetrics".to_string(),
            tag: "internal".to_string(),
            summary: "Internal process metrics".to_string(),
            description: "Internal metrics scrape endpoint; excluded from public OpenAPI."
                .to_string(),
            authenticated: true,
            internal: true,
            path_params: Vec::new(),
            request_schema: None,
            response_status: 200,
            response_schema: "HealthResponse".to_string(),
        },
        ApiRoute {
            method: HttpMethod::Get,
            path: "/internal/debug/jobs".to_string(),
            operation_id: "internalDebugJobs".to_string(),
            tag: "internal".to_string(),
            summary: "Internal job store inspection".to_string(),
            description: "Internal job store diagnostic dump; excluded from public OpenAPI."
                .to_string(),
            authenticated: true,
            internal: true,
            path_params: Vec::new(),
            request_schema: None,
            response_status: 200,
            response_schema: "HealthResponse".to_string(),
        },
        ApiRoute {
            method: HttpMethod::Post,
            path: "/internal/gc".to_string(),
            operation_id: "internalTriggerGc".to_string(),
            tag: "internal".to_string(),
            summary: "Internal expired-job eviction trigger".to_string(),
            description: "Triggers immediate eviction of expired jobs; internal only.".to_string(),
            authenticated: true,
            internal: true,
            path_params: Vec::new(),
            request_schema: None,
            response_status: 200,
            response_schema: "HealthResponse".to_string(),
        },
    ]
}

/// Returns only the public (non-internal) routes from [`implemented_routes`].
pub fn public_routes() -> Vec<ApiRoute> {
    implemented_routes()
        .into_iter()
        .filter(|route| !route.internal && !is_internal_path(&route.path))
        .collect()
}

/// Extracts `{param}` placeholder names from a route path template.
fn extract_template_params(path: &str) -> Result<Vec<String>, ScanError> {
    let mut params = Vec::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return Err(ScanError::Config(format!(
                "unclosed path parameter in route '{path}'"
            )));
        };
        let name = after_open[..close].trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            return Err(ScanError::Config(format!(
                "invalid path parameter '{{{name}}}' in route '{path}'"
            )));
        }
        params.push(name.to_string());
        rest = &after_open[close + 1..];
    }
    if rest.contains('}') {
        return Err(ScanError::Config(format!(
            "unmatched '}}' in route '{path}'"
        )));
    }
    Ok(params)
}

/// Validates a single public route before adding it to the OpenAPI specification.
fn validate_public_route(route: &ApiRoute) -> Result<(), ScanError> {
    if route.path.is_empty() || !route.path.starts_with('/') {
        return Err(ScanError::Config(format!(
            "route path must start with '/': '{}'",
            route.path
        )));
    }
    if route.path.len() > MAX_PATH_LEN {
        return Err(ScanError::Config(format!(
            "route path exceeds maximum length of {MAX_PATH_LEN} bytes: '{}'",
            route.path
        )));
    }
    if route.operation_id.trim().is_empty() {
        return Err(ScanError::Config(format!(
            "route '{}' has an empty operation_id",
            route.path
        )));
    }
    if route.summary.trim().is_empty() || route.description.trim().is_empty() {
        return Err(ScanError::Config(format!(
            "route '{}' must have non-empty summary and description",
            route.path
        )));
    }
    if route.response_schema.trim().is_empty() {
        return Err(ScanError::Config(format!(
            "route '{}' must declare a response_schema",
            route.path
        )));
    }
    let placeholders = extract_template_params(&route.path)?;
    let declared: Vec<String> = route.path_params.iter().map(|p| p.name.clone()).collect();
    if placeholders != declared {
        return Err(ScanError::Config(format!(
            "route '{}' path parameters {placeholders:?} do not match declared parameters {declared:?}",
            route.path
        )));
    }
    Ok(())
}

/// Builds the OpenAPI 3.1.0 JSON document from the provided route table.
///
/// Internal routes (`route.internal == true` or `is_internal_path(&route.path)`)
/// are excluded automatically. The resulting document is deterministically
/// ordered and bounded in size.
pub fn generate_openapi_from_routes(routes: &[ApiRoute]) -> Result<Value, ScanError> {
    if routes.len() > MAX_ROUTES {
        return Err(ScanError::Config(format!(
            "route table has {} entries, exceeding limit of {MAX_ROUTES}",
            routes.len()
        )));
    }

    let public: Vec<&ApiRoute> = routes
        .iter()
        .filter(|route| !route.internal && !is_internal_path(&route.path))
        .collect();

    if public.is_empty() {
        return Err(ScanError::Config(
            "cannot generate OpenAPI specification from an empty public route set".to_string(),
        ));
    }

    let mut seen_ops = BTreeSet::new();
    let mut seen_methods = BTreeSet::new();
    let mut paths_map: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();

    for route in &public {
        validate_public_route(route)?;
        if !seen_ops.insert(route.operation_id.clone()) {
            return Err(ScanError::Config(format!(
                "duplicate operationId '{}' in route table",
                route.operation_id
            )));
        }
        if !seen_methods.insert((route.path.clone(), route.method)) {
            return Err(ScanError::Config(format!(
                "duplicate route '{} {}'",
                route.method, route.path
            )));
        }

        let operation = build_operation(route);
        paths_map
            .entry(route.path.clone())
            .or_default()
            .insert(route.method.as_str().to_string(), operation);
    }

    let mut paths_obj = Map::new();
    for (path, methods) in paths_map {
        let mut method_obj = Map::new();
        for (method, op) in methods {
            method_obj.insert(method, op);
        }
        paths_obj.insert(path, Value::Object(method_obj));
    }

    let doc = json!({
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": "Soroban Security Scanner HTTP API",
            "version": VERSION,
            "summary": "Opt-in, bounded HTTP API contract for deterministic Soroban security analysis.",
            "description": "Machine-readable OpenAPI 3.1.0 contract for the opt-in `soroban-scan` HTTP service. The service binds to loopback by default, enforces bearer authentication and per-token rate limits, caps payload and job-store sizes, never executes scanned code, and never exposes internal endpoints or secrets.",
            "contact": {
                "name": TOOL_NAME,
                "url": "https://github.com/AyinkxLab/soroban-security-scanner"
            },
            "license": {
                "name": "MIT",
                "identifier": "MIT"
            }
        },
        "servers": [
            {
                "url": "http://127.0.0.1:8080",
                "description": "Default local loopback listener (opt-in)"
            }
        ],
        "tags": [
            {
                "name": "system",
                "description": "Liveness and version metadata."
            },
            {
                "name": "scans",
                "description": "Synchronous, bounded in-memory security analysis."
            },
            {
                "name": "jobs",
                "description": "Asynchronous scan job submission, polling, and report retrieval."
            },
            {
                "name": "rules",
                "description": "Built-in security rule catalog and remediation details."
            }
        ],
        "paths": Value::Object(paths_obj),
        "components": build_components()
    });

    let serialized = serde_json::to_string_pretty(&doc)
        .map_err(|err| ScanError::Config(format!("failed to serialize OpenAPI JSON: {err}")))?;
    if serialized.len() > MAX_OPENAPI_BYTES {
        return Err(ScanError::Config(format!(
            "generated OpenAPI document ({} bytes) exceeds maximum size of {MAX_OPENAPI_BYTES} bytes",
            serialized.len()
        )));
    }

    Ok(doc)
}

/// Builds the OpenAPI 3.1.0 JSON document from [`implemented_routes`].
pub fn generate_openapi() -> Result<Value, ScanError> {
    generate_openapi_from_routes(&implemented_routes())
}

/// Renders the canonical pretty-printed OpenAPI 3.1.0 JSON document with a
/// trailing newline.
pub fn render_openapi_json() -> Result<String, ScanError> {
    let doc = generate_openapi()?;
    let mut text = serde_json::to_string_pretty(&doc)
        .map_err(|err| ScanError::Config(format!("failed to serialize OpenAPI JSON: {err}")))?;
    text.push('\n');
    Ok(text)
}

fn build_operation(route: &ApiRoute) -> Value {
    let mut op = Map::new();
    op.insert("operationId".to_string(), json!(route.operation_id));
    op.insert("tags".to_string(), json!([route.tag]));
    op.insert("summary".to_string(), json!(route.summary));
    op.insert("description".to_string(), json!(route.description));

    if route.authenticated {
        op.insert("security".to_string(), json!([{ "bearerAuth": [] }]));
    } else {
        op.insert("security".to_string(), json!([]));
    }

    if !route.path_params.is_empty() {
        let params: Vec<Value> = route
            .path_params
            .iter()
            .map(|param| {
                json!({
                    "name": param.name,
                    "in": "path",
                    "required": true,
                    "description": param.description,
                    "schema": {
                        "type": "string",
                        "pattern": param.pattern
                    }
                })
            })
            .collect();
        op.insert("parameters".to_string(), Value::Array(params));
    }

    if let Some(schema_name) = &route.request_schema {
        op.insert(
            "requestBody".to_string(),
            json!({
                "required": true,
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": format!("#/components/schemas/{schema_name}")
                        }
                    }
                }
            }),
        );
    }

    let mut responses = Map::new();
    let status_key = route.response_status.to_string();
    let success_description = match route.response_status {
        202 => "Scan job accepted and queued.",
        _ => "Successful response.",
    };
    responses.insert(
        status_key,
        json!({
            "description": success_description,
            "headers": {
                "X-RateLimit-Limit": {
                    "$ref": "#/components/headers/X-RateLimit-Limit"
                },
                "X-RateLimit-Remaining": {
                    "$ref": "#/components/headers/X-RateLimit-Remaining"
                },
                "X-RateLimit-Reset": {
                    "$ref": "#/components/headers/X-RateLimit-Reset"
                }
            },
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": format!("#/components/schemas/{}", route.response_schema)
                    }
                }
            }
        }),
    );

    responses.insert(
        "400".to_string(),
        json!({ "$ref": "#/components/responses/BadRequest" }),
    );
    if route.authenticated {
        responses.insert(
            "401".to_string(),
            json!({ "$ref": "#/components/responses/Unauthorized" }),
        );
    }
    if !route.path_params.is_empty() {
        responses.insert(
            "404".to_string(),
            json!({ "$ref": "#/components/responses/NotFound" }),
        );
    }
    if route.request_schema.is_some() {
        responses.insert(
            "413".to_string(),
            json!({ "$ref": "#/components/responses/PayloadTooLarge" }),
        );
    }
    responses.insert(
        "429".to_string(),
        json!({ "$ref": "#/components/responses/TooManyRequests" }),
    );
    responses.insert(
        "503".to_string(),
        json!({ "$ref": "#/components/responses/ServiceUnavailable" }),
    );

    op.insert("responses".to_string(), Value::Object(responses));
    Value::Object(op)
}

fn build_components() -> Value {
    json!({
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "description": "Opt-in bearer token configured by the operator. Compared in constant time and never logged or echoed."
            }
        },
        "headers": {
            "X-RateLimit-Limit": {
                "description": "Maximum requests permitted in the current rate-limit window.",
                "schema": { "type": "integer", "minimum": 1 }
            },
            "X-RateLimit-Remaining": {
                "description": "Remaining requests permitted in the current rate-limit window.",
                "schema": { "type": "integer", "minimum": 0 }
            },
            "X-RateLimit-Reset": {
                "description": "Seconds remaining until the rate-limit window resets.",
                "schema": { "type": "integer", "minimum": 0 }
            },
            "Retry-After": {
                "description": "Seconds the client should wait before retrying a rate-limited request.",
                "schema": { "type": "integer", "minimum": 1 }
            }
        },
        "responses": {
            "BadRequest": {
                "description": "The request payload or parameters failed validation.",
                "content": {
                    "application/json": {
                        "schema": { "$ref": "#/components/schemas/ApiError" }
                    }
                }
            },
            "Unauthorized": {
                "description": "Missing or invalid bearer authentication token.",
                "content": {
                    "application/json": {
                        "schema": { "$ref": "#/components/schemas/ApiError" }
                    }
                }
            },
            "NotFound": {
                "description": "The requested job or rule identifier does not exist or has expired.",
                "content": {
                    "application/json": {
                        "schema": { "$ref": "#/components/schemas/ApiError" }
                    }
                }
            },
            "PayloadTooLarge": {
                "description": "The submitted source payload exceeds the configured size or file-count limit.",
                "content": {
                    "application/json": {
                        "schema": { "$ref": "#/components/schemas/ApiError" }
                    }
                }
            },
            "TooManyRequests": {
                "description": "Per-token rate limit exceeded.",
                "headers": {
                    "Retry-After": {
                        "$ref": "#/components/headers/Retry-After"
                    },
                    "X-RateLimit-Limit": {
                        "$ref": "#/components/headers/X-RateLimit-Limit"
                    },
                    "X-RateLimit-Remaining": {
                        "$ref": "#/components/headers/X-RateLimit-Remaining"
                    },
                    "X-RateLimit-Reset": {
                        "$ref": "#/components/headers/X-RateLimit-Reset"
                    }
                },
                "content": {
                    "application/json": {
                        "schema": { "$ref": "#/components/schemas/ApiError" }
                    }
                }
            },
            "ServiceUnavailable": {
                "description": "The bounded job store is at capacity and cannot accept new work.",
                "content": {
                    "application/json": {
                        "schema": { "$ref": "#/components/schemas/ApiError" }
                    }
                }
            }
        },
        "schemas": {
            "ApiError": {
                "type": "object",
                "description": "Structured error response returned by all non-2xx endpoints.",
                "required": ["code", "message"],
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Stable machine-readable error code (for example `auth_required`, `rate_limited`, `store_full`, `invalid_request`)."
                    },
                    "message": {
                        "type": "string",
                        "description": "Human-readable error summary free of secrets and internal paths."
                    }
                },
                "additionalProperties": false
            },
            "HealthResponse": {
                "type": "object",
                "description": "Service liveness and version status.",
                "required": ["status", "tool", "version"],
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["ok"]
                    },
                    "tool": {
                        "type": "string",
                        "const": TOOL_NAME
                    },
                    "version": {
                        "type": "string",
                        "description": "Semantic version of the running scanner."
                    }
                },
                "additionalProperties": false
            },
            "SourceFileInput": {
                "type": "object",
                "description": "A single in-memory source file submitted for analysis.",
                "required": ["path", "content"],
                "properties": {
                    "path": {
                        "type": "string",
                        "maxLength": 256,
                        "description": "Root-relative file path using forward slashes (`src/lib.rs` or `Cargo.toml`). Must not contain `..` or leading slashes."
                    },
                    "content": {
                        "type": "string",
                        "maxLength": MAX_REQUEST_FILE_BYTES,
                        "description": "UTF-8 source or manifest text."
                    }
                },
                "additionalProperties": false
            },
            "ScanRequest": {
                "type": "object",
                "description": "Bounded synchronous scan request payload.",
                "required": ["files"],
                "properties": {
                    "files": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": MAX_REQUEST_FILES,
                        "items": { "$ref": "#/components/schemas/SourceFileInput" }
                    },
                    "min_severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"]
                    },
                    "min_confidence": {
                        "type": "string",
                        "enum": ["low", "medium", "high"]
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["soroban", "generic", "auto"]
                    },
                    "enabled_rules": {
                        "type": "array",
                        "maxItems": 64,
                        "items": {
                            "type": "string",
                            "pattern": "^SS-[0-9]{3}$"
                        }
                    },
                    "disabled_rules": {
                        "type": "array",
                        "maxItems": 64,
                        "items": {
                            "type": "string",
                            "pattern": "^SS-[0-9]{3}$"
                        }
                    },
                    "max_findings": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10000
                    }
                },
                "additionalProperties": false
            },
            "ScanJobRequest": {
                "type": "object",
                "description": "Bounded asynchronous scan job submission payload.",
                "required": ["scan"],
                "properties": {
                    "scan": { "$ref": "#/components/schemas/ScanRequest" },
                    "ttl_seconds": {
                        "type": "integer",
                        "minimum": 60,
                        "maximum": 86400,
                        "description": "Optional retention TTL in seconds for the completed job record (bounded by the server maximum)."
                    }
                },
                "additionalProperties": false
            },
            "ScanJobStatus": {
                "type": "object",
                "description": "Lifecycle state of an asynchronous scan job.",
                "required": ["job_id", "status", "created_at", "expires_at"],
                "properties": {
                    "job_id": {
                        "type": "string",
                        "pattern": "^[a-z0-9-]{8,64}$"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["queued", "running", "done", "failed"]
                    },
                    "created_at": {
                        "type": "string",
                        "description": "UTC creation timestamp (`YYYY-MM-DDTHH:MM:SSZ`)."
                    },
                    "expires_at": {
                        "type": "string",
                        "description": "UTC expiration timestamp (`YYYY-MM-DDTHH:MM:SSZ`) after which the job is evicted."
                    },
                    "error": {
                        "type": ["string", "null"],
                        "description": "Failure summary when `status` is `failed`."
                    }
                },
                "additionalProperties": false
            },
            "SourceLocation": {
                "type": "object",
                "description": "1-based source location relative to the scan root.",
                "required": ["file", "line"],
                "properties": {
                    "file": { "type": "string" },
                    "line": { "type": "integer", "minimum": 1 },
                    "column": { "type": "integer", "minimum": 1 },
                    "end_line": { "type": "integer", "minimum": 1 },
                    "end_column": { "type": "integer", "minimum": 1 }
                },
                "additionalProperties": true
            },
            "Finding": {
                "type": "object",
                "description": "A deterministic, evidence-backed security finding matching `docs/integration/report.schema.json`.",
                "required": [
                    "rule_id",
                    "title",
                    "description",
                    "severity",
                    "confidence",
                    "category",
                    "location",
                    "evidence",
                    "remediation",
                    "references",
                    "fingerprint"
                ],
                "properties": {
                    "rule_id": { "type": "string", "pattern": "^SS-[0-9]{3}$" },
                    "title": { "type": "string" },
                    "description": { "type": "string" },
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"]
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["low", "medium", "high"]
                    },
                    "category": { "type": "string" },
                    "location": { "$ref": "#/components/schemas/SourceLocation" },
                    "evidence": { "type": "string" },
                    "remediation": { "type": "string" },
                    "references": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "fingerprint": { "type": "string" }
                },
                "additionalProperties": true
            },
            "Diagnostic": {
                "type": "object",
                "description": "Structured diagnostic message emitted during discovery or parsing.",
                "required": ["level", "message"],
                "properties": {
                    "level": { "type": "string" },
                    "message": { "type": "string" },
                    "path": { "type": ["string", "null"] },
                    "line": { "type": ["integer", "null"] }
                },
                "additionalProperties": true
            },
            "ScanReport": {
                "type": "object",
                "description": "Machine-readable security report matching `docs/integration/report.schema.json` (`schema_version = \"1\"`).",
                "required": [
                    "schema_version",
                    "tool",
                    "project",
                    "stats",
                    "effective_config",
                    "findings",
                    "diagnostics"
                ],
                "properties": {
                    "schema_version": {
                        "type": "string",
                        "const": "1"
                    },
                    "tool": { "type": "object" },
                    "project": { "type": "object" },
                    "stats": { "type": "object" },
                    "effective_config": { "type": "object" },
                    "findings": {
                        "type": "array",
                        "items": { "$ref": "#/components/schemas/Finding" }
                    },
                    "diagnostics": {
                        "type": "array",
                        "items": { "$ref": "#/components/schemas/Diagnostic" }
                    }
                },
                "additionalProperties": true
            },
            "RuleDetail": {
                "type": "object",
                "description": "Metadata and remediation guidance for a security detector.",
                "required": [
                    "id",
                    "title",
                    "description",
                    "default_severity",
                    "default_confidence",
                    "category",
                    "remediation",
                    "references"
                ],
                "properties": {
                    "id": { "type": "string", "pattern": "^SS-[0-9]{3}$" },
                    "title": { "type": "string" },
                    "description": { "type": "string" },
                    "default_severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"]
                    },
                    "default_confidence": {
                        "type": "string",
                        "enum": ["low", "medium", "high"]
                    },
                    "category": { "type": "string" },
                    "remediation": { "type": "string" },
                    "references": {
                        "type": "array",
                        "items": { "type": "string" }
                    }
                },
                "additionalProperties": false
            },
            "RuleListResponse": {
                "type": "object",
                "description": "Catalog of registered security detectors.",
                "required": ["rules"],
                "properties": {
                    "rules": {
                        "type": "array",
                        "items": { "$ref": "#/components/schemas/RuleDetail" }
                    }
                },
                "additionalProperties": false
            }
        }
    })
}

/// Collects every `"$ref"` string in a JSON value tree.
fn collect_refs(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(reference)) = map.get("$ref") {
                out.push(reference.clone());
            }
            for child in map.values() {
                collect_refs(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_refs(item, out);
            }
        }
        _ => {}
    }
}

/// Resolves a local JSON pointer (`#/components/...`) inside `doc`.
fn resolve_pointer<'a>(doc: &'a Value, pointer: &str) -> Option<&'a Value> {
    let stripped = pointer.strip_prefix('#')?;
    doc.pointer(stripped)
}

/// Validates an OpenAPI JSON document against the specification rules and the
/// implemented route table.
///
/// Returns `Ok(())` when the document is valid, complete, free of internal
/// endpoints and secrets, and matches every non-internal route in `routes`.
pub fn validate_openapi(doc: &Value, routes: &[ApiRoute]) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    let serialized = match serde_json::to_string(doc) {
        Ok(text) => text,
        Err(err) => {
            return Err(vec![format!("failed to serialize document: {err}")]);
        }
    };

    if serialized.len() > MAX_OPENAPI_BYTES {
        errors.push(format!(
            "document size {} exceeds maximum of {MAX_OPENAPI_BYTES} bytes",
            serialized.len()
        ));
    }

    for pattern in FORBIDDEN_SECRET_PATTERNS {
        if serialized.contains(pattern) {
            errors.push(format!(
                "document contains forbidden secret-like pattern '{pattern}'"
            ));
        }
    }

    if doc.get("openapi").and_then(Value::as_str) != Some(OPENAPI_VERSION) {
        errors.push(format!(
            "expected openapi version '{OPENAPI_VERSION}', got {:?}",
            doc.get("openapi")
        ));
    }

    let info = doc.get("info").and_then(Value::as_object);
    match info {
        Some(info) => {
            for field in ["title", "version", "description"] {
                if info
                    .get(field)
                    .and_then(Value::as_str)
                    .is_none_or(|s| s.trim().is_empty())
                {
                    errors.push(format!("info.{field} must be a non-empty string"));
                }
            }
        }
        None => errors.push("missing top-level 'info' object".to_string()),
    }

    if doc
        .get("servers")
        .and_then(Value::as_array)
        .is_none_or(|servers| servers.is_empty())
    {
        errors.push("top-level 'servers' must be a non-empty array".to_string());
    }

    if doc.get("components").and_then(Value::as_object).is_none() {
        errors.push("missing top-level 'components' object".to_string());
    }

    let Some(paths) = doc.get("paths").and_then(Value::as_object) else {
        errors.push("missing top-level 'paths' object".to_string());
        return Err(errors);
    };

    // Check that no internal paths or routes marked internal appear in `paths`.
    for path_key in paths.keys() {
        if is_internal_path(path_key) {
            errors.push(format!(
                "internal endpoint '{path_key}' must not be included in OpenAPI paths"
            ));
        }
    }
    for route in routes.iter().filter(|r| r.internal) {
        if let Some(methods) = paths.get(&route.path).and_then(Value::as_object) {
            if methods.contains_key(route.method.as_str()) {
                errors.push(format!(
                    "internal route '{} {}' must not be included in OpenAPI paths",
                    route.method, route.path
                ));
            }
        }
    }

    // Check that expected public routes and documented operations match 1:1.
    let expected_public: Vec<&ApiRoute> = routes
        .iter()
        .filter(|r| !r.internal && !is_internal_path(&r.path))
        .collect();

    let mut expected_pairs = BTreeSet::new();
    for route in &expected_public {
        expected_pairs.insert((route.path.clone(), route.method.as_str().to_string()));
        let Some(path_item) = paths.get(&route.path).and_then(Value::as_object) else {
            errors.push(format!(
                "missing implemented public route path '{}' in OpenAPI document",
                route.path
            ));
            continue;
        };
        let Some(operation) = path_item
            .get(route.method.as_str())
            .and_then(Value::as_object)
        else {
            errors.push(format!(
                "missing HTTP method '{}' for path '{}' in OpenAPI document",
                route.method, route.path
            ));
            continue;
        };

        if operation.get("operationId").and_then(Value::as_str) != Some(route.operation_id.as_str())
        {
            errors.push(format!(
                "route '{} {}' operationId mismatch: expected '{}', got {:?}",
                route.method,
                route.path,
                route.operation_id,
                operation.get("operationId")
            ));
        }

        let Some(responses) = operation.get("responses").and_then(Value::as_object) else {
            errors.push(format!(
                "route '{} {}' is missing 'responses'",
                route.method, route.path
            ));
            continue;
        };
        let status_key = route.response_status.to_string();
        if !responses.contains_key(&status_key) {
            errors.push(format!(
                "route '{} {}' is missing expected response status {}",
                route.method, route.path, route.response_status
            ));
        }
    }

    for (path_key, path_val) in paths {
        let Some(path_item) = path_val.as_object() else {
            errors.push(format!("path '{path_key}' must be a JSON object"));
            continue;
        };
        for method_key in path_item.keys() {
            if !expected_pairs.contains(&(path_key.clone(), method_key.clone())) {
                errors.push(format!(
                    "OpenAPI document contains unimplemented route '{} {}'",
                    method_key, path_key
                ));
            }
        }
    }

    // Verify that every $ref pointer resolves cleanly inside the document.
    let mut refs = Vec::new();
    collect_refs(doc, &mut refs);
    for reference in refs {
        if !reference.starts_with("#/components/") || resolve_pointer(doc, &reference).is_none() {
            errors.push(format!("unresolved $ref pointer '{reference}'"));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_document_validates_against_implemented_routes() {
        let routes = implemented_routes();
        let doc = generate_openapi_from_routes(&routes).expect("OpenAPI generation must succeed");
        validate_openapi(&doc, &routes).expect("generated OpenAPI document must validate");
    }

    #[test]
    fn internal_endpoints_are_never_included() {
        let routes = implemented_routes();
        assert!(
            routes.iter().any(|r| r.internal),
            "route table must include internal endpoints to prove filtering"
        );
        let doc = generate_openapi_from_routes(&routes).unwrap();
        let paths = doc["paths"].as_object().unwrap();

        for path in paths.keys() {
            assert!(
                !is_internal_path(path),
                "internal path {path} leaked into OpenAPI document"
            );
        }
        assert!(!paths.contains_key("/internal/metrics"));
        assert!(!paths.contains_key("/internal/debug/jobs"));
        assert!(!paths.contains_key("/internal/gc"));
    }

    #[test]
    fn validator_rejects_leaked_internal_endpoint() {
        let routes = implemented_routes();
        let mut doc = generate_openapi_from_routes(&routes).unwrap();
        doc["paths"]["/internal/metrics"] = json!({
            "get": {
                "operationId": "internalMetrics",
                "responses": { "200": { "description": "ok" } }
            }
        });
        let errors = validate_openapi(&doc, &routes).unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("/internal/metrics")),
            "expected internal route error, got: {errors:?}"
        );
    }

    #[test]
    fn validator_detects_route_drift() {
        let mut routes = implemented_routes();
        let doc = generate_openapi_from_routes(&routes).unwrap();

        routes.push(ApiRoute {
            method: HttpMethod::Delete,
            path: "/v1/jobs/{job_id}".to_string(),
            operation_id: "cancelScanJob".to_string(),
            tag: "jobs".to_string(),
            summary: "Cancel a queued scan job".to_string(),
            description: "Cancels a scan job.".to_string(),
            authenticated: true,
            internal: false,
            path_params: vec![RouteParam {
                name: "job_id".to_string(),
                description: "Job ID.".to_string(),
                pattern: "^[a-z0-9-]{8,64}$".to_string(),
            }],
            request_schema: None,
            response_status: 200,
            response_schema: "ScanJobStatus".to_string(),
        });

        let errors = validate_openapi(&doc, &routes).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("missing HTTP method 'delete'")),
            "expected drift error for missing route, got: {errors:?}"
        );
    }

    #[test]
    fn validator_rejects_broken_schema_references_and_secrets() {
        let routes = implemented_routes();
        let mut doc = generate_openapi_from_routes(&routes).unwrap();
        doc["paths"]["/v1/health"]["get"]["description"] =
            json!("leaked token ghp_1234567890abcdef");
        doc["paths"]["/v1/health"]["get"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["$ref"] = json!("#/components/schemas/DoesNotExist");

        let errors = validate_openapi(&doc, &routes).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("ghp_")));
        assert!(errors.iter().any(|e| e.contains("DoesNotExist")));
    }

    #[test]
    fn output_is_deterministic_across_invocations() {
        let first = render_openapi_json().unwrap();
        let second = render_openapi_json().unwrap();
        assert_eq!(first, second);
    }
}
