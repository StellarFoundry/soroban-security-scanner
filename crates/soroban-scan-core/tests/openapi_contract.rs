//! OpenAPI 3.1.0 contract generation, validation, and CI drift checks (`#355`).
//!
//! Ensures `docs/integration/openapi.json` stays byte-for-byte in sync with the
//! route table in `soroban_scan_core::openapi`, validates structurally, excludes
//! internal endpoints, and aligns with `docs/integration/report.schema.json`.
//!
//! Update procedure when a public route changes:
//!
//! ```text
//! UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test openapi_contract
//! ```

use std::path::PathBuf;

use serde_json::Value;

use soroban_scan_core::openapi::{
    generate_openapi_from_routes, implemented_routes, is_internal_path, public_routes,
    render_openapi_json, validate_openapi,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn openapi_path() -> PathBuf {
    repo_root().join("docs/integration/openapi.json")
}

#[test]
fn openapi_document_matches_committed_artifact() {
    let path = openapi_path();
    let generated = render_openapi_json()
        .expect("OpenAPI JSON must render")
        .replace("\r\n", "\n");

    if std::env::var("UPDATE_SNAPSHOTS").as_deref() == Ok("1") {
        std::fs::write(&path, generated.as_bytes())
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
        return;
    }

    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| {
            panic!(
                "missing OpenAPI artifact {}: {error}\n\
                 Generate it with `soroban-scan openapi --output docs/integration/openapi.json`",
                path.display()
            )
        })
        .replace("\r\n", "\n");

    assert_eq!(
        committed, generated,
        "docs/integration/openapi.json has drifted from implemented_routes(). \
         Regenerate with `soroban-scan openapi --output docs/integration/openapi.json`."
    );
}

#[test]
fn openapi_document_validates_and_matches_public_routes() {
    let routes = implemented_routes();
    let public = public_routes();
    assert!(!public.is_empty());
    assert!(
        routes.len() > public.len(),
        "implemented_routes must contain internal endpoints to verify exclusion"
    );

    let doc = generate_openapi_from_routes(&routes).expect("OpenAPI generation must succeed");
    validate_openapi(&doc, &routes).expect("OpenAPI document must validate");

    let paths = doc["paths"].as_object().expect("paths must be an object");
    for route in &public {
        let item = paths
            .get(&route.path)
            .unwrap_or_else(|| panic!("missing public path {}", route.path));
        assert!(
            item.get(route.method.as_str()).is_some(),
            "missing method {} on {}",
            route.method,
            route.path
        );
    }

    for route in routes.iter().filter(|r| r.internal) {
        assert!(
            !paths.contains_key(&route.path),
            "internal route {} must not appear in OpenAPI paths",
            route.path
        );
    }
    for key in paths.keys() {
        assert!(
            !is_internal_path(key),
            "internal path {key} must not appear in OpenAPI paths"
        );
    }
}

#[test]
fn openapi_report_schema_aligns_with_report_schema_json() {
    let report_schema_text =
        std::fs::read_to_string(repo_root().join("docs/integration/report.schema.json"))
            .expect("report.schema.json must exist");
    let report_schema: Value =
        serde_json::from_str(&report_schema_text).expect("report.schema.json must parse");

    let openapi_doc =
        generate_openapi_from_routes(&implemented_routes()).expect("OpenAPI must generate");

    let expected_top_required = report_schema["required"]
        .as_array()
        .expect("report.schema.json required array");
    let actual_top_required = openapi_doc["components"]["schemas"]["ScanReport"]["required"]
        .as_array()
        .expect("OpenAPI ScanReport required array");
    assert_eq!(actual_top_required, expected_top_required);

    let expected_finding_required = report_schema["properties"]["findings"]["items"]["required"]
        .as_array()
        .expect("report.schema.json Finding required array");
    let actual_finding_required = openapi_doc["components"]["schemas"]["Finding"]["required"]
        .as_array()
        .expect("OpenAPI Finding required array");
    assert_eq!(actual_finding_required, expected_finding_required);
}
