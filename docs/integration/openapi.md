# OpenAPI contract generation

This page documents the machine-readable OpenAPI 3.1.0 contract for the opt-in
`soroban-scan` HTTP service (`#355`).

The published specification lives at [`openapi.json`](openapi.json) alongside
[`report.schema.json`](report.schema.json) and the
[Observatory integration contract](observatory.md).

## Route-driven generation

The OpenAPI document is generated deterministically from the route table in
`soroban_scan_core::openapi::implemented_routes()` rather than maintained by
hand. Every public route declares its HTTP method, path template, `operationId`,
tag, authentication requirement, path parameters, request body schema, and
response schema:

| Method | Path | `operationId` | Auth | Summary |
| ------ | ---- | ------------- | ---- | ------- |
| `GET` | `/v1/health` | `getHealth` | No | Check service health and scanner version. |
| `POST` | `/v1/scan` | `runScan` | Bearer | Run a synchronous, bounded security scan. |
| `POST` | `/v1/jobs` | `submitScanJob` | Bearer | Submit an asynchronous scan job (`202 Accepted`). |
| `GET` | `/v1/jobs/{job_id}` | `getScanJob` | Bearer | Poll scan job status (`queued`, `running`, `done`, `failed`). |
| `GET` | `/v1/jobs/{job_id}/report` | `getScanJobReport` | Bearer | Fetch the report for a completed scan job. |
| `GET` | `/v1/rules` | `listRules` | Bearer | List all registered security rules. |
| `GET` | `/v1/rules/{rule_id}` | `getRule` | Bearer | Explain a security rule by ID (`SS-###`). |

## Internal endpoint exclusion

Internal operator routes (such as `/internal/metrics`, `/internal/debug/jobs`,
and `/internal/gc`, as well as any `/internal/*`, `/_internal/*`, `/debug/*`, or
`/metrics/*` path) are marked `internal: true` in the route table and are
**never** emitted in the generated OpenAPI specification. Both the Rust
validator (`soroban_scan_core::openapi::validate_openapi`) and the Python CI
validator (`tools/check_openapi.py`) fail if an internal route ever appears in
`paths`.

## Generating and checking the contract

Generate the specification to stdout or write it to disk with the CLI:

```bash
# Print the OpenAPI 3.1.0 JSON contract to stdout
soroban-scan openapi

# Regenerate the committed specification
soroban-scan openapi --output docs/integration/openapi.json

# Verify that a specification validates and has not drifted from the route table
soroban-scan openapi --check docs/integration/openapi.json
```

You can also refresh the committed artifact via the integration test snapshot
workflow:

```bash
UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test openapi_contract
```

## CI validation, drift check, and artifact publication

CI enforces three checks on every push and pull request:

1. **Rust contract & drift test** (`crates/soroban-scan-core/tests/openapi_contract.rs`
   and `crates/soroban-scan-cli/tests/cli.rs`): compares the committed
   [`docs/integration/openapi.json`](openapi.json) byte-for-byte with
   `render_openapi_json()`, verifies that all `$ref` pointers resolve, confirms
   internal routes are excluded, and checks alignment with
   [`report.schema.json`](report.schema.json).
2. **CLI & Python validation** (`soroban-scan openapi --check` and
   `python tools/check_openapi.py`): validates the committed contract in CI.
3. **Artifact upload**: the `openapi` job in `.github/workflows/ci.yml` uploads
   `docs/integration/openapi.json` as the `openapi-spec` workflow artifact for
   downstream SDK generators and API consumers.

## Security considerations

- **Opt-in:** generating or validating the OpenAPI contract is an explicit CLI
  or library action and performs no network I/O.
- **Bounded:** the route table (`MAX_ROUTES = 64`), path length
  (`MAX_PATH_LEN = 128`), request payload schemas (`MAX_REQUEST_FILES = 64`,
  `MAX_REQUEST_FILE_BYTES = 256 KiB`), and rendered specification size
  (`MAX_OPENAPI_BYTES = 256 KiB`) are strictly capped.
- **Free of secrets:** no environment variables, tokens, credentials, or host
  paths are read during generation, and validation rejects documents containing
  secret-like patterns.
