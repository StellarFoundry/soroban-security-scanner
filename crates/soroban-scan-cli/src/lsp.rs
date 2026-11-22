//! Minimal stdio language server.
//!
//! Implements the subset of LSP that `docs/editors.md` promises: full document
//! sync, diagnostics from the deterministic scanner, and document symbols.
//! JSON-RPC 2.0 framing is handled by hand with `serde_json`; there is no
//! network access and no extra dependency.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::model::DiagnosticCode;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::severity::Severity;
use soroban_scan_core::source::{self, ItemKind};

/// Reject oversized messages so a client cannot exhaust server memory.
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Configuration filename discovered at the workspace root.
const CONFIG_FILE: &str = "soroban-scan.toml";

/// Stable diagnostic source shown for both scan findings and config errors.
const SOURCE: &str = "soroban-scan";

/// Effective workspace configuration and the last reload error, if any.
struct WorkspaceConfig {
    config: ScanConfig,
    config_uri: Option<String>,
    error: Option<String>,
}

impl WorkspaceConfig {
    fn defaults() -> Self {
        WorkspaceConfig {
            config: ScanConfig::default(),
            config_uri: None,
            error: None,
        }
    }
}

/// LSP `SymbolKind` values used by the outline.
const SYMBOL_CLASS: u32 = 5;
const SYMBOL_FUNCTION: u32 = 12;
const SYMBOL_STRUCT: u32 = 23;
const SYMBOL_EVENT: u32 = 24;

/// Runs the language server until the client sends `exit`.
pub fn run(registry: &RuleRegistry) -> Result<u8, String> {
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    let mut documents: BTreeMap<String, String> = BTreeMap::new();
    let mut workspace_root: Option<PathBuf> = None;
    let mut workspace_config = WorkspaceConfig::defaults();
    let mut shutdown_requested = false;

    while let Some(message) = read_message(&mut reader)? {
        let id = message.get("id").cloned();
        let method = message.get("method").and_then(Value::as_str);
        let params = message.get("params").cloned().unwrap_or(Value::Null);

        match method {
            Some("initialize") => {
                workspace_root = workspace_root_from(&params);
                reload_workspace_config(&mut workspace_config, workspace_root.as_deref());
                respond(
                    &mut writer,
                    id,
                    json!({
                        "capabilities": {
                            "textDocumentSync": { "openClose": true, "change": 1 },
                            "documentSymbolProvider": true,
                            "hoverProvider": true
                        },
                        "serverInfo": {
                            "name": "soroban-scan",
                            "version": soroban_scan_core::VERSION
                        }
                    }),
                )?;
                publish_config_diagnostics(&mut writer, &workspace_config)?;
            }
            Some("initialized") => {}
            Some("shutdown") => {
                shutdown_requested = true;
                respond(&mut writer, id, Value::Null)?;
            }
            Some("exit") => break,
            Some("textDocument/didOpen") => {
                if let Some((uri, text)) = opened_document(&params) {
                    documents.insert(uri.clone(), text.clone());
                    publish_diagnostics(
                        &mut writer,
                        registry,
                        &workspace_config.config,
                        &uri,
                        &text,
                    )?;
                }
            }
            Some("textDocument/didChange") => {
                let uri = params
                    .pointer("/textDocument/uri")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if let Some(text) = changed_text(&params) {
                    documents.insert(uri.clone(), text.clone());
                    publish_diagnostics(
                        &mut writer,
                        registry,
                        &workspace_config.config,
                        &uri,
                        &text,
                    )?;
                }
            }
            Some("textDocument/didSave") => {
                if let Some(uri) = params.pointer("/textDocument/uri").and_then(Value::as_str) {
                    if let Some(text) = documents.get(uri) {
                        publish_diagnostics(
                            &mut writer,
                            registry,
                            &workspace_config.config,
                            uri,
                            text,
                        )?;
                    }
                }
            }
            Some("textDocument/didClose") => {
                if let Some(uri) = params.pointer("/textDocument/uri").and_then(Value::as_str) {
                    documents.remove(uri);
                    let notification = json!({
                        "jsonrpc": "2.0",
                        "method": "textDocument/publishDiagnostics",
                        "params": { "uri": uri, "diagnostics": [] }
                    });
                    send(&mut writer, &notification)?;
                }
            }
            Some("workspace/didChangeConfiguration") | Some("workspace/didChangeWatchedFiles") => {
                reload_and_republish(
                    &mut writer,
                    registry,
                    workspace_root.as_deref(),
                    &mut workspace_config,
                    &documents,
                )?;
            }
            Some("textDocument/documentSymbol") => {
                let result = params
                    .pointer("/textDocument/uri")
                    .and_then(Value::as_str)
                    .and_then(|uri| documents.get(uri))
                    .map(|text| document_symbols(text))
                    .unwrap_or_else(|| json!([]));
                respond(&mut writer, id, result)?;
            }
            Some("textDocument/hover") => {
                let result = params
                    .pointer("/textDocument/uri")
                    .and_then(Value::as_str)
                    .and_then(|uri| documents.get(uri))
                    .and_then(|text| {
                        let line = params.pointer("/position/line")?.as_u64()? as usize;
                        let character = params.pointer("/position/character")?.as_u64()? as usize;
                        hover(registry, text, line, character)
                    })
                    .unwrap_or(Value::Null);
                respond(&mut writer, id, result)?;
            }
            Some(_) if id.is_some() => {
                respond_error(&mut writer, id, -32601, "method not found")?;
            }
            Some(_) => {}
            None => {}
        }
    }

    // `exit` after `shutdown` is a clean stop; the process still returns 0 so a
    // client that simply closes the pipe is not reported as a crash.
    let _ = shutdown_requested;
    Ok(0)
}

/// Extracts the first workspace folder URI, falling back to `rootUri`.
fn workspace_root_from(params: &Value) -> Option<PathBuf> {
    let uri = params
        .get("workspaceFolders")
        .and_then(Value::as_array)
        .and_then(|folders| folders.first())
        .and_then(|folder| folder.get("uri"))
        .and_then(Value::as_str)
        .or_else(|| params.get("rootUri").and_then(Value::as_str))?;
    uri_to_path(uri)
}

/// Reloads `soroban-scan.toml` from the workspace root, replacing the effective
/// configuration only when the file parses.
fn reload_workspace_config(state: &mut WorkspaceConfig, root: Option<&Path>) {
    let Some(root) = root else {
        state.config = ScanConfig::default();
        state.config_uri = None;
        state.error = None;
        return;
    };

    let path = root.join(CONFIG_FILE);
    state.config_uri = Some(path_to_uri(&path));
    if !path.is_file() {
        state.config = ScanConfig::default();
        state.error = None;
        return;
    }

    match std::fs::read_to_string(&path) {
        Ok(text) => match ScanConfig::from_toml(&text) {
            Ok(config) => {
                state.config = config;
                state.error = None;
            }
            Err(error) => {
                state.error = Some(format!("invalid configuration {}: {error}", path.display()));
            }
        },
        Err(error) => {
            state.error = Some(format!(
                "cannot read configuration {}: {error}",
                path.display()
            ));
        }
    }
}

/// Publishes (or clears) the configuration diagnostic at the config file URI.
fn publish_config_diagnostics<W: Write>(
    writer: &mut W,
    state: &WorkspaceConfig,
) -> Result<(), String> {
    let Some(uri) = &state.config_uri else {
        return Ok(());
    };
    let diagnostics = match &state.error {
        Some(message) => vec![json!({
            "range": range_raw(1, 1, 1, 1),
            "severity": 1,
            "code": "LSP-CONFIG-001",
            "source": SOURCE,
            "message": message
        })],
        None => Vec::new(),
    };
    send(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": { "uri": uri, "diagnostics": diagnostics }
        }),
    )
}

/// Reloads configuration and refreshes diagnostics for every open document.
fn reload_and_republish<W: Write>(
    writer: &mut W,
    registry: &RuleRegistry,
    root: Option<&Path>,
    state: &mut WorkspaceConfig,
    documents: &BTreeMap<String, String>,
) -> Result<(), String> {
    reload_workspace_config(state, root);
    publish_config_diagnostics(writer, state)?;
    for (uri, text) in documents {
        publish_diagnostics(writer, registry, &state.config, uri, text)?;
    }
    Ok(())
}

/// Converts a `file:` URI to a filesystem path.
fn uri_to_path(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    let decoded = percent_decode(rest);
    let path = if decoded.len() >= 3
        && decoded.starts_with('/')
        && decoded.as_bytes()[1].is_ascii_alphabetic()
        && decoded.as_bytes()[2] == b':'
    {
        &decoded[1..]
    } else {
        decoded.as_str()
    };
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// Converts a filesystem path to a `file:` URI with percent-encoded bytes.
fn path_to_uri(path: &Path) -> String {
    let mut text = path.to_string_lossy().replace('\\', "/");
    if !text.starts_with('/') {
        text.insert(0, '/');
    }
    let mut encoded = String::from("file://");
    for byte in text.bytes() {
        let keep =
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/' | b':');
        if keep {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// Decodes `%XX` escapes in a URI path; invalid escapes are kept literally.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = (bytes[index + 1] as char).to_digit(16);
            let low = (bytes[index + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                decoded.push((high * 16 + low) as u8);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn opened_document(params: &Value) -> Option<(String, String)> {
    let uri = params.pointer("/textDocument/uri")?.as_str()?.to_string();
    let text = params.pointer("/textDocument/text")?.as_str()?.to_string();
    Some((uri, text))
}

fn changed_text(params: &Value) -> Option<String> {
    params
        .pointer("/contentChanges")?
        .as_array()?
        .last()?
        .get("text")?
        .as_str()
        .map(str::to_string)
}

fn read_message<R: BufRead>(reader: &mut R) -> Result<Option<Value>, String> {
    let mut content_length = None;
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|error| format!("cannot read LSP header: {error}"))?;
        if read == 0 {
            return Ok(None);
        }
        let header = line.trim_end_matches(['\r', '\n']);
        if header.is_empty() {
            break;
        }
        if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = value.trim().parse::<usize>().ok();
        }
    }

    let length = content_length.ok_or_else(|| "missing Content-Length header".to_string())?;
    if length > MAX_MESSAGE_BYTES {
        return Err(format!(
            "LSP message is too large ({length} bytes; limit {MAX_MESSAGE_BYTES})"
        ));
    }
    let mut body = vec![0u8; length];
    reader
        .read_exact(&mut body)
        .map_err(|error| format!("cannot read LSP body: {error}"))?;
    let message =
        serde_json::from_slice(&body).map_err(|error| format!("invalid LSP JSON: {error}"))?;
    Ok(Some(message))
}

fn send<W: Write>(writer: &mut W, message: &Value) -> Result<(), String> {
    let body = serde_json::to_vec(message)
        .map_err(|error| format!("cannot serialize LSP message: {error}"))?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())
        .and_then(|_| writer.write_all(&body))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("cannot write LSP message: {error}"))
}

fn respond<W: Write>(writer: &mut W, id: Option<Value>, result: Value) -> Result<(), String> {
    send(
        writer,
        &json!({ "jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "result": result }),
    )
}

fn respond_error<W: Write>(
    writer: &mut W,
    id: Option<Value>,
    code: i64,
    message: &str,
) -> Result<(), String> {
    send(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "id": id.unwrap_or(Value::Null),
            "error": { "code": code, "message": message }
        }),
    )
}

fn publish_diagnostics<W: Write>(
    writer: &mut W,
    registry: &RuleRegistry,
    config: &ScanConfig,
    uri: &str,
    text: &str,
) -> Result<(), String> {
    let diagnostics = diagnostics_for(registry, config, uri, text);
    send(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": { "uri": uri, "diagnostics": diagnostics }
        }),
    )
}

fn diagnostics_for(
    registry: &RuleRegistry,
    config: &ScanConfig,
    uri: &str,
    text: &str,
) -> Vec<Value> {
    let name = document_name(uri);
    let outcome = engine::scan_source_str(text, &name, config, registry);
    let mut diagnostics = Vec::new();

    for finding in &outcome.findings {
        let line = finding.location.line;
        let column = finding.location.column.unwrap_or(1);
        let end_line = finding.location.end_line.unwrap_or(line);
        let end_column = match finding.location.end_column {
            Some(column) => column,
            None if end_line == line => column + 1,
            None => 1,
        };
        diagnostics.push(json!({
            "range": range_raw(line, column, end_line, end_column),
            "severity": match finding.severity {
                Severity::Critical | Severity::High => 1,
                Severity::Medium => 2,
                Severity::Low => 3,
                Severity::Info => 4,
            },
            "code": finding.rule_id,
            "source": SOURCE,
            "message": format!("{}: {}", finding.title, finding.evidence),
            "data": { "fingerprint": finding.fingerprint }
        }));
    }

    for diagnostic in &outcome.diagnostics {
        if diagnostic.code != DiagnosticCode::ParseFailed {
            continue;
        }
        diagnostics.push(json!({
            "range": range_raw(1, 1, 1, 1),
            "severity": 1,
            "code": diagnostic.code.as_str(),
            "source": SOURCE,
            "message": diagnostic.message
        }));
    }

    diagnostics
}

/// Returns hover content for the rule id under the cursor, or `None`.
///
/// Rule metadata comes from the in-process registry, so hover works offline and
/// never reads a file or fetches documentation.
fn hover(registry: &RuleRegistry, text: &str, line: usize, character: usize) -> Option<Value> {
    let line_text = text.lines().nth(line)?;
    let (start, end, id) = find_rule_ids(line_text)
        .into_iter()
        .find(|(start, end, _)| character >= *start && character < *end)?;
    Some(json!({
        "contents": {
            "kind": "markdown",
            "value": hover_text(registry, &id)
        },
        "range": {
            "start": { "line": line, "character": start },
            "end": { "line": line, "character": end }
        }
    }))
}

fn hover_text(registry: &RuleRegistry, id: &str) -> String {
    let normalized = id.to_ascii_uppercase();
    let Some(rule) = registry.by_id(&normalized) else {
        return format!(
            "### {normalized}\n\nNo rule with this id is registered. \
             Run `soroban-scan rules` to list the shipped rule ids."
        );
    };
    let meta = rule.metadata();
    format!(
        "### {} — {}\n\n**Severity:** {}  \n**Confidence:** {}  \n**Category:** {}\n\n{}\n\n**Remediation:** {}",
        meta.id,
        meta.title,
        meta.default_severity.as_str(),
        meta.default_confidence.as_str(),
        meta.category.as_str(),
        meta.description,
        meta.remediation
    )
}

/// Finds `SS-###` tokens and their character offsets on one line.
fn find_rule_ids(line: &str) -> Vec<(usize, usize, String)> {
    const PREFIX: &[char] = &['S', 'S', '-'];
    let chars: Vec<char> = line.chars().collect();
    let mut found = Vec::new();
    let mut index = 0;
    while index + 6 <= chars.len() {
        let prefix_matches = PREFIX
            .iter()
            .zip(&chars[index..])
            .all(|(expected, actual)| expected.eq_ignore_ascii_case(actual));
        let boundary_before = index == 0 || !chars[index - 1].is_ascii_alphanumeric();
        let digits = &chars[index + 3..index + 6];
        let boundary_after = index + 6 == chars.len() || !chars[index + 6].is_ascii_alphanumeric();
        if prefix_matches
            && boundary_before
            && boundary_after
            && digits.iter().all(char::is_ascii_digit)
        {
            found.push((
                index,
                index + 6,
                chars[index..index + 6].iter().collect::<String>(),
            ));
            index += 6;
        } else {
            index += 1;
        }
    }
    found
}

/// Returns a JSON document-symbol array for one source text.
fn document_symbols(text: &str) -> Value {
    let parsed = source::parse_source(Path::new("document.rs"), Path::new("."), text);
    let mut contracts: BTreeMap<String, Value> = BTreeMap::new();
    let mut children: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut top_level: Vec<Value> = Vec::new();
    let mut contract_structs: BTreeSet<String> = BTreeSet::new();

    for item in &parsed.items {
        let is_contract = item.kind == ItemKind::Struct && has_attribute(item, "contract");
        let is_impl = item.kind == ItemKind::Impl && has_attribute(item, "contractimpl");
        if is_contract || is_impl {
            if is_contract {
                contract_structs.insert(item.name.clone());
            }
            contracts.entry(item.name.clone()).or_insert_with(|| {
                symbol_json(
                    &item.name,
                    SYMBOL_CLASS,
                    text,
                    item.line,
                    item.column,
                    item.end_line,
                )
            });
        }
    }

    for function in &parsed.functions {
        let symbol = symbol_json(
            function
                .in_impl
                .as_ref()
                .map_or(function.qualified_name.as_str(), |_| function.name.as_str()),
            SYMBOL_FUNCTION,
            text,
            function.line,
            function.column,
            function.end_line,
        );
        match function
            .in_impl
            .as_ref()
            .filter(|parent| contracts.contains_key(*parent))
        {
            Some(parent) => children.entry(parent.clone()).or_default().push(symbol),
            None => top_level.push(symbol),
        }
    }

    for item in &parsed.items {
        if !matches!(item.kind, ItemKind::Struct | ItemKind::Enum) {
            continue;
        }
        if contract_structs.contains(&item.name) {
            continue;
        }
        let kind = if has_attribute(item, "contractevent") {
            SYMBOL_EVENT
        } else {
            SYMBOL_STRUCT
        };
        top_level.push(symbol_json(
            &item.name,
            kind,
            text,
            item.line,
            item.column,
            item.end_line,
        ));
    }

    for (name, mut symbol) in contracts {
        let mut children = children.remove(&name).unwrap_or_default();
        sort_symbols(&mut children);
        symbol["children"] = Value::Array(children);
        top_level.push(symbol);
    }
    sort_symbols(&mut top_level);
    Value::Array(top_level)
}

fn has_attribute(item: &source::ItemSummary, name: &str) -> bool {
    item.attributes.iter().any(|attribute| attribute == name)
}

fn sort_symbols(symbols: &mut [Value]) {
    symbols.sort_by(|left, right| {
        let left_start = &left["range"]["start"];
        let right_start = &right["range"]["start"];
        let left_line = left_start["line"].as_u64().unwrap_or(0);
        let right_line = right_start["line"].as_u64().unwrap_or(0);
        left_line
            .cmp(&right_line)
            .then_with(|| {
                left_start["character"]
                    .as_u64()
                    .unwrap_or(0)
                    .cmp(&right_start["character"].as_u64().unwrap_or(0))
            })
            .then_with(|| left["name"].as_str().cmp(&right["name"].as_str()))
    });
}

fn symbol_json(
    name: &str,
    kind: u32,
    text: &str,
    line: usize,
    column: usize,
    end_line: usize,
) -> Value {
    let start_line = line.max(1);
    let end_line = end_line.max(start_line);
    json!({
        "name": name,
        "kind": kind,
        "range": {
            "start": { "line": start_line - 1, "character": column.saturating_sub(1) },
            "end": { "line": end_line - 1, "character": line_length(text, end_line) }
        },
        "selectionRange": selection_range(text, start_line, column, name)
    })
}

/// LSP positions are UTF-16 code units; the Rust frontend reports 1-based
/// characters. For the ASCII identifiers these ranges cover they coincide.
fn line_length(text: &str, line: usize) -> usize {
    text.lines()
        .nth(line.saturating_sub(1))
        .map(|line| line.chars().count())
        .unwrap_or(0)
}

fn selection_range(text: &str, line: usize, column: usize, name: &str) -> Value {
    let start = column.saturating_sub(1);
    let line_text = text.lines().nth(line.saturating_sub(1)).unwrap_or_default();
    let chars: Vec<char> = line_text.chars().collect();
    let start = start.min(chars.len());
    let tail: String = chars[start..].iter().collect();
    let target = name.rsplit("::").next().unwrap_or(name);
    let offset = tail
        .find(target)
        .map(|byte| tail[..byte].chars().count())
        .unwrap_or(0);
    let end = if offset == 0 && !tail.starts_with(target) {
        chars.len()
    } else {
        (start + offset + target.chars().count()).min(chars.len())
    };
    json!({
        "start": { "line": line - 1, "character": start },
        "end": { "line": line - 1, "character": end }
    })
}

fn range_raw(line: usize, column: usize, end_line: usize, end_column: usize) -> Value {
    json!({
        "start": {
            "line": line.saturating_sub(1),
            "character": column.saturating_sub(1)
        },
        "end": {
            "line": end_line.saturating_sub(1),
            "character": end_column.saturating_sub(1)
        }
    })
}

fn document_name(uri: &str) -> String {
    uri.rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("document.rs")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbol_fixture() -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/lsp/symbols.rs"),
        )
        .expect("read document-symbol fixture")
    }

    fn symbol_snapshot_path() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/document-symbols.json")
    }

    #[test]
    fn document_symbols_match_snapshot() {
        let text = symbol_fixture();
        let actual = serde_json::to_string_pretty(&document_symbols(&text)).unwrap() + "\n";
        let path = symbol_snapshot_path();

        if std::env::var("UPDATE_SNAPSHOTS").as_deref() == Ok("1") {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, actual.as_bytes()).unwrap();
            return;
        }

        let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "missing snapshot {}: {error}\n\
                 Generate it with UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-cli document_symbols",
                path.display()
            )
        });
        assert_eq!(expected, actual);
    }

    #[test]
    fn hover_covers_every_registered_rule() {
        let registry = RuleRegistry::with_default_rules();
        for meta in registry.metadata() {
            let content = hover_text(&registry, meta.id);
            assert!(content.contains(meta.id), "missing id for {}", meta.id);
            assert!(
                content.contains(meta.default_severity.as_str()),
                "missing severity for {}",
                meta.id
            );
            assert!(
                content.contains(meta.default_confidence.as_str()),
                "missing confidence for {}",
                meta.id
            );
            assert!(
                content.contains(meta.remediation),
                "missing remediation for {}",
                meta.id
            );
        }
    }

    #[test]
    fn hover_finds_rule_id_at_cursor() {
        let registry = RuleRegistry::with_default_rules();
        let result = hover(&registry, "// see SS-001 for details", 0, 9).expect("hover");
        let value = result["contents"]["value"].as_str().unwrap();
        assert!(value.contains("SS-001"));
        assert_eq!(result["range"]["start"]["character"], 7);
        assert_eq!(result["range"]["end"]["character"], 13);
        assert!(hover(&registry, "// see SS-001 for details", 0, 0).is_none());
    }

    #[test]
    fn unknown_rule_hover_falls_back() {
        let registry = RuleRegistry::with_default_rules();
        let result = hover(&registry, "// SS-999", 0, 4).expect("hover");
        let value = result["contents"]["value"].as_str().unwrap();
        assert!(value.contains("SS-999"));
        assert!(value.contains("No rule with this id is registered"));
    }

    #[test]
    fn symbol_ranges_are_within_the_document() {
        let text = symbol_fixture();
        let symbols = document_symbols(&text);
        let line_count = text.lines().count();
        for symbol in symbols.as_array().unwrap() {
            check_range(symbol, line_count);
        }
    }

    fn check_range(symbol: &Value, line_count: usize) {
        let start = symbol["range"]["start"]["line"].as_u64().unwrap() as usize;
        let end = symbol["range"]["end"]["line"].as_u64().unwrap() as usize;
        assert!(start < line_count);
        assert!(end < line_count);
        assert!(start <= end);
        if let Some(children) = symbol["children"].as_array() {
            for child in children {
                check_range(child, line_count);
            }
        }
    }
}
