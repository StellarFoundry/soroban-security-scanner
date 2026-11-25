//! Minimal stdio language server.
//!
//! Implements the subset of LSP that `docs/editors.md` promises: full document
//! sync, diagnostics from the deterministic scanner, document symbols, and
//! quick fixes that insert documented inline suppressions.
//! JSON-RPC 2.0 framing is handled by hand with `serde_json`; there is no
//! network access and no extra dependency.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use soroban_scan_core::confidence::Confidence;
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

/// Reason placeholder inserted by the suppression quick fix. It is deliberately
/// not a valid justification: the developer must replace it before committing.
const REASON_PLACEHOLDER: &str = "TODO: explain why this finding is accepted";

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

/// Maximum analyzed document size. Larger buffers are kept for symbols and
/// hover but are not scanned, so one large file cannot stall the server.
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Maximum diagnostics published for one document.
const MAX_DIAGNOSTICS: usize = 200;

/// Time allowed for one analysis before a warning replaces its diagnostics.
const ANALYSIS_TIMEOUT: Duration = Duration::from_secs(2);

/// Idle time after a change before analysis starts, so typing does not scan
/// every keystroke.
const CHANGE_DEBOUNCE: Duration = Duration::from_millis(150);

/// Bounded work limits for the language server.
#[derive(Clone, Copy)]
struct Limits {
    max_document_bytes: usize,
    max_diagnostics: usize,
    analysis_timeout: Duration,
    debounce: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_document_bytes: MAX_DOCUMENT_BYTES,
            max_diagnostics: MAX_DIAGNOSTICS,
            analysis_timeout: ANALYSIS_TIMEOUT,
            debounce: CHANGE_DEBOUNCE,
        }
    }
}

struct PendingAnalysis {
    generation: u64,
    due: Instant,
}

struct InFlightAnalysis {
    generation: u64,
    started: Instant,
    timed_out: bool,
}

struct AnalysisResult {
    uri: String,
    generation: u64,
    diagnostics: Vec<Value>,
}

enum Event {
    Message(Value),
    Analyzed(AnalysisResult),
    Closed,
    ReadError(String),
}

struct ServerState {
    registry: Arc<RuleRegistry>,
    limits: Limits,
    documents: BTreeMap<String, String>,
    pending: BTreeMap<String, PendingAnalysis>,
    inflight: BTreeMap<String, InFlightAnalysis>,
    workspace_root: Option<PathBuf>,
    workspace_config: WorkspaceConfig,
    next_generation: u64,
    shutdown_requested: bool,
}

impl ServerState {
    fn new(registry: Arc<RuleRegistry>, limits: Limits) -> Self {
        ServerState {
            registry,
            limits,
            documents: BTreeMap::new(),
            pending: BTreeMap::new(),
            inflight: BTreeMap::new(),
            workspace_root: None,
            workspace_config: WorkspaceConfig::defaults(),
            next_generation: 0,
            shutdown_requested: false,
        }
    }

    fn schedule(&mut self, uri: String, debounce: Duration) {
        self.next_generation += 1;
        self.pending.insert(
            uri,
            PendingAnalysis {
                generation: self.next_generation,
                due: Instant::now() + debounce,
            },
        );
    }

    /// Starts analyses that are due. A document with an active worker waits, so
    /// a burst of changes cannot create unbounded threads.
    fn start_due<W: Write>(
        &mut self,
        writer: &mut W,
        events: &mpsc::Sender<Event>,
    ) -> Result<(), String> {
        let now = Instant::now();
        let due: Vec<String> = self
            .pending
            .iter()
            .filter(|(uri, pending)| pending.due <= now && !self.inflight.contains_key(*uri))
            .filter(|(uri, pending)| {
                pending.due <= now
                    && self
                        .inflight
                        .get(*uri)
                        .is_none_or(|active| active.timed_out)
            })
            .map(|(uri, _)| uri.clone())
            .collect();

        for uri in due {
            let Some(pending) = self.pending.remove(&uri) else {
                continue;
            };
            let text = self
                .documents
                .get(&uri)
                .cloned()
                .unwrap_or_else(String::new);
            if text.len() > self.limits.max_document_bytes {
                publish_diagnostics(
                    writer,
                    &uri,
                    vec![server_diagnostic(
                        "LSP-DOCUMENT-LIMIT",
                        2,
                        format!(
                            "document is {} bytes; analysis is skipped above the {} byte limit",
                            text.len(),
                            self.limits.max_document_bytes
                        ),
                    )],
                )?;
                continue;
            }

            self.inflight.insert(
                uri.clone(),
                InFlightAnalysis {
                    generation: pending.generation,
                    started: now,
                    timed_out: false,
                },
            );
            let registry = Arc::clone(&self.registry);
            let config = self.workspace_config.config.clone();
            let events = events.clone();
            let max_diagnostics = self.limits.max_diagnostics;
            let worker_uri = uri.clone();
            thread::spawn(move || {
                let diagnostics =
                    diagnostics_with_limit(&registry, &config, &worker_uri, &text, max_diagnostics);
                let _ = events.send(Event::Analyzed(AnalysisResult {
                    uri: worker_uri,
                    generation: pending.generation,
                    diagnostics,
                }));
            });
        }
        Ok(())
    }

    /// Marks analyses that exceeded the time limit and reports it once.
    fn expire_inflight<W: Write>(&mut self, writer: &mut W) -> Result<(), String> {
        let now = Instant::now();
        let expired: Vec<String> = self
            .inflight
            .iter()
            .filter(|(_, active)| {
                !active.timed_out && now >= active.started + self.limits.analysis_timeout
            })
            .map(|(uri, _)| uri.clone())
            .collect();
        for uri in expired {
            if let Some(active) = self.inflight.get_mut(&uri) {
                active.timed_out = true;
            }
            publish_diagnostics(
                writer,
                &uri,
                vec![server_diagnostic(
                    "LSP-ANALYSIS-TIMEOUT",
                    2,
                    format!(
                        "analysis exceeded {} ms; diagnostics may be incomplete",
                        self.limits.analysis_timeout.as_millis()
                    ),
                )],
            )?;
        }
        Ok(())
    }

    /// Time until the next pending deadline or in-flight timeout.
    fn next_wait(&self) -> Duration {
        let now = Instant::now();
        let mut next: Option<Instant> = None;
        for (uri, pending) in &self.pending {
            let deadline = match self.inflight.get(uri) {
                Some(active) if !active.timed_out => active.started + self.limits.analysis_timeout,
                Some(_) => continue,
                None => pending.due,
            };
            next = Some(next.map_or(deadline, |current| current.min(deadline)));
        }
        for active in self.inflight.values().filter(|active| !active.timed_out) {
            let deadline = active.started + self.limits.analysis_timeout;
            next = Some(next.map_or(deadline, |current| current.min(deadline)));
        }
        match next {
            Some(deadline) => deadline.saturating_duration_since(now),
            None => Duration::from_secs(3600),
        }
    }

    fn handle_result<W: Write>(
        &mut self,
        writer: &mut W,
        result: AnalysisResult,
    ) -> Result<(), String> {
        let Some(active) = self.inflight.get(&result.uri) else {
            return Ok(());
        };
        if active.generation != result.generation {
            return Ok(());
        }
        let timed_out = active.timed_out;
        self.inflight.remove(&result.uri);
        if timed_out || !self.documents.contains_key(&result.uri) {
            return Ok(());
        }
        if self
            .pending
            .get(&result.uri)
            .is_some_and(|pending| pending.generation > result.generation)
        {
            return Ok(());
        }
        publish_diagnostics(writer, &result.uri, result.diagnostics)
    }

    fn handle_message<W: Write>(&mut self, writer: &mut W, message: Value) -> Result<bool, String> {
        let id = message.get("id").cloned();
        let method = message.get("method").and_then(Value::as_str);
        let params = message.get("params").cloned().unwrap_or(Value::Null);

        match method {
            Some("initialize") => {
                self.workspace_root = workspace_root_from(&params);
                reload_workspace_config(&mut self.workspace_config, self.workspace_root.as_deref());
                respond(
                    writer,
                    id,
                    json!({
                        "capabilities": {
                            "textDocumentSync": { "openClose": true, "change": 1 },
                            "documentSymbolProvider": true,
                            "hoverProvider": true,
                            "codeActionProvider": {
                                "codeActionKinds": ["quickfix"],
                                "resolveProvider": false
                            }
                        },
                        "serverInfo": {
                            "name": "soroban-scan",
                            "version": soroban_scan_core::VERSION
                        }
                    }),
                )?;
                publish_config_diagnostics(writer, &self.workspace_config)?;
            }
            Some("initialized") => {}
            Some("shutdown") => {
                self.shutdown_requested = true;
                respond(writer, id, Value::Null)?;
            }
            Some("exit") => return Ok(false),
            Some("textDocument/didOpen") => {
                if let Some((uri, text)) = opened_document(&params) {
                    self.update_document(writer, uri, text, Duration::ZERO)?;
                }
            }
            Some("textDocument/didChange") => {
                let uri = params
                    .pointer("/textDocument/uri")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if let Some(text) = changed_text(&params) {
                    self.update_document(writer, uri, text, self.limits.debounce)?;
                }
            }
            Some("textDocument/didSave") => {
                if let Some(uri) = params.pointer("/textDocument/uri").and_then(Value::as_str) {
                    if self.documents.contains_key(uri) {
                        self.schedule(uri.to_string(), Duration::ZERO);
                    }
                }
            }
            Some("textDocument/didClose") => {
                if let Some(uri) = params.pointer("/textDocument/uri").and_then(Value::as_str) {
                    self.documents.remove(uri);
                    self.pending.remove(uri);
                    if let Some(active) = self.inflight.get_mut(uri) {
                        active.timed_out = true;
                    }
                    publish_diagnostics(writer, uri, Vec::new())?;
                }
            }
            Some("workspace/didChangeConfiguration") | Some("workspace/didChangeWatchedFiles") => {
                reload_workspace_config(&mut self.workspace_config, self.workspace_root.as_deref());
                publish_config_diagnostics(writer, &self.workspace_config)?;
                let uris: Vec<String> = self.documents.keys().cloned().collect();
                for uri in uris {
                    self.schedule(uri, Duration::ZERO);
                }
            }
            Some("textDocument/documentSymbol") => {
                let result = params
                    .pointer("/textDocument/uri")
                    .and_then(Value::as_str)
                    .and_then(|uri| self.documents.get(uri))
                    .map(|text| document_symbols(text))
                    .unwrap_or_else(|| json!([]));
                respond(writer, id, result)?;
            }
            Some("textDocument/hover") => {
                let result = params
                    .pointer("/textDocument/uri")
                    .and_then(Value::as_str)
                    .and_then(|uri| self.documents.get(uri))
                    .and_then(|text| {
                        let line = params.pointer("/position/line")?.as_u64()? as usize;
                        let character = params.pointer("/position/character")?.as_u64()? as usize;
                        hover(&self.registry, text, line, character)
                    })
                    .unwrap_or(Value::Null);
                respond(writer, id, result)?;
            }
            Some("textDocument/codeAction") => {
                let result = params
                    .pointer("/textDocument/uri")
                    .and_then(Value::as_str)
                    .and_then(|uri| {
                        self.documents
                            .get(uri)
                            .map(|text| code_actions(uri, text, &params))
                    })
                    .unwrap_or_else(|| json!([]));
                respond(writer, id, result)?;
            }
            Some(_) if id.is_some() => {
                respond_error(writer, id, -32601, "method not found")?;
            }
            Some(_) => {}
            None => {}
        }
        Ok(true)
    }

    fn update_document<W: Write>(
        &mut self,
        writer: &mut W,
        uri: String,
        text: String,
        debounce: Duration,
    ) -> Result<(), String> {
        self.pending.remove(&uri);
        if text.len() > self.limits.max_document_bytes {
            self.documents.remove(&uri);
            if let Some(active) = self.inflight.get_mut(&uri) {
                active.timed_out = true;
            }
            return publish_diagnostics(
                writer,
                &uri,
                vec![server_diagnostic(
                    "LSP-DOCUMENT-LIMIT",
                    2,
                    format!(
                        "document is {} bytes; the {} byte per-document limit is exceeded, so its contents are not retained or analyzed",
                        text.len(),
                        self.limits.max_document_bytes
                    ),
                )],
            );
        }

        self.documents.insert(uri.clone(), text);
        self.schedule(uri, debounce);
        Ok(())
    }
}

/// Runs the language server until the client sends `exit`.
pub fn run(registry: RuleRegistry) -> Result<u8, String> {
    let limits = Limits::default();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    let (events, receiver) = mpsc::channel();
    let reader_events = events.clone();
    thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut reader = BufReader::new(stdin);
        loop {
            match read_message(&mut reader) {
                Ok(Some(message)) => {
                    if reader_events.send(Event::Message(message)).is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    let _ = reader_events.send(Event::Closed);
                    break;
                }
                Err(error) => {
                    let _ = reader_events.send(Event::ReadError(error));
                    break;
                }
            }
        }
    });

    let mut state = ServerState::new(Arc::new(registry), limits);
    loop {
        state.start_due(&mut writer, &events)?;
        state.expire_inflight(&mut writer)?;
        match receiver.recv_timeout(state.next_wait()) {
            Ok(Event::Message(message)) => {
                if !state.handle_message(&mut writer, message)? {
                    break;
                }
            }
            Ok(Event::Analyzed(result)) => state.handle_result(&mut writer, result)?,
            Ok(Event::Closed) | Err(RecvTimeoutError::Disconnected) => break,
            Ok(Event::ReadError(error)) => return Err(error),
            Err(RecvTimeoutError::Timeout) => {}
        }
    }

    // `exit` after `shutdown` is a clean stop; the process still returns 0 so a
    // client that simply closes the pipe is not reported as a crash.
    let _ = state.shutdown_requested;
    Ok(0)
}

fn server_diagnostic(code: &str, severity: u8, message: String) -> Value {
    json!({
        "range": range_raw(1, 1, 1, 1),
        "severity": severity,
        "code": code,
        "source": SOURCE,
        "message": message
    })
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
    uri: &str,
    diagnostics: Vec<Value>,
) -> Result<(), String> {
    send(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": { "uri": uri, "diagnostics": diagnostics }
        }),
    )
}

/// Scans a document and caps the published diagnostics.
fn diagnostics_with_limit(
    registry: &RuleRegistry,
    config: &ScanConfig,
    uri: &str,
    text: &str,
    max_diagnostics: usize,
) -> Vec<Value> {
    let mut diagnostics = diagnostics_for(registry, config, uri, text);
    if diagnostics.len() <= max_diagnostics {
        return diagnostics;
    }
    let omitted = diagnostics.len() - max_diagnostics;
    diagnostics.truncate(max_diagnostics);
    diagnostics.push(server_diagnostic(
        "LSP-DIAGNOSTICS-TRUNCATED",
        2,
        format!("{omitted} additional diagnostics omitted (limit {max_diagnostics})"),
    ));
    diagnostics
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
            "range": range_for(text, line, column, end_line, end_column),
            "severity": diagnostic_severity(finding.severity, finding.confidence),
            "code": finding.rule_id,
            "source": SOURCE,
            "message": format!("{}: {}", finding.title, finding.evidence),
            "data": {
                "fingerprint": finding.fingerprint,
                "confidence": finding.confidence.as_str()
            }
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

/// Maps a finding severity and confidence to an LSP `DiagnosticSeverity`.
///
/// Severity supplies the base level: critical/high is error, medium warning,
/// low information, and info a hint. A low-confidence finding is capped at
/// warning so a heuristic high-severity result does not look certain.
fn diagnostic_severity(severity: Severity, confidence: Confidence) -> u8 {
    let base = match severity {
        Severity::Critical | Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    };
    if confidence == Confidence::Low && base < 2 {
        2
    } else {
        base
    }
}

/// Converts a 1-based byte column to a zero-based UTF-16 LSP position.
///
/// The scanner reports byte columns. LSP counts UTF-16 code units, so a
/// multi-byte character occupies more than one byte but one or two UTF-16
/// units. A column inside a multi-byte character is clamped to its start, and
/// CRLF line endings are stripped before counting.
fn lsp_position(text: &str, line: usize, column: usize) -> (usize, usize) {
    if line == 0 {
        return (0, 0);
    }
    let lines: Vec<&str> = text.lines().collect();
    let line_index = line - 1;
    let Some(line_text) = lines.get(line_index) else {
        return (lines.len().saturating_sub(1), 0);
    };
    let mut byte = column.saturating_sub(1).min(line_text.len());
    while byte > 0 && !line_text.is_char_boundary(byte) {
        byte -= 1;
    }
    (line_index, line_text[..byte].encode_utf16().count())
}

/// Builds an LSP range from scanner byte positions.
fn range_for(text: &str, line: usize, column: usize, end_line: usize, end_column: usize) -> Value {
    let (start_line, start_character) = lsp_position(text, line, column);
    let (end_line, end_character) = lsp_position(text, end_line, end_column);
    json!({
        "start": { "line": start_line, "character": start_character },
        "end": { "line": end_line, "character": end_character }
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

/// True only for the documented `SS-` plus three digits rule-id shape.
fn is_rule_id(value: &str) -> bool {
    let Some(digits) = value.strip_prefix("SS-") else {
        return false;
    };
    digits.len() == 3 && digits.bytes().all(|byte| byte.is_ascii_digit())
}

/// Avoids offering a second directive for a rule that is already suppressed.
fn has_suppression(text: &str, rule_id: &str) -> bool {
    text.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("soroban-scan:") {
            return false;
        }
        let Some(start) = lower.find("ignore") else {
            return false;
        };
        let mut targets = lower[start + "ignore".len()..]
            .split(|character: char| character.is_whitespace() || character == ',');
        let rule_id = rule_id.to_ascii_lowercase();
        targets.any(|word| word == rule_id.as_str() || word == "all")
    })
}

/// Builds the directive text for an insertion at the start of `line`.
///
/// The leading whitespace of the target line is preserved so the comment lines
/// up with the code it suppresses, and the document's line ending is reused.
fn suppression_edit_text(text: &str, line: usize, rule_id: &str) -> Option<String> {
    let line_text = text.lines().nth(line)?;
    let indent: String = line_text
        .chars()
        .take_while(|character| character.is_whitespace())
        .collect();
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    Some(format!(
        "{indent}// soroban-scan: ignore {rule_id} -- {REASON_PLACEHOLDER}{newline}"
    ))
}

/// Returns at most one quick fix per scanner diagnostic in the request context.
///
/// The analysis is never rerun here: the client supplies the diagnostics it
/// already received, and only diagnostics from this server with a valid rule id
/// are offered. Config and truncation diagnostics have no rule id and are
/// skipped, so a quick fix can never silently change scanner configuration.
fn code_actions(uri: &str, text: &str, params: &Value) -> Value {
    let Some(diagnostics) = params
        .pointer("/context/diagnostics")
        .and_then(Value::as_array)
    else {
        return json!([]);
    };
    let mut actions = Vec::new();
    for diagnostic in diagnostics.iter().take(MAX_DIAGNOSTICS) {
        if diagnostic["source"].as_str() != Some(SOURCE) {
            continue;
        }
        let Some(rule_id) = diagnostic["code"].as_str() else {
            continue;
        };
        if !is_rule_id(rule_id) || has_suppression(text, rule_id) {
            continue;
        }
        let Some(line) = diagnostic["range"]["start"]["line"]
            .as_u64()
            .and_then(|line| usize::try_from(line).ok())
        else {
            continue;
        };
        let Some(new_text) = suppression_edit_text(text, line, rule_id) else {
            continue;
        };
        actions.push(json!({
            "title": format!("Suppress {rule_id} with a documented reason"),
            "kind": "quickfix",
            "diagnostics": [diagnostic],
            "edit": {
                "changes": {
                    uri: [{
                        "range": {
                            "start": { "line": line, "character": 0 },
                            "end": { "line": line, "character": 0 }
                        },
                        "newText": new_text
                    }]
                }
            }
        }));
    }
    Value::Array(actions)
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

    #[test]
    fn ascii_positions_are_zero_based() {
        let text = "ab\ncd\nef";
        assert_eq!(lsp_position(text, 1, 1), (0, 0));
        assert_eq!(lsp_position(text, 2, 3), (1, 2));
        assert_eq!(lsp_position(text, 9, 1), (2, 0));
        assert_eq!(lsp_position(text, 0, 1), (0, 0));
    }

    #[test]
    fn unicode_columns_become_utf16_units() {
        // Each Greek letter is two bytes and one UTF-16 unit.
        let text = "αβx";
        assert_eq!(lsp_position(text, 1, 1), (0, 0));
        assert_eq!(lsp_position(text, 1, 3), (0, 1));
        assert_eq!(lsp_position(text, 1, 5), (0, 2));

        // An emoji is four bytes and two UTF-16 units. A column inside it is
        // clamped to the character start.
        let text = "😀x";
        assert_eq!(lsp_position(text, 1, 5), (0, 2));
        assert_eq!(lsp_position(text, 1, 3), (0, 0));
        assert_eq!(lsp_position(text, 1, 99), (0, 3));
    }

    #[test]
    fn crlf_lines_keep_the_same_character_offsets() {
        let text = "α\r\nβx\r\n";
        assert_eq!(lsp_position(text, 1, 3), (0, 1));
        assert_eq!(lsp_position(text, 2, 1), (1, 0));
        assert_eq!(lsp_position(text, 2, 3), (1, 1));
    }

    #[test]
    fn severity_and_confidence_map_to_lsp_levels() {
        let cases = [
            (Severity::Critical, Confidence::High, 1),
            (Severity::High, Confidence::Medium, 1),
            (Severity::Critical, Confidence::Low, 2),
            (Severity::High, Confidence::Low, 2),
            (Severity::Medium, Confidence::High, 2),
            (Severity::Medium, Confidence::Low, 2),
            (Severity::Low, Confidence::High, 3),
            (Severity::Info, Confidence::High, 4),
        ];
        for (severity, confidence, expected) in cases {
            assert_eq!(
                diagnostic_severity(severity, confidence),
                expected,
                "{severity:?}/{confidence:?}"
            );
        }
    }

    #[test]
    fn diagnostic_limit_adds_a_truncation_notice() {
        let registry = RuleRegistry::with_default_rules();
        let diagnostics = diagnostics_with_limit(
            &registry,
            &ScanConfig::default(),
            "document.rs",
            "#[contractimpl]\nimpl Vault { pub fn set(env: Env, value: u32) { env.storage().persistent().set(&1u32, &value); } }\n",
            0,
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0]["code"], "LSP-DIAGNOSTICS-TRUNCATED");
    }

    #[test]
    fn finding_ranges_use_utf16_offsets() {
        let registry = RuleRegistry::with_default_rules();
        let text = r#"#[contractimpl]
impl Vault {
    pub fn set(env: Env, value: u32) { /* αβ */ env.storage().persistent().set(&1u32, &value); }
}
"#;
        let diagnostics = diagnostics_for(&registry, &ScanConfig::default(), "unicode.rs", text);
        let finding = diagnostics
            .iter()
            .find(|diagnostic| diagnostic["code"] == "SS-006")
            .expect("SS-006 diagnostic");
        // The prefix before `env.storage` is 48 bytes but 46 UTF-16 units
        // because of the two non-ASCII characters in the comment.
        let source_line = text.lines().nth(2).unwrap();
        let byte_column = source_line.find("env.storage").unwrap();
        assert!(byte_column > 46, "the prefix contains multi-byte text");
        assert_eq!(finding["range"]["start"]["character"].as_u64(), Some(46));
        assert_eq!(finding["data"]["confidence"], "low");
    }

    fn diagnostic(line: u64, source: &str, code: &str) -> Value {
        json!({
            "source": source,
            "code": code,
            "range": {
                "start": { "line": line, "character": 4 },
                "end": { "line": line, "character": 8 }
            }
        })
    }

    fn action_params(diagnostics: Vec<Value>) -> Value {
        json!({
            "textDocument": { "uri": "file:///vault.rs" },
            "context": { "diagnostics": diagnostics }
        })
    }

    #[test]
    fn code_action_inserts_a_documented_suppression() {
        let text = "impl Vault {\n    pub fn set() {}\n}\n";
        let params = action_params(vec![diagnostic(1, SOURCE, "SS-001")]);
        let actions = code_actions("file:///vault.rs", text, &params);
        let actions = actions.as_array().expect("code actions");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["kind"], "quickfix");
        assert!(actions[0]["title"].as_str().unwrap().contains("SS-001"));
        let edit = &actions[0]["edit"]["changes"]["file:///vault.rs"][0];
        assert_eq!(
            edit["newText"],
            "    // soroban-scan: ignore SS-001 -- TODO: explain why this finding is accepted\n"
        );
        assert_eq!(edit["range"]["start"]["line"], 1);
        assert_eq!(edit["range"]["start"]["character"], 0);
        assert_eq!(actions[0]["diagnostics"][0]["code"], "SS-001");
    }

    #[test]
    fn code_action_reuses_crlf_line_endings() {
        let text = "impl Vault {\r\n    pub fn set() {}\r\n}\r\n";
        let params = action_params(vec![diagnostic(1, SOURCE, "SS-043")]);
        let actions = code_actions("file:///vault.rs", text, &params);
        let new_text = &actions[0]["edit"]["changes"]["file:///vault.rs"][0]["newText"];
        assert!(new_text.as_str().unwrap().ends_with("\r\n"));
        assert!(new_text.as_str().unwrap().contains("SS-043"));
    }

    #[test]
    fn code_action_skips_foreign_config_and_malformed_diagnostics() {
        let diagnostics = vec![
            diagnostic(1, "rust-analyzer", "SS-001"),
            diagnostic(1, SOURCE, "LSP-CONFIG-001"),
            diagnostic(1, SOURCE, "SS-1"),
            diagnostic(1, SOURCE, "SS-001x"),
            diagnostic(99, SOURCE, "SS-001"),
        ];
        let text = "impl Vault {\n    pub fn set() {}\n}\n";
        assert_eq!(
            code_actions("file:///vault.rs", text, &action_params(diagnostics)),
            json!([])
        );
    }

    #[test]
    fn code_action_skips_an_existing_suppression() {
        let text = "// soroban-scan: ignore SS-001 -- reviewed\npub fn set() {}\n";
        let params = action_params(vec![diagnostic(1, SOURCE, "SS-001")]);
        assert_eq!(code_actions("file:///vault.rs", text, &params), json!([]));

        let all = "// soroban-scan: ignore all -- generated file\npub fn set() {}\n";
        assert_eq!(code_actions("file:///vault.rs", all, &params), json!([]));
    }
}
