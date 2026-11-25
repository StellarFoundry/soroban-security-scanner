//! Black-box language-server test with a mock stdio client (#336).
//!
//! Spawns both LSP entry points with a mock stdio client and exercises
//! initialize, open, change, save, hover, document symbols, shutdown, and exit.
//! Every wait is bounded so a hung server fails the test instead of blocking CI.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_soroban-scan"))
}

fn standalone_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_soroban-scan-lsp"))
}

fn violation_source() -> &'static str {
    r#"use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Vault {
    pub fn set(env: Env, value: u32) {
        env.storage().persistent().set(&1u32, &value);
    }
}
"#
}

fn clean_source() -> &'static str {
    r#"use soroban_sdk::{contractimpl, symbol_short, Address, Env};

// SS-001 reference for hover.
#[contractimpl]
impl Vault {
    pub fn set(env: Env, admin: Address, value: u32) {
        admin.require_auth();
        env.storage().temporary().set(&1u32, &value);
        env.events().publish((symbol_short!("set"),), value);
    }
}
"#
}

struct Client {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    rx: Receiver<Value>,
}

impl Client {
    fn spawn() -> Self {
        let mut command = Command::new(bin());
        command.arg("lsp");
        Self::spawn_command(&mut command)
    }

    fn spawn_standalone() -> Self {
        let mut command = Command::new(standalone_bin());
        Self::spawn_command(&mut command)
    }

    fn spawn_command(command: &mut Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn soroban-scan lsp");
        let stdout = child.stdout.take().expect("stdout was piped");
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            while let Some(message) = read_message(&mut reader) {
                if tx.send(message).is_err() {
                    break;
                }
            }
        });

        Client {
            stdin: child.stdin.take(),
            child: Some(child),
            rx,
        }
    }

    fn send(&mut self, message: &Value) {
        let body = serde_json::to_vec(message).expect("serialize message");
        let stdin = self.stdin.as_mut().expect("stdin is open");
        write!(stdin, "Content-Length: {}\r\n\r\n", body.len()).expect("write header");
        stdin.write_all(&body).expect("write body");
        stdin.flush().expect("flush");
    }

    fn recv_until<F>(&self, mut predicate: F) -> Value
    where
        F: FnMut(&Value) -> bool,
    {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let message = self
                .rx
                .recv_timeout(remaining)
                .expect("timed out waiting for a language-server message");
            if predicate(&message) {
                return message;
            }
        }
    }

    fn wait_for_exit(mut self, timeout: Duration) -> ExitStatus {
        drop(self.stdin.take());
        let mut child = self.child.take().expect("child is present");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(child.wait());
        });
        rx.recv_timeout(timeout)
            .expect("language server did not exit within the time limit")
            .expect("failed to wait for the language server")
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn read_message<R: BufRead>(reader: &mut R) -> Option<Value> {
    let mut length = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let header = line.trim_end_matches(['\r', '\n']);
        if header.is_empty() {
            break;
        }
        if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse::<usize>().ok();
        }
    }
    let mut body = vec![0u8; length?];
    reader.read_exact(&mut body).ok()?;
    serde_json::from_slice(&body).ok()
}

fn request(id: u64, method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

fn notification(method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "method": method, "params": params })
}

fn did_open(uri: &str, text: &str) -> Value {
    notification(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": uri, "languageId": "rust", "version": 1, "text": text } }),
    )
}

fn did_change(uri: &str, version: u64, text: &str) -> Value {
    notification(
        "textDocument/didChange",
        json!({
            "textDocument": { "uri": uri, "version": version },
            "contentChanges": [{ "text": text }]
        }),
    )
}

fn did_save(uri: &str) -> Value {
    notification(
        "textDocument/didSave",
        json!({ "textDocument": { "uri": uri } }),
    )
}

fn diagnostics_for(uri: &str) -> impl FnMut(&Value) -> bool {
    let uri = uri.to_string();
    move |message: &Value| {
        message["method"] == "textDocument/publishDiagnostics" && message["params"]["uri"] == uri
    }
}

fn rule_codes(message: &Value) -> Vec<&str> {
    message["params"]["diagnostics"]
        .as_array()
        .map(|diagnostics| {
            diagnostics
                .iter()
                .filter_map(|diagnostic| diagnostic["code"].as_str())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn language_server_handles_open_change_hover_symbols_and_shutdown() {
    let uri = "file:///tmp/soroban-scan-lsp.rs";
    let mut client = Client::spawn();

    client.send(&request(
        1,
        "initialize",
        json!({ "processId": null, "capabilities": {} }),
    ));
    let initialized = client.recv_until(|message| message["id"] == json!(1));
    let capabilities = &initialized["result"]["capabilities"];
    assert!(capabilities.get("textDocumentSync").is_some());
    assert_eq!(capabilities["hoverProvider"], json!(true));
    assert_eq!(capabilities["documentSymbolProvider"], json!(true));

    client.send(&notification("initialized", json!({})));
    client.send(&did_open(uri, violation_source()));

    let opened = client.recv_until(diagnostics_for(uri));
    assert!(
        rule_codes(&opened).contains(&"SS-001"),
        "expected SS-001 diagnostics, got: {opened}"
    );

    client.send(&did_change(uri, 2, clean_source()));
    let changed = client.recv_until(diagnostics_for(uri));
    assert!(
        !rule_codes(&changed).contains(&"SS-001"),
        "didChange must replace the document buffer and clear SS-001: {changed}"
    );

    let (line, character) = rule_id_position(clean_source(), "SS-001");
    client.send(&request(
        2,
        "textDocument/hover",
        json!({
            "textDocument": { "uri": uri },
            "position": { "line": line, "character": character }
        }),
    ));
    let hovered = client.recv_until(|message| message["id"] == json!(2));
    let content = hovered["result"]["contents"]["value"]
        .as_str()
        .expect("hover markdown");
    assert!(content.contains("SS-001"));
    assert!(content.contains("Severity:"));
    assert!(content.contains("Remediation:"));

    client.send(&request(
        3,
        "textDocument/documentSymbol",
        json!({ "textDocument": { "uri": uri } }),
    ));
    let symbols = client.recv_until(|message| message["id"] == json!(3));
    let symbols = symbols["result"].as_array().expect("document symbols");
    assert!(symbols.iter().any(|symbol| symbol["name"] == "Vault"));
    assert!(symbol_names(symbols).contains(&"set".to_string()));

    client.send(&request(4, "shutdown", Value::Null));
    let shutdown = client.recv_until(|message| message["id"] == json!(4));
    assert_eq!(shutdown["result"], Value::Null);

    client.send(&notification("exit", Value::Null));
    let status = client.wait_for_exit(Duration::from_secs(10));
    assert!(status.success(), "language server exited with {status:?}");
}

#[test]
fn language_server_offers_a_documented_suppression_quick_fix() {
    let uri = "file:///tmp/soroban-scan-code-action.rs";
    let mut client = Client::spawn();

    client.send(&request(
        1,
        "initialize",
        json!({ "processId": null, "capabilities": {} }),
    ));
    let initialized = client.recv_until(|message| message["id"] == json!(1));
    let capabilities = &initialized["result"]["capabilities"];
    assert_eq!(
        capabilities["codeActionProvider"]["resolveProvider"],
        json!(false)
    );
    assert_eq!(
        capabilities["codeActionProvider"]["codeActionKinds"][0],
        json!("quickfix")
    );

    client.send(&notification("initialized", json!({})));
    client.send(&did_open(uri, violation_source()));
    let opened = client.recv_until(diagnostics_for(uri));
    let finding = opened["params"]["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .find(|diagnostic| diagnostic["code"] == json!("SS-001"))
        .cloned()
        .expect("SS-001 diagnostic");

    client.send(&request(
        2,
        "textDocument/codeAction",
        json!({
            "textDocument": { "uri": uri },
            "range": finding["range"],
            "context": { "diagnostics": [finding] }
        }),
    ));
    let replied = client.recv_until(|message| message["id"] == json!(2));
    let actions = replied["result"].as_array().expect("code actions");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0]["kind"], json!("quickfix"));
    let edit = &actions[0]["edit"]["changes"][uri][0];
    let inserted = edit["newText"].as_str().expect("inserted directive");
    assert!(inserted.contains("soroban-scan: ignore SS-001 -- TODO:"));
    assert_eq!(edit["range"]["start"]["character"], json!(0));

    client.send(&request(3, "shutdown", Value::Null));
    client.recv_until(|message| message["id"] == json!(3));
    client.send(&notification("exit", Value::Null));
    let status = client.wait_for_exit(Duration::from_secs(10));
    assert!(status.success(), "language server exited with {status:?}");
}

#[test]
fn standalone_binary_handshakes_and_publishes_saved_document_diagnostics() {
    let uri = "file:///soroban-scan-lsp-standalone.rs";
    let mut client = Client::spawn_standalone();
    client.send(&request(
        1,
        "initialize",
        json!({ "processId": null, "capabilities": {} }),
    ));
    let initialized = client.recv_until(|message| message["id"] == json!(1));
    assert_eq!(
        initialized["result"]["serverInfo"]["name"],
        json!("soroban-scan")
    );
    assert!(initialized["result"]["capabilities"]["textDocumentSync"].is_object());

    client.send(&notification("initialized", json!({})));
    client.send(&did_open(uri, violation_source()));
    let opened = client.recv_until(diagnostics_for(uri));
    assert!(rule_codes(&opened).contains(&"SS-001"));

    client.send(&did_save(uri));
    let saved = client.recv_until(diagnostics_for(uri));
    assert!(rule_codes(&saved).contains(&"SS-001"));

    client.send(&request(2, "shutdown", Value::Null));
    client.recv_until(|message| message["id"] == json!(2));
    client.send(&notification("exit", Value::Null));
    let status = client.wait_for_exit(Duration::from_secs(10));
    assert!(status.success(), "language server exited with {status:?}");
}

fn temp_workspace(label: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("soroban-scan-lsp-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create temporary workspace");
    root
}

fn file_uri(path: &Path) -> String {
    let mut text = path.to_string_lossy().replace('\\', "/");
    if !text.starts_with('/') {
        text.insert(0, '/');
    }
    format!("file://{text}")
}

#[test]
fn language_server_loads_and_reloads_workspace_configuration() {
    let root = temp_workspace("config");
    let config_path = root.join("soroban-scan.toml");
    let config_uri = file_uri(&config_path);
    fs::write(&config_path, "min_severity = \"critical\"\n").expect("write config");

    let uri = "file:///tmp/soroban-scan-lsp-config.rs";
    let mut client = Client::spawn();

    client.send(&request(
        1,
        "initialize",
        json!({ "processId": null, "rootUri": file_uri(&root), "capabilities": {} }),
    ));
    client.recv_until(|message| message["id"] == json!(1));
    client.send(&notification("initialized", json!({})));
    client.send(&did_open(uri, violation_source()));

    let opened = client.recv_until(diagnostics_for(uri));
    assert!(
        !rule_codes(&opened).contains(&"SS-001"),
        "workspace min_severity must filter SS-001: {opened}"
    );

    fs::write(&config_path, "min_severity = \"info\"\n").expect("update config");
    client.send(&notification(
        "workspace/didChangeWatchedFiles",
        json!({ "changes": [{ "uri": config_uri.clone(), "type": 2 }] }),
    ));
    let reloaded = client.recv_until(diagnostics_for(uri));
    assert!(
        rule_codes(&reloaded).contains(&"SS-001"),
        "reloaded config must report SS-001: {reloaded}"
    );

    fs::write(&config_path, "min_severity = \"nope\"\n").expect("write invalid config");
    client.send(&notification(
        "workspace/didChangeConfiguration",
        json!({ "settings": {} }),
    ));
    let error = client.recv_until(|message| {
        message["method"] == "textDocument/publishDiagnostics"
            && message["params"]["uri"] == config_uri
            && message["params"]["diagnostics"]
                .as_array()
                .is_some_and(|diagnostics| !diagnostics.is_empty())
    });
    let diagnostics = error["params"]["diagnostics"].as_array().unwrap();
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic["source"] == "soroban-scan"
            && diagnostic["severity"] == json!(1)
            && diagnostic["code"] == "LSP-CONFIG-001"
    }));

    client.send(&request(2, "shutdown", Value::Null));
    client.recv_until(|message| message["id"] == json!(2));
    client.send(&notification("exit", Value::Null));
    let status = client.wait_for_exit(Duration::from_secs(10));
    assert!(status.success(), "language server exited with {status:?}");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn oversized_documents_are_discarded_and_reported() {
    let mut client = Client::spawn();
    client.send(&request(
        1,
        "initialize",
        json!({ "processId": null, "capabilities": {} }),
    ));
    client.recv_until(|message| message["id"] == json!(1));
    client.send(&notification("initialized", json!({})));

    // Oversized content is discarded instead of being retained for outline/hover.
    let oversized = format!(
        "#[contract]\npub struct ShouldNotBeRetained;\n// SS-001\n// {}\n",
        "x".repeat(1024 * 1024 + 1)
    );
    let large_uri = "file:///tmp/soroban-scan-lsp-large.rs";
    client.send(&did_open(large_uri, &oversized));
    let large_diagnostics = client.recv_until(diagnostics_for(large_uri));
    assert!(
        rule_codes(&large_diagnostics).contains(&"LSP-DOCUMENT-LIMIT"),
        "expected a document-limit diagnostic, got: {large_diagnostics}"
    );

    // The server must still answer requests after skipping the large document.
    client.send(&request(
        2,
        "textDocument/documentSymbol",
        json!({ "textDocument": { "uri": large_uri } }),
    ));
    let symbols = client.recv_until(|message| message["id"] == json!(2));
    assert_eq!(symbols["result"], json!([]));

    client.send(&request(
        3,
        "textDocument/hover",
        json!({
            "textDocument": { "uri": large_uri },
            "position": { "line": 2, "character": 4 }
        }),
    ));
    let hover = client.recv_until(|message| message["id"] == json!(3));
    assert_eq!(hover["result"], Value::Null);

    client.send(&request(4, "shutdown", Value::Null));
    client.recv_until(|message| message["id"] == json!(4));
    client.send(&notification("exit", Value::Null));
    let status = client.wait_for_exit(Duration::from_secs(10));
    assert!(status.success(), "language server exited with {status:?}");
}

fn rule_id_position(text: &str, rule: &str) -> (usize, usize) {
    for (line, content) in text.lines().enumerate() {
        if let Some(byte) = content.find(rule) {
            return (line, content[..byte].chars().count());
        }
    }
    panic!("rule id {rule} is not present in the fixture");
}

fn symbol_names(symbols: &[Value]) -> Vec<String> {
    let mut names = Vec::new();
    for symbol in symbols {
        if let Some(name) = symbol["name"].as_str() {
            names.push(name.to_string());
        }
        if let Some(children) = symbol["children"].as_array() {
            names.extend(symbol_names(children));
        }
    }
    names
}
