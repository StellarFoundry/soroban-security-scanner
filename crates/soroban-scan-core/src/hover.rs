//! Hover content for rule IDs, for editor (LSP) integrations.
//!
//! Everything here is offline: the text comes from the built-in rule metadata
//! only, never from the network or from the scanned document. Output is
//! bounded so a hostile document cannot cause unbounded work or allocation.

use serde_json::{json, Value};

use crate::registry::{is_valid_rule_id, RuleRegistry};

/// Longest line (in bytes) that is inspected for a rule ID.
pub const MAX_LINE_BYTES: usize = 4096;

/// Longest hover markdown (in bytes) that is returned.
pub const MAX_HOVER_BYTES: usize = 4096;

/// Builds hover markdown for a rule ID.
///
/// Known rules get severity, confidence, and a short remediation. Unknown
/// (or malformed) IDs get a generic fallback instead of an error.
pub fn hover_markdown(registry: &RuleRegistry, rule_id: &str) -> String {
    let text = match registry.metadata().find(|m| m.id == rule_id) {
        Some(meta) => format!(
            "**{id}: {title}**\n\n- Severity: {severity}\n- Confidence: {confidence}\n\n**Remediation:** {remediation}\n\nRun `soroban-scan explain {id}` for details.",
            id = meta.id,
            title = meta.title,
            severity = meta.default_severity,
            confidence = meta.default_confidence,
            remediation = meta.remediation,
        ),
        None => "Unknown rule ID. Run `soroban-scan rules` to list the available rules."
            .to_string(),
    };
    truncate_utf8(text, MAX_HOVER_BYTES)
}

fn truncate_utf8(mut text: String, max: usize) -> String {
    if text.len() > max {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// Finds an `SS-###` token covering the 0-based UTF-16 `character` offset of
/// `line` (the unit LSP uses for positions).
pub fn rule_id_at(line: &str, character: usize) -> Option<&str> {
    if line.len() > MAX_LINE_BYTES {
        return None;
    }
    // Convert the UTF-16 offset to a byte offset.
    let mut utf16 = 0;
    let mut byte = line.len();
    for (i, c) in line.char_indices() {
        if utf16 >= character {
            byte = i;
            break;
        }
        utf16 += c.len_utf16();
    }
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    let start = line[..byte].rfind(|c: char| !is_word(c)).map_or(0, |i| {
        i + line[i..].chars().next().map_or(1, char::len_utf8)
    });
    let end = line[byte..]
        .find(|c: char| !is_word(c))
        .map_or(line.len(), |i| byte + i);
    let word = &line[start..end];
    is_valid_rule_id(word).then_some(word)
}

/// Handles a `textDocument/hover` JSON-RPC request against `document`, the
/// current text of the requested document.
///
/// Returns a JSON-RPC response. The result is `null` when the position is not
/// on a rule ID, as the LSP specification allows.
pub fn handle_hover_request(registry: &RuleRegistry, document: &str, request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let position = &request["params"]["position"];
    let (Some(line), Some(character)) = (position["line"].as_u64(), position["character"].as_u64())
    else {
        return json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32602, "message": "invalid params: missing position" },
        });
    };
    let result = usize::try_from(line)
        .ok()
        .and_then(|line| document.lines().nth(line))
        .zip(usize::try_from(character).ok())
        .and_then(|(text, character)| rule_id_at(text, character))
        .map_or(Value::Null, |rule_id| {
            json!({
                "contents": {
                    "kind": "markdown",
                    "value": hover_markdown(registry, rule_id),
                },
            })
        });
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(line: u64, character: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "textDocument/hover",
            "params": {
                "textDocument": { "uri": "file:///lib.rs" },
                "position": { "line": line, "character": character },
            },
        })
    }

    #[test]
    fn every_shipped_rule_has_hover_content() {
        let registry = RuleRegistry::with_default_rules();
        for meta in registry.metadata() {
            let doc = format!("// {}", meta.id);
            let response = handle_hover_request(&registry, &doc, &request(0, 4));
            let value = response["result"]["contents"]["value"]
                .as_str()
                .unwrap_or_else(|| panic!("no hover for {}", meta.id));
            assert!(value.contains(meta.id));
            assert!(value.contains(meta.default_severity.as_str()));
            assert!(value.contains(meta.default_confidence.as_str()));
            assert!(value.contains(meta.remediation));
            assert_eq!(response["id"], 7);
            assert_eq!(response["result"]["contents"]["kind"], "markdown");
        }
    }

    #[test]
    fn unknown_rule_falls_back_gracefully() {
        let registry = RuleRegistry::with_default_rules();
        let response = handle_hover_request(&registry, "// SS-999", &request(0, 4));
        let value = response["result"]["contents"]["value"].as_str().unwrap();
        assert!(value.starts_with("Unknown rule ID"));
    }

    #[test]
    fn non_rule_position_returns_null() {
        let registry = RuleRegistry::with_default_rules();
        let response = handle_hover_request(&registry, "let x = 1; // SS-001", &request(0, 2));
        assert!(response["result"].is_null());
        let response = handle_hover_request(&registry, "x", &request(5, 0));
        assert!(response["result"].is_null());
    }

    #[test]
    fn missing_position_is_an_invalid_params_error() {
        let registry = RuleRegistry::with_default_rules();
        let response = handle_hover_request(&registry, "", &json!({"id": 1, "params": {}}));
        assert_eq!(response["error"]["code"], -32602);
    }

    #[test]
    fn utf16_offsets_and_oversized_lines_are_handled() {
        // "é" is 2 bytes but one UTF-16 unit; "😀" is 2 UTF-16 units.
        assert_eq!(rule_id_at("é😀 SS-001", 5), Some("SS-001"));
        assert_eq!(rule_id_at("é😀 SS-001", 3), None);
        let long = format!("SS-001{}", " ".repeat(MAX_LINE_BYTES));
        assert_eq!(rule_id_at(&long, 2), None);
    }
}
