//! Small, opt-in HTTP transport for the in-process scan API.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use serde_json::Value;
use soroban_scan_core::api_auth::ApiAuthConfig;
use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::service::{ApiRequest, JobLimits, ScanApi};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Starts a sequential, bounded HTTP server. It intentionally accepts only
/// loopback binds and requires its bearer token through the environment.
pub fn run(bind: SocketAddr, config: ScanConfig, registry: RuleRegistry) -> Result<u8, String> {
    if !bind.ip().is_loopback() {
        return Err("HTTP API may only bind to a loopback address".to_string());
    }
    let token = std::env::var("SOROBAN_SCAN_API_TOKEN")
        .map_err(|_| "SOROBAN_SCAN_API_TOKEN must be set to enable the HTTP API".to_string())?;
    let auth = ApiAuthConfig {
        bearer_token: Some(token),
    };
    auth.validate()
        .map_err(|_| "SOROBAN_SCAN_API_TOKEN is invalid".to_string())?;
    let listener =
        TcpListener::bind(bind).map_err(|error| format!("cannot bind HTTP API: {error}"))?;
    eprintln!(
        "soroban-scan API listening on {}",
        listener.local_addr().unwrap_or(bind)
    );
    let api = ScanApi::with_scan(auth, JobLimits::default(), config, registry);
    for incoming in listener.incoming() {
        match incoming {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                let _ = handle_connection(&mut stream, &api);
            }
            Err(error) => eprintln!("HTTP API connection failed: {error}"),
        }
    }
    Ok(0)
}

fn handle_connection(stream: &mut TcpStream, api: &ScanApi) -> std::io::Result<()> {
    let response = match read_request(stream) {
        Ok((method, path, authorization, body)) => {
            let request = ApiRequest {
                method,
                path,
                authorization,
                body,
            };
            let response = api.handle(&request);
            let (status, body) = if response.status == 202 {
                let accepted: Value = serde_json::from_str(&response.body).unwrap_or(Value::Null);
                if let Some(id) = accepted.get("job_id").and_then(Value::as_str) {
                    let _ = api.run_next();
                    let completed = api.handle(
                        &ApiRequest::new("GET", format!("/v1/jobs/{id}"), "")
                            .with_authorization(
                                request.authorization.as_deref().unwrap_or_default(),
                            ),
                    );
                    let report = serde_json::from_str::<Value>(&completed.body)
                        .ok()
                        .and_then(|value| value.get("report").cloned())
                        .filter(|value| !value.is_null())
                        .map(|value| value.to_string())
                        .unwrap_or(response.body);
                    (if completed.status == 200 { 200 } else { completed.status }, report)
                } else {
                    (response.status, response.body)
                }
            } else {
                (response.status, response.body)
            };
            (status, body)
        }
        Err(status) => (
            status,
            serde_json::json!({"error":{"code":"invalid_request","message":"invalid or oversized HTTP request"}}).to_string(),
        ),
    };
    let status_text = match response.0 {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response.0,
        status_text,
        response.1.len(),
        response.1
    )
}

fn read_request(stream: &mut TcpStream) -> Result<(String, String, Option<String>, Vec<u8>), u16> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 2048];
    let header_end = loop {
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err(413);
        }
        let count = stream.read(&mut buffer).map_err(|_| 400u16)?;
        if count == 0 {
            return Err(400);
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > MAX_HEADER_BYTES && !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            return Err(413);
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end]).map_err(|_| 400u16)?;
    let mut lines = headers.split("\r\n");
    let mut request_line = lines.next().ok_or(400u16)?.split_whitespace();
    let method = request_line.next().ok_or(400u16)?.to_string();
    let path = request_line.next().ok_or(400u16)?.to_string();
    if request_line.next().is_none() {
        return Err(400);
    }
    let mut length = None;
    let mut authorization = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or(400u16)?;
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(value.trim().parse::<usize>().map_err(|_| 400u16)?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(400);
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.trim().to_string());
        }
    }
    let length = length.unwrap_or(0);
    if length > MAX_BODY_BYTES {
        return Err(413);
    }
    let already_read = bytes.len().saturating_sub(header_end);
    if already_read > length {
        return Err(400);
    }
    while bytes.len() - header_end < length {
        let remaining = length - (bytes.len() - header_end);
        let chunk_len = remaining.min(buffer.len());
        let count = stream.read(&mut buffer[..chunk_len]).map_err(|_| 400u16)?;
        if count == 0 {
            return Err(400);
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok((method, path, authorization, bytes[header_end..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_scans_a_fixture_and_returns_cli_json_report() {
        let api = ScanApi::new(
            ApiAuthConfig {
                bearer_token: Some("test-token".to_string()),
            },
            JobLimits::default(),
        );
        let body = r#"{"source":"pub fn fixture() {}","file":"fixture.rs"}"#;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_connection(&mut stream, &api).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        write!(
            client,
            "POST /v1/scans HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        server.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        let response_body = response.split_once("\r\n\r\n").unwrap().1;
        let report: Value = serde_json::from_str(response_body).unwrap();
        let cli = serde_json::from_str::<Value>(
            &soroban_scan_core::report::render_json(&soroban_scan_core::engine::scan_source_str(
                "pub fn fixture() {}",
                "fixture.rs",
                &ScanConfig::default(),
                &RuleRegistry::with_default_rules(),
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(report["schema_version"], cli["schema_version"]);
        assert_eq!(
            report["findings"].as_array().unwrap().len(),
            cli["findings"].as_array().unwrap().len()
        );
    }
}
