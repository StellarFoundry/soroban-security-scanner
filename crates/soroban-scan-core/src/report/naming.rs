//! Deterministic report artifact names.
//!
//! The scheme is `<project>-<commit7>-<YYYYMMDDTHHMMSSZ>.<extension>`. Every
//! part is validated or sanitized: names never contain path separators, shell
//! metacharacters, credentials, or other secrets copied from free-form input.

use crate::report::OutputFormat;

/// Maximum length of the sanitized project label.
pub const MAX_PROJECT_LEN: usize = 64;
/// Minimum accepted length of a commit hash.
pub const MIN_COMMIT_LEN: usize = 7;
/// Maximum accepted length of a commit hash.
pub const MAX_COMMIT_LEN: usize = 64;

/// Sanitizes a project label for use in a file name.
///
/// Only ASCII letters, digits, `.`, `_`, and `-` are kept; every other run of
/// characters becomes a single `-`. The result is lowercased, trimmed, and
/// bounded, so a project name can never add a path separator or shell syntax.
pub fn sanitize_project(value: &str) -> Result<String, String> {
    let mut label = String::new();
    let mut pending_dash = false;
    for ch in value.chars() {
        if ch == '-' {
            pending_dash = !label.is_empty();
            continue;
        }
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' {
            if pending_dash && !label.is_empty() && !label.ends_with('-') {
                label.push('-');
            }
            pending_dash = false;
            label.push(ch);
        } else {
            pending_dash = !label.is_empty();
        }
    }
    let label = label.trim_matches(['-', '.']).to_ascii_lowercase();
    if label.is_empty() {
        return Err("project must contain at least one letter or digit".to_string());
    }
    Ok(label.chars().take(MAX_PROJECT_LEN).collect())
}

/// Returns the lowercase, 7-character short form of a commit hash.
pub fn short_commit(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.len() < MIN_COMMIT_LEN
        || value.len() > MAX_COMMIT_LEN
        || !value.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return Err(format!(
            "commit must be {MIN_COMMIT_LEN}-{MAX_COMMIT_LEN} hexadecimal characters"
        ));
    }
    Ok(value[..MIN_COMMIT_LEN].to_ascii_lowercase())
}

/// Parses a UTC timestamp in `YYYY-MM-DDTHH:MM:SSZ` form and returns the
/// compact `YYYYMMDDTHHMMSSZ` form used in artifact names.
pub fn parse_timestamp(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.len() != 20 || !value.ends_with('Z') || value.as_bytes()[10] != b'T' {
        return Err(format!(
            "timestamp must be a UTC YYYY-MM-DDTHH:MM:SSZ value, got '{value}'"
        ));
    }
    crate::config::validate_iso_date(&value[..10])?;
    let time = &value[11..19];
    let parts: Vec<&str> = time.split(':').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.len() != 2 || !part.chars().all(|ch| ch.is_ascii_digit()))
    {
        return Err(format!(
            "timestamp must be a UTC YYYY-MM-DDTHH:MM:SSZ value, got '{value}'"
        ));
    }
    let hour = parts[0].parse::<u32>().unwrap_or(24);
    let minute = parts[1].parse::<u32>().unwrap_or(60);
    let second = parts[2].parse::<u32>().unwrap_or(60);
    if hour > 23 || minute > 59 || second > 59 {
        return Err(format!("timestamp has an invalid time: '{value}'"));
    }
    Ok(format!(
        "{}{}{}T{}{}{}Z",
        &value[0..4],
        &value[5..7],
        &value[8..10],
        &time[0..2],
        &time[3..5],
        &time[6..8]
    ))
}

/// Returns the current UTC time in compact `YYYYMMDDTHHMMSSZ` form.
pub fn current_timestamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    let date = crate::config::utc_date_from_unix(seconds).replace('-', "");
    let seconds_of_day = seconds.rem_euclid(86_400);
    format!(
        "{date}T{:02}{:02}{:02}Z",
        seconds_of_day / 3_600,
        (seconds_of_day % 3_600) / 60,
        seconds_of_day % 60
    )
}

/// Returns the canonical extension for an output format.
pub fn extension(format: OutputFormat) -> &'static str {
    match format {
        OutputFormat::Json => "json",
        OutputFormat::Sarif => "sarif",
        OutputFormat::Markdown => "md",
        OutputFormat::Html => "html",
        OutputFormat::Junit => "xml",
        OutputFormat::Terminal | OutputFormat::Github => "txt",
    }
}

/// Builds the deterministic artifact name for a report.
pub fn artifact_name(
    project: &str,
    commit: &str,
    timestamp: Option<&str>,
    format: OutputFormat,
) -> Result<String, String> {
    let project = sanitize_project(project)?;
    let commit = short_commit(commit)?;
    let timestamp = match timestamp {
        Some(value) => parse_timestamp(value)?,
        None => current_timestamp(),
    };
    Ok(format!(
        "{project}-{commit}-{timestamp}.{}",
        extension(format)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_deterministic_name_from_validated_parts() {
        let name = artifact_name(
            "Vault Contract",
            "ABCDEF123456",
            Some("2024-03-01T10:20:30Z"),
            OutputFormat::Json,
        )
        .unwrap();
        assert_eq!(name, "vault-contract-abcdef1-20240301T102030Z.json");
        let again = artifact_name(
            "Vault Contract",
            "ABCDEF123456",
            Some("2024-03-01T10:20:30Z"),
            OutputFormat::Json,
        )
        .unwrap();
        assert_eq!(name, again);
    }

    #[test]
    fn sanitizes_project_names_without_path_or_shell_syntax() {
        assert_eq!(
            sanitize_project("../../etc/passwd; rm -rf ~").unwrap(),
            "etc-passwd-rm-rf"
        );
        assert_eq!(
            sanitize_project("Vault__Main.v2").unwrap(),
            "vault__main.v2"
        );
        assert!(sanitize_project("---").is_err());
    }

    #[test]
    fn rejects_invalid_commits_and_timestamps() {
        assert!(short_commit("abc").is_err());
        assert!(short_commit("not-hex!").is_err());
        assert!(parse_timestamp("2024-03-01 10:20:30").is_err());
        assert!(parse_timestamp("2024-02-30T10:20:30Z").is_err());
        assert!(parse_timestamp("2024-03-01T24:00:00Z").is_err());
    }

    #[test]
    fn current_timestamp_has_the_compact_shape() {
        let value = current_timestamp();
        assert_eq!(value.len(), 16, "{value}");
        assert_eq!(&value[8..9], "T");
        assert!(value.ends_with('Z'));
    }
}
