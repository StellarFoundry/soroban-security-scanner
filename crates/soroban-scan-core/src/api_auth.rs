//! Fail-closed bearer authentication for an opt-in scan API.

use serde::{Deserialize, Serialize};

/// Maximum API authentication configuration size (64 KiB).
pub const MAX_API_AUTH_CONFIG_BYTES: usize = 64 * 1024;
/// Maximum configured or presented bearer token length.
pub const MAX_API_BEARER_TOKEN_BYTES: usize = 4096;

/// Authentication settings for an API adapter.
///
/// The token is deliberately omitted from serialization and redacted from debug
/// output so diagnostic/config display paths cannot disclose it.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiAuthConfig {
    #[serde(skip_serializing)]
    pub bearer_token: Option<String>,
}

impl std::fmt::Debug for ApiAuthConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApiAuthConfig")
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Authentication failure. Messages never include credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApiAuthError {
    #[error("API authentication is not configured")]
    NotConfigured,
    #[error("missing or invalid bearer token")]
    Unauthorized,
    #[error("invalid API authentication configuration")]
    InvalidConfiguration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiConfigFile {
    api: ApiAuthConfig,
}

impl ApiAuthConfig {
    /// Parse the API section from a TOML configuration file and validate it.
    pub fn from_toml(text: &str) -> Result<Self, ApiAuthError> {
        if text.len() > MAX_API_AUTH_CONFIG_BYTES {
            return Err(ApiAuthError::InvalidConfiguration);
        }
        let config: ApiConfigFile =
            toml::from_str(text).map_err(|_| ApiAuthError::InvalidConfiguration)?;
        config.api.validate()?;
        Ok(config.api)
    }

    /// Validate the configured secret before an API server starts.
    pub fn validate(&self) -> Result<(), ApiAuthError> {
        if self
            .bearer_token
            .as_deref()
            .is_some_and(|token| !valid_bearer_token(token))
        {
            return Err(ApiAuthError::InvalidConfiguration);
        }
        Ok(())
    }

    /// Accept a request only when its bearer credential matches configuration.
    ///
    /// `None` is always rejected, so a server cannot become public by omitting
    /// authentication configuration. Header parsing is strict and token bytes
    /// are compared without an early exit.
    pub fn authenticate(&self, authorization: Option<&str>) -> Result<(), ApiAuthError> {
        self.validate()?;
        let expected = self
            .bearer_token
            .as_deref()
            .ok_or(ApiAuthError::NotConfigured)?;
        let header = authorization.ok_or(ApiAuthError::Unauthorized)?;
        let (scheme, provided) = header.split_once(' ').ok_or(ApiAuthError::Unauthorized)?;
        if !scheme.eq_ignore_ascii_case("Bearer") || !valid_bearer_token(provided) {
            return Err(ApiAuthError::Unauthorized);
        }
        if constant_time_eq(expected.as_bytes(), provided.as_bytes()) {
            Ok(())
        } else {
            Err(ApiAuthError::Unauthorized)
        }
    }
}

fn valid_bearer_token(token: &str) -> bool {
    if token.is_empty() || token.len() > MAX_API_BEARER_TOKEN_BYTES {
        return false;
    }
    let bytes = token.as_bytes();
    let first_padding = bytes.iter().position(|byte| *byte == b'=');
    let body = first_padding.map_or(bytes, |index| &bytes[..index]);
    let padding_is_valid =
        first_padding.is_none_or(|index| bytes[index..].iter().all(|byte| *byte == b'='));
    !body.is_empty()
        && padding_is_valid
        && body.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
}

fn constant_time_eq(expected: &[u8], provided: &[u8]) -> bool {
    let mut difference = expected.len() ^ provided.len();
    for index in 0..MAX_API_BEARER_TOKEN_BYTES {
        let expected_byte = expected.get(index).copied().unwrap_or_default();
        let provided_byte = provided.get(index).copied().unwrap_or_default();
        difference |= usize::from(expected_byte ^ provided_byte);
    }
    std::hint::black_box(difference) == 0
}
