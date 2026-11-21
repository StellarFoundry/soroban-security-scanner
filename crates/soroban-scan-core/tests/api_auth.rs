//! Bearer authentication behavior and secret-handling tests.

use soroban_scan_core::api_auth::{
    ApiAuthConfig, ApiAuthError, MAX_API_AUTH_CONFIG_BYTES, MAX_API_BEARER_TOKEN_BYTES,
};

#[test]
fn configured_bearer_token_is_accepted() {
    let config = ApiAuthConfig::from_toml("[api]\nbearer_token = \"opaque-token_123\"\n").unwrap();

    assert_eq!(config.authenticate(Some("Bearer opaque-token_123")), Ok(()));
    assert_eq!(config.authenticate(Some("bearer opaque-token_123")), Ok(()));
}

#[test]
fn missing_invalid_and_malformed_credentials_are_rejected() {
    let config = ApiAuthConfig {
        bearer_token: Some("expected-token".to_string()),
    };

    for header in [
        None,
        Some("Basic expected-token"),
        Some("Bearer"),
        Some("Bearer "),
        Some("Bearer wrong-token"),
        Some("Bearer expected-token extra"),
        Some(" Bearer expected-token"),
    ] {
        assert_eq!(config.authenticate(header), Err(ApiAuthError::Unauthorized));
    }
}

#[test]
fn authentication_fails_closed_without_configuration() {
    assert_eq!(
        ApiAuthConfig::default().authenticate(Some("Bearer any-token")),
        Err(ApiAuthError::NotConfigured)
    );
    assert_eq!(
        ApiAuthConfig::default().authenticate(None),
        Err(ApiAuthError::NotConfigured)
    );
}

#[test]
fn invalid_secrets_are_rejected_without_echoing_them() {
    assert_eq!(
        ApiAuthConfig::from_toml("[api]\nbearer_token = \"\"\n"),
        Err(ApiAuthError::InvalidConfiguration)
    );
    assert_eq!(
        ApiAuthConfig::from_toml("[api]\nbearer_token = \"bad token\"\n"),
        Err(ApiAuthError::InvalidConfiguration)
    );
    assert_eq!(
        ApiAuthConfig::from_toml(&" ".repeat(MAX_API_AUTH_CONFIG_BYTES + 1)),
        Err(ApiAuthError::InvalidConfiguration)
    );
    let oversized = "a".repeat(MAX_API_BEARER_TOKEN_BYTES + 1);
    let config = ApiAuthConfig {
        bearer_token: Some(oversized),
    };
    assert_eq!(config.validate(), Err(ApiAuthError::InvalidConfiguration));
}

#[test]
fn configured_secret_is_redacted_from_debug_and_serialization() {
    let secret = "do-not-disclose-this-token";
    let config = ApiAuthConfig {
        bearer_token: Some(secret.to_string()),
    };

    assert!(!format!("{config:?}").contains(secret));
    assert!(!toml::to_string(&config).unwrap().contains(secret));
    assert!(!ApiAuthError::Unauthorized.to_string().contains(secret));
}
