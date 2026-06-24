use oauth2_test_server::IssuerConfig;

#[test]
fn test_config_from_yaml() {
    let yaml = r#"
port: 8080
scheme: https
host: example.com
require_state: false
access_token_expires_in: 7200
cleanup_interval_secs: 0
"#;

    let config = IssuerConfig::from_yaml(yaml).unwrap();
    assert_eq!(config.port, 8080);
    assert_eq!(config.scheme, "https");
    assert_eq!(config.host, "example.com");
    assert!(!config.require_state);
    assert_eq!(config.access_token_expires_in, 7200);
    assert_eq!(config.cleanup_interval_secs, 0);
}

#[test]
fn test_config_from_toml() {
    let toml = r#"
port = 9090
scheme = "http"
host = "test.example.com"
require_state = false
access_token_expires_in = 1800
refresh_token_expires_in = 86400
cleanup_interval_secs = 600
"#;

    let config = IssuerConfig::from_toml(toml).unwrap();
    assert_eq!(config.port, 9090);
    assert_eq!(config.scheme, "http");
    assert_eq!(config.host, "test.example.com");
    assert!(!config.require_state);
    assert_eq!(config.access_token_expires_in, 1800);
    assert_eq!(config.refresh_token_expires_in, 86400);
    assert_eq!(config.cleanup_interval_secs, 600);
}

#[test]
fn test_config_defaults() {
    let config = IssuerConfig::default();
    assert_eq!(config.port, 0);
    assert_eq!(config.scheme, "http");
    assert_eq!(config.host, "localhost");
    assert!(config.require_state);
    assert_eq!(config.access_token_expires_in, 3600);
    assert_eq!(config.cleanup_interval_secs, 300);
}

#[test]
fn test_config_sample_file() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config.sample.yaml");
    let config = IssuerConfig::from_file(&path).unwrap();

    assert_eq!(config.scheme, "http");
    assert_eq!(config.host, "localhost");
    assert_eq!(config.port, 8090);
    assert_eq!(config.default_user_id, "test-user-123");
    assert!(config.require_state);
    assert!(config.generate_client_secret_for_dcr);
    assert!(config.allowed_origins.is_empty());
    assert_eq!(config.access_token_expires_in, 3600);
    assert_eq!(config.refresh_token_expires_in, 2592000);
    assert_eq!(config.authorization_code_expires_in, 600);
    assert_eq!(config.cleanup_interval_secs, 300);

    assert!(config.scopes_supported.contains("openid"));
    assert!(config.scopes_supported.contains("email"));
    assert!(config.claims_supported.contains(&"email".to_string()));
    assert!(config.grant_types_supported.contains("authorization_code"));
    assert!(config.response_types_supported.contains("code"));
    assert!(config
        .token_endpoint_auth_methods_supported
        .contains("none"));
    assert!(config.code_challenge_methods_supported.contains("S256"));
    assert_eq!(config.subject_types_supported, vec!["public"]);
    assert_eq!(config.id_token_signing_alg_values_supported, vec!["RS256"]);
}
