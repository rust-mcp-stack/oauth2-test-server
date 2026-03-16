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
