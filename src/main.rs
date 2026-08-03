use colored::Colorize;
use oauth2_test_server::{IssuerConfig, OAuthTestServer};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Default, PartialEq, Eq)]
struct StartupOptions {
    config_path: Option<PathBuf>,
    scheme: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    default_user_id: Option<String>,
    require_state: Option<bool>,
    generate_client_secret_for_dcr: Option<bool>,
    access_token_expires_in: Option<u64>,
    refresh_token_expires_in: Option<u64>,
    authorization_code_expires_in: Option<u64>,
    cleanup_interval_secs: Option<u64>,
}

#[derive(Debug)]
enum ParseResult {
    Run(StartupOptions),
    Help,
    GenerateConfigSampleYaml,
    GenerateConfigEnvSample,
}

fn print_usage(program: &str) {
    eprintln!("Usage: {program} [options]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --config, -c <path>                     Load config from YAML/TOML file");
    eprintln!("  --scheme <http|https>                   Override issuer URL scheme");
    eprintln!("  --host <host>                           Override bind host");
    eprintln!("  --port <u16>                            Override bind port");
    eprintln!("  --default-user-id <sub>                 Override default user subject");
    eprintln!("  --require-state <true|false>            Override state requirement");
    eprintln!("  --generate-client-secret-for-dcr <bool> Override DCR client-secret generation");
    eprintln!("  --access-token-expires-in <seconds>     Override access token TTL");
    eprintln!("  --refresh-token-expires-in <seconds>    Override refresh token TTL");
    eprintln!("  --authorization-code-expires-in <secs>  Override auth code TTL");
    eprintln!("  --cleanup-interval-secs <seconds>       Override cleanup interval");
    eprintln!("  -generate-config-sample-yaml            Generate ./.config.sample.yaml and exit");
    eprintln!("  -generate-config-env-sample             Generate ./.config.sample.env and exit");
    eprintln!("  --help, -h                              Show this help message");
}

fn parse_bool(flag: &str, value: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(format!("invalid boolean for {flag}: {value}")),
    }
}

fn parse_number<T>(flag: &str, value: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    value
        .parse::<T>()
        .map_err(|_| format!("invalid value for {flag}: {value}"))
}

fn next_arg_value<I>(iter: &mut I, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    iter.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_startup_options<I>(args: I) -> Result<ParseResult, String>
where
    I: IntoIterator<Item = String>,
{
    let mut iter = args.into_iter();
    let _program = iter
        .next()
        .unwrap_or_else(|| "oauth2-test-server".to_string());

    let mut options = StartupOptions::default();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(ParseResult::Help),
            "-generate-config-sample-yaml" | "--generate-config-sample-yaml" => {
                return Ok(ParseResult::GenerateConfigSampleYaml)
            }
            "-generate-config-env-sample" | "--generate-config-env-sample" => {
                return Ok(ParseResult::GenerateConfigEnvSample)
            }
            "--config" | "-c" => {
                let path = next_arg_value(&mut iter, "--config")?;
                options.config_path = Some(PathBuf::from(path));
            }
            "--scheme" => options.scheme = Some(next_arg_value(&mut iter, "--scheme")?),
            "--host" => options.host = Some(next_arg_value(&mut iter, "--host")?),
            "--port" => {
                let value = next_arg_value(&mut iter, "--port")?;
                options.port = Some(parse_number("--port", &value)?);
            }
            "--default-user-id" => {
                options.default_user_id = Some(next_arg_value(&mut iter, "--default-user-id")?)
            }
            "--require-state" => {
                let value = next_arg_value(&mut iter, "--require-state")?;
                options.require_state = Some(parse_bool("--require-state", &value)?);
            }
            "--generate-client-secret-for-dcr" => {
                let value = next_arg_value(&mut iter, "--generate-client-secret-for-dcr")?;
                options.generate_client_secret_for_dcr = Some(parse_bool(
                    "--generate-client-secret-for-dcr",
                    &value,
                )?);
            }
            "--access-token-expires-in" => {
                let value = next_arg_value(&mut iter, "--access-token-expires-in")?;
                options.access_token_expires_in =
                    Some(parse_number("--access-token-expires-in", &value)?);
            }
            "--refresh-token-expires-in" => {
                let value = next_arg_value(&mut iter, "--refresh-token-expires-in")?;
                options.refresh_token_expires_in =
                    Some(parse_number("--refresh-token-expires-in", &value)?);
            }
            "--authorization-code-expires-in" => {
                let value = next_arg_value(&mut iter, "--authorization-code-expires-in")?;
                options.authorization_code_expires_in =
                    Some(parse_number("--authorization-code-expires-in", &value)?);
            }
            "--cleanup-interval-secs" => {
                let value = next_arg_value(&mut iter, "--cleanup-interval-secs")?;
                options.cleanup_interval_secs = Some(parse_number("--cleanup-interval-secs", &value)?);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(ParseResult::Run(options))
}

fn apply_env_overrides_with<F>(config: &mut IssuerConfig, mut get_env: F) -> Result<(), String>
where
    F: FnMut(&str) -> Option<String>,
{
    if let Some(v) = get_env("OAUTH_SCHEME") {
        config.scheme = v;
    }
    if let Some(v) = get_env("OAUTH_HOST") {
        config.host = v;
    }
    if let Some(v) = get_env("OAUTH_PORT") {
        config.port = parse_number("OAUTH_PORT", &v)?;
    }
    if let Some(v) = get_env("OAUTH_DEFAULT_USER_ID") {
        config.default_user_id = v;
    }
    if let Some(v) = get_env("OAUTH_REQUIRE_STATE") {
        config.require_state = parse_bool("OAUTH_REQUIRE_STATE", &v)?;
    }
    if let Some(v) = get_env("OAUTH_GENERATE_CLIENT_SECRET_FOR_DCR") {
        config.generate_client_secret_for_dcr =
            parse_bool("OAUTH_GENERATE_CLIENT_SECRET_FOR_DCR", &v)?;
    }
    if let Some(v) = get_env("OAUTH_ACCESS_TOKEN_EXPIRES_IN") {
        config.access_token_expires_in = parse_number("OAUTH_ACCESS_TOKEN_EXPIRES_IN", &v)?;
    }
    if let Some(v) = get_env("OAUTH_REFRESH_TOKEN_EXPIRES_IN") {
        config.refresh_token_expires_in = parse_number("OAUTH_REFRESH_TOKEN_EXPIRES_IN", &v)?;
    }
    if let Some(v) = get_env("OAUTH_AUTHORIZATION_CODE_EXPIRES_IN") {
        config.authorization_code_expires_in =
            parse_number("OAUTH_AUTHORIZATION_CODE_EXPIRES_IN", &v)?;
    }
    if let Some(v) = get_env("OAUTH_CLEANUP_INTERVAL_SECS") {
        config.cleanup_interval_secs = parse_number("OAUTH_CLEANUP_INTERVAL_SECS", &v)?;
    }

    Ok(())
}

fn apply_cli_overrides(config: &mut IssuerConfig, options: &StartupOptions) {
    if let Some(v) = &options.scheme {
        config.scheme = v.clone();
    }
    if let Some(v) = &options.host {
        config.host = v.clone();
    }
    if let Some(v) = options.port {
        config.port = v;
    }
    if let Some(v) = &options.default_user_id {
        config.default_user_id = v.clone();
    }
    if let Some(v) = options.require_state {
        config.require_state = v;
    }
    if let Some(v) = options.generate_client_secret_for_dcr {
        config.generate_client_secret_for_dcr = v;
    }
    if let Some(v) = options.access_token_expires_in {
        config.access_token_expires_in = v;
    }
    if let Some(v) = options.refresh_token_expires_in {
        config.refresh_token_expires_in = v;
    }
    if let Some(v) = options.authorization_code_expires_in {
        config.authorization_code_expires_in = v;
    }
    if let Some(v) = options.cleanup_interval_secs {
        config.cleanup_interval_secs = v;
    }
}

fn load_config_with<F>(options: &StartupOptions, get_env: F) -> Result<IssuerConfig, String>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut config = if let Some(path) = &options.config_path {
        #[cfg(feature = "config")]
        {
            IssuerConfig::from_file(path)
                .map_err(|err| format!("failed to load config file {}: {err}", path.display()))?
        }

        #[cfg(not(feature = "config"))]
        {
            return Err(
                "this binary was built without the 'config' feature; --config is unavailable"
                    .to_string(),
            );
        }
    } else {
        IssuerConfig {
            port: 8090,
            ..Default::default()
        }
    };

    apply_env_overrides_with(&mut config, get_env)?;
    apply_cli_overrides(&mut config, options);

    Ok(config)
}

fn load_config(options: &StartupOptions) -> Result<IssuerConfig, String> {
    load_config_with(options, |key| std::env::var(key).ok())
}

#[cfg(feature = "config")]
fn generate_config_sample_file_at(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Err(format!("{} already exists", path.display()));
    }

    let sample = IssuerConfig::to_sample_yaml()
        .map_err(|err| format!("failed to generate sample config content: {err}"))?;
    std::fs::write(path, sample)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))
}

#[cfg(not(feature = "config"))]
fn generate_config_sample_file_at(_path: &Path) -> Result<(), String> {
    Err("this binary was built without the 'config' feature; sample generation is unavailable"
        .to_string())
}

fn generate_config_sample_file() -> Result<(), String> {
    generate_config_sample_file_at(Path::new("./.config.sample.yaml"))
}

#[cfg(feature = "config")]
fn generate_config_env_sample_file_at(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Err(format!("{} already exists", path.display()));
    }

    let sample = IssuerConfig::to_sample_env()
        .map_err(|err| format!("failed to generate sample env config content: {err}"))?;
    std::fs::write(path, sample)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))
}

#[cfg(not(feature = "config"))]
fn generate_config_env_sample_file_at(_path: &Path) -> Result<(), String> {
    Err("this binary was built without the 'config' feature; sample generation is unavailable"
        .to_string())
}

fn generate_config_env_sample_file() -> Result<(), String> {
    generate_config_env_sample_file_at(Path::new("./.config.sample.env"))
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt::init();

    let startup = match parse_startup_options(std::env::args()) {
        Ok(ParseResult::Run(startup)) => startup,
        Ok(ParseResult::Help) => {
            print_usage("oauth2-test-server");
            return ExitCode::SUCCESS;
        }
        Ok(ParseResult::GenerateConfigSampleYaml) => {
            if let Err(err) = generate_config_sample_file() {
                eprintln!("{err}");
                return ExitCode::from(2);
            }
            println!("Generated ./.config.sample.yaml");
            return ExitCode::SUCCESS;
        }
        Ok(ParseResult::GenerateConfigEnvSample) => {
            if let Err(err) = generate_config_env_sample_file() {
                eprintln!("{err}");
                return ExitCode::from(2);
            }
            println!("Generated ./.config.sample.env");
            return ExitCode::SUCCESS;
        }
        Err(err) => {
            eprintln!("{err}");
            print_usage("oauth2-test-server");
            return ExitCode::from(2);
        }
    };

    let config = match load_config(&startup) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(2);
        }
    };

    let server = OAuthTestServer::start_with_config(config).await;

    println!(
        "{} {}",
        "OAuth Test Server running on".green().bold(),
        server.base_url().to_string().blue().bold()
    );
    println!(" {} {}", "• Discovery:".bold(), server.endpoints.discovery);
    println!(" {} {}", "• Jwks:".bold(), server.endpoints.jwks);
    println!(" {} {}", "• Authorize:".bold(), server.endpoints.authorize);
    println!(" {} {}", "• Token:".bold(), server.endpoints.token);
    println!(
        " {} {}",
        "• Device Code:".bold(),
        server.endpoints.device_code
    );
    println!(
        " {} {}",
        "• Device Token:".bold(),
        server.endpoints.device_token
    );
    println!(" {} {}", "• Register:".bold(), server.endpoints.register);
    println!(
        " {} {}",
        "• Introspection:".bold(),
        server.endpoints.introspect
    );
    println!(" {} {}", "• UserInfo:".bold(), server.endpoints.userinfo);
    println!(" {} {}", "• Revoke:".bold(), server.endpoints.revoke);

    if let Err(err) = server.wait_for_shutdown().await {
        eprintln!("{err}");
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {

    use super::{
        apply_env_overrides_with, generate_config_env_sample_file_at,
        generate_config_sample_file_at, load_config_with, parse_startup_options, ParseResult,
        StartupOptions,
    };
    use base64::{engine::general_purpose, Engine};
    use oauth2_test_server::models::IdTokenClaims;
    use oauth2_test_server::testkit::AuthorizeParams;
    use oauth2_test_server::IssuerConfig;
    use reqwest::StatusCode;

    #[test]
    fn parse_startup_options_accepts_config_path() {
        let args = vec![
            "oauth2-test-server".to_string(),
            "--config".to_string(),
            "./config.sample.yaml".to_string(),
        ];

        let parsed = parse_startup_options(args).unwrap();
        let ParseResult::Run(options) = parsed else {
            panic!("expected ParseResult::Run");
        };

        assert_eq!(
            options,
            StartupOptions {
                config_path: Some(std::path::PathBuf::from("./config.sample.yaml")),
                ..Default::default()
            }
        );
    }

    #[test]
    fn parse_startup_options_rejects_missing_config_value() {
        let args = vec!["oauth2-test-server".to_string(), "--config".to_string()];
        let err = parse_startup_options(args).unwrap_err();
        assert!(err.contains("missing value for --config"));
    }

    #[test]
    fn parse_startup_options_rejects_unknown_argument() {
        let args = vec!["oauth2-test-server".to_string(), "--bogus".to_string()];
        let err = parse_startup_options(args).unwrap_err();
        assert!(err.contains("unknown argument"));
    }

    #[test]
    fn parse_startup_options_accepts_scalar_overrides() {
        let args = vec![
            "oauth2-test-server".to_string(),
            "--port".to_string(),
            "8088".to_string(),
            "--require-state".to_string(),
            "false".to_string(),
            "--default-user-id".to_string(),
            "alice".to_string(),
            "--access-token-expires-in".to_string(),
            "7200".to_string(),
        ];

        let parsed = parse_startup_options(args).unwrap();
        let ParseResult::Run(options) = parsed else {
            panic!("expected ParseResult::Run");
        };

        assert_eq!(options.port, Some(8088));
        assert_eq!(options.require_state, Some(false));
        assert_eq!(options.default_user_id.as_deref(), Some("alice"));
        assert_eq!(options.access_token_expires_in, Some(7200));
    }

    #[test]
    fn parse_startup_options_rejects_invalid_scalar_override() {
        let args = vec![
            "oauth2-test-server".to_string(),
            "--port".to_string(),
            "not-a-number".to_string(),
        ];
        let err = parse_startup_options(args).unwrap_err();
        assert!(err.contains("invalid value for --port"));
    }

    #[test]
    fn parse_startup_options_accepts_generate_config_sample_yaml_flag() {
        let args = vec![
            "oauth2-test-server".to_string(),
            "-generate-config-sample-yaml".to_string(),
        ];

        let parsed = parse_startup_options(args).unwrap();
        assert!(matches!(parsed, ParseResult::GenerateConfigSampleYaml));
    }

    #[test]
    fn parse_startup_options_accepts_generate_config_env_sample_flag() {
        let args = vec![
            "oauth2-test-server".to_string(),
            "-generate-config-env-sample".to_string(),
        ];

        let parsed = parse_startup_options(args).unwrap();
        assert!(matches!(parsed, ParseResult::GenerateConfigEnvSample));
    }

    #[cfg(feature = "config")]
    #[test]
    fn generate_config_sample_file_at_creates_file_and_rejects_existing_path() {
        let temp_dir = std::env::temp_dir().join(format!(
            "oauth2-test-server-config-sample-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join(".config.sample.yaml");

        generate_config_sample_file_at(&file_path).unwrap();

        let created = std::fs::read_to_string(&file_path).unwrap();
        assert!(created.contains("# OAuth2 Test Server — Sample Configuration"));
        assert!(created.contains("scheme:"));
        assert!(created.contains("id_token_signing_alg_values_supported:"));

        let err = generate_config_sample_file_at(&file_path).unwrap_err();
        assert!(err.contains("already exists"));

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[cfg(feature = "config")]
    #[test]
    fn generate_config_env_sample_file_at_creates_file_and_rejects_existing_path() {
        let temp_dir = std::env::temp_dir().join(format!(
            "oauth2-test-server-env-config-sample-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join(".config.sample.env");

        generate_config_env_sample_file_at(&file_path).unwrap();

        let created = std::fs::read_to_string(&file_path).unwrap();
        assert!(created.contains("# OAuth2 Test Server — Sample Environment Configuration"));
        assert!(created.contains("OAUTH_SCHEME="));
        assert!(created.contains("OAUTH_ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED="));

        let err = generate_config_env_sample_file_at(&file_path).unwrap_err();
        assert!(err.contains("already exists"));

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn load_config_uses_defaults_when_no_path_is_provided() {
        let config = load_config_with(&StartupOptions::default(), |_| None).unwrap();
        assert_eq!(config.port, 8090);
    }

    #[cfg(feature = "config")]
    #[test]
    fn load_config_reads_yaml_file() {
        let temp_path = std::env::temp_dir().join(format!(
            "oauth2-test-server-config-{}.yaml",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&temp_path, "port: 4711\ndefault_user_id: from-file\n").unwrap();

        let options = StartupOptions {
            config_path: Some(temp_path.clone()),
            ..Default::default()
        };
        let config = load_config_with(&options, |_| None).unwrap();

        assert_eq!(config.port, 4711);
        assert_eq!(config.default_user_id, "from-file");

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn env_overrides_apply_only_when_present() {
        let mut config = IssuerConfig {
            host: "from-file".to_string(),
            port: 8000,
            require_state: true,
            ..Default::default()
        };

        apply_env_overrides_with(&mut config, |key| match key {
            "OAUTH_HOST" => Some("from-env".to_string()),
            "OAUTH_REQUIRE_STATE" => Some("false".to_string()),
            _ => None,
        })
        .unwrap();

        assert_eq!(config.host, "from-env");
        assert_eq!(config.port, 8000);
        assert!(!config.require_state);
    }

    #[test]
    fn env_overrides_reject_invalid_values() {
        let mut config = IssuerConfig::default();
        let err = apply_env_overrides_with(&mut config, |key| match key {
            "OAUTH_PORT" => Some("bad-port".to_string()),
            _ => None,
        })
        .unwrap_err();

        assert!(err.contains("invalid value for OAUTH_PORT"));
    }

    #[cfg(feature = "config")]
    #[test]
    fn load_config_applies_precedence_cli_over_env_over_file() {
        let temp_path = std::env::temp_dir().join(format!(
            "oauth2-test-server-config-precedence-{}.yaml",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(
            &temp_path,
            "port: 4711\ndefault_user_id: from-file\nrequire_state: true\n",
        )
        .unwrap();

        let options = StartupOptions {
            config_path: Some(temp_path.clone()),
            port: Some(7777),
            ..Default::default()
        };

        let config = load_config_with(&options, |key| match key {
            "OAUTH_PORT" => Some("9000".to_string()),
            "OAUTH_DEFAULT_USER_ID" => Some("from-env".to_string()),
            "OAUTH_REQUIRE_STATE" => Some("false".to_string()),
            _ => None,
        })
        .unwrap();

        assert_eq!(config.port, 7777);
        assert_eq!(config.default_user_id, "from-env");
        assert!(!config.require_state);

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn load_config_rejects_invalid_env_values() {
        let options = StartupOptions::default();
        let err = load_config_with(&options, |key| match key {
            "OAUTH_ACCESS_TOKEN_EXPIRES_IN" => Some("oops".to_string()),
            _ => None,
        })
        .unwrap_err();

        assert!(err.contains("invalid value for OAUTH_ACCESS_TOKEN_EXPIRES_IN"));
    }

    #[tokio::test]
    async fn test_id_token_in_auth_code_flow() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid profile email",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();
        let nonce = "test-nonce-123";

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid profile email")
                .nonce(nonce)
                .pkce(pkce.clone()),
        );

        let code = server.approve_consent(&auth_url, "test-user").await;
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        assert!(token_response.get("access_token").is_some());
        assert!(token_response.get("id_token").is_some());

        let id_token = token_response["id_token"].as_str().unwrap();
        let parts: Vec<&str> = id_token.split('.').collect();
        let payload = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: IdTokenClaims = serde_json::from_slice(&payload).unwrap();

        assert_eq!(claims.nonce, Some(nonce.to_string()));
        assert!(claims.at_hash.is_some());
        assert!(claims.c_hash.is_some());
    }

    #[tokio::test]
    async fn test_id_token_omits_nonce_when_not_sent() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
            }))
            .await;

        let pkce = server.pkce_pair();

        let token = server
            .complete_auth_flow(
                &client,
                AuthorizeParams::new()
                    .redirect_uri("http://localhost:8080/callback")
                    .scope("openid")
                    .pkce(pkce.clone()),
                "test-user",
            )
            .await;

        let id_token = token["id_token"].as_str().unwrap();
        let parts: Vec<&str> = id_token.split('.').collect();
        let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload_str = std::str::from_utf8(&payload_bytes).unwrap();

        assert!(
            !payload_str.contains("\"nonce\""),
            "nonce key should be absent when no nonce was sent, got: {payload_str}"
        );
    }

    #[tokio::test]
    async fn test_no_id_token_without_openid_scope() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "profile email",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("profile email")
                .pkce(pkce.clone()),
        );

        let code = server.approve_consent(&auth_url, "test-user").await;
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        assert!(token_response.get("access_token").is_some());
        assert!(token_response.get("id_token").is_none());
    }

    #[tokio::test]
    async fn test_id_token_contains_user_claims() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid profile email",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid profile email")
                .pkce(pkce.clone()),
        );

        let code = server.approve_consent(&auth_url, "testuser123").await;
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        let id_token = token_response["id_token"].as_str().unwrap();
        let parts: Vec<&str> = id_token.split('.').collect();
        let payload = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: IdTokenClaims = serde_json::from_slice(&payload).unwrap();

        assert_eq!(claims.sub, "testuser123");
    }

    #[tokio::test]
    async fn test_id_token_has_standard_claims() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .pkce(pkce.clone()),
        );

        let code = server.approve_consent(&auth_url, "test-user").await;
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        let id_token = token_response["id_token"].as_str().unwrap();
        let parts: Vec<&str> = id_token.split('.').collect();
        let payload = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: IdTokenClaims = serde_json::from_slice(&payload).unwrap();

        assert!(claims.iss.starts_with("http"));
        assert!(!claims.sub.is_empty());
        assert!(claims.exp > claims.iat);
        assert!(claims.auth_time.is_some());
        assert!(claims.azp.is_some());
        assert!(claims.sid.is_some());
    }

    #[tokio::test]
    async fn test_prompt_consent() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .prompt("consent")
                .pkce(pkce.clone()),
        );

        let code = server.approve_consent(&auth_url, "test-user").await;
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        assert!(token_response.get("access_token").is_some());
    }

    #[tokio::test]
    async fn test_prompt_none_returns_error() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .prompt("none"),
        );

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn test_prompt_invalid_returns_error() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .prompt("invalid_prompt"),
        );

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn test_max_age_parameter() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .max_age("3600")
                .pkce(pkce.clone()),
        );

        let resp = server.http.get(auth_url.clone()).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_max_age_invalid_returns_error() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .max_age("not_a_number"),
        );

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn test_claims_parameter() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid profile email",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let claims_json = serde_json::json!({
            "id_token": {
                "email": {"essential": true},
                "name": {"essential": false}
            }
        })
        .to_string();

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid profile email")
                .claims(claims_json)
                .pkce(pkce.clone()),
        );

        let resp = server.http.get(auth_url.clone()).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_claims_invalid_returns_error() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .claims("not valid json"),
        );

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn test_ui_locales_parameter() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .ui_locales("en-US fr-FR"),
        );

        let resp = server.http.get(auth_url.clone()).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_response_mode_form_post() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .response_mode("form_post")
                .pkce(pkce.clone()),
        );

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.text().await.unwrap();
        assert!(body.contains("<form"));
        assert!(body.contains("method=\"POST\""));
        assert!(body.contains("name=\"code\""));
    }

    #[tokio::test]
    async fn test_unsupported_response_type() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams {
                response_type: "invalid",
                state: Some("test-state".to_string()),
                ..Default::default()
            },
        );

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=unsupported_response_type"));
    }

    #[tokio::test]
    async fn test_state_parameter_required() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(&client, AuthorizeParams::new().no_state());

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn test_state_returned_in_token_response() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();
        let state = "test-state-12345";

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .state(state)
                .pkce(pkce.clone()),
        );

        let code = server.approve_consent(&auth_url, "test-user").await;
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        assert!(token_response.get("state").is_some());
        assert_eq!(token_response["state"].as_str().unwrap(), state);
    }

    #[tokio::test]
    async fn test_token_expiration_check() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .pkce(pkce.clone()),
        );

        let code = server.approve_consent(&auth_url, "test-user").await;
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        let access_token = token_response["access_token"].as_str().unwrap();

        let introspection = server.introspect_token(&client, access_token).await;
        assert!(introspection["active"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_require_state_configurable() {
        use oauth2_test_server::IssuerConfig;

        let config = IssuerConfig {
            require_state: false,
            port: 0,
            ..Default::default()
        };

        let server = oauth2_test_server::OAuthTestServer::start_with_config(config).await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .no_state()
                .redirect_uri("http://localhost:8080/callback"),
        );

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        println!("Location: {}", location);
        assert!(location.contains("code="));
    }

    #[tokio::test]
    async fn test_device_code_flow() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid profile",
                "client_name": "test-device-client",
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"]
            }))
            .await;

        let scope = "openid profile".to_string();
        let device_code_resp = server
            .http
            .post(server.base_url.join("device/code").unwrap())
            .form(&[("client_id", &client.client_id), ("scope", &scope)])
            .send()
            .await
            .unwrap();

        assert_eq!(device_code_resp.status(), StatusCode::OK);

        let device_code_data: serde_json::Value = device_code_resp.json().await.unwrap();

        assert!(device_code_data.get("device_code").is_some());
        assert!(device_code_data.get("user_code").is_some());
        assert!(device_code_data.get("verification_uri").is_some());

        let device_code = device_code_data["device_code"].as_str().unwrap();

        server
            .approve_device_code(device_code, "test-device-user")
            .await;

        let token_resp = server
            .http
            .post(server.base_url.join("device/token").unwrap())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
                ("client_id", &client.client_id),
            ])
            .send()
            .await
            .unwrap();

        assert_eq!(token_resp.status(), StatusCode::OK);

        let token_data: serde_json::Value = token_resp.json().await.unwrap();

        assert!(token_data.get("access_token").is_some());
        assert!(token_data.get("refresh_token").is_some());
    }

    #[tokio::test]
    async fn test_device_code_invalid_client() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let scope = "openid".to_string();
        let device_code_resp = server
            .http
            .post(server.base_url.join("device/code").unwrap())
            .form(&[("client_id", "invalid-client"), ("scope", &scope)])
            .send()
            .await
            .unwrap();

        assert_eq!(device_code_resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_device_code_unauthorized() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "client_name": "test-client",
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"]
            }))
            .await;

        let scope = "openid".to_string();
        let device_code_resp = server
            .http
            .post(server.base_url.join("device/code").unwrap())
            .form(&[("client_id", &client.client_id), ("scope", &scope)])
            .send()
            .await
            .unwrap();

        let device_code_data: serde_json::Value = device_code_resp.json().await.unwrap();
        let device_code = device_code_data["device_code"].as_str().unwrap();

        let token_resp = server
            .http
            .post(server.base_url.join("device/token").unwrap())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
                ("client_id", &client.client_id),
            ])
            .send()
            .await
            .unwrap();

        let token_data: serde_json::Value = token_resp.json().await.unwrap();

        assert_eq!(token_data["error"], "authorization_pending");
    }

    #[tokio::test]
    async fn test_token_cleanup() {
        use oauth2_test_server::IssuerConfig;

        let config = IssuerConfig {
            cleanup_interval_secs: 1,
            access_token_expires_in: 2,
            port: 0,
            ..Default::default()
        };

        let server = oauth2_test_server::OAuthTestServer::start_with_config(config).await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .pkce(pkce.clone()),
        );

        let code = server.approve_consent(&auth_url, "test-user").await;
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        let access_token = token_response["access_token"].as_str().unwrap();

        let introspection = server.introspect_token(&client, access_token).await;
        assert!(introspection["active"].as_bool().unwrap());

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        let introspection_after = server.introspect_token(&client, access_token).await;
        assert!(!introspection_after["active"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_complete_auth_flow() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid profile email",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let token_response = server
            .complete_auth_flow(
                &client,
                AuthorizeParams::new()
                    .redirect_uri("http://localhost:8080/callback")
                    .scope("openid profile")
                    .pkce(pkce),
                "test-user",
            )
            .await;

        assert!(token_response.get("access_token").is_some());
        assert!(token_response.get("id_token").is_some());
        assert!(token_response.get("refresh_token").is_some());
    }

    #[tokio::test]
    async fn test_complete_device_flow() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid profile",
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
                "client_name": "test-device-client"
            }))
            .await;

        let token_response = server
            .complete_device_flow(&client, "openid profile", "device-user")
            .await;

        assert!(token_response.get("access_token").is_some());
        assert!(token_response.get("refresh_token").is_some());
    }
}
