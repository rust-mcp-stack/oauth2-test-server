use serde_json::{json, Value};
use std::collections::HashSet;

/// Server-level configuration for the OAuth2 / OIDC issuer.
///
/// Construct via [`IssuerConfig::default()`] and override individual fields,
/// or build one from scratch for full control.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IssuerConfig {
    #[serde(default = "default_scheme")]
    pub scheme: String,
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default)]
    pub port: u16,

    // OIDC / OAuth capabilities
    #[serde(default = "default_scopes_supported")]
    pub scopes_supported: HashSet<String>,
    #[serde(default = "default_claims_supported")]
    pub claims_supported: Vec<String>,
    #[serde(default = "default_grant_types_supported")]
    pub grant_types_supported: HashSet<String>,
    #[serde(default = "default_response_types_supported")]
    pub response_types_supported: HashSet<String>,
    #[serde(default = "default_token_endpoint_auth_methods_supported")]
    pub token_endpoint_auth_methods_supported: HashSet<String>,
    #[serde(default = "default_code_challenge_methods_supported")]
    pub code_challenge_methods_supported: HashSet<String>,
    #[serde(default = "default_subject_types_supported")]
    pub subject_types_supported: Vec<String>,
    #[serde(default = "default_id_token_signing_alg_values_supported")]
    pub id_token_signing_alg_values_supported: Vec<String>,

    #[serde(default = "default_generate_client_secret")]
    pub generate_client_secret_for_dcr: bool,

    /// CORS origins to allow. If empty, all origins are allowed.
    #[serde(default)]
    pub allowed_origins: Vec<String>,

    /// Default `sub` claim value used when no user is logged in.
    #[serde(default = "default_user_id")]
    pub default_user_id: String,

    /// Require `state` parameter in authorization requests (RFC 6749 compliance).
    /// Default: true
    #[serde(default = "default_true")]
    pub require_state: bool,

    /// Access token expiration time in seconds.
    /// Default: 3600 (1 hour)
    #[serde(default = "default_access_token_expires")]
    pub access_token_expires_in: u64,

    /// Refresh token expiration time in seconds.
    /// Default: 86400 * 30 (30 days)
    #[serde(default = "default_refresh_token_expires")]
    pub refresh_token_expires_in: u64,

    /// Authorization code expiration time in seconds.
    /// Default: 600 (10 minutes)
    #[serde(default = "default_code_expires")]
    pub authorization_code_expires_in: u64,

    /// Cleanup interval for expired tokens/codes in seconds.
    /// Default: 300 (5 minutes). Set to 0 to disable.
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,
}

fn default_true() -> bool {
    true
}
fn default_access_token_expires() -> u64 {
    3600
}
fn default_refresh_token_expires() -> u64 {
    86400 * 30
}
fn default_code_expires() -> u64 {
    600
}
fn default_cleanup_interval() -> u64 {
    300
}

fn default_scheme() -> String {
    "http".into()
}
fn default_host() -> String {
    "localhost".into()
}
fn default_generate_client_secret() -> bool {
    true
}
fn default_user_id() -> String {
    "test-user-123".into()
}

fn default_scopes_supported() -> HashSet<String> {
    [
        "openid",
        "profile",
        "email",
        "offline_access",
        "address",
        "phone",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_claims_supported() -> Vec<String> {
    vec![
        "sub".to_string(),
        "name".to_string(),
        "given_name".to_string(),
        "family_name".to_string(),
        "email".to_string(),
        "email_verified".to_string(),
        "picture".to_string(),
        "locale".to_string(),
    ]
}
fn default_grant_types_supported() -> HashSet<String> {
    ["authorization_code", "refresh_token", "client_credentials"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_response_types_supported() -> HashSet<String> {
    ["code", "token", "id_token"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_token_endpoint_auth_methods_supported() -> HashSet<String> {
    [
        "client_secret_basic",
        "client_secret_post",
        "none",
        "private_key_jwt",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_code_challenge_methods_supported() -> HashSet<String> {
    ["plain", "S256"].iter().map(|s| s.to_string()).collect()
}
fn default_subject_types_supported() -> Vec<String> {
    vec!["public".to_string()]
}
fn default_id_token_signing_alg_values_supported() -> Vec<String> {
    vec!["RS256".to_string()]
}

impl Default for IssuerConfig {
    fn default() -> Self {
        let mut scopes = HashSet::new();
        scopes.extend([
            "openid".into(),
            "profile".into(),
            "email".into(),
            "offline_access".into(),
            "address".into(),
            "phone".into(),
        ]);

        let mut grants = HashSet::new();
        grants.extend([
            "authorization_code".into(),
            "refresh_token".into(),
            "client_credentials".into(),
        ]);

        let mut auth_methods = HashSet::new();
        auth_methods.extend([
            "client_secret_basic".into(),
            "client_secret_post".into(),
            "none".into(),
            "private_key_jwt".into(),
        ]);

        Self {
            scheme: "http".into(),
            host: "localhost".into(),
            port: 0, // 0 = OS assigns a random free port
            scopes_supported: scopes,
            claims_supported: vec![
                "sub".into(),
                "name".into(),
                "given_name".into(),
                "family_name".into(),
                "email".into(),
                "email_verified".into(),
                "picture".into(),
                "locale".into(),
            ],
            generate_client_secret_for_dcr: true,
            grant_types_supported: grants,
            response_types_supported: ["code".into(), "token".into(), "id_token".into()].into(),
            token_endpoint_auth_methods_supported: auth_methods,
            code_challenge_methods_supported: ["plain".into(), "S256".into()].into(),
            subject_types_supported: vec!["public".into()],
            id_token_signing_alg_values_supported: vec!["RS256".into()],
            // Empty by default → CorsLayer uses AllowOrigin::any()
            allowed_origins: vec![],
            default_user_id: "test-user-123".into(),
            require_state: true,
            access_token_expires_in: 3600,
            refresh_token_expires_in: 86400 * 30,
            authorization_code_expires_in: 600,
            cleanup_interval_secs: 300,
        }
    }
}

impl IssuerConfig {
    /// Load configuration from environment variables, prefixed with `OAUTH_`.
    pub fn from_env() -> Result<Self, envy::Error> {
        dotenvy::dotenv().ok();
        envy::prefixed("OAUTH_").from_env::<Self>()
    }

    /// Build the OpenID Connect Discovery document for this issuer.
    pub fn to_discovery_document(&self, issuer: String) -> Value {
        let iss = issuer;
        json!({
            "issuer": iss,
            "authorization_endpoint": format!("{}/authorize", iss),
            "token_endpoint": format!("{}/token", iss),
            "userinfo_endpoint": format!("{}/userinfo", iss),
            "jwks_uri": format!("{}/.well-known/jwks.json", iss),
            "registration_endpoint": format!("{}/register", iss),
            "revocation_endpoint": format!("{}/revoke", iss),
            "introspection_endpoint": format!("{}/introspect", iss),
            "scopes_supported": self.scopes_supported.iter().collect::<Vec<_>>(),
            "claims_supported": &self.claims_supported,
            "grant_types_supported": self.grant_types_supported.iter().collect::<Vec<_>>(),
            "response_types_supported": self.response_types_supported.iter().collect::<Vec<_>>(),
            "token_endpoint_auth_methods_supported": self.token_endpoint_auth_methods_supported.iter().collect::<Vec<_>>(),
            "code_challenge_methods_supported": self.code_challenge_methods_supported.iter().collect::<Vec<_>>(),
            "subject_types_supported": &self.subject_types_supported,
            "id_token_signing_alg_values_supported": &self.id_token_signing_alg_values_supported,
        })
    }

    /// Validates that all requested scopes are in `scopes_supported`.
    /// Returns the original scope string on success, or an error message on failure.
    pub fn validate_scope(&self, scope: &str) -> Result<String, String> {
        let requested: HashSet<_> = scope.split_whitespace().map(|s| s.to_string()).collect();
        let unknown: Vec<_> = requested
            .difference(&self.scopes_supported)
            .cloned()
            .collect();
        if unknown.is_empty() {
            Ok(scope.to_string())
        } else {
            Err(format!("invalid_scope: {}", unknown.join(" ")))
        }
    }

    /// Returns `true` if the given grant type is in `grant_types_supported`.
    pub fn validate_grant_type(&self, grant: &str) -> bool {
        self.grant_types_supported.contains(grant)
    }

    /// Load configuration from a file (YAML or TOML).
    /// The format is detected from the file extension.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = IssuerConfig::from_file("config.yaml").unwrap();
    /// let config = IssuerConfig::from_file("config.toml").unwrap();
    /// ```
    #[cfg(feature = "config")]
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        use std::fs;

        let content = fs::read_to_string(path)?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        match ext.to_lowercase().as_str() {
            "yaml" | "yml" => Self::from_yaml(&content),
            "toml" => Self::from_toml(&content),
            _ => Err(ConfigError::UnsupportedFormat(ext.to_string())),
        }
    }

    /// Load configuration from YAML string.
    #[cfg(feature = "config")]
    pub fn from_yaml(yaml: &str) -> Result<Self, ConfigError> {
        serde_yaml::from_str(yaml).map_err(ConfigError::YamlParseError)
    }

    /// Load configuration from TOML string.
    #[cfg(feature = "config")]
    pub fn from_toml(toml_str: &str) -> Result<Self, ConfigError> {
        toml::from_str(toml_str).map_err(ConfigError::TomlParseError)
    }

    /// Generate a commented YAML sample that includes every configurable option.
    ///
    /// The rendered fields are derived from `IssuerConfig` serialization so newly
    /// added fields automatically appear in the generated output.
    #[cfg(feature = "config")]
    pub fn to_sample_yaml() -> Result<String, ConfigError> {
        let sample = Self {
            port: 8090,
            ..Default::default()
        };

        let value = serde_yaml::to_value(&sample).map_err(ConfigError::YamlSerializeError)?;
        let mut mapping = value
            .as_mapping()
            .cloned()
            .ok_or(ConfigError::SampleGenerationError(
                "issuer config did not serialize to a mapping".to_string(),
            ))?;

        let mut out = String::new();
        out.push_str("# OAuth2 Test Server — Sample Configuration\n");
        out.push_str("# Copy this file, edit the values, and load it via\n");
        out.push_str("#   IssuerConfig::from_file(\"path/to/config.yaml\")\n");
        out.push_str("#\n");
        out.push_str("# All fields are optional — defaults are shown below.\n");

        let ordered_sections = sample_sections();
        let inline_comments = sample_inline_comments();

        for (section_header, keys) in ordered_sections {
            out.push_str("\n");
            out.push_str(section_header);
            out.push_str("\n");

            for key in keys {
                if let Some(field_value) = take_mapping_field(&mut mapping, key) {
                    let comment = inline_comments.get(key).copied();
                    append_yaml_field(&mut out, key, &field_value, comment)?;
                }
            }
        }

        let mut extras = mapping
            .into_iter()
            .filter_map(|(k, v)| match k {
                serde_yaml::Value::String(name) => Some((name, v)),
                _ => None,
            })
            .collect::<Vec<_>>();
        extras.sort_by(|(left, _), (right, _)| left.cmp(right));

        if !extras.is_empty() {
            out.push_str("\n# --- Additional Options ---\n");
            for (name, field_value) in extras {
                append_yaml_field(&mut out, &name, &field_value, None)?;
            }
        }

        Ok(out)
    }

    /// Generate a commented .env sample that includes every configurable option.
    ///
    /// The rendered fields are derived from `IssuerConfig` serialization so newly
    /// added fields automatically appear in the generated output.
    #[cfg(feature = "config")]
    pub fn to_sample_env() -> Result<String, ConfigError> {
        let sample = Self {
            port: 8090,
            ..Default::default()
        };

        let value = serde_yaml::to_value(&sample).map_err(ConfigError::YamlSerializeError)?;
        let mut mapping = value
            .as_mapping()
            .cloned()
            .ok_or(ConfigError::SampleGenerationError(
                "issuer config did not serialize to a mapping".to_string(),
            ))?;

        let mut out = String::new();
        out.push_str("# OAuth2 Test Server — Sample Environment Configuration\n");
        out.push_str("# Copy this file, edit values, and then export/source it before running oauth2-test-server\n");
        out.push_str("#\n");
        out.push_str("# All fields are optional — defaults are shown below.\n");

        let ordered_sections = sample_sections();
        let inline_comments = sample_inline_comments();

        for (section_header, keys) in ordered_sections {
            out.push_str("\n");
            out.push_str(section_header);
            out.push_str("\n");

            for key in keys {
                if let Some(field_value) = take_mapping_field(&mut mapping, key) {
                    let env_key = config_key_to_env_var(key);
                    let rendered = render_env_value(&field_value)?;

                    out.push_str(&env_key);
                    out.push('=');
                    out.push_str(&rendered);
                    if let Some(comment) = inline_comments.get(key).copied() {
                        out.push_str(" # ");
                        out.push_str(comment);
                    }
                    out.push('\n');
                }
            }
        }

        let mut extras = mapping
            .into_iter()
            .filter_map(|(k, v)| match k {
                serde_yaml::Value::String(name) => Some((name, v)),
                _ => None,
            })
            .collect::<Vec<_>>();
        extras.sort_by(|(left, _), (right, _)| left.cmp(right));

        if !extras.is_empty() {
            out.push_str("\n# --- Additional Options ---\n");
            for (name, field_value) in extras {
                let env_key = config_key_to_env_var(&name);
                let rendered = render_env_value(&field_value)?;
                out.push_str(&env_key);
                out.push('=');
                out.push_str(&rendered);
                out.push('\n');
            }
        }

        Ok(out)
    }
}

#[cfg(feature = "config")]
fn sample_sections() -> [(&'static str, &'static [&'static str]); 5] {
    [
        ("# --- Server ---", &["scheme", "host", "port"]),
        ("# --- User Identity ---", &["default_user_id"]),
        (
            "# --- Security ---",
            &[
                "require_state",
                "generate_client_secret_for_dcr",
                "allowed_origins",
            ],
        ),
        (
            "# --- Token Lifetimes (seconds) ---",
            &[
                "access_token_expires_in",
                "refresh_token_expires_in",
                "authorization_code_expires_in",
                "cleanup_interval_secs",
            ],
        ),
        (
            "# --- OIDC Capabilities ---",
            &[
                "scopes_supported",
                "claims_supported",
                "grant_types_supported",
                "response_types_supported",
                "token_endpoint_auth_methods_supported",
                "code_challenge_methods_supported",
                "subject_types_supported",
                "id_token_signing_alg_values_supported",
            ],
        ),
    ]
}

#[cfg(feature = "config")]
fn sample_inline_comments() -> std::collections::HashMap<&'static str, &'static str> {
    [
        ("port", "0 = random free port"),
        ("default_user_id", "sub claim in tokens/userinfo"),
        (
            "require_state",
            "require state param in /authorize",
        ),
        (
            "generate_client_secret_for_dcr",
            "auto-generate secret on DCR",
        ),
        ("allowed_origins", "CORS (empty = allow all)"),
        ("access_token_expires_in", "1 hour"),
        ("refresh_token_expires_in", "30 days"),
        ("authorization_code_expires_in", "10 minutes"),
        (
            "cleanup_interval_secs",
            "cleanup expired every 5 min (0 = off)",
        ),
    ]
    .into_iter()
    .collect::<std::collections::HashMap<_, _>>()
}

#[cfg(feature = "config")]
fn config_key_to_env_var(key: &str) -> String {
    let mut out = String::with_capacity("OAUTH_".len() + key.len());
    out.push_str("OAUTH_");

    for ch in key.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }

    out
}

#[cfg(feature = "config")]
fn render_env_value(value: &serde_yaml::Value) -> Result<String, ConfigError> {
    match value {
        serde_yaml::Value::Null => Ok(String::new()),
        serde_yaml::Value::Bool(v) => Ok(v.to_string()),
        serde_yaml::Value::Number(v) => Ok(v.to_string()),
        serde_yaml::Value::String(v) => Ok(v.clone()),
        serde_yaml::Value::Sequence(items) => {
            let parts = items
                .iter()
                .map(render_env_scalar)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(parts.join(","))
        }
        _ => serde_json::to_string(value).map_err(|err| {
            ConfigError::SampleGenerationError(format!(
                "failed to render env value as JSON: {err}"
            ))
        }),
    }
}

#[cfg(feature = "config")]
fn render_env_scalar(value: &serde_yaml::Value) -> Result<String, ConfigError> {
    match value {
        serde_yaml::Value::Bool(v) => Ok(v.to_string()),
        serde_yaml::Value::Number(v) => Ok(v.to_string()),
        serde_yaml::Value::String(v) => Ok(v.clone()),
        serde_yaml::Value::Null => Ok(String::new()),
        _ => Err(ConfigError::SampleGenerationError(
            "unsupported nested value in sequence while rendering env sample".to_string(),
        )),
    }
}

#[cfg(feature = "config")]
fn take_mapping_field(
    mapping: &mut serde_yaml::Mapping,
    key: &str,
) -> Option<serde_yaml::Value> {
    mapping.remove(serde_yaml::Value::String(key.to_string()))
}

#[cfg(feature = "config")]
fn append_yaml_field(
    out: &mut String,
    key: &str,
    value: &serde_yaml::Value,
    inline_comment: Option<&str>,
) -> Result<(), ConfigError> {
    let rendered = serde_yaml::to_string(value)
        .map_err(ConfigError::YamlSerializeError)?
        .trim_end()
        .to_string();

    if rendered.contains('\n') {
        out.push_str(key);
        out.push_str(":\n");
        for line in rendered.lines() {
            out.push_str("  ");
            out.push_str(line);
            out.push('\n');
        }
    } else {
        out.push_str(key);
        out.push_str(": ");
        out.push_str(&rendered);
        if let Some(comment) = inline_comment {
            out.push_str(" # ");
            out.push_str(comment);
        }
        out.push('\n');
    }

    Ok(())
}

#[cfg(feature = "config")]
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML parse error: {0}")]
    YamlParseError(serde_yaml::Error),
    #[error("TOML parse error: {0}")]
    TomlParseError(toml::de::Error),
    #[error("YAML serialize error: {0}")]
    YamlSerializeError(serde_yaml::Error),
    #[error("Unsupported config format: {0}")]
    UnsupportedFormat(String),
    #[error("Sample generation error: {0}")]
    SampleGenerationError(String),
}

#[cfg(test)]
mod tests {
    use super::IssuerConfig;
    use std::collections::HashSet;

    #[cfg(feature = "config")]
    #[test]
    fn sample_yaml_includes_all_configurable_keys() {
        let sample_yaml = IssuerConfig::to_sample_yaml().unwrap();
        let sample_value: serde_yaml::Value = serde_yaml::from_str(&sample_yaml).unwrap();
        let sample_mapping = sample_value.as_mapping().unwrap();

        let defaults = IssuerConfig {
            port: 8090,
            ..Default::default()
        };
        let default_value = serde_yaml::to_value(defaults).unwrap();
        let default_mapping = default_value.as_mapping().unwrap();

        let sample_keys = sample_mapping
            .keys()
            .filter_map(|value| value.as_str().map(|s| s.to_string()))
            .collect::<HashSet<_>>();
        let default_keys = default_mapping
            .keys()
            .filter_map(|value| value.as_str().map(|s| s.to_string()))
            .collect::<HashSet<_>>();

        assert_eq!(sample_keys, default_keys);
    }

    #[cfg(feature = "config")]
    #[test]
    fn sample_yaml_contains_expected_comment_headers() {
        let sample_yaml = IssuerConfig::to_sample_yaml().unwrap();
        assert!(sample_yaml.contains("# OAuth2 Test Server — Sample Configuration"));
        assert!(sample_yaml.contains("# --- Server ---"));
        assert!(sample_yaml.contains("# --- OIDC Capabilities ---"));
    }

    #[cfg(feature = "config")]
    #[test]
    fn sample_env_contains_expected_comment_headers() {
        let sample_env = IssuerConfig::to_sample_env().unwrap();
        assert!(sample_env.contains("# OAuth2 Test Server — Sample Environment Configuration"));
        assert!(sample_env.contains("# --- Server ---"));
        assert!(sample_env.contains("# --- OIDC Capabilities ---"));
    }

    #[cfg(feature = "config")]
    #[test]
    fn sample_env_includes_all_configurable_keys() {
        let sample_env = IssuerConfig::to_sample_env().unwrap();
        let sample_keys = sample_env
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                line.split_once('=').map(|(key, _)| key.to_string())
            })
            .collect::<HashSet<_>>();

        let defaults = IssuerConfig {
            port: 8090,
            ..Default::default()
        };
        let default_value = serde_yaml::to_value(defaults).unwrap();
        let default_mapping = default_value.as_mapping().unwrap();

        let default_env_keys = default_mapping
            .keys()
            .filter_map(|value| value.as_str().map(super::config_key_to_env_var))
            .collect::<HashSet<_>>();

        assert_eq!(sample_keys, default_env_keys);
    }
}
