use chrono::Utc;
use serde::{Deserialize, Serialize};

/// A registered OAuth2 client (RFC 7591 Dynamic Client Registration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub scope: String,
    pub token_endpoint_auth_method: String,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub contacts: Vec<String>,
    pub policy_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub jwks: Option<serde_json::Value>,
    pub jwks_uri: Option<String>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub registration_access_token: Option<String>,
    pub registration_client_uri: Option<String>,
}

/// A short-lived authorization code used in the authorization code flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub user_id: String,
    pub nonce: Option<String>,
    pub state: Option<String>,
}

/// An issued access token (JWT) along with its metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub client_id: String,
    pub scope: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub user_id: String,
    pub revoked: bool,
}

/// JWT claims structure used for encoding/decoding access tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub scope: Option<String>,
    pub auth_time: Option<usize>,
    pub typ: String,
    pub azp: Option<String>,
    pub sid: Option<String>,
    pub jti: String,
}

/// ID Token claims structure per OpenID Connect Core 1.0.
/// Contains standard claims plus token hash values for security validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer identifier (must match the issuer URL)
    pub iss: String,
    /// Subject identifier (unique user ID)
    pub sub: String,
    /// Audience (client_id)
    pub aud: String,
    /// Expiration time
    pub exp: usize,
    /// Issued at time
    pub iat: usize,
    /// Authentication time
    pub auth_time: Option<usize>,
    /// Nonce value from authorization request (must be echoed if present)
    pub nonce: Option<String>,
    /// Access token hash (at_hash) - OIDC Core Section 3.2.2.9
    pub at_hash: Option<String>,
    /// Authorization code hash (c_hash) - OIDC Core Section 3.2.2.9
    pub c_hash: Option<String>,
    /// Authorized party (client_id)
    pub azp: Option<String>,
    /// Token type
    pub typ: Option<String>,
    /// Session ID
    pub sid: Option<String>,
    /// JWT ID
    pub jti: Option<String>,
    /// User claims (name, email, etc.)
    #[serde(flatten)]
    pub user_claims: serde_json::Value,
}

impl IdTokenClaims {
    /// Create new ID token claims with standard claims.
    pub fn new(
        issuer: &str,
        subject: &str,
        audience: &str,
        expires_at: usize,
        issued_at: usize,
    ) -> Self {
        Self {
            iss: issuer.to_string(),
            sub: subject.to_string(),
            aud: audience.to_string(),
            exp: expires_at,
            iat: issued_at,
            auth_time: Some(issued_at),
            nonce: None,
            at_hash: None,
            c_hash: None,
            azp: None,
            typ: Some("IDToken".to_string()),
            sid: Some(format!("sid-{}", uuid::Uuid::new_v4())),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            user_claims: serde_json::json!({}),
        }
    }

    /// Set nonce value.
    pub fn with_nonce(mut self, nonce: &str) -> Self {
        self.nonce = Some(nonce.to_string());
        self
    }

    /// Set access token hash (at_hash).
    pub fn with_at_hash(mut self, at_hash: &str) -> Self {
        self.at_hash = Some(at_hash.to_string());
        self
    }

    /// Set authorization code hash (c_hash).
    pub fn with_c_hash(mut self, c_hash: &str) -> Self {
        self.c_hash = Some(c_hash.to_string());
        self
    }

    /// Set authorized party.
    pub fn with_azp(mut self, azp: &str) -> Self {
        self.azp = Some(azp.to_string());
        self
    }

    /// Set user claims (name, email, picture, etc.).
    pub fn with_user_claims(mut self, claims: serde_json::Value) -> Self {
        self.user_claims = claims;
        self
    }
}

/// Device Code flow (RFC 8628) - Request sent by the device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeRequest {
    pub client_id: String,
    pub scope: Option<String>,
}

/// Device Code flow (RFC 8628) - Response from the authorization server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

/// Device Code flow (RFC 8628) - Polling token request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTokenRequest {
    pub grant_type: String,
    pub device_code: String,
    pub client_id: String,
    pub client_secret: Option<String>,
}

/// Device authorization state stored on the server
#[derive(Debug, Clone)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub user_id: Option<String>,
    pub approved: bool,
}
