use base64::{engine::general_purpose, Engine};
use chrono::{Duration, Utc};
use jsonwebtoken::jwk::{CommonParameters, Jwk};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use rsa::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::models::{Claims, IdTokenClaims};

/// RSA key pair used for signing and verifying JWT access tokens.
pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
    pub public_pem: String,
    /// Key ID embedded in JWT headers and JWKS; unique per server instance.
    pub kid: String,
}

impl Keys {
    /// Generate a fresh 2048-bit RSA key pair for this server instance.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();

        let private_key =
            RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate RSA key pair");
        let public_key = private_key.to_public_key();

        let private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("failed to encode private key as PKCS8 PEM")
            .to_string();

        let public_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .expect("failed to encode public key as PEM")
            .to_string();

        let encoding =
            EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("failed to build EncodingKey");
        let decoding =
            DecodingKey::from_rsa_pem(public_pem.as_bytes()).expect("failed to build DecodingKey");
        let kid = format!("key-{}", Uuid::new_v4());

        Keys {
            encoding,
            decoding,
            public_pem,
            kid,
        }
    }
}

/// Build the JWKS JSON document (public keys) for a given key set.
pub fn build_jwks_json(keys: &Keys) -> serde_json::Value {
    let public_key = rsa::RsaPublicKey::from_public_key_pem(&keys.public_pem)
        .expect("failed to re-parse stored public key");

    let jwk = Jwk {
        common: CommonParameters {
            key_algorithm: Some(jsonwebtoken::jwk::KeyAlgorithm::RS256),
            key_id: Some(keys.kid.clone()),
            ..Default::default()
        },
        algorithm: jsonwebtoken::jwk::AlgorithmParameters::RSA(
            jsonwebtoken::jwk::RSAKeyParameters {
                n: general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                e: general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
                key_type: jsonwebtoken::jwk::RSAKeyType::RSA,
            },
        ),
    };

    json!({ "keys": [jwk] })
}

/// Sign and return a JWT access token.
pub fn issue_jwt(
    issuer: &str,
    client_id: &str,
    user_id: &str,
    requested_scope: &str,
    expires_in: i64,
    keys: &Keys,
) -> Result<String, jsonwebtoken::errors::Error> {
    let iat = Utc::now().timestamp() as usize;
    let exp = (Utc::now() + Duration::seconds(expires_in)).timestamp() as usize;

    let scopes: Vec<&str> = requested_scope.split_whitespace().collect();

    let claims = Claims {
        iss: issuer.to_string(),
        sub: user_id.to_string(),
        aud: client_id.to_string(),
        exp,
        iat,
        scope: Some(scopes.join(" ")),
        auth_time: Some(iat),
        typ: "Bearer".to_string(),
        azp: Some(client_id.to_string()),
        sid: Some(format!("sid-{}", Uuid::new_v4())),
        jti: Uuid::new_v4().to_string(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_string());
    header.kid = Some(keys.kid.clone());

    encode(&header, &claims, &keys.encoding)
}

/// Generate a short authorization code.
pub fn generate_code() -> String {
    Uuid::new_v4().to_string()[..20].to_string()
}

/// Generate an opaque access/refresh token string.
pub fn generate_token_string() -> String {
    format!("tok_{}", Uuid::new_v4().to_string().replace("-", ""))
}

/// Calculate at_hash (Access Token Hash) per OIDC Core Section 3.2.2.9.
/// Used to validate that an access token was issued alongside an ID token.
pub fn calculate_at_hash(access_token: &str) -> String {
    let hash = Sha256::digest(access_token.as_bytes());
    let half = &hash[..hash.len() / 2];
    general_purpose::URL_SAFE_NO_PAD.encode(half)
}

/// Calculate c_hash (Code Hash) per OIDC Core Section 3.2.2.9.
/// Used to validate that an authorization code was issued alongside an ID token.
pub fn calculate_c_hash(authorization_code: &str) -> String {
    let hash = Sha256::digest(authorization_code.as_bytes());
    let half = &hash[..hash.len() / 2];
    general_purpose::URL_SAFE_NO_PAD.encode(half)
}

#[allow(clippy::too_many_arguments)]
/// Sign and return an ID Token per OpenID Connect Core 1.0.
pub fn issue_id_token(
    issuer: &str,
    client_id: &str,
    user_id: &str,
    nonce: Option<&str>,
    at_hash: Option<&str>,
    c_hash: Option<&str>,
    expires_in: i64,
    user_claims: serde_json::Value,
    keys: &Keys,
) -> Result<String, jsonwebtoken::errors::Error> {
    let iat = Utc::now().timestamp() as usize;
    let exp = (Utc::now() + Duration::seconds(expires_in)).timestamp() as usize;

    let mut claims = IdTokenClaims::new(issuer, user_id, client_id, exp, iat);

    if let Some(n) = nonce {
        claims = claims.with_nonce(n);
    }
    if let Some(hash) = at_hash {
        claims = claims.with_at_hash(hash);
    }
    if let Some(hash) = c_hash {
        claims = claims.with_c_hash(hash);
    }
    claims = claims.with_azp(client_id);
    claims = claims.with_user_claims(user_claims);

    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_string());
    header.kid = Some(keys.kid.clone());

    encode(&header, &claims, &keys.encoding)
}
