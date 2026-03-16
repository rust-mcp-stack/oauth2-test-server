use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Centralized error type for OAuth2 endpoints that return JSON errors.
#[derive(Debug, Error)]
pub enum OauthError {
    #[error("invalid_request")]
    InvalidRequest(Option<String>),

    #[error("invalid_client")]
    InvalidClient,

    #[error("invalid_grant")]
    InvalidGrant,

    #[error("unauthorized_client")]
    UnauthorizedClient(Option<String>),

    #[error("unsupported_grant_type")]
    UnsupportedGrantType,

    #[error("invalid_scope")]
    InvalidScope(String),

    #[error("server_error")]
    ServerError,

    #[error("invalid_token")]
    InvalidToken(Option<String>),

    #[error("authorization_pending")]
    AuthorizationPending,

    #[error("slow_down")]
    SlowDown,

    #[error("expired_token")]
    ExpiredToken,

    #[error("{error}")]
    Custom {
        status: StatusCode,
        error: String,
        description: Option<String>,
    },
}

impl IntoResponse for OauthError {
    fn into_response(self) -> Response {
        let (status, error, description) = match &self {
            OauthError::InvalidRequest(desc) => {
                (StatusCode::BAD_REQUEST, "invalid_request", desc.clone())
            }
            OauthError::InvalidClient => (StatusCode::BAD_REQUEST, "invalid_client", None),
            OauthError::InvalidGrant => (StatusCode::BAD_REQUEST, "invalid_grant", None),
            OauthError::UnauthorizedClient(desc) => {
                (StatusCode::BAD_REQUEST, "unauthorized_client", desc.clone())
            }
            OauthError::UnsupportedGrantType => {
                (StatusCode::BAD_REQUEST, "unsupported_grant_type", None)
            }
            OauthError::InvalidScope(desc) => {
                (StatusCode::BAD_REQUEST, "invalid_scope", Some(desc.clone()))
            }
            OauthError::ServerError => (StatusCode::INTERNAL_SERVER_ERROR, "server_error", None),
            OauthError::InvalidToken(desc) => {
                (StatusCode::UNAUTHORIZED, "invalid_token", desc.clone())
            }
            OauthError::AuthorizationPending => {
                (StatusCode::BAD_REQUEST, "authorization_pending", None)
            }
            OauthError::SlowDown => (StatusCode::BAD_REQUEST, "slow_down", None),
            OauthError::ExpiredToken => (StatusCode::BAD_REQUEST, "expired_token", None),
            OauthError::Custom {
                status,
                error,
                description,
            } => (*status, error.as_str(), description.clone()),
        };

        let mut body = serde_json::Map::new();
        body.insert("error".to_string(), json!(error));
        if let Some(desc) = description {
            body.insert("error_description".to_string(), json!(desc));
        }

        (status, Json(body)).into_response()
    }
}
