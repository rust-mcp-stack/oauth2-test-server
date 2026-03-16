use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use chrono::Utc;
use serde_json::json;

use crate::{error::OauthError, store::AppState};

pub async fn userinfo(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, OauthError> {
    let auth = headers.get("Authorization").and_then(|v| v.to_str().ok());

    if let Some(auth) = auth {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            if let Some(t) = state.store.get_token(token).await {
                if t.revoked || t.expires_at < Utc::now() {
                    return Err(OauthError::InvalidToken(Some(
                        "Token expired or revoked".to_string(),
                    )));
                }
                let response = json!({
                    "sub": t.user_id,
                    "name": "Test User",
                    "email": "test@example.com",
                    "picture": "https://example.com/avatar.jpg"
                });
                return Ok(Json(response));
            }
        }
    }

    Err(OauthError::InvalidToken(None))
}
