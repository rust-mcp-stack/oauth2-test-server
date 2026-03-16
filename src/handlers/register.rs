use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::store::AppState;

/// `POST /register` — RFC 7591 Dynamic Client Registration.
#[tracing::instrument(skip(state, metadata))]
pub async fn register_client(
    State(state): State<AppState>,
    Json(metadata): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::error::OauthError> {
    let client = state.register_client(metadata).await?;
    let registration_access_token = Uuid::new_v4().to_string();
    let response = json!({
        "client_id": client.client_id,
        "client_secret": client.client_secret,
        "client_id_issued_at": Utc::now().timestamp(),
        "registration_client_uri": client.registration_client_uri,
        "registration_access_token": registration_access_token,
        "redirect_uris": client.redirect_uris,
        "grant_types": client.grant_types,
        "response_types": client.response_types,
        "scope": client.scope,
        "token_endpoint_auth_method": client.token_endpoint_auth_method
    });

    Ok((StatusCode::CREATED, Json(response)))
}

/// `GET /register/:client_id` — Retrieve a registered client's metadata.
#[tracing::instrument(skip(state))]
pub async fn get_client(
    State(state): State<AppState>,
    axum::extract::Path(client_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    if let Some(client) = state.store.get_client(&client_id).await {
        let response = json!({
            "client_id": client.client_id,
            "client_name": client.client_name,
            "redirect_uris": client.redirect_uris,
            "grant_types": client.grant_types,
            "scope": client.scope
        });
        (StatusCode::OK, Json(response)).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "client_not_found" })),
        )
            .into_response()
    }
}
