use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use std::collections::HashMap;

use crate::store::AppState;

pub async fn revoke(
    State(state): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let token = form.get("token").cloned().unwrap_or_default();
    if let Some(mut t) = state.store.get_token(&token).await {
        t.revoked = true;
        state.store.update_token(&token, t).await;
    }
    if let Some(mut t) = state.store.get_refresh_token(&token).await {
        t.revoked = true;
        state.store.update_refresh_token(&token, t).await;
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}
