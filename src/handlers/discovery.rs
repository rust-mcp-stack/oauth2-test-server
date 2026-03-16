use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use crate::store::AppState;

/// `GET /.well-known/openid-configuration` — OIDC Discovery document.
pub async fn well_known_openid_configuration(State(state): State<AppState>) -> impl IntoResponse {
    let discovery = state.config.to_discovery_document(state.base_url.clone());
    (StatusCode::OK, Json(discovery))
}

/// `GET /.well-known/jwks.json` — Public keys for JWT validation.
pub async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, Json((*state.jwks_json).clone()))
}

/// `GET /error` — Human-readable OAuth error page.
pub async fn error_page(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Html<String> {
    let error = params.get("error").map(|s| s.as_str()).unwrap_or("unknown");
    let description = params
        .get("error_description")
        .map(|s| s.as_str())
        .unwrap_or("");
    axum::response::Html(format!("<h1>OAuth Error: {error}</h1><p>{description}</p>"))
}
