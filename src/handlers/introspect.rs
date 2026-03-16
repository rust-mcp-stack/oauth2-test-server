use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use jsonwebtoken::{Algorithm, Validation};
use serde_json::json;
use std::collections::HashMap;

use crate::{models::Claims, store::AppState};

pub async fn introspect(
    State(state): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let token = match form.get("token") {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_request"})),
            )
                .into_response()
        }
    };

    let stored_token = state.store.get_token(token).await;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false; // Allow introspection of expired tokens
    validation.required_spec_claims.clear(); // Be permissive
    validation.validate_aud = false;

    match jsonwebtoken::decode::<Claims>(token, &state.keys.decoding, &validation) {
        Ok(token_data) => {
            let claims = token_data.claims;

            let is_expired = Utc::now().timestamp() > claims.exp as i64;
            let is_revoked = stored_token.map(|t| t.revoked).unwrap_or(false);
            let active = !is_revoked && !is_expired;

            let mut response = json!({
                "active": active,
                "scope": claims.scope,
                "client_id": claims.aud,
                "sub": claims.sub,
                "iss": claims.iss,
                "aud": claims.aud,
                "iat": claims.iat,
                "exp": claims.exp,
                "jti": claims.jti,
                "token_type": "Bearer",
                "azp": claims.azp,
                "auth_time": claims.auth_time,
                "sid": claims.sid,
            });

            if claims.scope.is_none() {
                response.as_object_mut().unwrap().remove("scope");
            }

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(err) => {
            println!(">>> err {:?} ", err);
            (StatusCode::OK, Json(json!({"active": false}))).into_response()
        }
    }
}
