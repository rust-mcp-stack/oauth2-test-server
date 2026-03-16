use axum::{
    extract::{Form, State},
    http::HeaderMap,
    response::IntoResponse,
    Json,
};
use base64::{engine::general_purpose, Engine};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use sha2::Digest;
use std::collections::HashSet;

use crate::{
    crypto::{
        calculate_at_hash, calculate_c_hash, generate_token_string, issue_id_token, issue_jwt,
    },
    error::OauthError,
    models::Token,
    store::AppState,
};

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub _redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub _client_secret: Option<String>,
    pub refresh_token: Option<String>,
    pub code_verifier: Option<String>,
    pub scope: Option<String>,
}

#[tracing::instrument(skip(state, form, _headers))]
pub async fn token_endpoint(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Form(form): Form<TokenRequest>,
) -> Result<impl IntoResponse, OauthError> {
    match form.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(state, form).await,
        "refresh_token" => handle_refresh_token(state, form).await,
        "client_credentials" => handle_client_credentials(state, form).await,
        _ => Err(OauthError::UnsupportedGrantType),
    }
}

async fn handle_authorization_code(
    state: AppState,
    form: TokenRequest,
) -> Result<Json<serde_json::Value>, OauthError> {
    let code = form.code.as_deref().unwrap_or("");
    let code_obj = state
        .store
        .remove_code(code)
        .await
        .ok_or(OauthError::InvalidGrant)?;

    if code_obj.expires_at < Utc::now() {
        return Err(OauthError::InvalidGrant);
    }

    if let (Some(challenge), Some(verifier)) = (&code_obj.code_challenge, &form.code_verifier) {
        let method = code_obj.code_challenge_method.as_deref().unwrap_or("plain");
        let computed = if method == "S256" {
            general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()))
        } else {
            verifier.clone()
        };
        if computed != *challenge {
            return Err(OauthError::InvalidGrant);
        }
    }

    let refresh_token = generate_token_string();

    let jwt = issue_jwt(
        state.issuer(),
        &code_obj.client_id,
        &code_obj.user_id,
        &code_obj.scope,
        state.config.access_token_expires_in as i64,
        &state.keys,
    )
    .map_err(|_| OauthError::ServerError)?;

    let scopes: HashSet<&str> = code_obj.scope.split_whitespace().collect();
    let include_id_token = scopes.contains("openid");

    let id_token = if include_id_token {
        let at_hash = calculate_at_hash(&jwt);
        let c_hash = calculate_c_hash(code);

        let user_claims = json!({
            "name": code_obj.user_id.clone(),
        });

        let id_token = issue_id_token(
            state.issuer(),
            &code_obj.client_id,
            &code_obj.user_id,
            code_obj.nonce.as_deref(),
            Some(&at_hash),
            Some(&c_hash),
            state.config.access_token_expires_in as i64,
            user_claims,
            &state.keys,
        )
        .map_err(|_| OauthError::ServerError)?;

        Some(id_token)
    } else {
        None
    };

    let token = Token {
        access_token: jwt.clone(),
        refresh_token: Some(refresh_token.clone()),
        client_id: code_obj.client_id.clone(),
        scope: code_obj.scope.clone(),
        expires_at: Utc::now() + Duration::seconds(state.config.access_token_expires_in as i64),
        user_id: code_obj.user_id.clone(),
        revoked: false,
    };

    state.store.insert_token(jwt.clone(), token.clone()).await;
    state
        .store
        .insert_refresh_token(refresh_token.clone(), token)
        .await;

    let mut response = json!({
        "access_token": jwt,
        "token_type": "Bearer",
        "expires_in": state.config.access_token_expires_in,
        "refresh_token": refresh_token,
        "scope": code_obj.scope
    });

    if let Some(id) = id_token {
        response["id_token"] = serde_json::Value::String(id);
    }

    if let Some(ref state) = code_obj.state {
        response["state"] = serde_json::Value::String(state.clone());
    }

    Ok(Json(response))
}

async fn handle_refresh_token(
    state: AppState,
    form: TokenRequest,
) -> Result<Json<serde_json::Value>, OauthError> {
    let rt = form.refresh_token.as_deref().unwrap_or("");
    let mut token = state
        .store
        .get_refresh_token(rt)
        .await
        .ok_or(OauthError::InvalidGrant)?;

    if token.revoked {
        return Err(OauthError::InvalidGrant);
    }

    let new_access_token = issue_jwt(
        state.issuer(),
        &token.client_id,
        &token.user_id,
        &token.scope,
        state.config.access_token_expires_in as i64,
        &state.keys,
    )
    .map_err(|_| OauthError::ServerError)?;

    let new_refresh_token = generate_token_string();

    let new_token = Token {
        access_token: new_access_token.clone(),
        refresh_token: Some(new_refresh_token.clone()),
        client_id: token.client_id.clone(),
        scope: token.scope.clone(),
        expires_at: Utc::now() + Duration::seconds(state.config.access_token_expires_in as i64),
        user_id: token.user_id.clone(),
        revoked: false,
    };

    state
        .store
        .insert_token(new_access_token.clone(), new_token.clone())
        .await;
    state
        .store
        .insert_refresh_token(new_refresh_token.clone(), new_token)
        .await;

    token.revoked = true;
    state.store.update_refresh_token(rt, token.clone()).await;

    Ok(Json(json!({
        "access_token": new_access_token,
        "token_type": "Bearer",
        "expires_in": state.config.access_token_expires_in,
        "refresh_token": new_refresh_token,
        "scope": token.scope
    })))
}

async fn handle_client_credentials(
    state: AppState,
    form: TokenRequest,
) -> Result<Json<serde_json::Value>, OauthError> {
    let client_id = form.client_id.as_deref().unwrap_or("");
    let client = state
        .store
        .get_client(client_id)
        .await
        .ok_or(OauthError::InvalidClient)?;

    let requested_scopes: HashSet<String> = form
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    if let Some(requested_scope) = form.scope.as_deref() {
        if let Err(e) = state.config.validate_scope(requested_scope) {
            return Err(OauthError::InvalidScope(e));
        }

        let client_scopes: HashSet<_> = client.scope.split_whitespace().collect();
        let requested_scopes_set: HashSet<_> = requested_scope.split_whitespace().collect();

        let not_permitted: Vec<_> = requested_scopes_set
            .difference(&client_scopes)
            .cloned()
            .collect();

        if !not_permitted.is_empty() {
            return Err(OauthError::InvalidScope(format!(
                "Client not authorized for scopes: {}",
                not_permitted.join(" ")
            )));
        }
    }

    let registered_scopes: HashSet<String> = client
        .scope
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let granted_scopes: Vec<String> = requested_scopes
        .intersection(&registered_scopes)
        .cloned()
        .collect();

    if granted_scopes.is_empty() && !requested_scopes.is_empty() {
        return Err(OauthError::InvalidScope(
            "Requested scopes not allowed for this client".to_string(),
        ));
    }

    let final_scope = if requested_scopes.is_empty() {
        client.scope.clone()
    } else {
        granted_scopes.join(" ")
    };

    let access_token = issue_jwt(
        state.issuer(),
        client_id,
        "client",
        &final_scope,
        state.config.access_token_expires_in as i64,
        &state.keys,
    )
    .map_err(|_| OauthError::ServerError)?;

    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": state.config.access_token_expires_in,
        "scope": final_scope
    })))
}
