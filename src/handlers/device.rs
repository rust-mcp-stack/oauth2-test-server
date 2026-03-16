use axum::{
    extract::{Form, State},
    response::IntoResponse,
    Json,
};
use chrono::{Duration, Utc};
use rand::Rng;
use serde::Deserialize;
use serde_json::json;

use crate::{
    crypto::{generate_token_string, issue_jwt},
    error::OauthError,
    models::{DeviceAuthorization, DeviceCodeResponse, DeviceTokenRequest},
    store::AppState,
};

#[derive(Deserialize, Debug)]
pub struct DeviceCodeRequest {
    pub client_id: String,
    pub scope: Option<String>,
}

const DEVICE_CODE_CHARSET: &[u8] = b"BCDFGHJKLMNPQRSTUVWXYZ23456789";

fn generate_user_code() -> String {
    let mut rng = rand::thread_rng();
    let code: String = (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..DEVICE_CODE_CHARSET.len());
            DEVICE_CODE_CHARSET[idx] as char
        })
        .collect();
    code.chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

pub async fn device_code(
    State(state): State<AppState>,
    Form(form): Form<DeviceCodeRequest>,
) -> Result<impl IntoResponse, OauthError> {
    let client = state
        .store
        .get_client(&form.client_id)
        .await
        .ok_or(OauthError::InvalidClient)?;

    let scope = form.scope.clone().unwrap_or_else(|| client.scope.clone());

    if let Err(e) = state.config.validate_scope(&scope) {
        return Err(OauthError::InvalidScope(e));
    }

    let device_code = generate_token_string();
    let user_code = generate_user_code();
    let expires_in = state.config.authorization_code_expires_in;
    let interval = 5;

    let device_auth = DeviceAuthorization {
        device_code: device_code.clone(),
        user_code: user_code.clone(),
        client_id: form.client_id.clone(),
        scope: scope.clone(),
        expires_at: Utc::now() + Duration::seconds(expires_in as i64),
        user_id: None,
        approved: false,
    };

    state
        .store
        .insert_device_code(device_code.clone(), device_auth)
        .await;

    let verification_uri = format!("{}/device", state.issuer());
    let verification_uri_complete = Some(format!("{}?user_code={}", verification_uri, user_code));

    Ok(Json(DeviceCodeResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in,
        interval,
    }))
}

pub async fn device_token(
    State(state): State<AppState>,
    Form(form): Form<DeviceTokenRequest>,
) -> Result<impl IntoResponse, OauthError> {
    if form.grant_type != "urn:ietf:params:oauth:grant-type:device_code" {
        return Err(OauthError::UnsupportedGrantType);
    }

    let device_auth = state
        .store
        .get_device_code(&form.device_code)
        .await
        .ok_or(OauthError::InvalidGrant)?;

    if device_auth.expires_at < Utc::now() {
        return Err(OauthError::InvalidGrant);
    }

    if device_auth.client_id != form.client_id {
        return Err(OauthError::InvalidClient);
    }

    if !device_auth.approved {
        return Err(OauthError::AuthorizationPending);
    }

    let client = state
        .store
        .get_client(&form.client_id)
        .await
        .ok_or(OauthError::InvalidClient)?;

    let user_id = device_auth
        .user_id
        .clone()
        .unwrap_or_else(|| "device-user".to_string());

    let jwt = issue_jwt(
        state.issuer(),
        &client.client_id,
        &user_id,
        &device_auth.scope,
        state.config.access_token_expires_in as i64,
        &state.keys,
    )
    .map_err(|_| OauthError::ServerError)?;

    let refresh_token = generate_token_string();

    let token = crate::models::Token {
        access_token: jwt.clone(),
        refresh_token: Some(refresh_token.clone()),
        client_id: client.client_id.clone(),
        scope: device_auth.scope.clone(),
        expires_at: Utc::now() + Duration::seconds(state.config.access_token_expires_in as i64),
        user_id: user_id.clone(),
        revoked: false,
    };

    state.store.insert_token(jwt.clone(), token.clone()).await;
    state
        .store
        .insert_refresh_token(refresh_token.clone(), token)
        .await;

    Ok(Json(json!({
        "access_token": jwt,
        "token_type": "Bearer",
        "expires_in": state.config.access_token_expires_in,
        "refresh_token": refresh_token,
        "scope": device_auth.scope
    })))
}
