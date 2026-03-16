use axum::{
    extract::{Query, State},
    response::IntoResponse,
    response::Redirect,
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use std::collections::HashSet;

use crate::{
    crypto::generate_code,
    models::{AuthorizationCode, Token},
    store::AppState,
};

#[derive(Deserialize, Debug)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub response_mode: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<String>,
    pub claims: Option<String>,
    pub ui_locales: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum Prompt {
    None,
    Login,
    #[default]
    Consent,
    SelectAccount,
}

#[allow(clippy::should_implement_trait)]
impl Prompt {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "none" => Some(Prompt::None),
            "login" => Some(Prompt::Login),
            "consent" => Some(Prompt::Consent),
            "select_account" => Some(Prompt::SelectAccount),
            _ => None,
        }
    }
}

/// `GET /authorize` — OAuth2 authorization endpoint (authorization code flow).
///
/// In this test server, consent is auto-granted. The `default_user_id` from
/// [`IssuerConfig`] is used as the authenticated user.
#[tracing::instrument(skip(state))]
pub async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeQuery>,
) -> impl IntoResponse {
    let client = match state.store.get_client(&params.client_id).await {
        Some(c) => c,
        None => {
            return Redirect::to(&format!(
                "/error?error=invalid_client&state={}",
                params.state.as_deref().unwrap_or("")
            ))
            .into_response();
        }
    };

    if state.config.require_state && params.state.is_none() {
        return Redirect::to(
            "/error?error=invalid_request&error_description=state_parameter_required",
        )
        .into_response();
    }

    let supported_response_types = [
        "code",
        "token",
        "id_token",
        "code token",
        "code id_token",
        "token id_token",
        "code token id_token",
    ];
    if !supported_response_types.contains(&params.response_type.as_str()) {
        return Redirect::to(&format!(
            "/error?error=unsupported_response_type&state={}",
            params.state.as_deref().unwrap_or("")
        ))
        .into_response();
    }

    if let Some(ref prompt) = params.prompt {
        if let Some(p) = Prompt::from_str(prompt) {
            match p {
                Prompt::None => {
                    return Redirect::to(&format!(
                        "/error?error=invalid_request&error_description=prompt=none requires no existing session&state={}",
                        params.state.as_deref().unwrap_or("")
                    ))
                    .into_response();
                }
                Prompt::Login | Prompt::Consent | Prompt::SelectAccount => {}
            }
        } else {
            return Redirect::to(&format!(
                "/error?error=invalid_request&error_description=invalid prompt value&state={}",
                params.state.as_deref().unwrap_or("")
            ))
            .into_response();
        }
    }

    if let Some(ref max_age) = params.max_age {
        if max_age.parse::<i64>().is_err() {
            return Redirect::to(&format!(
                "/error?error=invalid_request&error_description=max_age must be an integer&state={}",
                params.state.as_deref().unwrap_or("")
            ))
            .into_response();
        }
    }

    if let Some(ref claims) = params.claims {
        if serde_json::from_str::<serde_json::Value>(claims).is_err() {
            return Redirect::to(&format!(
                "/error?error=invalid_request&error_description=invalid claims parameter&state={}",
                params.state.as_deref().unwrap_or("")
            ))
            .into_response();
        }
    }

    let redirect_uri = match &params.redirect_uri {
        Some(uri) => {
            if !client.redirect_uris.contains(uri) {
                return Redirect::to(&format!(
                    "/error?error=invalid_request&state={}",
                    params.state.as_deref().unwrap_or("")
                ))
                .into_response();
            }
            uri.clone()
        }
        None => match client.redirect_uris.first() {
            Some(uri) => uri.clone(),
            None => {
                return Redirect::to(&format!(
                    "/error?error=invalid_request&state={}&error_description=no_redirect_uri",
                    params.state.as_deref().unwrap_or("")
                ))
                .into_response();
            }
        },
    };

    let code = generate_code();

    let requested_scopes: HashSet<String> = params
        .scope
        .clone()
        .unwrap_or_default()
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let registered_scopes: HashSet<String> = client
        .scope
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let granted_scopes: Vec<String> = requested_scopes
        .intersection(&registered_scopes)
        .cloned()
        .collect();
    let final_scope = granted_scopes.join(" ");

    let auth_code = AuthorizationCode {
        code: code.clone(),
        client_id: params.client_id.clone(),
        redirect_uri: redirect_uri.clone(),
        scope: final_scope,
        expires_at: Utc::now()
            + Duration::seconds(state.config.authorization_code_expires_in as i64),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
        user_id: state.config.default_user_id.clone(),
        nonce: params.nonce.clone(),
        state: params.state.clone(),
    };

    state.store.insert_code(code.clone(), auth_code).await;

    let response_mode = params.response_mode.as_deref().unwrap_or("query");
    let state_param = params.state.as_deref().unwrap_or("");

    match response_mode {
        "form_post" => {
            let form_html = format!(
                r#"<!DOCTYPE html>
<html>
<head><title>Redirect</title></head>
<body>
<form id="form" method="POST" action="{}">
<input type="hidden" name="code" value="{}"/>
<input type="hidden" name="state" value="{}"/>
</form>
<script>document.getElementById('form').submit();</script>
</body>
</html>"#,
                redirect_uri, code, state_param
            );
            (
                http::StatusCode::OK,
                [("Content-Type", "text/html")],
                form_html,
            )
                .into_response()
        }
        "fragment" => {
            let redirect_url = format!("{}?code={}&state={}#", redirect_uri, code, state_param);
            Redirect::to(&redirect_url).into_response()
        }
        _ => {
            let redirect_url = format!("{}?code={}&state={}", redirect_uri, code, state_param);
            Redirect::to(&redirect_url).into_response()
        }
    }
}

/// Helper used by the testkit to store a pre-built `Token` directly.
pub async fn store_token(state: &AppState, token: Token) {
    let jwt = token.access_token.clone();
    if let Some(rt) = token.refresh_token.clone() {
        state.store.insert_refresh_token(rt, token.clone()).await;
    }
    state.store.insert_token(jwt, token).await;
}
