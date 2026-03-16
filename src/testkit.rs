use base64::{engine::general_purpose, Engine};
use jsonwebtoken::{encode, Algorithm, Header};
use rand::RngExt;
use reqwest::{Client as HttpClient, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::task::JoinError;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PkcePair {
    pub code_verifier: String,
    pub code_challenge: String,
}

#[derive(Debug, Default)]
pub struct AuthorizeParams {
    pub response_type: &'static str,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub response_mode: Option<String>,
    pub pkce: Option<PkcePair>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<String>,
    pub claims: Option<String>,
    pub ui_locales: Option<String>,
}

impl AuthorizeParams {
    pub fn new() -> Self {
        Self {
            response_type: "code",
            redirect_uri: "http://localhost/cb".to_string(),
            scope: "openid".to_string(),
            state: Some(Uuid::new_v4().to_string()),
            response_mode: None,
            pkce: None,
            nonce: None,
            prompt: None,
            max_age: None,
            claims: None,
            ui_locales: None,
        }
    }

    pub fn redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = uri.into();
        self
    }

    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = scope.into();
        self
    }

    pub fn state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    pub fn no_state(mut self) -> Self {
        self.state = None;
        self
    }

    pub fn response_mode(mut self, mode: impl Into<String>) -> Self {
        self.response_mode = Some(mode.into());
        self
    }

    pub fn pkce(mut self, pkce: PkcePair) -> Self {
        self.pkce = Some(pkce);
        self
    }

    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    pub fn prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    pub fn max_age(mut self, max_age: impl Into<String>) -> Self {
        self.max_age = Some(max_age.into());
        self
    }

    pub fn claims(mut self, claims: impl Into<String>) -> Self {
        self.claims = Some(claims.into());
        self
    }

    pub fn ui_locales(mut self, locales: impl Into<String>) -> Self {
        self.ui_locales = Some(locales.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct OauthEndpoints {
    pub oauth_server: String,
    pub discovery: String,
    pub authorize: String,
    pub token: String,
    pub register: String,
    pub introspect: String,
    pub revoke: String,
    pub userinfo: String,
    pub jwks: String,
    pub device_code: String,
    pub device_token: String,
}

/// Start a test server with full programmatic control.
///
/// ```
/// use oauth2_test_server::OAuthTestServer;
///
/// #[tokio::test]
/// async fn test() {
/// let server = OAuthTestServer::start().await;
/// println!("server: {}", server.base_url());
/// println!("authorize endpoint: {}", server.endpoints.authorize_url);
/// // register a client
/// let client = server.register_client(
///     serde_json::json!({ "scope": "openid", "redirect_uris":["http://localhost:8080/callback"]}),
/// );
/// // generate a jwt
/// let jwt = server.generate_jwt(&client, server.jwt_options().user_id("bob").build());
/// assert_eq!(jwt.split('.').count(), 3);
/// assert_eq!(server.clients().read().iter().len(), 1);
/// assert_eq!(server.tokens().read().iter().len(), 1);
/// }
/// ```
pub struct OAuthTestServer {
    state: AppState,
    pub base_url: url::Url,
    pub endpoints: OauthEndpoints,
    pub http: HttpClient,
    _handle: tokio::task::JoinHandle<()>,
}

impl OAuthTestServer {
    pub async fn start() -> Self {
        let config = IssuerConfig {
            port: 0,
            ..Default::default()
        };
        Self::start_with_config(config).await
    }

    pub async fn start_with_config(config: IssuerConfig) -> Self {
        // config.port = 0;
        let mut state = AppState::new(config.clone());
        let (addr, handle) = state.clone().start().await;
        let base_url: Url = format!("http://{addr}").parse().unwrap();
        state.base_url = base_url.to_string().trim_end_matches("/").to_string();
        let endpoints: OauthEndpoints = OauthEndpoints {
            oauth_server: base_url.clone().to_string(),
            discovery: format!("{base_url}.well-known/openid-configuration"),
            register: format!("{base_url}register"),
            authorize: format!("{base_url}authorize"),
            token: format!("{base_url}token"),
            introspect: format!("{base_url}introspect"),
            revoke: format!("{base_url}revoke"),
            userinfo: format!("{base_url}userinfo"),
            jwks: format!("{base_url}.well-known/jwks.json"),
            device_code: format!("{base_url}device/code"),
            device_token: format!("{base_url}device/token"),
        };

        Self {
            state,
            base_url,
            endpoints,
            http: HttpClient::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            _handle: handle,
        }
    }

    pub async fn wait_for_shutdown(self) -> Result<(), JoinError> {
        self._handle.await
    }

    pub async fn register_client(&self, metadata: serde_json::Value) -> Client {
        self.state
            .register_client(metadata)
            .await
            .expect("client registration failed")
    }

    pub async fn register_client_with_secret(&self, metadata: Value, force_secret: bool) -> Client {
        let mut meta = metadata;
        if let Some(obj) = meta.as_object_mut() {
            obj.insert(
                "generate_client_secret_for_dcr".to_string(),
                json!(force_secret),
            );
        }
        self.register_client(meta).await
    }

    pub fn generate_jwt(&self, client: &Client, options: JwtOptions) -> String {
        self.state
            .generate_jwt(client, options)
            .expect("JWT generation failed")
    }

    pub async fn generate_token(&self, client: &Client, options: JwtOptions) -> Token {
        self.state
            .generate_token(client, options)
            .await
            .expect("Token generation failed")
    }

    pub async fn clients(&self) -> Vec<Client> {
        self.state.store.get_all_clients().await
    }

    pub async fn codes(&self) -> Vec<AuthorizationCode> {
        self.state.store.get_all_codes().await
    }

    pub async fn tokens(&self) -> Vec<Token> {
        self.state.store.get_all_tokens().await
    }

    pub async fn refresh_tokens(&self) -> Vec<Token> {
        self.state.store.get_all_refresh_tokens().await
    }

    pub async fn clear_clients(&self) {
        self.state.store.clear_clients().await;
    }

    pub async fn clear_codes(&self) {
        self.state.store.clear_codes().await;
    }

    pub async fn clear_tokens(&self) {
        self.state.store.clear_tokens().await;
    }

    pub async fn clear_refresh_tokens(&self) {
        self.state.store.clear_refresh_tokens().await;
    }

    pub async fn clear_device_codes(&self) {
        self.state.store.clear_device_codes().await;
    }

    pub async fn clear_all(&self) {
        self.state.store.clear_all().await;
    }

    pub async fn approve_device_code(&self, device_code: &str, user_id: &str) {
        self.state
            .approve_device_code(device_code, user_id)
            .await
            .expect("device code not found");
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    pub fn jwt_options(&self) -> JwtOptionsBuilder {
        JwtOptionsBuilder::default()
    }

    pub fn pkce_pair(&self) -> PkcePair {
        let verifier_bytes: [u8; 32] = rand::rng().random();
        let code_verifier = general_purpose::URL_SAFE_NO_PAD.encode(verifier_bytes);
        let challenge =
            general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        PkcePair {
            code_verifier,
            code_challenge: challenge,
        }
    }

    pub fn authorize_url(&self, client: &Client, params: AuthorizeParams) -> Url {
        let mut url = self.base_url.join("authorize").unwrap();
        let mut query = url.query_pairs_mut();

        query
            .append_pair("response_type", params.response_type)
            .append_pair("client_id", &client.client_id)
            .append_pair("redirect_uri", &params.redirect_uri)
            .append_pair("scope", &params.scope);

        if let Some(state) = params.state {
            query.append_pair("state", &state);
        }

        if let Some(ref response_mode) = params.response_mode {
            query.append_pair("response_mode", response_mode);
        }

        if let Some(pkce) = params.pkce {
            query
                .append_pair("code_challenge", &pkce.code_challenge)
                .append_pair("code_challenge_method", "S256");
        }

        if let Some(nonce) = params.nonce {
            query.append_pair("nonce", &nonce);
        }

        if let Some(ref prompt) = params.prompt {
            query.append_pair("prompt", prompt);
        }

        if let Some(ref max_age) = params.max_age {
            query.append_pair("max_age", max_age);
        }

        if let Some(ref claims) = params.claims {
            query.append_pair("claims", claims);
        }

        if let Some(ref ui_locales) = params.ui_locales {
            query.append_pair("ui_locales", ui_locales);
        }

        drop(query);
        url
    }

    pub fn rotate_keys(&self) {
        // In real impl, regenerate KEYS and update JWKS_JSON
        unimplemented!("Key rotation not implemented in test server")
    }

    pub async fn approve_consent(&self, auth_url: &Url, user_id: &str) -> String {
        let resp = self.http.get(auth_url.clone()).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let redirect = Url::parse(location).unwrap();
        let code = redirect
            .query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.to_string())
            .expect("no code in redirect");

        // Store user_id for later token claims
        let code_obj = self
            .state
            .store
            .get_code(&code)
            .await
            .expect("code not found");
        let mut code_obj = code_obj.clone();
        code_obj.user_id = user_id.to_string();
        self.state.store.insert_code(code.clone(), code_obj).await;

        code
    }

    pub async fn exchange_code(
        &self,
        client: &Client,
        code: &str,
        pkce: Option<&PkcePair>,
    ) -> Value {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", "http://localhost/cb"),
        ];

        if let Some(pkce) = pkce {
            form.push(("code_verifier", &pkce.code_verifier));
        }

        let resp = self
            .http
            .post(self.base_url.join("token").unwrap())
            .basic_auth(&client.client_id, client.client_secret.as_ref())
            .form(&form)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }

    pub async fn refresh_token(&self, client: &Client, refresh_token: &str) -> Value {
        let resp = self
            .http
            .post(self.base_url.join("token").unwrap())
            .basic_auth(&client.client_id, client.client_secret.as_ref())
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await
            .unwrap();

        resp.json().await.unwrap()
    }

    pub async fn introspect_token(&self, client: &Client, token: &str) -> Value {
        let resp = self
            .http
            .post(self.base_url.join("introspect").unwrap())
            .basic_auth(&client.client_id, client.client_secret.as_ref())
            .form(&[("token", token)])
            .send()
            .await
            .unwrap();

        resp.json().await.unwrap()
    }

    pub async fn revoke_token(&self, client: &Client, token: &str) {
        let resp = self
            .http
            .post(self.base_url.join("revoke").unwrap())
            .basic_auth(&client.client_id, client.client_secret.as_ref())
            .form(&[("token", token)])
            .send()
            .await
            .unwrap();

        assert!(resp.status().is_success());
    }

    pub fn client_assertion_jwt(&self, client: &Client) -> String {
        let claims = json!({
            "iss": client.client_id,
            "sub": client.client_id,
            "aud": self.issuer(),
            "exp": (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp(),
            "iat": chrono::Utc::now().timestamp(),
            "jti": Uuid::new_v4().to_string(),
        });

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.state.keys.kid.clone());

        encode(&header, &claims, &self.state.keys.encoding).unwrap()
    }

    pub fn base_url(&self) -> &url::Url {
        &self.base_url
    }

    pub fn issuer(&self) -> &str {
        self.state.issuer()
    }

    /// Complete the full authorization code flow with PKCE in one call.
    /// Returns the token response including access_token, refresh_token, and optionally id_token.
    pub async fn complete_auth_flow(
        &self,
        client: &Client,
        params: AuthorizeParams,
        user_id: &str,
    ) -> Value {
        let pkce = params.pkce.clone();

        let auth_url = self.authorize_url(client, params);
        let code = self.approve_consent(&auth_url, user_id).await;

        self.exchange_code(client, &code, pkce.as_ref()).await
    }

    /// Complete the full device code flow in one call.
    /// Returns the token response.
    pub async fn complete_device_flow(&self, client: &Client, scope: &str, user_id: &str) -> Value {
        let scope_str = scope.to_string();
        let device_resp = self
            .http
            .post(self.base_url.join("device/code").unwrap())
            .form(&[("client_id", &client.client_id), ("scope", &scope_str)])
            .send()
            .await
            .unwrap();

        let device_data: Value = device_resp.json().await.unwrap();
        let device_code = device_data["device_code"].as_str().unwrap();

        self.approve_device_code(device_code, user_id).await;

        let token_resp = self
            .http
            .post(self.base_url.join("device/token").unwrap())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
                ("client_id", &client.client_id),
            ])
            .send()
            .await
            .unwrap();

        token_resp.json().await.unwrap()
    }

    /// Perform client credentials grant.
    pub async fn client_credentials_grant(&self, client: &Client, scope: Option<&str>) -> Value {
        let mut form = vec![("grant_type", "client_credentials")];

        if let Some(s) = scope {
            form.push(("scope", s));
        }

        let resp = self
            .http
            .post(self.base_url.join("token").unwrap())
            .basic_auth(&client.client_id, client.client_secret.as_ref())
            .form(&form)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }
}

#[derive(Debug, Default)]
pub struct JwtOptions {
    pub user_id: String,
    pub scope: Option<String>,
    pub expires_in: i64,
}

#[derive(Default)]
pub struct JwtOptionsBuilder {
    user_id: Option<String>,
    scope: Option<String>,
    expires_in: Option<i64>,
}

impl JwtOptionsBuilder {
    pub fn user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    pub fn expires_in(mut self, seconds: i64) -> Self {
        self.expires_in = Some(seconds);
        self
    }

    pub fn build(self) -> JwtOptions {
        JwtOptions {
            user_id: self.user_id.unwrap_or("test-user-123".to_string()),
            scope: self.scope,
            expires_in: self.expires_in.unwrap_or(3600),
        }
    }
}

use crate::config::IssuerConfig;
use crate::models::{AuthorizationCode, Client, Token};
use crate::store::AppState;
