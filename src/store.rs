use chrono::{Duration, Utc};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};
use tokio::{net::TcpListener, task::JoinHandle};
use uuid::Uuid;

use crate::{
    config::IssuerConfig,
    crypto::{build_jwks_json, generate_token_string, issue_jwt, Keys},
    models::{AuthorizationCode, Client, DeviceAuthorization, Token},
};

#[async_trait::async_trait]
pub trait OauthStore: Send + Sync {
    async fn get_client(&self, client_id: &str) -> Option<Client>;
    async fn insert_client(&self, client: Client);

    async fn get_code(&self, code: &str) -> Option<AuthorizationCode>;
    async fn remove_code(&self, code: &str) -> Option<AuthorizationCode>;
    async fn insert_code(&self, code: String, auth_code: AuthorizationCode);
    async fn cleanup_expired_codes(&self) -> usize;

    async fn get_token(&self, token: &str) -> Option<Token>;
    async fn insert_token(&self, token: String, value: Token);
    async fn update_token(&self, token: &str, value: Token);
    async fn cleanup_expired_tokens(&self) -> usize;

    async fn get_refresh_token(&self, token: &str) -> Option<Token>;
    async fn insert_refresh_token(&self, token: String, value: Token);
    async fn update_refresh_token(&self, token: &str, value: Token);
    async fn cleanup_expired_refresh_tokens(&self) -> usize;

    async fn get_device_code(&self, device_code: &str) -> Option<DeviceAuthorization>;
    async fn insert_device_code(&self, device_code: String, auth: DeviceAuthorization);
    async fn update_device_code(&self, device_code: &str, auth: DeviceAuthorization);
    async fn cleanup_expired_device_codes(&self) -> usize;

    async fn get_all_clients(&self) -> Vec<Client>;
    async fn get_all_codes(&self) -> Vec<AuthorizationCode>;
    async fn get_all_tokens(&self) -> Vec<Token>;
    async fn get_all_refresh_tokens(&self) -> Vec<Token>;

    async fn clear_clients(&self);
    async fn clear_codes(&self);
    async fn clear_tokens(&self);
    async fn clear_refresh_tokens(&self);
    async fn clear_device_codes(&self);
    async fn clear_all(&self);
}

#[derive(Clone)]
pub struct InMemoryStore {
    clients: Arc<RwLock<HashMap<String, Client>>>,
    codes: Arc<RwLock<HashMap<String, AuthorizationCode>>>,
    tokens: Arc<RwLock<HashMap<String, Token>>>,
    refresh_tokens: Arc<RwLock<HashMap<String, Token>>>,
    device_codes: Arc<RwLock<HashMap<String, DeviceAuthorization>>>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            codes: Arc::new(RwLock::new(HashMap::new())),
            tokens: Arc::new(RwLock::new(HashMap::new())),
            refresh_tokens: Arc::new(RwLock::new(HashMap::new())),
            device_codes: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl OauthStore for InMemoryStore {
    async fn get_client(&self, client_id: &str) -> Option<Client> {
        self.clients.read().unwrap().get(client_id).cloned()
    }

    async fn insert_client(&self, client: Client) {
        self.clients
            .write()
            .unwrap()
            .insert(client.client_id.clone(), client);
    }

    async fn get_code(&self, code: &str) -> Option<AuthorizationCode> {
        self.codes.read().unwrap().get(code).cloned()
    }

    async fn remove_code(&self, code: &str) -> Option<AuthorizationCode> {
        self.codes.write().unwrap().remove(code)
    }

    async fn insert_code(&self, code: String, auth_code: AuthorizationCode) {
        self.codes.write().unwrap().insert(code, auth_code);
    }

    async fn get_token(&self, token: &str) -> Option<Token> {
        self.tokens.read().unwrap().get(token).cloned()
    }

    async fn insert_token(&self, token: String, value: Token) {
        self.tokens.write().unwrap().insert(token, value);
    }

    async fn update_token(&self, token: &str, value: Token) {
        if let Some(t) = self.tokens.write().unwrap().get_mut(token) {
            *t = value;
        }
    }

    async fn get_refresh_token(&self, token: &str) -> Option<Token> {
        self.refresh_tokens.read().unwrap().get(token).cloned()
    }

    async fn insert_refresh_token(&self, token: String, value: Token) {
        self.refresh_tokens.write().unwrap().insert(token, value);
    }

    async fn update_refresh_token(&self, token: &str, value: Token) {
        if let Some(t) = self.refresh_tokens.write().unwrap().get_mut(token) {
            *t = value;
        }
    }

    async fn get_device_code(&self, device_code: &str) -> Option<DeviceAuthorization> {
        self.device_codes.read().unwrap().get(device_code).cloned()
    }

    async fn insert_device_code(&self, device_code: String, auth: DeviceAuthorization) {
        self.device_codes.write().unwrap().insert(device_code, auth);
    }

    async fn update_device_code(&self, device_code: &str, auth: DeviceAuthorization) {
        if let Some(a) = self.device_codes.write().unwrap().get_mut(device_code) {
            *a = auth;
        }
    }

    async fn cleanup_expired_codes(&self) -> usize {
        let now = Utc::now();
        let mut count = 0;
        let mut codes = self.codes.write().unwrap();
        codes.retain(|_, code| {
            if code.expires_at < now {
                count += 1;
                false
            } else {
                true
            }
        });
        count
    }

    async fn cleanup_expired_tokens(&self) -> usize {
        let now = Utc::now();
        let mut count = 0;
        let mut tokens = self.tokens.write().unwrap();
        tokens.retain(|_, token| {
            if token.expires_at < now {
                count += 1;
                false
            } else {
                true
            }
        });
        count
    }

    async fn cleanup_expired_refresh_tokens(&self) -> usize {
        let now = Utc::now();
        let mut count = 0;
        let mut tokens = self.refresh_tokens.write().unwrap();
        tokens.retain(|_, token| {
            if token.expires_at < now {
                count += 1;
                false
            } else {
                true
            }
        });
        count
    }

    async fn cleanup_expired_device_codes(&self) -> usize {
        let now = Utc::now();
        let mut count = 0;
        let mut codes = self.device_codes.write().unwrap();
        codes.retain(|_, code| {
            if code.expires_at < now {
                count += 1;
                false
            } else {
                true
            }
        });
        count
    }

    async fn get_all_clients(&self) -> Vec<Client> {
        self.clients.read().unwrap().values().cloned().collect()
    }

    async fn get_all_codes(&self) -> Vec<AuthorizationCode> {
        self.codes.read().unwrap().values().cloned().collect()
    }

    async fn get_all_tokens(&self) -> Vec<Token> {
        self.tokens.read().unwrap().values().cloned().collect()
    }

    async fn get_all_refresh_tokens(&self) -> Vec<Token> {
        self.refresh_tokens
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    async fn clear_clients(&self) {
        self.clients.write().unwrap().clear();
    }

    async fn clear_codes(&self) {
        self.codes.write().unwrap().clear();
    }

    async fn clear_tokens(&self) {
        self.tokens.write().unwrap().clear();
    }

    async fn clear_refresh_tokens(&self) {
        self.refresh_tokens.write().unwrap().clear();
    }

    async fn clear_device_codes(&self) {
        self.device_codes.write().unwrap().clear();
    }

    async fn clear_all(&self) {
        self.clear_clients().await;
        self.clear_codes().await;
        self.clear_tokens().await;
        self.clear_refresh_tokens().await;
        self.clear_device_codes().await;
    }
}

/// Shared in-memory state for the OAuth2 server.
///
/// Holds the issuer configuration, cryptographic keys, and abstract stores.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<IssuerConfig>,
    pub base_url: String,
    pub store: Arc<dyn OauthStore>,
    pub keys: Arc<Keys>,
    pub jwks_json: Arc<serde_json::Value>,
}

impl AppState {
    /// Create a new state with a freshly generated RSA key pair, and an in-memory store.
    pub fn new(config: IssuerConfig) -> Self {
        Self::with_store(config, Arc::new(InMemoryStore::default()))
    }

    /// Create a new state providing a custom store implementation.
    pub fn with_store(config: IssuerConfig, store: Arc<dyn OauthStore>) -> Self {
        let base_url = format!("{}://{}:{}", config.scheme, config.host, config.port);
        let keys = Arc::new(Keys::generate());
        let jwks_json = Arc::new(build_jwks_json(&keys));
        Self {
            config: Arc::new(config),
            store,
            base_url,
            keys,
            jwks_json,
        }
    }

    /// Returns the OAuth2 issuer URL (e.g. `http://localhost:8090`).
    pub fn issuer(&self) -> &str {
        self.base_url.as_str()
    }

    /// Register a new client from RFC 7591 metadata JSON.
    pub async fn register_client(
        &self,
        metadata: serde_json::Value,
    ) -> Result<Client, crate::error::OauthError> {
        let requested_scope = metadata
            .get("scope")
            .and_then(|v| v.as_str())
            .unwrap_or("openid");

        self.config
            .validate_scope(requested_scope)
            .map_err(crate::error::OauthError::InvalidScope)?;

        let client_id = Uuid::new_v4().to_string();

        let client_secret = if self.config.generate_client_secret_for_dcr
            || metadata
                .get("token_endpoint_auth_method")
                .and_then(|v| v.as_str())
                != Some("none")
        {
            Some(generate_token_string())
        } else {
            None
        };

        let redirect_uris = metadata
            .get("redirect_uris")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|u| u.as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();

        let grant_types = metadata
            .get("grant_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>()
            })
            .unwrap_or_else(|| vec!["authorization_code".to_string()]);

        let requires_redirect_uri = grant_types.iter().all(|g| {
            !matches!(
                g.as_str(),
                "client_credentials" | "urn:ietf:params:oauth:grant-type:device_code"
            )
        });

        if redirect_uris.is_empty() && requires_redirect_uri {
            return Err(crate::error::OauthError::InvalidRequest(Some(
                "redirect_uris required".to_string(),
            )));
        }

        let client = Client {
            client_id: client_id.clone(),
            client_secret,
            redirect_uris,
            grant_types: metadata
                .get("grant_types")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_else(|| vec!["authorization_code".to_string()]),
            response_types: metadata
                .get("response_types")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_else(|| vec!["code".to_string()]),
            scope: metadata
                .get("scope")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            token_endpoint_auth_method: metadata
                .get("token_endpoint_auth_method")
                .and_then(|v| v.as_str())
                .unwrap_or("client_secret_basic")
                .to_string(),
            client_name: metadata
                .get("client_name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            client_uri: metadata
                .get("client_uri")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            logo_uri: metadata
                .get("logo_uri")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            contacts: metadata
                .get("contacts")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
            policy_uri: metadata
                .get("policy_uri")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            tos_uri: metadata
                .get("tos_uri")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            jwks: metadata.get("jwks").cloned(),
            jwks_uri: metadata
                .get("jwks_uri")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            software_id: metadata
                .get("software_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            software_version: metadata
                .get("software_version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            registration_access_token: None,
            registration_client_uri: Some(format!("{}/register/{}", self.issuer(), client_id)),
        };

        self.store.insert_client(client.clone()).await;

        Ok(client)
    }

    /// Issue a JWT and store it; used by `testkit` helpers.
    #[cfg(feature = "testing")]
    pub async fn generate_token(
        &self,
        client: &Client,
        options: crate::testkit::JwtOptions,
    ) -> Result<Token, jsonwebtoken::errors::Error> {
        let user_id = options.user_id.clone();
        let jwt = self.generate_jwt(client, options)?;
        let refresh_token = generate_token_string();
        let token = Token {
            access_token: jwt.clone(),
            refresh_token: Some(refresh_token.clone()),
            client_id: client.client_id.clone(),
            scope: client.scope.clone(),
            expires_at: Utc::now() + Duration::hours(1),
            user_id,
            revoked: false,
        };
        self.store.insert_token(jwt.clone(), token.clone()).await;
        self.store
            .insert_refresh_token(refresh_token, token.clone())
            .await;
        Ok(token)
    }

    /// Sign a JWT for the given client; used by `testkit` helpers.
    #[cfg(feature = "testing")]
    pub fn generate_jwt(
        &self,
        client: &Client,
        options: crate::testkit::JwtOptions,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let scope = options.scope.unwrap_or_else(|| client.scope.clone());
        issue_jwt(
            self.issuer(),
            &client.client_id,
            &options.user_id,
            &scope,
            options.expires_in,
            &self.keys,
        )
    }

    #[cfg(feature = "testing")]
    pub async fn approve_device_code(&self, device_code: &str, user_id: &str) -> Option<()> {
        let mut device_auth = self.store.get_device_code(device_code).await?;
        device_auth.approved = true;
        device_auth.user_id = Some(user_id.to_string());
        self.store
            .update_device_code(device_code, device_auth)
            .await;
        Some(())
    }

    /// Build the Axum router and bind to a TCP listener.
    pub async fn start(mut self) -> (SocketAddr, JoinHandle<()>) {
        let port = self.config.port;
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(addr)
            .await
            .expect("Failed to bind TCP listener - port may be in use");
        let local_addr = listener
            .local_addr()
            .expect("Failed to get local address from listener");
        let base_url = format!(
            "{}://{}:{}",
            self.config.scheme,
            self.config.host,
            local_addr.port()
        );
        self.base_url = base_url;

        let cleanup_interval = self.config.cleanup_interval_secs;
        let store = self.store.clone();

        let cleanup_handle = if cleanup_interval > 0 {
            Some(tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(tokio::time::Duration::from_secs(cleanup_interval));
                loop {
                    interval.tick().await;
                    let codes_cleaned = store.cleanup_expired_codes().await;
                    let tokens_cleaned = store.cleanup_expired_tokens().await;
                    let refresh_cleaned = store.cleanup_expired_refresh_tokens().await;
                    let device_codes_cleaned = store.cleanup_expired_device_codes().await;
                    if codes_cleaned > 0
                        || tokens_cleaned > 0
                        || refresh_cleaned > 0
                        || device_codes_cleaned > 0
                    {
                        tracing::debug!(
                            "Cleaned up expired entries: codes={}, tokens={}, refresh={}, device_codes={}",
                            codes_cleaned, tokens_cleaned, refresh_cleaned, device_codes_cleaned
                        );
                    }
                }
            }))
        } else {
            None
        };

        let router = crate::router::build_router(self);
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let combined_handle = tokio::spawn(async move {
            if let Some(cleanup) = cleanup_handle {
                tokio::select! {
                    _ = server_handle => {}
                    _ = cleanup => {}
                }
            } else {
                server_handle.await.unwrap();
            }
        });
        (local_addr, combined_handle)
    }
}
