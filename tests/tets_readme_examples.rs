use oauth2_test_server::{AuthorizeParams, OAuthTestServer};

#[tokio::test]
async fn quick_start() {
    let server = OAuthTestServer::start().await;
    println!("server: {}", server.base_url());

    let client = server
        .register_client(serde_json::json!({
            "scope": "openid",
            "redirect_uris": ["http://localhost:8080/callback"],
            "client_name": "rust-mcp-sdk"
        }))
        .await;

    let token = server
        .generate_token(&client, server.jwt_options().user_id("rustmcp").build())
        .await;

    assert_eq!(token.access_token.split('.').count(), 3);
}

#[tokio::test]
async fn auth_code_flow_with_pkce() {
    let server = OAuthTestServer::start().await;

    let client = server
        .register_client(serde_json::json!({
            "scope": "openid profile email",
            "redirect_uris": ["http://localhost:8080/callback"],
            "client_name": "test-client"
        }))
        .await;

    let pkce = server.pkce_pair();

    let auth_url = server.authorize_url(
        &client,
        AuthorizeParams::new()
            .redirect_uri("http://localhost:8080/callback")
            .scope("openid profile")
            .nonce("test-nonce-123")
            .pkce(pkce.clone()),
    );

    let code = server.approve_consent(&auth_url, "test-user").await;

    let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

    assert!(token_response.get("access_token").is_some());
    assert!(token_response.get("id_token").is_some());
    assert!(token_response.get("refresh_token").is_some());
}

#[tokio::test]
async fn complete_auth_flow() {
    let server = OAuthTestServer::start().await;

    let client = server
        .register_client(serde_json::json!({
            "scope": "openid profile email",
            "redirect_uris": ["http://localhost:8080/callback"],
            "client_name": "test-client"
        }))
        .await;

    let token = server
        .complete_auth_flow(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid profile"),
            "test-user",
        )
        .await;

    assert!(token.get("access_token").is_some());
    assert!(token.get("id_token").is_some());
}

#[tokio::test]
async fn device_code_flow() {
    let server = OAuthTestServer::start().await;

    let client = server
        .register_client(serde_json::json!({
            "scope": "openid profile",
            "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
            "client_name": "device-client"
        }))
        .await;

    let token = server
        .complete_device_flow(&client, "openid profile", "device-user")
        .await;

    assert!(token.get("access_token").is_some());
    assert!(token.get("refresh_token").is_some());
}

#[tokio::test]
async fn token_introspection_and_revoke() {
    let server = OAuthTestServer::start().await;

    let client = server
        .register_client(serde_json::json!({
            "scope": "openid",
            "redirect_uris": ["http://localhost:8080/callback"],
        }))
        .await;

    let pkce = server.pkce_pair();
    let auth_url = server.authorize_url(
        &client,
        AuthorizeParams::new()
            .redirect_uri("http://localhost:8080/callback")
            .scope("openid")
            .pkce(pkce.clone()),
    );
    let code = server.approve_consent(&auth_url, "test-user").await;
    let token = server.exchange_code(&client, &code, Some(&pkce)).await;

    let access_token = token["access_token"].as_str().unwrap();

    let introspection = server.introspect_token(&client, access_token).await;
    assert!(introspection["active"].as_bool().unwrap());

    server.revoke_token(&client, access_token).await;

    let introspection_after = server.introspect_token(&client, access_token).await;
    assert!(!introspection_after["active"].as_bool().unwrap());
}

#[tokio::test]
async fn custom_token() {
    let server = OAuthTestServer::start().await;

    let client = server
        .register_client(serde_json::json!({
            "scope": "openid profile email",
            "redirect_uris": ["http://localhost:8080/callback"]
        }))
        .await;

    let jwt = server.generate_jwt(
        &client,
        server
            .jwt_options()
            .user_id("custom-user")
            .scope("openid profile")
            .expires_in(7200)
            .build(),
    );

    assert!(jwt.split('.').count() == 3);
}

#[tokio::test]
async fn with_config() {
    use oauth2_test_server::IssuerConfig;

    let config = IssuerConfig {
        require_state: false,
        port: 0,
        ..Default::default()
    };

    let server = OAuthTestServer::start_with_config(config).await;

    let client = server
        .register_client(serde_json::json!({
            "scope": "openid",
            "redirect_uris": ["http://localhost:8080/callback"],
        }))
        .await;

    let token = server
        .generate_token(&client, server.jwt_options().user_id("testuser").build())
        .await;

    assert!(!token.access_token.is_empty());
}

#[tokio::test]
async fn test_accessor_methods() {
    let server = OAuthTestServer::start().await;

    assert_eq!(server.clients().await.len(), 0);
    assert_eq!(server.codes().await.len(), 0);
    assert_eq!(server.tokens().await.len(), 0);
    assert_eq!(server.refresh_tokens().await.len(), 0);

    let client = server
        .register_client(serde_json::json!({
            "scope": "openid",
            "redirect_uris": ["http://localhost:8080/callback"],
            "client_name": "test-client"
        }))
        .await;

    assert_eq!(server.clients().await.len(), 1);
    assert_eq!(server.clients().await[0].client_id, client.client_id);

    let _token = server
        .generate_token(&client, server.jwt_options().user_id("testuser").build())
        .await;

    assert_eq!(server.tokens().await.len(), 1);
    assert_eq!(server.refresh_tokens().await.len(), 1);
}

#[tokio::test]
async fn test_clear_methods() {
    let server = OAuthTestServer::start().await;

    let client = server
        .register_client(serde_json::json!({
            "scope": "openid",
            "redirect_uris": ["http://localhost:8080/callback"],
        }))
        .await;

    server
        .generate_token(&client, server.jwt_options().user_id("testuser").build())
        .await;

    assert_eq!(server.clients().await.len(), 1);
    assert_eq!(server.tokens().await.len(), 1);

    server.clear_clients().await;
    assert_eq!(server.clients().await.len(), 0);
    assert_eq!(server.tokens().await.len(), 1);

    server.clear_tokens().await;
    assert_eq!(server.tokens().await.len(), 0);
    assert_eq!(server.refresh_tokens().await.len(), 1);

    server.clear_refresh_tokens().await;
    assert_eq!(server.refresh_tokens().await.len(), 0);

    server.clear_all().await;
    assert_eq!(server.clients().await.len(), 0);
    assert_eq!(server.codes().await.len(), 0);
    assert_eq!(server.tokens().await.len(), 0);
    assert_eq!(server.refresh_tokens().await.len(), 0);
}
