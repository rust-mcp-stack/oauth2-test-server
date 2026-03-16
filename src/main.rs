use colored::Colorize;
use oauth2_test_server::{IssuerConfig, OAuthTestServer};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let config = IssuerConfig {
        port: 8090,
        ..Default::default()
    };
    let server = OAuthTestServer::start_with_config(config).await;

    println!(
        "{} {}",
        "OAuth Test Server running on".green().bold(),
        server.base_url().to_string().blue().bold()
    );
    println!(" {} {}", "• Discovery:".bold(), server.endpoints.discovery);
    println!(" {} {}", "• Jwks:".bold(), server.endpoints.jwks);
    println!(" {} {}", "• Authorize:".bold(), server.endpoints.authorize);
    println!(" {} {}", "• Token:".bold(), server.endpoints.token);
    println!(
        " {} {}",
        "• Device Code:".bold(),
        server.endpoints.device_code
    );
    println!(
        " {} {}",
        "• Device Token:".bold(),
        server.endpoints.device_token
    );
    println!(" {} {}", "• Register:".bold(), server.endpoints.register);
    println!(
        " {} {}",
        "• Introspection:".bold(),
        server.endpoints.introspect
    );
    println!(" {} {}", "• UserInfo:".bold(), server.endpoints.userinfo);
    println!(" {} {}", "• Revoke:".bold(), server.endpoints.revoke);

    if let Err(err) = server.wait_for_shutdown().await {
        eprintln!("{err}");
    }
}

#[cfg(test)]
mod tests {

    use base64::{engine::general_purpose, Engine};
    use oauth2_test_server::models::IdTokenClaims;
    use oauth2_test_server::testkit::AuthorizeParams;
    use reqwest::StatusCode;

    #[tokio::test]
    async fn test_id_token_in_auth_code_flow() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid profile email",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();
        let nonce = "test-nonce-123";

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid profile email")
                .nonce(nonce)
                .pkce(pkce.clone()),
        );

        let code = server.approve_consent(&auth_url, "test-user").await;
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        assert!(token_response.get("access_token").is_some());
        assert!(token_response.get("id_token").is_some());

        let id_token = token_response["id_token"].as_str().unwrap();
        let parts: Vec<&str> = id_token.split('.').collect();
        let payload = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: IdTokenClaims = serde_json::from_slice(&payload).unwrap();

        assert_eq!(claims.nonce, Some(nonce.to_string()));
        assert!(claims.at_hash.is_some());
        assert!(claims.c_hash.is_some());
    }

    #[tokio::test]
    async fn test_no_id_token_without_openid_scope() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "profile email",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("profile email")
                .pkce(pkce.clone()),
        );

        let code = server.approve_consent(&auth_url, "test-user").await;
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        assert!(token_response.get("access_token").is_some());
        assert!(token_response.get("id_token").is_none());
    }

    #[tokio::test]
    async fn test_id_token_contains_user_claims() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

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
                .scope("openid profile email")
                .pkce(pkce.clone()),
        );

        let code = server.approve_consent(&auth_url, "testuser123").await;
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        let id_token = token_response["id_token"].as_str().unwrap();
        let parts: Vec<&str> = id_token.split('.').collect();
        let payload = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: IdTokenClaims = serde_json::from_slice(&payload).unwrap();

        assert_eq!(claims.sub, "testuser123");
    }

    #[tokio::test]
    async fn test_id_token_has_standard_claims() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
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
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        let id_token = token_response["id_token"].as_str().unwrap();
        let parts: Vec<&str> = id_token.split('.').collect();
        let payload = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: IdTokenClaims = serde_json::from_slice(&payload).unwrap();

        assert!(claims.iss.starts_with("http"));
        assert!(!claims.sub.is_empty());
        assert!(claims.exp > claims.iat);
        assert!(claims.auth_time.is_some());
        assert!(claims.azp.is_some());
        assert!(claims.sid.is_some());
    }

    #[tokio::test]
    async fn test_prompt_consent() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .prompt("consent")
                .pkce(pkce.clone()),
        );

        let code = server.approve_consent(&auth_url, "test-user").await;
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        assert!(token_response.get("access_token").is_some());
    }

    #[tokio::test]
    async fn test_prompt_none_returns_error() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .prompt("none"),
        );

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn test_prompt_invalid_returns_error() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .prompt("invalid_prompt"),
        );

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn test_max_age_parameter() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .max_age("3600")
                .pkce(pkce.clone()),
        );

        let resp = server.http.get(auth_url.clone()).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_max_age_invalid_returns_error() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .max_age("not_a_number"),
        );

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn test_claims_parameter() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid profile email",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let claims_json = serde_json::json!({
            "id_token": {
                "email": {"essential": true},
                "name": {"essential": false}
            }
        })
        .to_string();

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid profile email")
                .claims(claims_json)
                .pkce(pkce.clone()),
        );

        let resp = server.http.get(auth_url.clone()).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_claims_invalid_returns_error() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .claims("not valid json"),
        );

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn test_ui_locales_parameter() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .ui_locales("en-US fr-FR"),
        );

        let resp = server.http.get(auth_url.clone()).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn test_response_mode_form_post() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .response_mode("form_post")
                .pkce(pkce.clone()),
        );

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.text().await.unwrap();
        assert!(body.contains("<form"));
        assert!(body.contains("method=\"POST\""));
        assert!(body.contains("name=\"code\""));
    }

    #[tokio::test]
    async fn test_unsupported_response_type() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams {
                response_type: "invalid",
                state: Some("test-state".to_string()),
                ..Default::default()
            },
        );

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=unsupported_response_type"));
    }

    #[tokio::test]
    async fn test_state_parameter_required() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(&client, AuthorizeParams::new().no_state());

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn test_state_returned_in_token_response() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();
        let state = "test-state-12345";

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid")
                .state(state)
                .pkce(pkce.clone()),
        );

        let code = server.approve_consent(&auth_url, "test-user").await;
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        assert!(token_response.get("state").is_some());
        assert_eq!(token_response["state"].as_str().unwrap(), state);
    }

    #[tokio::test]
    async fn test_token_expiration_check() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
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
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        let access_token = token_response["access_token"].as_str().unwrap();

        let introspection = server.introspect_token(&client, access_token).await;
        assert!(introspection["active"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_require_state_configurable() {
        use oauth2_test_server::IssuerConfig;

        let config = IssuerConfig {
            require_state: false,
            port: 0,
            ..Default::default()
        };

        let server = oauth2_test_server::OAuthTestServer::start_with_config(config).await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let auth_url = server.authorize_url(
            &client,
            AuthorizeParams::new()
                .no_state()
                .redirect_uri("http://localhost:8080/callback"),
        );

        let resp = server.http.get(auth_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        println!("Location: {}", location);
        assert!(location.contains("code="));
    }

    #[tokio::test]
    async fn test_device_code_flow() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid profile",
                "client_name": "test-device-client",
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"]
            }))
            .await;

        let scope = "openid profile".to_string();
        let device_code_resp = server
            .http
            .post(server.base_url.join("device/code").unwrap())
            .form(&[("client_id", &client.client_id), ("scope", &scope)])
            .send()
            .await
            .unwrap();

        assert_eq!(device_code_resp.status(), StatusCode::OK);

        let device_code_data: serde_json::Value = device_code_resp.json().await.unwrap();

        assert!(device_code_data.get("device_code").is_some());
        assert!(device_code_data.get("user_code").is_some());
        assert!(device_code_data.get("verification_uri").is_some());

        let device_code = device_code_data["device_code"].as_str().unwrap();

        server
            .approve_device_code(device_code, "test-device-user")
            .await;

        let token_resp = server
            .http
            .post(server.base_url.join("device/token").unwrap())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
                ("client_id", &client.client_id),
            ])
            .send()
            .await
            .unwrap();

        assert_eq!(token_resp.status(), StatusCode::OK);

        let token_data: serde_json::Value = token_resp.json().await.unwrap();

        assert!(token_data.get("access_token").is_some());
        assert!(token_data.get("refresh_token").is_some());
    }

    #[tokio::test]
    async fn test_device_code_invalid_client() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let scope = "openid".to_string();
        let device_code_resp = server
            .http
            .post(server.base_url.join("device/code").unwrap())
            .form(&[("client_id", "invalid-client"), ("scope", &scope)])
            .send()
            .await
            .unwrap();

        assert_eq!(device_code_resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_device_code_unauthorized() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "client_name": "test-client",
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"]
            }))
            .await;

        let scope = "openid".to_string();
        let device_code_resp = server
            .http
            .post(server.base_url.join("device/code").unwrap())
            .form(&[("client_id", &client.client_id), ("scope", &scope)])
            .send()
            .await
            .unwrap();

        let device_code_data: serde_json::Value = device_code_resp.json().await.unwrap();
        let device_code = device_code_data["device_code"].as_str().unwrap();

        let token_resp = server
            .http
            .post(server.base_url.join("device/token").unwrap())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
                ("client_id", &client.client_id),
            ])
            .send()
            .await
            .unwrap();

        let token_data: serde_json::Value = token_resp.json().await.unwrap();

        assert_eq!(token_data["error"], "authorization_pending");
    }

    #[tokio::test]
    async fn test_token_cleanup() {
        use oauth2_test_server::IssuerConfig;

        let config = IssuerConfig {
            cleanup_interval_secs: 1,
            access_token_expires_in: 2,
            port: 0,
            ..Default::default()
        };

        let server = oauth2_test_server::OAuthTestServer::start_with_config(config).await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
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
        let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;

        let access_token = token_response["access_token"].as_str().unwrap();

        let introspection = server.introspect_token(&client, access_token).await;
        assert!(introspection["active"].as_bool().unwrap());

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        let introspection_after = server.introspect_token(&client, access_token).await;
        assert!(!introspection_after["active"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_complete_auth_flow() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid profile email",
                "redirect_uris": ["http://localhost:8080/callback"],
                "client_name": "test-client"
            }))
            .await;

        let pkce = server.pkce_pair();

        let token_response = server
            .complete_auth_flow(
                &client,
                AuthorizeParams::new()
                    .redirect_uri("http://localhost:8080/callback")
                    .scope("openid profile")
                    .pkce(pkce),
                "test-user",
            )
            .await;

        assert!(token_response.get("access_token").is_some());
        assert!(token_response.get("id_token").is_some());
        assert!(token_response.get("refresh_token").is_some());
    }

    #[tokio::test]
    async fn test_complete_device_flow() {
        let server = oauth2_test_server::OAuthTestServer::start().await;

        let client = server
            .register_client(serde_json::json!({
                "scope": "openid profile",
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
                "client_name": "test-device-client"
            }))
            .await;

        let token_response = server
            .complete_device_flow(&client, "openid profile", "device-user")
            .await;

        assert!(token_response.get("access_token").is_some());
        assert!(token_response.get("refresh_token").is_some());
    }
}
