# OAuth 2.0 Test Server

A fast, fully configurable, in-memory OAuth 2.0 + OpenID Connect authorization server for testing, zero-HTTP mode and DCR support for testing auth flow in MCP Servers and MCP Clients.

This server was developed with the purpose of supporting testing and development of the [<img align="top" src="https://raw.githubusercontent.com/rust-mcp-stack/rust-mcp-schema/refs/heads/main/assets/rust-mcp-stack-icon.png" width="24" style="border-radius:0.1rem;">  rust-mcp-sdk](https://github.com/rust-mcp-stack/rust-mcp-sdk), but it works perfectly as a general-purpose auth mocking in any Rust (or non-Rust) project , unit tests, integration suites, local dev, or quick prototypes.  
Refer to [Key Features](#key-features) to find out more.

# 
**⚠️ For testing/development only**
- In-memory storage (not persistent)
- No rate limiting or attack protection
- Use in test suites, CI/CD, local development


## Purpose

This server implements all major OAuth 2.0 flows and OpenID Connect core features in-memory, making it ideal for:

- Testing OAuth clients (web, mobile, SPA, backend)
- Specifically tailored for testing authentication flow MCP Servers and Clients, with DCR support
- End-to-end flow validation
- Local development
- Integration testing of authorization flows
- Local development against a real OAuth provider
- Demonstrating OAuth concepts
- CI/CD pipeline validation


## Supported Standards


 | Standard | Implemented |
 |--------|-------------|
 | [RFC 6749](https://tools.ietf.org/html/rfc6749) – OAuth 2.0 | Full |
 | [RFC 6750](https://tools.ietf.org/html/rfc6750) – Bearer Token | Yes |
 | [RFC 7636](https://tools.ietf.org/html/rfc7636) – PKCE | Yes (`plain`, `S256`) |
 | [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) – Dynamic Client Registration | Yes |
 | [RFC 7662](https://tools.ietf.org/html/rfc7662) – Token Introspection | Yes |
 | [RFC 7009](https://tools.ietf.org/html/rfc7009) – Token Revocation | Yes |
 | [RFC 7519](https://tools.ietf.org/html/rfc7519) – JWT Access Tokens (RS256) | Yes |
 | [RFC 8628](https://tools.ietf.org/html/rfc8628) – Device Code Flow | Yes |
 | [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Yes |
 | [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | Yes (ID Tokens, UserInfo, Claims) |

 ## Key Features

 - **Dynamic Client Registration (DCR)** (`POST /register`) with full metadata support
 - **Authorization Code Flow** with **PKCE** (`/authorize`, `/token`)
 - **Refresh Token Flow** with rotation and revocation
 - **Client Credentials Grant**
 - **Device Code Flow (RFC 8628)** (`/device/code`, `/device/token`)
 - **JWT Access Tokens** signed with **RS256** (auto-generated RSA key pair)
 - **ID Tokens** with `at_hash`, `c_hash`, `nonce`, standard claims
 - **Token Introspection** (`POST /introspect`) with expiration checking
 - **Token Revocation** (`POST /revoke`)
 - **OpenID Connect Discovery** (`.well-known/openid-configuration`)
 - **JWKS Endpoint** (`.well-known/jwks.json`)
 - **UserInfo Endpoint** (`GET /userinfo`)
 - **In-memory stores** (clients, codes, tokens, device codes) - no external DB required
 - **Background TTL cleanup** for expired tokens/codes
 - **Full error handling** with redirect errors and JSON error responses
 - **State parameter** (required by default, configurable)
 - **Scope**, **redirect_uri** validation
 - **Authorization parameters**: `prompt`, `max_age`, `claims`, `ui_locales`, `response_mode`
 - **Configurable via YAML/TOML files** or environment variables

 ## Endpoints

 | Method | Path | Description |
 |-------|------|-------------|
 | `GET`  | `/.well-known/openid-configuration` | OIDC Discovery |
 | `GET`  | `/.well-known/jwks.json`           | Public keys for JWT validation |
 | `POST` | `/register`                        | Dynamic client registration |
 | `GET`  | `/register/:client_id`             | Retrieve registered client |
 | `GET`  | `/authorize`                       | Authorization endpoint (code flow) |
 | `POST` | `/token`                           | Token endpoint (all grants) |
 | `POST` | `/device/code`                     | Device code flow - initiate |
 | `POST` | `/device/token`                   | Device code flow - poll token |
 | `POST` | `/introspect`                      | RFC 7662 introspection |
 | `POST` | `/revoke`                          | RFC 7009 revocation |
 | `GET`  | `/userinfo`                        | OIDC user info (requires Bearer token) |
 | `GET`  | `/error`                           | Human-readable error page |


> Note:  `/token` endpoint supports all OAuth2 grant types: `Authorization Code`, `Refresh Token`, `Client Credentials`.
The Device Code flow uses separate endpoints (`/device/code` and `/device/token`) since it's a polling mechanism, but the main `/token` endpoint handles the three most common grants.

 ## In-Memory Stores

 - `clients`: `HashMap<String, Client>` - registered clients
 - `codes`: `HashMap<String, AuthorizationCode>` - short-lived auth codes
 - `tokens`: `HashMap<String, Token>` - access tokens (JWTs)
 - `refresh_tokens`: `HashMap<String, Token>` - refresh token mapping
 - `device_codes`: `HashMap<String, DeviceAuthorization>` - device code flow state

 ## Security & Testing

 - **No persistence** - perfect for isolated tests
 - **Auto-generated RSA key pair** on startup
 - **PKCE verification** (`S256` and `plain`)
 - **Token revocation propagation**
 - **Expiration enforcement** (configurable TTL)
 - **Background cleanup** of expired tokens/codes
 - **Scope and redirect_uri validation**
 - **State parameter** (required by default, configurable)
 - **ID Token security** (`at_hash`, `c_hash` validation)
 - **Configurable token expiration times**




## Run as a Standalone Binary (Great for Manual Testing & Debugging)

You can run the server directly from your terminal - no code required.

### 1. Install it globally using one of the following methods:
<!-- x-release-please-start-version -->
  - **Cargo**
    ```bash
    cargo install oauth2-test-server
    ```

  - **Shell script**
    ```bash
    curl --proto '=https' --tlsv1.2 -LsSf https://github.com/rust-mcp-stack/oauth2-test-server/releases/download/v0.1.3/oauth2-test-server-installer.sh | sh
    ```
  
  - **PowerShell script**
    ```bash
    powershell -ExecutionPolicy Bypass -c "irm https://github.com/rust-mcp-stack/oauth2-test-server/releases/download/v0.1.3/oauth2-test-server-installer.ps1 | iex"
    ```

  - **Homebrew**
    ```bash
    brew install rust-mcp-stack/tap/oauth2-test-server
    ```
  
  - **NPM**

    ```sh
    npm i -g @rustmcp/oauth2-test-server@latest
    ```
    > The npm package is provided for convenience. It runs the same underlying Rust binary but can be installed and used as a standard npm package.
  
  - **Download Binaries**
    <table>
    <thead>
        <tr>
        <th>Platform</th>
        <th>File</th>
        <th>Checksum</th>
        </tr>
    </thead>
    <tbody>
        <tr>      
        <td>Apple Silicon macOS</td>
        <td>
        <a href="https://github.com/rust-mcp-stack/oauth2-test-server/releases/download/v0.4.1/oauth2-test-server-aarch64-apple-darwin.tar.gz">oauth2-test-server-aarch64-apple-darwin.tar.gz</a>
        </td>
        <td>
        <a href="https://github.com/rust-mcp-stack/oauth2-test-server/releases/download/v0.4.1/oauth2-test-server-aarch64-apple-darwin.tar.gz.sha256">checksum</a>
        </td>
        </tr>
        <tr>
        <td>Intel macOS</td>
        <td>
        <a href="https://github.com/rust-mcp-stack/oauth2-test-server/releases/download/v0.4.1/oauth2-test-server-x86_64-apple-darwin.tar.gz">oauth2-test-server-x86_64-apple-darwin.tar.gz</a>
        </td>
        <td>
        <a href="https://github.com/rust-mcp-stack/oauth2-test-server/releases/download/v0.4.1/oauth2-test-server-x86_64-apple-darwin.tar.gz.sha256">checksum</a>
        </td>
        </tr>
        <tr>
        <td>x64 Windows (zip)</td>  
        <td>
        <a href="https://github.com/rust-mcp-stack/oauth2-test-server/releases/download/v0.4.1/oauth2-test-server-x86_64-pc-windows-msvc.zip">oauth2-test-server-x86_64-pc-windows-msvc.zip</a>
        </td>        
        <td>
        <a href="https://github.com/rust-mcp-stack/oauth2-test-server/releases/download/v0.4.1/oauth2-test-server-x86_64-pc-windows-msvc.zip.sha256">checksum</a>
        </td>
        </tr>
        <tr>
        <td>x64 Windows (msi)</td>
        <td>
        <a href="https://github.com/rust-mcp-stack/oauth2-test-server/releases/download/v0.4.1/oauth2-test-server-x86_64-pc-windows-msvc.msi">oauth2-test-server-x86_64-pc-windows-msvc.msi</a>
        </td>        
        <td>
        <a href="https://github.com/rust-mcp-stack/oauth2-test-server/releases/download/v0.4.1/oauth2-test-server-x86_64-pc-windows-msvc.msi.sha256">checksum</a>
        </td>
        </tr>
        <tr>
        <td>ARM64 Linux</td>
        <td>
        <a href="https://github.com/rust-mcp-stack/oauth2-test-server/releases/download/v0.4.1/oauth2-test-server-aarch64-unknown-linux-gnu.tar.gz">oauth2-test-server-aarch64-unknown-linux-gnu.tar.gz</a>
        </td>        
        <td>
        <a href="https://github.com/rust-mcp-stack/oauth2-test-server/releases/download/v0.4.1/oauth2-test-server-aarch64-unknown-linux-gnu.tar.gz.sha256">checksum</a>
        </td>
        </tr>
        <tr>
        <td>x64 Linux</td>
        <td>
        <a href="https://github.com/rust-mcp-stack/oauth2-test-server/releases/download/v0.4.1/oauth2-test-server-x86_64-unknown-linux-gnu.tar.gz">oauth2-test-server-x86_64-unknown-linux-gnu.tar.gz</a>
        </td>        
        <td>
        <a href="https://github.com/rust-mcp-stack/oauth2-test-server/releases/download/v0.4.1/oauth2-test-server-x86_64-unknown-linux-gnu.tar.gz.sha256">checksum</a>
        </td>
        </tr>
    </tbody>
    </table>

<!-- x-release-please-end -->


### 2. Start the server

```bash
oauth2-test-server
```

You’ll see:
```
OAuth Test Server running on http://127.0.0.1:8090/
 • Discovery: http://127.0.0.1:8090/.well-known/openid-configuration
 • Jwks: http://127.0.0.1:8090/.well-known/jwks.json
 • Authorize: http://127.0.0.1:8090/authorize
 • Token: http://127.0.0.1:8090/token
 • Device Code: http://127.0.0.1:8090/device/code
 • Device Token: http://127.0.0.1:8090/device/token
 • Register: http://127.0.0.1:8090/register
 • Introspection: http://127.0.0.1:8090/introspect
 • UserInfo: http://127.0.0.1:8090/userinfo
 • Revoke: http://127.0.0.1:8090/revoke
```

Quick test with curl:

 ```bash
 # Register a client
 curl -X POST http://localhost:8090/register -H "Content-Type: application/json" -d '{
   "redirect_uris": ["http://localhost:8090/callback"],
   "grant_types": ["authorization_code"],
   "response_types": ["code"],
   "scope": "openid profile email"
 }'
 ```

 ## How to Use in Tests

### Quick Start
```rust
#[tokio::test]
async fn quick_start() {
    let server = oauth2_test_server::OAuthTestServer::start().await;
    println!("server: {}", server.base_url());
    
    let client = server.register_client(serde_json::json!({
        "scope": "openid",
        "redirect_uris": ["http://localhost:8080/callback"],
        "client_name": "rust-mcp-sdk"
    })).await;
    
    // Generate a token directly
    let token = server.generate_token(&client, 
        server.jwt_options().user_id("rustmcp").build()
    ).await;
    
    assert_eq!(token.access_token.split('.').count(), 3);
}
```

### Authorization Code Flow with PKCE
```rust
#[tokio::test]
async fn auth_code_flow_with_pkce() {
    let server = OAuthTestServer::start().await;
    
    let client = server.register_client(serde_json::json!({
        "scope": "openid profile email",
        "redirect_uris": ["http://localhost:8080/callback"],
        "client_name": "test-client"
    })).await;
    
    let pkce = server.pkce_pair();
    
    let auth_url = server.authorize_url(&client, AuthorizeParams::new()
        .redirect_uri("http://localhost:8080/callback")
        .scope("openid profile")
        .nonce("test-nonce-123")
        .pkce(pkce.clone())
    );
    
    let code = server.approve_consent(&auth_url, "test-user").await;
    
    let token_response = server.exchange_code(&client, &code, Some(&pkce)).await;
    
    assert!(token_response.get("access_token").is_some());
    assert!(token_response.get("id_token").is_some()); // ID token with openid scope
    assert!(token_response.get("refresh_token").is_some());
}
```

### Complete Auth Flow (One-Liner)
```rust
#[tokio::test]
async fn complete_auth_flow() {
    let server = oauth2_test_server::OAuthTestServer::start().await;
    
    let client = server.register_client(serde_json::json!({
        "scope": "openid profile email",
        "redirect_uris": ["http://localhost:8080/callback"],
        "client_name": "test-client"
    })).await;
    
    // Complete flow in one call
    let token = server.complete_auth_flow(
        &client,
        AuthorizeParams::new()
            .redirect_uri("http://localhost:8080/callback")
            .scope("openid profile"),
        "test-user"
    ).await;
    
    assert!(token.get("access_token").is_some());
    assert!(token.get("id_token").is_some());
}
```

### Device Code Flow
```rust
#[tokio::test]
async fn device_code_flow() {
    let server = oauth2_test_server::OAuthTestServer::start().await;
    
    // Register client with device_code grant
    let client = server.register_client(serde_json::json!({
        "scope": "openid profile",
        "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
        "client_name": "device-client"
    })).await;
    
    // Complete device flow in one call
    let token = server.complete_device_flow(&client, "openid profile", "device-user").await;
    
    assert!(token.get("access_token").is_some());
    assert!(token.get("refresh_token").is_some());
}
```

### Token Introspection & Revocation
```rust
#[tokio::test]
async fn token_introspection_and_revoke() {
    let server = oauth2_test_server::OAuthTestServer::start().await;
    
    let client = server.register_client(serde_json::json!({
        "scope": "openid",
        "redirect_uris": ["http://localhost:8080/callback"],
    })).await;
    
    let pkce = server.pkce_pair();
    let auth_url = server.authorize_url(&client, AuthorizeParams::new()
        .redirect_uri("http://localhost:8080/callback")
        .scope("openid")
        .pkce(pkce.clone())
    );
    let code = server.approve_consent(&auth_url, "test-user").await;
    let token = server.exchange_code(&client, &code, Some(&pkce)).await;
    
    let access_token = token["access_token"].as_str().unwrap();
    
    // Introspect token
    let introspection = server.introspect_token(&client, access_token).await;
    assert!(introspection["active"].as_bool().unwrap());
    
    // Revoke token
    server.revoke_token(&client, access_token).await;
    
    // Verify revoked
    let introspection_after = server.introspect_token(&client, access_token).await;
    assert!(!introspection_after["active"].as_bool().unwrap());
}
```

### Custom Token Generation (for unit tests)
```rust
#[tokio::test]
async fn custom_token() {
    let server = oauth2_test_server::OAuthTestServer::start().await;
    
    let client = server.register_client(serde_json::json!({
        "scope": "openid profile email",
        "redirect_uris": ["http://localhost:8080/callback"]
    })).await;
    
    // Generate JWT directly with custom claims
    let jwt = server.generate_jwt(&client, 
        server.jwt_options()
            .user_id("custom-user")
            .scope("openid profile")
            .expires_in(7200)
            .build()
    );
    
    assert!(jwt.split('.').count() == 3);
}
```

### Loading from Config File
```rust
#[tokio::test]
async fn with_config() {
    use oauth2_test_server::IssuerConfig;
    
    let config = IssuerConfig {
        require_state: false,
        port: 0,
        ..Default::default()
    };
    
    let server = OAuthTestServer::start_with_config(config).await;
    
    let client = server.register_client(serde_json::json!({
        "scope": "openid",
        "redirect_uris": ["http://localhost:8080/callback"],
    })).await;
    
    let token = server.generate_token(&client, 
        server.jwt_options().user_id("testuser").build()
    ).await;
    
    assert!(!token.access_token.is_empty());
}
```


**⚠️ For testing/development only**
- In-memory storage (not persistent)
- No rate limiting or attack protection
- Use in test suites, CI/CD, local development
