//! # Rust OAuth2 Server
//!
//!
//! A **complete, standards-compliant OAuth 2.0 and OpenID Connect 1.0 Authorization Server**,
//! implemented in **pure Rust** using **Axum**. This server is specially designed to support
//! **testing authentication flow of MCP Servers and Clients**, with full support for Dynamic Client Registration (DCR).
//!
//! **⚠️ Warning: NOT** for production use - in-memory, no persistence, no rate limiting.
//!
//! ## Caution
//!
//! This server was developed with the purpose of supporting testing and development of
//! the **[`rust-mcp-sdk`](https://crates.io/crates/rust-mcp-sdk)**, and may not be maintained or updated regularly. Please consider this when integrating
//! or using this server in other contexts.
//!
//!
//! ## Purpose
//!
//! This server implements **all major OAuth 2.0 flows** and **OpenID Connect core features**
//! in-memory, making it ideal for:
//!
//! - Testing OAuth clients (web, mobile, SPA, backend)
//! - Specifically tailored for **testing authentication flow MCP Servers and Clients**, with DCR support
//! - Integration testing of authorization flows
//! - Local development against a real OAuth provider
//! - Demonstrating OAuth concepts
//! - CI/CD pipeline validation
//!
//! ## Supported Standards
//!
//! | Standard | Implemented |
//! |--------|-------------|
//! | [RFC 6749](https://tools.ietf.org/html/rfc6749) – OAuth 2.0 | Full |
//! | [RFC 6750](https://tools.ietf.org/html/rfc6750) – Bearer Token | Yes |
//! | [RFC 7636](https://tools.ietf.org/html/rfc7636) – PKCE | Yes (`plain`, `S256`) |
//! | [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) – Dynamic Client Registration | Yes |
//! | [RFC 7662](https://tools.ietf.org/html/rfc7662) – Token Introspection | Yes |
//! | [RFC 7009](https://tools.ietf.org/html/rfc7009) – Token Revocation | Yes |
//! | [RFC 7519](https://tools.ietf.org/html/rfc7519) – JWT Access Tokens (RS256) | Yes |
//! | [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Yes |
//! | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | Partial (UserInfo, `sub`, `iss`) |
//!
//! ## Key Features
//!
//! - **Dynamic Client Registration (DCR)** (`POST /register`) with full metadata support
//! - **Authorization Code Flow** with **PKCE** (`/authorize`, `/token`)
//! - **Refresh Token Flow** with rotation and revocation
//! - **Client Credentials Grant**
//! - **JWT Access Tokens** signed with **RS256** (auto-generated RSA key pair)
//! - **Token Introspection** (`POST /introspect`)
//! - **Token Revocation** (`POST /revoke`)
//! - **OpenID Connect Discovery** (`.well-known/openid-configuration`)
//! - **JWKS Endpoint** (`.well-known/jwks.json`)
//! - **UserInfo Endpoint** (`GET /userinfo`)
//! - **In-memory stores** (clients, codes, tokens) - no external DB required
//! - **Full error handling** with redirect errors and JSON error responses
//! - **State parameter**, **scope**, **redirect_uri validation**
//!
//! ## Endpoints
//!
//! | Method | Path | Description |
//! |-------|------|-------------|
//! | `GET`  | `/.well-known/openid-configuration` | OIDC Discovery |
//! | `GET`  | `/.well-known/jwks.json`           | Public keys for JWT validation |
//! | `POST` | `/register`                        | Dynamic client registration |
//! | `GET`  | `/register/:client_id`             | Retrieve registered client |
//! | `GET`  | `/authorize`                       | Authorization endpoint (code flow) |
//! | `POST` | `/token`                           | Token endpoint (all grants) |
//! | `POST` | `/introspect`                      | RFC 7662 introspection |
//! | `POST` | `/revoke`                          | RFC 7009 revocation |
//! | `GET`  | `/userinfo`                        | OIDC user info (requires Bearer token) |
//! | `GET`  | `/error`                           | Human-readable error page |
//!
//! ## In-Memory Stores
//!
//! - `clients`: `HashMap<String, Client>` - registered clients
//! - `codes`: `HashMap<String, AuthorizationCode>` - short-lived auth codes
//! - `tokens`: `HashMap<String, Token>` - access tokens (JWTs)
//! - `refresh_tokens`: `HashMap<String, Token>` - refresh token mapping
//!
//! ## Security & Testing
//!
//! - **No persistence** - perfect for isolated tests
//! - **Auto-generated RSA key pair** on startup
//! - **PKCE verification** (`S256` and `plain`)
//! - **Token revocation propagation**
//! - **Expiration enforcement**
//! - **Scope and redirect_uri validation**
//!
//!
//! ## Running
//!
//! ```bash
//! cargo run
//! # OAuth Test Server running on http://127.0.0.1:8090/
//! # • Discovery: http://127.0.0.1:8090/.well-known/openid-configuration
//! # • Jwks: http://127.0.0.1:8090/.well-known/jwks.json
//! # • Authorize: http://127.0.0.1:8090/register
//! # • Token: http://127.0.0.1:8090/token
//! # • Register: http://127.0.0.1:8090/authorize
//! # • Introspection: http://127.0.0.1:8090/introspect
//! # • UserInfo: http://127.0.0.1:8090/userinfo
//! # • Revoke: http://127.0.0.1:8090/revoke
//! ```
//!
//! ## Example Usage
//!
//! ```bash
//! # Register a client
//! curl -X POST http://localhost:8090/register -H "Content-Type: application/json" -d '{
//!   "redirect_uris": ["http://localhost:8090/callback"],
//!   "grant_types": ["authorization_code"],
//!   "response_types": ["code"],
//!   "scope": "openid profile email"
//! }'
//! ```
//!
//! ## How to Use in Tests
//!
//! ```
//! #[tokio::test]
//! async fn my_oauth_test() {
//! let server = oauth2_test_server::OAuthTestServer::start().await;
//! println!("server: {}", server.base_url());
//! println!("authorize endpoint: {}", server.endpoints.authorize);
//! // register a client
//! let client = server.register_client(serde_json::json!({ "scope": "openid",
//!         "redirect_uris":["http://localhost:8080/callback"],
//!         "client_name": "rust-mcp-sdk"
//!     })).await;
//! // generate a jwt for the client
//! let token = server.generate_token(&client, server.jwt_options().user_id("rustmcp").build()).await;
//! assert_eq!(token.access_token.split('.').count(), 3);
//! }
//!```
//!
//! ## Ideal For
//!
//! - Testing OAuth libraries
//! - End-to-end flow validation
//! - Local development
//! - Security research
//! - Teaching OAuth/OIDC
//!
//!  **⚠️ Warning: Not for production use** - in-memory, no persistence, no rate limiting.
pub mod config;
pub mod crypto;
pub mod error;
pub mod handlers;
pub mod models;
pub mod router;
pub mod store;

pub mod testkit;

pub use config::{ConfigError, IssuerConfig};
pub use crypto::{calculate_at_hash, calculate_c_hash, issue_id_token, Keys};
pub use models::{Client, IdTokenClaims, Token};
pub use store::AppState;

#[cfg(feature = "testing")]
pub use testkit::{
    AuthorizeParams, JwtOptions, JwtOptionsBuilder, OAuthTestServer, OauthEndpoints, PkcePair,
};
