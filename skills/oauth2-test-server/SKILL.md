# Use oauth2-test-server for Testing and CI

## When to use this skill

Use this skill when you need to test OAuth2/OIDC client behavior in Rust tests or CI pipelines without depending on external identity providers.

Typical cases:
- Integration tests that require authorization_code, refresh_token, device_code, DCR, or OIDC id_token behavior.
- CI smoke tests for auth flows.
- Reproducible auth tests that must run offline and deterministically.

## Core principles

1. Prefer in-process testkit in tests
- For Rust tests, start the server using `oauth2_test_server::OAuthTestServer` from the library API.
- This is faster and less flaky than spawning external processes.

2. Prefer dynamic ports in tests
- Use `IssuerConfig { port: 0, ..Default::default() }` or `OAuthTestServer::start()` so the OS chooses a free port.
- Avoid hardcoded ports in parallel CI.

3. Keep tests deterministic
- Set explicit token TTLs where timing matters.
- Avoid relying on ambient `OAUTH_*` env vars in tests unless the test explicitly validates env behavior.

4. Use precedence intentionally
- Standalone binary precedence is:
  1) scalar CLI overrides
  2) scalar `OAUTH_*` env vars
  3) YAML/TOML file via `--config`
  4) built-in defaults

## Recommended test patterns

### Pattern A: In-process integration test (preferred)

```rust
#[tokio::test]
async fn auth_code_flow_works() {
    let server = oauth2_test_server::OAuthTestServer::start().await;

    let client = server
        .register_client(serde_json::json!({
            "scope": "openid profile email",
            "redirect_uris": ["http://localhost:8080/callback"],
            "client_name": "ci-client"
        }))
        .await;

    let token = server
        .complete_auth_flow(
            &client,
            oauth2_test_server::testkit::AuthorizeParams::new()
                .redirect_uri("http://localhost:8080/callback")
                .scope("openid profile email"),
            "ci-user",
        )
        .await;

    assert!(token.get("access_token").is_some());
    assert!(token.get("id_token").is_some());
}
```

### Pattern B: Config-specific integration test

Use explicit config when validating behavior like state enforcement or token expiry.

```rust
let config = oauth2_test_server::IssuerConfig {
    require_state: true,
    access_token_expires_in: 300,
    port: 0,
    ..Default::default()
};
let server = oauth2_test_server::OAuthTestServer::start_with_config(config).await;
```

### Pattern C: Binary smoke test in CI

Use this only if you need to validate the CLI/binary path itself.

```bash
oauth2-test-server --config ./config.sample.yaml --port 9010
```

Generate sample config files:

```bash
oauth2-test-server -generate-config-sample-yaml
oauth2-test-server -generate-config-env-sample
```

Example env-driven startup:

```bash
OAUTH_PORT=9010 OAUTH_DEFAULT_USER_ID=ci-user oauth2-test-server
```

## CI command set

Run this minimal set in CI:

```bash
cargo test --bin oauth2-test-server
cargo test --test config
cargo test ./...
```

If runtime is a concern, run targeted suites first, then full suite on merge.

## Binary CLI overrides supported (scalar only)

- `--scheme`
- `--host`
- `--port`
- `--default-user-id`
- `--require-state`
- `--generate-client-secret-for-dcr`
- `--access-token-expires-in`
- `--refresh-token-expires-in`
- `--authorization-code-expires-in`
- `--cleanup-interval-secs`

## Binary helper options

- `-generate-config-sample-yaml` / `--generate-config-sample-yaml`
    Generates `./.config.sample.yaml` and exits.
- `-generate-config-env-sample` / `--generate-config-env-sample`
    Generates `./.config.sample.env` and exits.

Array/list fields (like scopes, claims, allowed_origins) are not CLI-overridable; set those in config files.

## Common pitfalls and fixes

1. Flaky tests due to fixed ports
- Fix: use `port: 0` and read `server.base_url()`.

2. Hidden env influence in CI
- Fix: clear or scope `OAUTH_*` vars in job steps unless testing env precedence.

3. Misunderstood precedence
- Fix: remember CLI scalar flags override env and file values.

4. Invalid bool/number inputs
- Fix: use explicit values:
  - bool: `true|false|1|0|yes|no`
  - numeric fields: unsigned integers

## Suggested CI snippet (GitHub Actions)

```yaml
- name: Run oauth2-test-server focused tests
  run: |
    cargo test --bin oauth2-test-server
    cargo test --test config
```

## Definition of done for auth test changes

- Tests use in-process server unless binary path is under test.
- No hardcoded ports in integration tests.
- New config fields are reflected in `config.sample.yaml` and guarded by tests.
- CI includes focused oauth2-test-server tests.
