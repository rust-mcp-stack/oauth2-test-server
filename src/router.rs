use axum::{
    http::{self, header, HeaderValue},
    routing::{get, post},
    Router,
};
use tower_http::{
    cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

use crate::{
    config::IssuerConfig,
    handlers::{
        authorize::authorize,
        device::{device_code, device_token},
        discovery::{jwks, well_known_openid_configuration},
        error::error_page,
        introspect::introspect,
        register::{get_client, register_client},
        revoke::revoke,
        token::token_endpoint,
        userinfo::userinfo,
    },
    store::AppState,
};

pub fn build_router(state: AppState) -> Router {
    let cors = build_cors_layer(&state.config);
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(well_known_openid_configuration),
        )
        .route("/.well-known/jwks.json", get(jwks))
        .route("/register", post(register_client))
        .route("/register/{client_id}", get(get_client))
        .route("/authorize", get(authorize))
        .route("/token", post(token_endpoint))
        .route("/device/code", post(device_code))
        .route("/device/token", post(device_token))
        .route("/introspect", post(introspect))
        .route("/revoke", post(revoke))
        .route("/userinfo", get(userinfo))
        .route("/error", get(error_page))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
        .layer(cors)
}

fn build_cors_layer(config: &IssuerConfig) -> CorsLayer {
    let allowed_origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    let allowed_methods =
        AllowMethods::list([http::Method::GET, http::Method::POST, http::Method::OPTIONS]);

    let allowed_headers = AllowHeaders::list([
        header::AUTHORIZATION,
        header::CONTENT_TYPE,
        header::ACCEPT,
        "x-requested-with"
            .parse()
            .expect("Static header name should be valid"),
    ]);

    let mut cors = CorsLayer::new()
        .allow_methods(allowed_methods)
        .allow_headers(allowed_headers)
        .max_age(std::time::Duration::from_secs(86400));

    if allowed_origins.is_empty() {
        cors = cors.allow_origin(AllowOrigin::any());
    } else {
        cors = cors
            .allow_origin(AllowOrigin::list(allowed_origins))
            .allow_credentials(true);
    }

    cors
}
