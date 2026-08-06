use axum::routing::{get, post};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tracing::info;

mod config;
mod infra;
mod keys;
mod openid;
mod tokens;

fn main() {
    let tracer_provider = infra::init_tracer_provider();

    let config_json =
        std::fs::read_to_string("config.json").expect("Unable to read config.json contents");
    let mut config: config::Config =
        serde_json::from_str(&config_json).expect("Invalid configuration json");

    if !config.issuer.ends_with('/') {
        config.issuer.push('/');
    }

    // Initialize tracing before sandboxing so we can log from apply_sandbox.
    infra::setup_tracing(&tracer_provider);

    info!("Loaded configuration");

    // Read the signing key before sandboxing (key gen happens outside the sandbox).
    let key_pair = keys::generate_keys(&config);

    // Apply landlock before creating the tokio runtime so all worker threads inherit
    // the restrictions via Linux's thread-descendant inheritance model.
    infra::apply_sandbox();

    let state = config::AppState::new(config, key_pair);

    let serve_dir = ServeDir::new("www").not_found_service(ServeFile::new("www/index.html"));

    let cors = CorsLayer::new()
        .allow_credentials(true)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_origin(AllowOrigin::predicate(
            |_headers: &axum::http::HeaderValue, _parts: &axum::http::request::Parts| true,
        ));

    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(openid::get_provider_metadata_route),
        )
        .route("/.well-known/jwks.json", get(openid::get_jwks_route))
        .route("/js/config.js", get(tokens::handle_configjs_route))
        .route("/token", post(tokens::handle_token_route))
        .with_state(state)
        .layer(axum_tracing_opentelemetry::middleware::OtelInResponseLayer::default())
        .layer(axum_tracing_opentelemetry::middleware::OtelAxumLayer::default())
        .layer(cors)
        .fallback_service(serve_dir);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime");

    runtime.block_on(async {
        info!("Created listener");
        let listener = tokio::net::TcpListener::bind("[::]:8000").await.unwrap();
        axum::serve(listener, app)
            .with_graceful_shutdown(infra::shutdown_signal())
            .await
            .unwrap();
        tracer_provider
            .shutdown()
            .expect("Failed to shut down tracer provider");
    });
}
