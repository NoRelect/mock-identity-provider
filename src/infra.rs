use opentelemetry::global;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_tracer_provider() -> SdkTracerProvider {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .build()
        .expect("Failed to build OTLP span exporter");

    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "mock_identity_provider".to_string());

    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(service_name)
        .build();

    SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build()
}

pub fn setup_tracing(_tracer_provider: &SdkTracerProvider) {
    let tracer = global::tracer("mock-identity-provider");

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();
}

pub fn apply_sandbox() {
    use landlock::{
        ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    };

    let abi = ABI::V6;

    let www_fd = match PathFd::new("www") {
        Ok(fd) => fd,
        Err(e) => {
            warn!("Landlock sandbox not applied: cannot open www/ ({e})");
            return;
        }
    };

    let result = (|| -> Result<_, landlock::RulesetError> {
        Ruleset::default()
            .handle_access(AccessFs::from_all(abi))?
            .create()?
            .add_rules([Ok::<_, landlock::RulesetError>(PathBeneath::new(
                www_fd,
                AccessFs::from_read(abi),
            ))])?
            .restrict_self()
    })();

    match result {
        Ok(status) => {
            info!("Landlock sandbox applied ({:?})", status.ruleset);
        }
        Err(e) => {
            warn!("Landlock not enforced: {e}");
        }
    }
}

pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
