mod activity;
mod config;
mod dns;
mod email;
mod error;
mod handlers;
mod middleware;
mod models;
mod state;
mod unkey;

use std::net::SocketAddr;

use anyhow::Result;
use axum::{Router, http};
use clap::Parser;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{config::Config, dns::HickoryDnsResolver, email::EmailSender, state::AppState};

#[derive(Parser)]
#[command(name = "api")]
#[command(about = "30s API server")]
struct Args {
    /// Run database migrations and exit
    #[arg(long)]
    migrate: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider before any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args = Args::parse();
    let config = envy::prefixed("THIRTY_SECS_").from_env::<Config>()?;

    // Initialize Sentry for error tracking (must be done early, guard must stay alive)
    let _sentry_guard = config.sentry_dsn.as_ref().map(|dsn| {
        sentry::init((
            dsn.as_str(),
            sentry::ClientOptions {
                release: sentry::release_name!(),
                environment: Some(config.env.clone().into()),
                ..Default::default()
            },
        ))
    });

    // Set up tracing: JSON in production, human-readable otherwise
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if config.is_production() {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer())
            .init();
    }

    let database = PgPoolOptions::new()
        .max_connections(25)
        .connect(&config.database_url)
        .await?;

    // Run migrations via init container only (--migrate flag)
    if args.migrate {
        tracing::info!("Running database migrations...");
        sqlx::migrate!("./migrations").run(&database).await?;
        tracing::info!("Migrations complete");
        return Ok(());
    }

    let redis = redis::Client::open(config.redis_url.as_str())?;
    let unkey = unkey::Client::new(&config.unkey_root_key, &config.unkey_api_id);
    let email = EmailSender::new(config.resend_api_key.clone(), config.smtp_url.clone())?;

    let dns = HickoryDnsResolver::new()?;

    let stripe = stripe::Client::new(&config.stripe_secret_key);

    let state = AppState {
        database,
        redis,
        unkey,
        email: std::sync::Arc::new(email),
        dns: std::sync::Arc::new(dns),
        stripe,
        stripe_webhook_secret: config.stripe_webhook_secret.clone(),
        stripe_price_id: config.stripe_price_id.clone(),
    };

    // Request ID header name
    let x_request_id = http::HeaderName::from_static("x-request-id");

    let app = Router::new()
        .nest("/health", handlers::health::router())
        .nest("/auth", handlers::auth::router())
        .nest("/billing", handlers::billing::router())
        .nest("/devices", handlers::devices::router())
        .nest("/drops", handlers::drops::router())
        .nest("/workspace", handlers::workspace::router())
        .nest("/workspace", handlers::activity::router())
        .with_state(state)
        // Request ID: generate UUID, include in logs, return in response
        .layer(PropagateRequestIdLayer::new(x_request_id.clone()))
        .layer(TraceLayer::new_for_http().make_span_with(
            |request: &http::Request<axum::body::Body>| {
                let request_id = request
                    .headers()
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-");

                tracing::info_span!(
                    "http",
                    method = %request.method(),
                    uri = %request.uri(),
                    request_id = %request_id,
                )
            },
        ))
        .layer(SetRequestIdLayer::new(x_request_id, MakeRequestUuid))
        .layer(RequestBodyLimitLayer::new(1024 * 1024)); // 1MB limit

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;

    tracing::info!("Listening on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Shutdown complete");

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl+C, shutting down..."),
        _ = terminate => tracing::info!("Received SIGTERM, shutting down..."),
    }
}
