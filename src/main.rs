use anyhow::Result;
use axum::{Router, routing::get};
use clap::Parser;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = index::APP_NAME, version, about)]
struct Cli {
    /// Address used by the initial development server.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,
}
#[derive(Serialize)]
struct Health {
    status: &'static str,
}

async fn health() -> axum::Json<Health> {
    axum::Json(Health { status: "ok" })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "index=info".into()))
        .json()
        .init();

    let cli = Cli::parse();
    let listener = TcpListener::bind(&cli.listen).await?;
    let app = Router::new().route("/health/live", get(health));

    tracing::info!(listen = %cli.listen, "server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_is_ok() {
        let axum::Json(response) = health().await;
        assert_eq!(response.status, "ok");
    }
}
