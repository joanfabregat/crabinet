use anyhow::Result;
use clap::Parser;
use index::app::{AppState, router};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = index::APP_NAME, version, about)]
struct Cli {
    /// Address used by the initial development server.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "index=info".into()))
        .json()
        .init();

    let cli = Cli::parse();
    let listener = TcpListener::bind(&cli.listen).await?;
    let app = router(AppState::new(true));

    tracing::info!(listen = %cli.listen, "server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
