use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use index::{
    app::{AppState, router},
    config::Config,
    password::hash_confirmed,
};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = index::APP_NAME, version, about)]
struct Cli {
    /// Immutable TOML configuration file. INDEX_CONFIG is the only environment override.
    #[arg(
        long,
        global = true,
        env = "INDEX_CONFIG",
        default_value = "config.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate the configuration and every referenced path, then exit.
    CheckConfig,
    /// Print the JSON Schema for the current configuration version.
    PrintConfigSchema,
    /// Prompt twice on the controlling terminal and print an Argon2id PHC string.
    HashPassword,
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "index=info".into()))
        .json()
        .init();

    let cli = Cli::parse();
    match cli.command {
        Some(Command::CheckConfig) => {
            Config::load(&cli.config).context("configuration check failed")?;
            println!("configuration is valid");
            return Ok(());
        }
        Some(Command::PrintConfigSchema) => {
            println!("{}", Config::schema_json()?);
            return Ok(());
        }
        Some(Command::HashPassword) => {
            let password = rpassword::prompt_password("Password: ")
                .context("cannot read password from the controlling terminal")?;
            let confirmation = rpassword::prompt_password("Confirm password: ")
                .context("cannot read password confirmation from the controlling terminal")?;
            let hash = hash_confirmed(&password, &confirmation)?;
            println!("{hash}");
            return Ok(());
        }
        None => {}
    }

    // Loading and validating every configured path is deliberately completed before the
    // listening socket is created. Invalid policy must never result in a partially started app.
    let config = Config::load(&cli.config).context("startup configuration is invalid")?;
    let listen = config.server().listen();
    let listener = TcpListener::bind(listen).await?;
    let app = router(AppState::new(true));

    tracing::info!(%listen, config = %config.source().display(), "server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
