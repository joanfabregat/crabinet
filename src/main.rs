use std::{
    path::PathBuf,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use crabinet::{
    app::{AppState, router},
    auth::AuthService,
    browse::{BrowseLimits, BrowseState, ConfiguredShare},
    config::Config,
    filesystem::{GlobalPolicy, ShareFs, ShareId},
    mutations::{
        MutationState, TRASH_GC_BATCH_ENTRIES, TRASH_GC_INTERVAL, TRASH_GC_SHARE_BUDGET,
        collect_expired_trash,
    },
    oidc::OidcService,
    password::hash_confirmed,
    preview::PreviewPolicy,
    server::{self, ServerLimits},
};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = crabinet::APP_NAME, version, about)]
struct Cli {
    /// Immutable TOML configuration file. CRABINET_CONFIG is the only environment override.
    #[arg(
        long,
        global = true,
        env = "CRABINET_CONFIG",
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
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "crabinet=info".into()),
        )
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
    let preview_policy = PreviewPolicy::new(config.server().max_preview_size())
        .context("configured preview limit is unsafe")?;
    let mutation_state = MutationState::from_max_upload_bytes(config.server().max_upload_size())
        .context("configured upload limit is unsafe")?;
    let browse = browse_state(&config).context("cannot initialize configured shares")?;
    let listen = config.server().listen();
    let auth = AuthService::from_config(&config).context("cannot initialize authentication")?;
    let oidc = if let Some(settings) = config.auth().oidc() {
        Some(
            OidcService::discover(
                settings.clone(),
                derive_key(b"crabinet:oidc-transaction:v1\0", config.session_secret()).to_vec(),
            )
            .await
            .map_err(anyhow::Error::msg)
            .context("cannot initialize OIDC provider")?,
        )
    } else {
        None
    };
    let listener = TcpListener::bind(listen).await?;
    let mut state = AppState::new(true)
        .with_browse(browse)
        .with_preview_policy(preview_policy)
        .with_mutations(mutation_state)
        .with_trash_retention_days(config.server().trash_retention_days())
        .with_auth_service(auth);
    if let Some(oidc) = oidc {
        state = state.with_oidc_service(oidc);
    }
    let gc_state = state.clone();
    let app = router(state);
    let gc_task = tokio::spawn(async move { trash_gc_loop(gc_state).await });

    let limits = ServerLimits {
        max_connections: config.server().max_connections(),
        header_read_timeout: Duration::from_secs(config.server().header_read_timeout_seconds()),
    };
    tracing::info!(
        %listen,
        config = %config.source().display(),
        max_connections = limits.max_connections,
        header_read_timeout_seconds = limits.header_read_timeout.as_secs(),
        "server listening"
    );
    // The accept loop runs until the process is terminated.
    server::serve(listener, app, limits).await;
    gc_task.abort();
    Ok(())
}

async fn trash_gc_loop(state: AppState) {
    let mut interval = tokio::time::interval(TRASH_GC_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        collect_expired_trash(
            &state,
            SystemTime::now(),
            TRASH_GC_BATCH_ENTRIES,
            TRASH_GC_SHARE_BUDGET,
        )
        .await;
    }
}

fn browse_state(config: &Config) -> Result<BrowseState> {
    let shares = config
        .shares()
        .iter()
        .map(|share| {
            let id = ShareId::new(share.id().to_owned()).context("invalid share identifier")?;
            let filesystem = if share.writable() {
                ShareFs::open(id, share.root())
            } else {
                ShareFs::open_read_only(id, share.root())
            }
            .context("cannot open configured share")?;
            let recovered = filesystem
                .recover_staging_files(100_000)
                .context("cannot recover interrupted staged writes")?;
            filesystem
                .recover_trash(100_000)
                .context("cannot recover interrupted trash operations")?;
            if recovered > 0 {
                tracing::warn!(
                    share_id = share.id(),
                    recovered,
                    "removed interrupted temporary files"
                );
            }
            ConfiguredShare::new(share.name(), filesystem)
                .context("cannot construct configured share")
        })
        .collect::<Result<Vec<_>>>()?;
    let limits = BrowseLimits {
        max_text_bytes: config.server().max_preview_size(),
        ..BrowseLimits::default()
    };
    BrowseState::new(
        shares,
        limits,
        GlobalPolicy::default(),
        derive_key(b"index:browse-cursor:v1\0", config.session_secret()),
    )
    .context("invalid browse policy")
}

fn derive_key(domain: &[u8], secret: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(secret);
    digest.finalize().into()
}
