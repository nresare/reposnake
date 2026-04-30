// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use axum::Router;
use clap::Parser;
use reposnake::config::Config;
use reposnake::service::{build_app_state, build_router};
use std::net::SocketAddr;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
struct Cli {
    #[arg(
        name = "config-file",
        short = 'c',
        long = "config-file",
        default_value = "/config"
    )]
    config_path: String,
    #[arg(long = "disable-auth", default_value_t = false)]
    disable_auth: bool,
    #[arg(long = "debug", default_value_t = false)]
    debug: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let log_filter = if cli.debug {
        "reposnake=debug,tower_http=info,axum::rejection=trace"
    } else {
        "reposnake=info,tower_http=info,axum::rejection=info"
    };
    tracing_subscriber::registry()
        .with(EnvFilter::new(log_filter))
        .with(tracing_subscriber::fmt::layer().compact())
        .init();

    if let Err(error) = run(cli).await {
        error!("{error:#}");
        std::process::exit(1);
    }

    Ok(())
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = Config::load(&cli.config_path)?;
    config.validate(cli.disable_auth)?;
    let bind_address: SocketAddr = config.bind_address.parse()?;
    let storage_directory = config.storage_directory.display().to_string();

    info!(
        version = VERSION,
        config_path = %cli.config_path,
        storage_directory = %storage_directory,
        disable_auth = cli.disable_auth,
        debug = cli.debug,
        "starting reposnake"
    );

    let state = build_app_state(&config, cli.disable_auth)?;
    let app: Router = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    info!(address = %bind_address, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}
