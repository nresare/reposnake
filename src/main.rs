// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The reposnake contributors

use axum::Router;
use clap::Parser;
use reposnake::config::Config;
use reposnake::service::{build_app_state, build_router};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{error, info, warn};
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
        default_value = "/config/reposnake.toml"
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
    let object_directory = config.object_store.directory_or_default();

    info!(
        version = VERSION,
        config_path = %cli.config_path,
        object_directory = %object_directory.display(),
        disable_auth = cli.disable_auth,
        debug = cli.debug,
        "starting reposnake"
    );

    let state = build_app_state(&config, cli.disable_auth).await?;
    let app: Router = build_router(state);
    let listeners = bind_listeners(bind_address).await?;
    serve_listeners(listeners, app).await?;
    Ok(())
}

async fn bind_listeners(bind_address: SocketAddr) -> anyhow::Result<Vec<TcpListener>> {
    let addresses = listener_addresses(bind_address);
    let mut listeners = Vec::with_capacity(addresses.len());
    for (index, address) in addresses.into_iter().enumerate() {
        let force_ipv6_only = bind_address.is_ipv4() && address.is_ipv6();
        let listener = match bind_listener(address, force_ipv6_only).await {
            Ok(listener) => listener,
            Err(error) if bind_address.is_ipv4() && address.is_ipv6() => {
                warn!(
                    address = %address,
                    error = %error,
                    "failed to bind IPv6 listener; continuing with IPv4 listener"
                );
                continue;
            }
            Err(error) => return Err(error),
        };
        info!(address = %listener.local_addr()?, "listening");
        listeners.push(listener);
        if index == 0 && !bind_address.is_ipv4() {
            break;
        }
    }
    Ok(listeners)
}

fn listener_addresses(bind_address: SocketAddr) -> Vec<SocketAddr> {
    if let SocketAddr::V4(address) = bind_address
        && address.ip().is_unspecified()
    {
        return vec![
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                address.port(),
                0,
                0,
            )),
            SocketAddr::V4(address),
        ];
    }
    if let SocketAddr::V4(address) = bind_address
        && address.ip().is_loopback()
    {
        return vec![
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, address.port(), 0, 0)),
            SocketAddr::V4(address),
        ];
    }
    vec![bind_address]
}

async fn bind_listener(address: SocketAddr, force_ipv6_only: bool) -> anyhow::Result<TcpListener> {
    let domain = match address {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(force_ipv6_only)?;
    }
    socket.bind(&address.into())?;
    socket.listen(1024)?;

    let listener: std::net::TcpListener = socket.into();
    listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(listener)?)
}

async fn serve_listeners(listeners: Vec<TcpListener>, app: Router) -> anyhow::Result<()> {
    let mut servers = JoinSet::new();
    for listener in listeners {
        let app = app.clone();
        servers.spawn(async move { axum::serve(listener, app).await });
    }

    if let Some(result) = servers.join_next().await {
        servers.abort_all();
        result??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{bind_listeners, listener_addresses};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn expands_ipv4_unspecified_bind_to_ipv6_and_ipv4_listeners() {
        let addresses = listener_addresses(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            8080,
        )));

        assert_eq!(
            addresses,
            vec![
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 8080, 0, 0)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8080)),
            ]
        );
    }

    #[test]
    fn expands_ipv4_loopback_bind_to_ipv6_and_ipv4_listeners() {
        let addresses =
            listener_addresses(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)));

        assert_eq!(
            addresses,
            vec![
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0)),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)),
            ]
        );
    }

    #[test]
    fn keeps_explicit_non_loopback_ipv4_bind_as_single_listener() {
        let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 8080));

        assert_eq!(listener_addresses(address), vec![address]);
    }

    #[tokio::test]
    async fn binds_ipv4_unspecified_listener() {
        let listeners = bind_listeners(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
            .await
            .unwrap();

        assert!(
            listeners
                .iter()
                .any(|listener| listener.local_addr().unwrap().is_ipv4())
        );
    }
}
