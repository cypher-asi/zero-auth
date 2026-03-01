use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use zid_server::{config::Config, create_router, state::AppState};

struct CliArgs {
    generate_key: bool,
    help: bool,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    CliArgs {
        generate_key: args.iter().any(|a| a == "--generate-key" || a == "-g"),
        help: args.iter().any(|a| a == "--help" || a == "-h"),
    }
}

fn print_help() {
    eprintln!(
        r#"zid-server - Zero-ID Identity Server

USAGE:
    cargo run -p zid-server [OPTIONS]

OPTIONS:
    -g, --generate-key   Generate a random SERVICE_MASTER_KEY for this session
                         (sets RUN_MODE=dev automatically)
    -h, --help           Print this help

ENVIRONMENT VARIABLES:
    RUN_MODE                      dev or prod (default: prod)
    SERVICE_MASTER_KEY            64-char hex key (required in prod)
    BIND_ADDRESS                  Listen address (default: 127.0.0.1:9999)
    DATABASE_PATH                 RocksDB path (default: ./data/zid.db)
    RUST_LOG                      Log level (default: zid_server=debug)

EXAMPLES:
    # Development with auto-generated key
    cargo run -p zid-server -- --generate-key

    # Production with explicit key
    SERVICE_MASTER_KEY=<your-key> cargo run -p zid-server --release
"#
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args();

    if args.help {
        print_help();
        return Ok(());
    }

    if args.generate_key {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let key_hex = hex::encode(key);

        std::env::set_var("RUN_MODE", "dev");
        std::env::set_var("SERVICE_MASTER_KEY", &key_hex);

        eprintln!("=== zid Dev Server ===");
        eprintln!();
        eprintln!("Generated SERVICE_MASTER_KEY for this session:");
        eprintln!("  {}", key_hex);
        eprintln!();
        eprintln!("Note: Tokens from this session won't work after restart.");
        eprintln!();
    }

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zid_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env()?;
    let bind_address = config.bind_address;
    tracing::info!("Starting zid server on {}", bind_address);

    let state = Arc::new(AppState::new(config).await?);
    let app = create_router(state);

    let listener = tokio::net::TcpListener::bind(&bind_address).await?;
    tracing::info!("Server listening on {}", bind_address);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Graceful shutdown initiated");
}
