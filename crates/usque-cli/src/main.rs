use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;
use usque_cli::Cli;
use usque_crypto::init as init_crypto;

#[tokio::main]
async fn main() -> Result<()> {
    init_crypto();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("usque=info".parse()?))
        .init();

    let cli = Cli::parse();
    usque_cli::cmd::execute(cli.command, &cli.config).await
}
