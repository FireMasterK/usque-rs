use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;
use usque_cli::Cli;
use usque_crypto::init as init_crypto;

#[tokio::main]
async fn main() -> Result<()> {
    init_crypto();
    // Tune crossfire's channel backoff for the host: on single-core
    // machines (VPS/VM) the lockless channels yield instead of
    // spinning, which crossfire reports as a ~2x gain there. No-op on
    // multi-core; idempotent, so library-level callers are safe too.
    crossfire::detect_backoff_cfg();

    // `h3=info` is deliberate: the only info-level event h3 emits is the
    // GOAWAY that precedes a server-initiated teardown, which is the one
    // clue that explains a Cloudflare `H3_REQUEST_CANCELLED`.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("usque=info".parse()?)
                .add_directive("h3=info".parse()?),
        )
        .init();

    let cli = Cli::parse();
    usque_cli::cmd::execute(cli.command, &cli.config).await
}
