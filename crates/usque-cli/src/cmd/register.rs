use std::io::{self, Write};

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Args;

use usque_config::{parse_endpoint_v4, parse_endpoint_v6, Config, DEFAULT_ENDPOINT_H2_V4};
use usque_crypto::generate_ec_keypair;
use usque_cloudflare_api::{self, CloudflareClient};

#[derive(Debug, Args)]
pub struct RegisterArgs {
    #[arg(short = 'l', long, default_value = usque_cloudflare_api::DEFAULT_LOCALE)]
    pub locale: String,
    #[arg(short = 'm', long, default_value = usque_cloudflare_api::DEFAULT_MODEL)]
    pub model: String,
    #[arg(short = 'n', long)]
    pub name: Option<String>,
    #[arg(long)]
    pub jwt: Option<String>,
    #[arg(short = 'a', long = "accept-tos")]
    pub accept_tos: bool,
}

pub async fn run(args: RegisterArgs, config_path: &str) -> Result<()> {
    if Config::load(config_path).is_ok() {
        print!("You already have a config. Do you want to overwrite it? (y/n) ");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        if line.trim() != "y" {
            return Ok(());
        }
    }

    let client = CloudflareClient::new();
    let account = usque_cloudflare_api::register(
        &client,
        &args.model,
        &args.locale,
        args.jwt.as_deref(),
        args.accept_tos,
    )
    .await?;

    let (priv_key, pub_key) = generate_ec_keypair()?;
    tracing::info!("Enrolling device key...");
    let token = account.token.clone().unwrap_or_default();
    let updated = usque_cloudflare_api::enroll_key(
        &client,
        &account.id,
        &token,
        &pub_key,
        args.name.as_deref().unwrap_or(""),
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let peer = updated
        .config
        .peers
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing peer in registration response"))?;

    let cfg = Config {
        private_key: STANDARD.encode(priv_key),
        endpoint_v4: parse_endpoint_v4(&peer.endpoint.v4),
        endpoint_v6: parse_endpoint_v6(&peer.endpoint.v6),
        endpoint_h2_v4: DEFAULT_ENDPOINT_H2_V4.to_string(),
        endpoint_h2_v6: String::new(),
        endpoint_pub_key: peer.public_key.clone(),
        license: updated.account.license,
        id: updated.id,
        access_token: token,
        ipv4: updated.config.interface.addresses.v4,
        ipv6: updated.config.interface.addresses.v6,
    };

    cfg.save(config_path)?;
    tracing::info!("Config saved to {config_path}");
    Ok(())
}
