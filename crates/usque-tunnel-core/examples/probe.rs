//! Diagnostic probe: does the CONNECT-IP session survive the client's
//! idle heartbeat datagrams?
//!
//! The client emits a "heartbeat" datagram every `keepalive_period` that
//! carries only the quarter-stream-id and context-id varints and **no IP
//! payload**. RFC 9484 defines the datagram payload as an IP packet, so
//! that heartbeat is not valid CONNECT-IP traffic. This probe measures
//! whether the server tolerates it:
//!
//! 1. connect with a very short keepalive period (so heartbeats fire),
//! 2. prove the tunnel works with an ICMP echo round-trip,
//! 3. idle long enough for several heartbeats,
//! 4. prove the tunnel still works with a second round-trip.
//!
//! ```bash
//! cargo run -p usque-tunnel-core --example probe -- config.json
//! ```

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use usque_config::Config;
use usque_crypto::{
    build_rustls_config, decode_endpoint_public_key, decode_private_key, init,
    prepare_quiche_client_credentials, TlsOptions,
};
use usque_masque::{connect_tunnel, ConnectOptions, PacketSession};

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn secs(name: &str, default: u64) -> Duration {
    Duration::from_secs(arg(name).and_then(|v| v.parse().ok()).unwrap_or(default))
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (pairs, remainder) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u16::from_be_bytes(*pair) as u32;
    }
    if let [last] = remainder {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IPv4 ICMP echo request from the tunnel address to `1.1.1.1`.
fn icmp_echo(src: [u8; 4], seq: u16) -> Bytes {
    let payload = b"usque-probe";
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.push(8); // echo request
    icmp.push(0); // code
    icmp.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp.extend_from_slice(&0x1234u16.to_be_bytes()); // identifier
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let csum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());

    let total_len = (20 + icmp.len()) as u16;
    let mut pkt = Vec::with_capacity(total_len as usize);
    pkt.push(0x45);
    pkt.push(0);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes()); // id
    pkt.extend_from_slice(&[0x40, 0x00]); // DF
    pkt.push(64); // TTL
    pkt.push(1); // ICMP
    pkt.extend_from_slice(&[0, 0]); // header checksum placeholder
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&[1, 1, 1, 1]);
    let hdr_csum = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&hdr_csum.to_be_bytes());
    pkt.extend_from_slice(&icmp);
    Bytes::from(pkt)
}

async fn roundtrip(session: &mut dyn PacketSession, src: [u8; 4], seq: u16) -> bool {
    if let Err(err) = session.write_packet(&icmp_echo(src, seq)).await {
        println!("  write failed: {err}");
        return false;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            println!("  no reply within 5s");
            return false;
        }
        match tokio::time::timeout(remaining, session.read_packet()).await {
            Err(_) => {
                println!("  no reply within 5s");
                return false;
            }
            Ok(Ok(Some(pkt))) => {
                // IPv4, protocol 1 (ICMP), echo reply (type 0).
                if pkt.len() >= 28 && pkt[0] >> 4 == 4 && pkt[9] == 1 && pkt[20] == 0 {
                    println!("  got ICMP echo reply ({} bytes)", pkt.len());
                    return true;
                }
            }
            Ok(Ok(None)) => {
                println!("  session reported closed");
                return false;
            }
            Ok(Err(err)) => {
                println!("  read failed: {err}");
                return false;
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("usque_masque=debug".parse()?),
        )
        .init();

    let config_path = arg("--config").unwrap_or_else(|| "config.json".into());
    let keepalive = secs("--keepalive", 2);
    let idle = secs("--idle", 12);
    let ping_every = arg("--ping-every").and_then(|v| v.parse::<u64>().ok());
    let cfg = Config::load(&config_path)?;
    init();

    let signing_key = decode_private_key(&cfg.private_key)?;
    let peer_key = decode_endpoint_public_key(&cfg.endpoint_pub_key)?;
    let tls_config = build_rustls_config(
        &signing_key,
        TlsOptions {
            sni: usque_cloudflare_api::CONNECT_SNI.to_string(),
            insecure: false,
            peer_public_key: peer_key.clone(),
            alpn: vec![b"h3".to_vec()],
        },
    )?;

    let endpoint = usque_config::select_endpoint(&cfg, false, false, 443)?;
    let options = ConnectOptions {
        tls_config,
        quiche_credentials: Arc::new(prepare_quiche_client_credentials(&signing_key)?),
        insecure: false,
        peer_public_key: peer_key,
        endpoint,
        sni: usque_cloudflare_api::CONNECT_SNI.to_string(),
        use_http2: false,
        keepalive_period: keepalive,
        initial_packet_size: 0,
        connect_uri: usque_cloudflare_api::CONNECT_URI.to_string(),
    };

    let src: [u8; 4] = cfg
        .ipv4
        .parse::<std::net::Ipv4Addr>()
        .map(|a| a.octets())
        .unwrap_or([172, 16, 0, 2]);

    println!(
        "connecting to {} (keepalive {:?}, idle {:?}, ping_every {:?})",
        options.endpoint, keepalive, idle, ping_every
    );
    let mut session = connect_tunnel(&options).await?;
    println!("connected; source {src:?}");

    println!("[1] round-trip before idling");
    let before = roundtrip(session.as_mut(), src, 1).await;

    // `--ping-for N` keeps the session busy for N seconds, then goes
    // silent for the rest of the idle window. That reproduces the shape
    // of a real tunnel: hours of traffic, then nothing.
    let ping_for = arg("--ping-for").and_then(|v| v.parse::<u64>().ok());
    println!("[2] idling {idle:?} (ping_for {ping_for:?})");
    let started = tokio::time::Instant::now();
    let mut seq = 10u16;
    let mut alive = true;
    while started.elapsed() < idle {
        let step = match ping_every {
            Some(period) => Duration::from_secs(period),
            None => idle - started.elapsed(),
        };
        let step = step.min(idle - started.elapsed());
        tokio::time::sleep(step).await;
        let still_pinging = match ping_for {
            Some(limit) => started.elapsed() < Duration::from_secs(limit),
            None => ping_every.is_some(),
        };
        if still_pinging {
            seq += 1;
            let ok = roundtrip(session.as_mut(), src, seq).await;
            println!("  t+{:?}: ping ok={ok}", started.elapsed());
            if !ok {
                alive = false;
                break;
            }
        }
    }

    println!("[3] round-trip after idling");
    let after = alive && roundtrip(session.as_mut(), src, 2).await;

    println!();
    println!("before={before} after={after}");
    if before && after {
        println!("RESULT: server tolerates the empty heartbeat datagram");
    } else if before && !after {
        println!("RESULT: session died across the idle window (heartbeat suspect)");
    } else {
        println!("RESULT: inconclusive (tunnel was not usable to begin with)");
    }

    let _ = session.close().await;
    Ok(())
}
