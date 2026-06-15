use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::sync::Notify;
use tracing::{info, warn};

use crate::device::TunnelDevice;
use crate::hooks::{run_hook, HookEnv};
use usque_masque::{connect_tunnel, PacketSession, SessionError};

#[derive(Debug, Clone)]
pub struct MaintainTunnelConfig {
    pub connect: usque_masque::ConnectOptions,
    pub mtu: usize,
    pub reconnect_delay: Duration,
    pub always_reconnect: bool,
    pub on_connect: String,
    pub on_disconnect: String,
    pub hook_env: HookEnv,
    /// Userspace wake signal (SOCKS/proxy activity without a valid IP packet yet).
    pub activity: Option<Arc<Notify>>,
}

fn is_valid_ip_packet(packet: &[u8]) -> bool {
    if packet.is_empty() {
        return false;
    }
    match packet[0] >> 4 {
        4 => packet.len() >= 20,
        6 => packet.len() >= 40,
        _ => false,
    }
}

fn log_ipv4_packet(direction: &str, packet: &[u8]) {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return;
    }
    tracing::debug!(
        "tunnel: {direction} ipv4 {}.{}.{}.{} -> {}.{}.{}.{} proto {} len {}",
        packet[12],
        packet[13],
        packet[14],
        packet[15],
        packet[16],
        packet[17],
        packet[18],
        packet[19],
        packet[9],
        packet.len()
    );
    if packet[9] == 6 && packet.len() >= 34 {
        let ip_hdr_len = (packet[0] & 0x0f) as usize * 4;
        if packet.len() >= ip_hdr_len + 14 {
            let sport = u16::from_be_bytes([packet[ip_hdr_len], packet[ip_hdr_len + 1]]);
            let dport = u16::from_be_bytes([packet[ip_hdr_len + 2], packet[ip_hdr_len + 3]]);
            let seq = u32::from_be_bytes([
                packet[ip_hdr_len + 4],
                packet[ip_hdr_len + 5],
                packet[ip_hdr_len + 6],
                packet[ip_hdr_len + 7],
            ]);
            let ack = u32::from_be_bytes([
                packet[ip_hdr_len + 8],
                packet[ip_hdr_len + 9],
                packet[ip_hdr_len + 10],
                packet[ip_hdr_len + 11],
            ]);
            let flags = packet[ip_hdr_len + 13];
            tracing::debug!(
                "tunnel: {direction} tcp {sport}->{dport} seq={seq} ack={ack} flags=0x{flags:02x}"
            );
            if direction == "out" && flags & 0x02 != 0 {
                tracing::debug!(
                    "tunnel: out syn hex {:02x?}",
                    &packet[..packet.len().min(52)]
                );
            }
        }
    }
}

pub struct TunnelSupervisor;

impl TunnelSupervisor {
    pub async fn maintain<D>(cfg: MaintainTunnelConfig, device: Arc<D>)
    where
        D: TunnelDevice + 'static,
    {
        // Cold-path wait buffer; only used to detect outbound activity
        // before the first connection. Reused per loop.
        let mut wait_buf = BytesMut::with_capacity(cfg.mtu);
        let mut pending_outbound: Option<Bytes> = None;

        loop {
            if !cfg.always_reconnect {
                pending_outbound = None;
                loop {
                    info!("Tunnel idle. Waiting for outbound activity before reconnecting...");
                    tokio::select! {
                        read = async {
                            wait_buf.clear();
                            device.read_packet(&mut wait_buf).await
                        } => match read {
                            Ok(n) if n > 0 && is_valid_ip_packet(&wait_buf[..n]) => {
                                info!("Detected outbound activity ({n} bytes). Reconnecting...");
                                let head = wait_buf.split_to(n);
                                pending_outbound = Some(head.freeze());
                                break;
                            }
                            Ok(_) => {}
                            Err(err) => {
                                warn!("Failed to read from device while waiting for activity: {err}");
                                tokio::time::sleep(cfg.reconnect_delay).await;
                            }
                        },
                        _ = async {
                            match &cfg.activity {
                                Some(n) => n.notified().await,
                                None => std::future::pending().await,
                            }
                        } => {
                            info!("Detected outbound activity (wake). Reconnecting...");
                            break;
                        }
                    }
                }
            }

            info!("Establishing MASQUE connection to {}", cfg.connect.endpoint);

            let mut session = match connect_tunnel(&cfg.connect).await {
                Ok(session) => session,
                Err(err) => {
                    warn!("Failed to connect tunnel: {err}");
                    tokio::time::sleep(cfg.reconnect_delay).await;
                    continue;
                }
            };

            info!("Connected to MASQUE server");

            if let Some(packet) = pending_outbound.take() {
                if let Err(err) = session.write_packet(packet).await {
                    warn!("Failed to forward pending outbound packet: {err}");
                }
            }

            if !cfg.on_connect.is_empty() {
                let mut env = cfg.hook_env.clone();
                env = env.with("USQUE_EVENT", "connect");
                env = env.with("USQUE_ENDPOINT", cfg.connect.endpoint.to_string());
                run_hook(&cfg.on_connect, env);
            }

            let err = Self::run_pumps(&cfg, &device, session.as_mut()).await;

            if !cfg.on_disconnect.is_empty() {
                let mut env = cfg.hook_env.clone();
                env = env.with("USQUE_EVENT", "disconnect");
                env = env.with("USQUE_ENDPOINT", cfg.connect.endpoint.to_string());
                run_hook(&cfg.on_disconnect, env);
            }

            let _ = session.close().await;
            warn!("Tunnel connection lost: {err:?}. Reconnecting...");
            tokio::time::sleep(cfg.reconnect_delay).await;
        }
    }

    async fn run_pumps<D>(
        cfg: &MaintainTunnelConfig,
        device: &Arc<D>,
        session: &mut dyn PacketSession,
    ) -> SessionError
    where
        D: TunnelDevice + 'static,
    {
        // Reusable scratch buffer for outbound packets. Recycled each
        // iteration by replacing it with a fresh allocation — we
        // can't reuse the same `BytesMut` because `split_to(n).freeze()`
        // advances the underlying pointer by `n`, so after enough
        // iterations the buffer's apparent capacity shrinks to zero
        // and `read_packet` silently truncates every subsequent
        // packet to 0 bytes (caught as a long-standing
        // "first 3 SOCKS requests work, the rest time out" bug).
        let mtu = cfg.mtu;
        let mut to_tunnel = BytesMut::with_capacity(mtu);
        let mut pkt_count: u64 = 0;
        tracing::info!("run_pumps starting, mtu={mtu}");

        loop {
            tokio::select! {
                read = async {
                    to_tunnel.clear();
                    device.read_packet(&mut to_tunnel).await
                } => {
                    match read {
                        Ok(0) => continue,
                        Ok(n) => {
                            pkt_count += 1;
                            tracing::debug!("pump#{}: read {} bytes from device", pkt_count, n);
                            if !is_valid_ip_packet(&to_tunnel[..n]) {
                                tracing::debug!("pump#{}: invalid IP packet", pkt_count);
                                continue;
                            }
                            tracing::debug!("tunnel: device -> masque ({n} bytes)");
                            log_ipv4_packet("out", &to_tunnel[..n]);
                            // Decrement the IP TTL/hop-limit in place on
                            // the reusable scratch. Doing it here (rather
                            // than inside the session) keeps the session
                            // API immutable with respect to the packet
                            // body — the session encodes a fresh prefix
                            // and `extend_from_slice`s the packet.
                            if let Err(err) = usque_masque::decrement_ttl(&mut to_tunnel[..n]) {
                                tracing::debug!("tunnel: skipping packet: {err}");
                                continue;
                            }
                            // Detach the first `n` bytes from the scratch
                            // and replace the scratch with a fresh
                            // allocation. `BytesMut::split_to(n).freeze()`
                            // is zero-copy for the resulting `Bytes`, but
                            // it advances the scratch's underlying pointer
                            // by `n`; reusing the scratch in subsequent
                            // iterations would shrink its capacity to
                            // zero after ~MTU/avg_pkt iterations. The
                            // `to_tunnel` allocation is a single
                            // amortised allocation per packet — cheap,
                            // and far cheaper than the original silent
                            // packet drops it was causing.
                            let head = to_tunnel.split_to(n);
                            let packet = head.freeze();
                            to_tunnel = BytesMut::with_capacity(mtu);
                            match session.write_packet(packet).await {
                                Ok(Some(icmp)) => {
                                    if let Err(err) = device.write_packet(icmp).await {
                                        return SessionError::Other(anyhow::anyhow!(
                                            "failed to write ICMP to device: {err}"
                                        ));
                                    }
                                }
                                Ok(None) => {}
                                Err(err) => return err,
                            }
                        }
                        Err(err) => {
                            return SessionError::Other(anyhow::anyhow!(
                                "failed to read from device: {err}"
                            ));
                        }
                    }
                }
                session_read = session.read_packet() => {
                    match session_read {
                        Ok(None) => continue,
                        Ok(Some(packet)) => {
                            tracing::debug!("tunnel: masque -> device ({} bytes)", packet.len());
                            log_ipv4_packet("in", &packet);
                            if let Err(err) = device.write_packet(packet).await {
                                return SessionError::Other(anyhow::anyhow!(
                                    "failed to write to device: {err}"
                                ));
                            }
                        }
                        Err(err) => return err,
                    }
                }
            }
        }
    }
}
