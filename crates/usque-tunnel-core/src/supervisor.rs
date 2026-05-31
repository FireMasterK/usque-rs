use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, Notify};
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
                tracing::debug!("tunnel: out syn hex {:02x?}", &packet[..packet.len().min(52)]);
            }
        }
    }
}

pub struct TunnelSupervisor;

impl TunnelSupervisor {
    pub async fn maintain<D>(cfg: MaintainTunnelConfig, device: Arc<Mutex<D>>)
    where
        D: TunnelDevice + 'static,
    {
        let mut wait_buf = vec![0u8; cfg.mtu];
        let mut pending_outbound: Option<Vec<u8>> = None;

        loop {
            if !cfg.always_reconnect {
                pending_outbound = None;
                loop {
                    info!("Tunnel idle. Waiting for outbound activity before reconnecting...");
                    tokio::select! {
                        read = async {
                            let mut dev = device.lock().await;
                            dev.read_packet(&mut wait_buf).await
                        } => match read {
                            Ok(n) if is_valid_ip_packet(&wait_buf[..n]) => {
                                info!("Detected outbound activity ({n} bytes). Reconnecting...");
                                pending_outbound = Some(wait_buf[..n].to_vec());
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
                if let Err(err) = session.write_packet(&packet).await {
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
        device: &Arc<Mutex<D>>,
        session: &mut dyn PacketSession,
    ) -> SessionError
    where
        D: TunnelDevice + 'static,
    {
        let mut to_tunnel = vec![0u8; cfg.mtu];
        let mut from_tunnel = vec![0u8; cfg.mtu];

        loop {
            tokio::select! {
                read = async {
                    let mut dev = device.lock().await;
                    dev.read_packet(&mut to_tunnel).await
                } => {
                    match read {
                        Ok(0) => continue,
                Ok(n) => {
                    if !is_valid_ip_packet(&to_tunnel[..n]) {
                        continue;
                    }
                    tracing::debug!("tunnel: device -> masque ({n} bytes)");
                    log_ipv4_packet("out", &to_tunnel[..n]);
                    match session.write_packet(&to_tunnel[..n]).await {
                                Ok(Some(icmp)) => {
                                    let mut dev = device.lock().await;
                                    if let Err(err) = dev.write_packet(&icmp).await {
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
                session_read = session.read_packet(&mut from_tunnel) => {
                    match session_read {
                        Ok(0) => continue,
                        Ok(n) => {
                            tracing::debug!("tunnel: masque -> device ({n} bytes)");
                            log_ipv4_packet("in", &from_tunnel[..n]);
                            let mut dev = device.lock().await;
                            if let Err(err) = dev.write_packet(&from_tunnel[..n]).await {
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
