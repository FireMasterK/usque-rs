use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun::{AbstractDevice, AsyncDevice, Configuration};

use crate::{NativeTun, NativeTunConfig};
use usque_tunnel_core::TunnelDevice;

struct TunAsyncDevice(AsyncDevice);

#[async_trait]
impl TunnelDevice for TunAsyncDevice {
    async fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).await
    }

    async fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.0.write_all(packet).await?;
        Ok(())
    }
}

pub async fn create(cfg: NativeTunConfig) -> Result<NativeTun> {
    let mut config = Configuration::default();
    if !cfg.name.is_empty() {
        config.tun_name(&cfg.name);
    }

    let mut dev = tun::create_as_async(&config).context("failed to create TUN device")?;
    if cfg.persist {
        dev.persist().context("failed to persist TUN device")?;
    }

    let name = dev.tun_name().context("failed to get interface name")?;

    if cfg.configure_link {
        configure_link(&name, cfg.mtu, cfg.ipv4.as_deref(), cfg.ipv6.as_deref()).await?;
    }

    Ok(NativeTun {
        device: Box::new(TunAsyncDevice(dev)),
        name,
    })
}

async fn configure_link(
    name: &str,
    mtu: usize,
    ipv4: Option<&str>,
    ipv6: Option<&str>,
) -> Result<()> {
    use futures::TryStreamExt;
    use rtnetlink::{new_connection, LinkUnspec};

    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links
        .try_next()
        .await
        .context("failed to query link")?
        .context("link not found")?;
    let index = link.header.index;

    handle
        .link()
        .change(
            LinkUnspec::new_with_index(index)
                .mtu(mtu as u32)
                .up()
                .build(),
        )
        .execute()
        .await
        .context("failed to set link up/mtu")?;

    if let Some(v4) = ipv4 {
        let ip: std::net::Ipv4Addr = v4.parse()?;
        handle
            .address()
            .add(index, ip.into(), 32)
            .execute()
            .await
            .context("failed to add IPv4 address")?;
    }

    if let Some(v6) = ipv6 {
        let ip: std::net::Ipv6Addr = v6.parse()?;
        handle
            .address()
            .add(index, ip.into(), 128)
            .execute()
            .await
            .context("failed to add IPv6 address")?;
    }

    Ok(())
}

use std::io;
