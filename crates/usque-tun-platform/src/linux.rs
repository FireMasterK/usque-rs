use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun::{AbstractDevice, AsyncDevice, Configuration};

use crate::{NativeTun, NativeTunConfig};
use usque_tunnel_core::TunnelDevice;

struct TunAsyncDevice(Arc<tokio::sync::Mutex<AsyncDevice>>);

#[async_trait]
impl TunnelDevice for TunAsyncDevice {
    async fn read_packet(&self, buf: &mut BytesMut) -> io::Result<usize> {
        // `tun::AsyncDevice`'s `AsyncRead` impl expects a `&mut [u8]`
        // slice. The supervisor's scratch `BytesMut` has `len == 0` and
        // `cap == MTU`, so dereffing gives a zero-length slice. Read
        // into the spare capacity instead, then commit with `set_len`.
        let spare = buf.spare_capacity_mut();
        let dst =
            unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr().cast::<u8>(), spare.len()) };
        // Lock the inner `AsyncDevice` only for the duration of the
        // syscall, never across an `await` outside it. Holding the
        // lock across the `read().await` would deadlock the supervisor
        // (the other arm needs the same lock to write an inbound
        // packet).
        let n = {
            let mut dev = self.0.lock().await;
            dev.read(dst).await?
        };
        unsafe {
            buf.set_len(n);
        }
        Ok(n)
    }

    async fn write_packet(&self, packet: Bytes) -> io::Result<()> {
        let mut dev = self.0.lock().await;
        dev.write_all(&packet).await?;
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
        device: Box::new(TunAsyncDevice(Arc::new(tokio::sync::Mutex::new(dev)))),
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
