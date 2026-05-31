use std::io;
use std::sync::Arc;

use tokio::sync::mpsc;
use usque_tunnel_core::TunnelDevice;

pub mod dns;
mod stack;

pub use stack::{VirtualStack, VirtualTcpStream};

/// Channel-backed packet device used by userspace modes.
pub struct ChannelDevice {
    inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    outbound: mpsc::UnboundedSender<Vec<u8>>,
}

impl ChannelDevice {
    pub fn pair() -> (
        Self,
        mpsc::UnboundedSender<Vec<u8>>,
        mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let (to_device_tx, to_device_rx) = mpsc::unbounded_channel();
        let (from_device_tx, from_device_rx) = mpsc::unbounded_channel();
        (
            Self {
                inbound: to_device_rx,
                outbound: from_device_tx,
            },
            to_device_tx,
            from_device_rx,
        )
    }
}

#[async_trait::async_trait]
impl TunnelDevice for ChannelDevice {
    async fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inbound.recv().await {
            Some(packet) => {
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok(n)
            }
            None => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    async fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.outbound
            .send(packet.to_vec())
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}

pub type SharedVirtualStack = Arc<VirtualStack>;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::Notify;

    use super::*;

    #[tokio::test]
    async fn stack_keeps_tunnel_channel_open() {
        let (mut device, to_tunnel, from_tunnel) = ChannelDevice::pair();
        let activity = Arc::new(Notify::new());
        let _stack = VirtualStack::start(None, None, 1280, from_tunnel, to_tunnel, activity);

        let read = tokio::spawn(async move { device.read_packet(&mut [0u8; 1280]).await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!read.is_finished(), "read should block while channel is open");
        read.abort();
    }
}
