use std::io;

use async_trait::async_trait;

/// Abstraction over native TUN and userspace packet devices.
#[async_trait]
pub trait TunnelDevice: Send + Sync {
    async fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    async fn write_packet(&mut self, packet: &[u8]) -> io::Result<()>;
}
