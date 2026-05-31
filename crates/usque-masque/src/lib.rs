mod capsule;
mod connect_ip;
mod datagram;
mod h2;
mod h3;
mod session;

use anyhow::Result;

pub use session::{ConnectOptions, PacketSession, SessionError};

pub use connect_ip::ConnectIpSession;

pub async fn connect_tunnel(options: &ConnectOptions) -> Result<Box<dyn PacketSession>> {
    if options.use_http2 {
        let session = h2::connect_h2(options).await?;
        Ok(Box::new(session))
    } else {
        let session = h3::connect_h3(options).await?;
        Ok(Box::new(session))
    }
}
