use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Method, Request, Uri};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use usque_crypto::init as init_crypto;

use crate::capsule::CapsuleReader;
use crate::connect_ip::{ConnectIpSession, Transport};

pub async fn connect_h2(options: &crate::session::ConnectOptions) -> Result<ConnectIpSession> {
    init_crypto();

    let tcp = TcpStream::connect(options.endpoint)
        .await
        .context("TCP dial failed")?;

    let server_name = ServerName::try_from(options.sni.clone())
        .map_err(|_| anyhow::anyhow!("invalid SNI hostname"))?;
    let tls_config = Arc::clone(&options.tls_config);
    let connector = TlsConnector::from(tls_config);
    let tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")?;

    let (client, connection) = h2::client::handshake(tls)
        .await
        .context("HTTP/2 handshake failed")?;

    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut client = client.ready().await.context("HTTP/2 client not ready")?;

    let uri: Uri = options.connect_uri.parse().context("invalid connect URI")?;

    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("cf-connect-proto", "cf-connect-ip")
        .header("capsule-protocol", "?1")
        .header("pq-enabled", "false")
        .header("user-agent", "")
        .body(())
        .context("failed to build CONNECT request")?;

    let (response_fut, mut send_stream) = client
        .send_request(request, false)
        .context("failed to send CONNECT request")?;

    let response = response_fut.await.context("CONNECT response failed")?;
    if response.status() != http::StatusCode::OK {
        let status = response.status();
        if status.as_u16() == 403 {
            anyhow::bail!(
                "login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service"
            );
        }
        anyhow::bail!("tunnel connection failed: {status}");
    }

    debug!("HTTP/2 CONNECT-IP established: {}", response.status());

    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(64);
    let session = ConnectIpSession::new(Transport::H2 { out: out_tx });
    let incoming = session.incoming_queue();
    let notify = session.notify();

    let mut recv_stream = response.into_body();
    tokio::spawn(async move {
        let mut reader = CapsuleReader::new();
        loop {
            match recv_stream.data().await {
                Some(Ok(data)) => {
                    reader.push(data);
                    let mut pushed = 0usize;
                    while let Some(packet) = reader.next_ip_packet() {
                        incoming.lock().await.push_back(packet);
                        pushed += 1;
                    }
                    if pushed > 0 {
                        // Compaction runs occasionally to bound the
                        // chunk chain length; O(1) per call.
                        if reader.chunk_count() > 16 {
                            reader.compact();
                        }
                        notify.notify_waiters();
                    }
                }
                Some(Err(err)) => {
                    warn!("h2 read error: {err}");
                    break;
                }
                None => break,
            }
        }
    });

    tokio::spawn(async move {
        while let Some(data) = out_rx.recv().await {
            if send_stream.send_data(data, false).is_err() {
                break;
            }
        }
    });

    Ok(session)
}
