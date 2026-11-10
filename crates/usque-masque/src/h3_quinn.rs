use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, Bytes};
use crossfire::mpsc;
use futures_util::future;
use http::Uri;
use parking_lot::Mutex;
use tokio::sync::Notify;
use tracing::{debug, warn};

use h3_datagram::datagram_handler::HandleDatagramsExt;
use usque_crypto::init as init_crypto;

use crate::capsule::CapsuleReader;
use crate::connect_ip::{ConnectIpSession, Transport};

/// Upper bound on the idle heartbeat cadence.
///
/// The heartbeat must be *well* below the edge's session reaper, not
/// merely equal to the transport keep-alive. Measured against
/// Cloudflare's MASQUE edge: an idle session is still ACKed at 30s but
/// is gone by 60s, while the QUIC idle timeout it advertises is ~56s.
/// A 30s heartbeat therefore races the reaper and loses, and the tunnel
/// dies on the QUIC idle timer. 10s leaves a comfortable margin; the
/// probe is two bytes, so the cost is nil.
const MAX_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(10);

fn heartbeat_interval(keepalive: std::time::Duration) -> std::time::Duration {
    keepalive.min(MAX_HEARTBEAT)
}

pub async fn connect_h3(options: &crate::session::ConnectOptions) -> Result<ConnectIpSession> {
    init_crypto();

    let bind_ip = match options.endpoint.ip() {
        std::net::IpAddr::V4(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        std::net::IpAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    };

    let mut endpoint =
        quinn::Endpoint::client((bind_ip, 0).into()).context("failed to create QUIC endpoint")?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(Arc::clone(&options.tls_config))
            .map_err(|err| anyhow!("invalid TLS client config for QUIC: {err}"))?,
    ));
    let mut transport = quinn::TransportConfig::default();
    if options.initial_packet_size > 0 {
        transport.initial_mtu(options.initial_packet_size as u16);
    }
    // Keep the QUIC connection alive across idle periods instead of timing out.
    let keepalive = if options.keepalive_period.is_zero() {
        std::time::Duration::from_secs(30)
    } else {
        options.keepalive_period
    };
    transport.keep_alive_interval(Some(keepalive));
    // Opting out locally does NOT disable the idle timeout. RFC 9000 §10.1
    // negotiates the *minimum* of both endpoints' `max_idle_timeout`, so
    // Cloudflare's advertised value still applies (measured: 56s). This
    // call only stops the client from imposing a shorter one of its own.
    // The session is therefore kept alive by the heartbeat datagram in
    // `connect_h3`, not by this setting — see `MAX_HEARTBEAT`.
    transport.max_idle_timeout(None);
    client_config.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client_config);

    let conn = endpoint
        .connect(options.endpoint, &options.sni)
        .context("failed to dial QUIC endpoint")?
        .await
        .context("QUIC dial failed")?;

    // Keep a handle for direct DATAGRAM sends: routing them through
    // h3-quinn's `DatagramSender` would `copy_to_bytes` the header and
    // payload into a fresh buffer (a full extra memcpy per packet).
    let conn_send = conn.clone();
    // Kept by the session so `close()` can send a CONNECTION_CLOSE.
    let conn_close = conn.clone();

    // Watch the QUIC connection directly instead of relying on h3-quinn's
    // error conversion: `ApplicationClose` there keeps only the error code,
    // while the raw `quinn::ConnectionError` also carries the peer's reason
    // string. Without this, every server-initiated teardown collapses into
    // an indistinguishable "Tunnel connection lost: Closed" in the
    // supervisor, so a Cloudflare "H3_REQUEST_CANCELLED" (0x10c) tells us
    // nothing about *why* the request was cancelled.
    let conn_watch = conn.clone();
    tokio::spawn(async move {
        let err = conn_watch.closed().await;
        match err {
            quinn::ConnectionError::LocallyClosed => {
                debug!("MASQUE QUIC connection closed locally: {err}");
            }
            err => warn!("MASQUE QUIC connection closed: {err}"),
        }
    });
    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::builder()
        .enable_datagram(true)
        .enable_extended_connect(true)
        // `B` (the frame body buffer type) is no longer constrained by a
        // `DatagramSender` — datagrams now go straight to quinn — so pin
        // it explicitly to `Bytes`.
        .build::<_, _, Bytes>(h3_conn)
        .await
        .map_err(|err| anyhow!("failed to build HTTP/3 client: {err}"))?;

    let (mut request_stream, response) = {
        let uri: Uri = options.connect_uri.parse().context("invalid connect URI")?;
        let protocol = h3::ext::Protocol::CF_CONNECT_IP;
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(uri)
            .header("capsule-protocol", "?1")
            .header("user-agent", "")
            .extension(protocol)
            .body(())
            .context("failed to build CONNECT request")?;

        let mut request_stream = send_request
            .send_request(request)
            .await
            .map_err(|err| anyhow!("failed to send CONNECT request: {err}"))?;
        let response = request_stream
            .recv_response()
            .await
            .map_err(|err| anyhow!("CONNECT response failed: {err}"))?;
        (request_stream, response)
    };

    let status = response.status().as_u16();
    if status != 200 {
        if status == 403 {
            anyhow::bail!(
                "login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service"
            );
        }
        anyhow::bail!("tunnel connection failed: {status}");
    }
    debug!("HTTP/3 CONNECT-IP established: {status}");

    let stream_id = request_stream.id();
    let mut datagram_reader = driver.get_datagram_reader();
    // Pre-encode the quarter-stream-id varint once per session; the
    // sender task prepends it to every payload without re-encoding.
    let mut header_buf = bytes::BytesMut::new();
    crate::capsule::put_varint(&mut header_buf, stream_id.into_inner() / 4);
    let header = header_buf.freeze();
    let header_out = header.clone();

    let (out_tx, out_rx) = mpsc::bounded_async::<Vec<u8>>(64);
    let incoming = Arc::new(Mutex::new(std::collections::VecDeque::new()));
    let notify = Arc::new(Notify::new());
    let closed = Arc::new(AtomicBool::new(false));

    // Drive the HTTP/3 connection state machine on a background task.
    // `poll_close` only resolves once the connection is finished, and its
    // value is the terminal error (a GOAWAY alone does not resolve it).
    // Log it: discarding it hides protocol-level failures that never
    // surface as a datagram read error.
    tokio::spawn(async move {
        let err = future::poll_fn(|cx| driver.poll_close(cx)).await;
        debug!("HTTP/3 connection driver finished: {err}");
    });

    // Drain the CONNECT response body (control-channel capsules this
    // client doesn't act on) and treat the stream as the connection's
    // lifetime gauge. Keep `send_request` alive here: dropping the last
    // `SendRequest` sends H3_NO_ERROR "Connection closed by client" and
    // tears down the connection.
    let closed_recv = Arc::clone(&closed);
    let notify_recv = Arc::clone(&notify);
    tokio::spawn(async move {
        // Kept alive for the whole task: dropping the last `SendRequest`
        // sends H3_NO_ERROR "Connection closed by client" and tears the
        // connection down.
        let send_request = send_request;
        let mut reader = CapsuleReader::new();
        // A GOAWAY means the edge is draining and will not accept new
        // requests on this connection. It is the usual precursor to the
        // `H3_REQUEST_CANCELLED` that kills a long-lived tunnel, so treat
        // it as a teardown and let the supervisor reconnect on a fresh
        // connection instead of waiting to be cancelled.
        let mut goaway_check = tokio::time::interval(std::time::Duration::from_secs(1));
        goaway_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                data = request_stream.recv_data() => match data {
                    Ok(Some(mut data)) => {
                        use bytes::Buf;
                        let chunk: Bytes = data.copy_to_bytes(data.remaining());
                        reader.push(chunk);
                        while reader.next_ip_packet().is_some() {}
                    }
                    // The server ended the CONNECT-IP request stream but kept
                    // the QUIC connection up. Surface the reason: a bare
                    // "Closed" hides whether this was a graceful end
                    // (H3_NO_ERROR) or the server cancelling the request
                    // (H3_REQUEST_CANCELLED).
                    Ok(None) => {
                        debug!("CONNECT-IP request stream finished by the server");
                        break;
                    }
                    Err(err) => {
                        warn!("CONNECT-IP request stream terminated: {err}");
                        break;
                    }
                },
                _ = goaway_check.tick() => {
                    if h3::ConnectionState::is_closing(&send_request) {
                        warn!(
                            "MASQUE server sent GOAWAY (draining); reconnecting before it \
                             cancels the CONNECT-IP request"
                        );
                        break;
                    }
                }
            }
        }
        closed_recv.store(true, Ordering::Relaxed);
        notify_recv.notify_waiters();
    });

    // Incoming IP packets arrive as H3 DATAGRAMs on the CONNECT stream.
    let incoming_recv = Arc::clone(&incoming);
    let closed_dgram = Arc::clone(&closed);
    let notify_dgram = Arc::clone(&notify);
    tokio::spawn(async move {
        loop {
            match datagram_reader.read_datagram().await {
                Ok(dgram) => {
                    // `dgram` is an owned `Datagram<Bytes>` already advanced
                    // past the quarter-stream-id varint by `Datagram::decode`;
                    // `into_payload` moves the `Bytes` out without copying.
                    let bytes = dgram.into_payload();
                    if let Some(packet) = crate::datagram::decode_h3_datagram_payload_owned(&bytes)
                    {
                        incoming_recv.lock().push_back(packet);
                        notify_dgram.notify_waiters();
                    }
                }
                Err(err) => {
                    warn!("h3 datagram read error: {err}");
                    closed_dgram.store(true, Ordering::Relaxed);
                    notify_dgram.notify_waiters();
                    break;
                }
            }
        }
    });

    // Outgoing packets are sent as H3 DATAGRAMs bound to the CONNECT stream.
    // Periodically emit a tiny heartbeat datagram so the QUIC connection and
    // CONNECT-IP session stay alive across application-level idle gaps
    // (transport keep-alive PINGs alone were insufficient). The cadence is
    // capped by `heartbeat_interval` so it never races the edge's reaper.
    let keepalive_tx = heartbeat_interval(keepalive);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(keepalive_tx);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // `write_packet` already emits the final wire layout
        // (quarter-stream-id header + context-id + packet) as one
        // contiguous Vec, so wrapping it into `Bytes` is a pure move —
        // no concat, no copy.
        loop {
            tokio::select! {
                msg = out_rx.recv() => {
                    match msg {
                        Ok(payload) => {
                            // `send_datagram_wait` blocks (applies backpressure)
                            // when the datagram send buffer is full instead of
                            // dropping oldest datagrams like `send_datagram` does.
                            match conn_send
                                .send_datagram_wait(Bytes::from(payload))
                                .await
                            {
                                Ok(()) => {}
                                // Unrecoverable for this packet only (e.g. an
                                // oversized IP packet): drop it and keep the
                                // tunnel running. Only breaking here would
                                // silently wedge the outbound channel.
                                Err(quinn::SendDatagramError::TooLarge) => {
                                    warn!("h3 datagram too large, dropping packet");
                                }
                                Err(err) => {
                                    warn!("h3 datagram send error: {err}");
                                    break;
                                }
                            }
                        }
                        // All senders dropped (session torn down): exit the task.
                        Err(_) => break,
                    }
                }
                _ = tick.tick() => {
                    let mut ping = bytes::BytesMut::with_capacity(header.len() + 1);
                    ping.put_slice(&header);
                    crate::capsule::put_varint(&mut ping, 0);
                    if conn_send.send_datagram_wait(ping.freeze()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    Ok(ConnectIpSession::with_capacity(
        incoming,
        notify,
        Transport::H3Quinn {
            header: header_out,
            out: out_tx,
            conn: Some(conn_close),
        },
        closed,
        1500,
    ))
}

#[cfg(test)]
mod tests {
    use super::{heartbeat_interval, MAX_HEARTBEAT};
    use bytes::Bytes;
    use h3_datagram::datagram::Datagram;

    /// The inbound datagram path must not copy: `Datagram::decode`
    /// advances past the quarter-stream-id varint, `into_payload`
    /// moves the `Bytes` out, and `decode_h3_datagram_payload_owned`
    /// slices off the context-id varint. All three steps only bump
    /// the refcount, so the decoded packet aliases the wire buffer.
    #[test]
    fn inbound_payload_aliases_wire_buffer() {
        // Wire layout: quarter-stream-id varint (1 byte, value 0) +
        // context-id varint (1 byte, value 0) + IPv4 TCP packet.
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2] = 0x00;
        packet[3] = 0x14;
        packet[8] = 63;
        packet[9] = 6;

        let mut wire = vec![0u8, 0u8];
        wire.extend_from_slice(&packet);
        let wire = Bytes::from(wire);

        let dgram = Datagram::decode(wire.clone()).expect("valid datagram");
        let payload = dgram.into_payload();
        let decoded =
            crate::datagram::decode_h3_datagram_payload_owned(&payload).expect("valid payload");

        assert_eq!(decoded.len(), packet.len());
        assert_eq!(&decoded[..], &packet[..]);
        // 1 byte quarter-stream-id + 1 byte context-id prefix skipped,
        // no copy in between.
        assert_eq!(
            decoded.as_ptr(),
            unsafe { wire.as_ptr().add(2) },
            "decoded packet must alias the wire buffer"
        );
    }

    /// The idle heartbeat must stay well below the edge's session reaper
    /// even when the user asks for a long transport keep-alive.
    #[test]
    fn heartbeat_is_capped_below_edge_reaper() {
        use std::time::Duration;

        assert_eq!(heartbeat_interval(Duration::from_secs(30)), MAX_HEARTBEAT);
        assert_eq!(heartbeat_interval(Duration::from_secs(60)), MAX_HEARTBEAT);
        assert_eq!(
            heartbeat_interval(Duration::from_secs(2)),
            Duration::from_secs(2)
        );
        assert!(MAX_HEARTBEAT < Duration::from_secs(20));
    }
}
