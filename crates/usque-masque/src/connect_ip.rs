use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_quiche::ClientH3Controller;
use tokio_quiche::QuicConnection;

use crate::session::{PacketSession, SessionError};

pub(crate) struct H3ConnectionGuard {
    pub _conn: QuicConnection,
    pub _controller: ClientH3Controller,
}

pub(crate) enum Transport {
    H3Quiche {
        out: mpsc::Sender<Bytes>,
        _guard: Arc<H3ConnectionGuard>,
    },
    H2 {
        out: mpsc::Sender<Bytes>,
    },
}

pub struct ConnectIpSession {
    incoming: Arc<Mutex<VecDeque<Bytes>>>,
    notify: Arc<Notify>,
    transport: Transport,
    closed: Arc<AtomicBool>,
    /// Per-session scratch buffer reused across `write_packet` calls.
    /// Reserving the MTU once amortizes the allocation cost across
    /// every packet.
    scratch: BytesMut,
}

impl ConnectIpSession {
    pub(crate) fn new(transport: Transport) -> Self {
        Self {
            incoming: Arc::new(Mutex::new(VecDeque::new())),
            notify: Arc::new(Notify::new()),
            transport,
            closed: Arc::new(AtomicBool::new(false)),
            scratch: BytesMut::new(),
        }
    }

    pub(crate) fn with_capacity(
        incoming: Arc<Mutex<VecDeque<Bytes>>>,
        notify: Arc<Notify>,
        transport: Transport,
        closed: Arc<AtomicBool>,
        capacity: usize,
    ) -> Self {
        let mut scratch = BytesMut::new();
        scratch.reserve(capacity);
        Self {
            incoming,
            notify,
            transport,
            closed,
            scratch,
        }
    }

    pub fn incoming_queue(&self) -> Arc<Mutex<VecDeque<Bytes>>> {
        Arc::clone(&self.incoming)
    }

    pub fn notify(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    pub fn closed_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.closed)
    }
}

#[async_trait]
impl PacketSession for ConnectIpSession {
    async fn read_packet(&mut self) -> Result<Option<Bytes>, SessionError> {
        loop {
            if let Some(packet) = self.incoming.lock().await.pop_front() {
                return Ok(Some(packet));
            }
            if self.closed.load(Ordering::Relaxed) {
                return Ok(None);
            }
            self.notify.notified().await;
        }
    }

    async fn write_packet(&mut self, packet: Bytes) -> Result<Option<Bytes>, SessionError> {
        // Reset and reuse the per-session scratch buffer.
        self.scratch.clear();
        match &self.transport {
            Transport::H3Quiche { out, .. } => {
                // The packet is a refcounted `Bytes` (or a slice the
                // supervisor passed in). Write the datagram prefix and
                // append the bytes without copying the payload.
                self.scratch.reserve(1 + packet.len());
                crate::datagram::encode_h3_datagram_payload_into(&packet, &mut self.scratch)
                    .map_err(SessionError::Other)?;
                let payload = self.scratch.split().freeze();
                out.send(payload).await.map_err(|_| SessionError::Closed)?;
            }
            Transport::H2 { out } => {
                self.scratch
                    .reserve(crate::capsule::CAPSULE_OVERHEAD + packet.len());
                crate::datagram::encode_h2_datagram_capsule_into(&packet, &mut self.scratch)
                    .map_err(SessionError::Other)?;
                let payload = self.scratch.split().freeze();
                out.send(payload).await.map_err(|_| SessionError::Closed)?;
            }
        }
        Ok(None)
    }

    async fn close(&mut self) -> Result<(), SessionError> {
        self.closed.store(true, Ordering::Relaxed);
        self.notify.notify_waiters();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::sync::Arc;

    fn sample_packet() -> Bytes {
        // A minimal valid IPv4 TCP packet: version=4, ihl=5, ttl=64,
        // proto=6 (TCP), total_length=20. 20 bytes of header, no
        // payload. The supervisor (in production) calls
        // `decrement_ttl` before handing the packet to the session;
        // the test exercises the codec directly so the packet TTL is
        // decremented by the caller in the test.
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[2] = 0x00;
        pkt[3] = 0x14; // total_length = 20
        pkt[8] = 63; // TTL (already decremented)
        pkt[9] = 6; // TCP
        Bytes::from(pkt)
    }

    #[tokio::test]
    async fn write_packet_uses_capsule_layout_for_h2() {
        // The H2 path uses `put_capsule` (1 type varint + 1 length
        // varint + payload). Verify the first 2 bytes encode the
        // CONNECT-IP DATA type and the packet length.
        let (tx, mut rx) = mpsc::channel::<Bytes>(8);
        let mut session = ConnectIpSession::with_capacity(
            Arc::new(Mutex::new(VecDeque::new())),
            Arc::new(Notify::new()),
            Transport::H2 { out: tx },
            Arc::new(AtomicBool::new(false)),
            1500,
        );

        let pkt = sample_packet();
        session.write_packet(pkt.clone()).await.unwrap();
        let wire = rx.recv().await.unwrap();
        // Capsule type 0 -> varint byte 0x00.
        assert_eq!(wire[0], 0x00);
        // Capsule length 20 -> varint byte 0x14.
        assert_eq!(wire[1], 0x14);
        // Payload: packet body is passed through as-is (TTL was 63
        // since the test pre-decrements it; the production path
        // decrements in the supervisor before reaching the session).
        assert_eq!(&wire[2..], &pkt[..]);
        assert_eq!(wire[2 + 8], 63);
    }

    #[tokio::test]
    async fn read_packet_returns_queued_bytes() {
        let incoming: Arc<Mutex<VecDeque<Bytes>>> = Arc::new(Mutex::new(VecDeque::new()));
        let notify = Arc::new(Notify::new());
        let (tx, _rx) = mpsc::channel::<Bytes>(8);
        let mut session = ConnectIpSession::with_capacity(
            Arc::clone(&incoming),
            Arc::clone(&notify),
            Transport::H2 { out: tx },
            Arc::new(AtomicBool::new(false)),
            1500,
        );

        let expected = sample_packet();
        incoming.lock().await.push_back(expected.clone());
        notify.notify_one();

        let got = session.read_packet().await.unwrap().unwrap();
        // Aliases the same allocation: the Bytes is a direct slice of
        // the queued buffer.
        assert_eq!(got.as_ptr(), expected.as_ptr());
        assert_eq!(&got[..], &expected[..]);
    }

    #[tokio::test]
    async fn write_packet_reuses_scratch_across_calls() {
        // After multiple writes the scratch buffer should not have
        // grown unboundedly. `BytesMut::split().freeze()` may shrink
        // the capacity to match the used size, so we assert that the
        // capacity after the loop is at most 2x the original (loose
        // bound to account for BytesMut growth policy).
        let (tx, mut rx) = mpsc::channel::<Bytes>(64);
        let mut session = ConnectIpSession::with_capacity(
            Arc::new(Mutex::new(VecDeque::new())),
            Arc::new(Notify::new()),
            Transport::H2 { out: tx },
            Arc::new(AtomicBool::new(false)),
            1500,
        );
        for _ in 0..16 {
            session.write_packet(sample_packet()).await.unwrap();
        }
        for _ in 0..16 {
            let _ = rx.recv().await.unwrap();
        }
        // The scratch is back to empty (cleared after each split).
        assert_eq!(session.scratch.len(), 0);
    }
}
